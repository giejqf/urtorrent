// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! One task per peer connection. The task owns the socket, feeds received
//! bytes into the sans-IO [`wire::Connection`], acts on the events it returns;
//! a companion writer task flushes whatever the connection queued (through
//! the session and torrent upload limiters), and an uploader task serves the
//! peer's requests from disk with backpressure on the outbound queue. All end
//! when the peer's [`Flag`] is set.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use metainfo::Bitfield;
use picker::Picker;
use uring::{Buffer, TcpStream};
use wire::{Connection, ConnectionParams, Event as WireEvent, Handshake, PeerHave, Request, Role};

use super::Ctx;
use super::local::{Either, Flag, Notify, select2};
use super::rate::Limiter;
use super::torrent::{self, INACTIVITY_TIMEOUT, KEEPALIVE_AFTER, REQUEST_TIMEOUT, Torrent};
use crate::api::{EncryptionMode, Event, PeerInfo, PeerSource};

/// Time allowed for an incoming peer to send its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Outgoing connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared view of one connection.
pub struct PeerHandle {
    pub key: u32,
    pub addr: SocketAddr,
    /// Our end of the connection (which listen family it belongs to).
    pub local: SocketAddr,
    pub incoming: bool,
    pub conn: RefCell<Connection>,
    /// Wakes the writer.
    pub out: Rc<Notify>,
    /// Set to end both tasks.
    close: Rc<Flag>,
    close_reason: RefCell<Option<String>>,
    pub downloaded: Cell<u64>,
    pub uploaded: Cell<u64>,
    client: RefCell<Option<String>>,
    peer_id: Cell<Option<[u8; 20]>>,
    last_recv: Cell<Instant>,
    last_send: Cell<Instant>,
    request_times: RefCell<Vec<(Request, Instant)>>,
    /// The availability this peer currently contributes to the picker.
    last_have: RefCell<Bitfield>,
    rate: Cell<u64>,
    rate_mark: Cell<u64>,
    /// Requests from the peer waiting to be read from disk and sent.
    upload_queue: RefCell<VecDeque<Request>>,
    upload_notify: Rc<Notify>,
    /// Signalled by the writer after each send (uploader backpressure).
    drained: Rc<Notify>,
    /// When we last unchoked this peer (choker rotation).
    pub last_unchoke: Cell<Option<Instant>>,
    /// MSE RC4 streams, when negotiated.
    cipher: RefCell<Cipher>,
    /// Negotiated encryption, for `PeerInfo`.
    pub encrypted: Cell<bool>,
    /// How we learned of the peer.
    pub source: PeerSource,
    /// The listen port the peer advertised (LTEP `p`).
    pub listen_port: Cell<Option<u16>>,
    /// The peer advertised `ut_holepunch`.
    pub holepunch: Cell<bool>,
    /// BEP 11 state.
    pub pex: RefCell<super::pex::PeerState>,
    /// BEP 9 state.
    pub meta: RefCell<super::metadata::PeerState>,
}

/// The RC4 layer between the socket and `wire` (absent for plaintext).
#[derive(Default)]
pub struct Cipher {
    pub enc: Option<mse::Rc4Stream>,
    pub dec: Option<mse::Rc4Stream>,
}

/// Outbound bytes queued beyond which the uploader waits for the writer.
const UPLOAD_BACKLOG: usize = 256 * 1024;
/// Disk reads the uploader keeps in flight per peer (16 KiB blocks: 256 KiB).
const UPLOAD_READ_BATCH: usize = 16;
/// Receive buffer size (and the largest download-limiter grant per read).
const RECV_SIZE: u64 = 64 * 1024;

impl PeerHandle {
    fn new(
        key: u32,
        addr: SocketAddr,
        local: SocketAddr,
        incoming: bool,
        conn: Connection,
        pieces: usize,
        source: PeerSource,
    ) -> PeerHandle {
        let now = Instant::now();
        PeerHandle {
            key,
            addr,
            local,
            incoming,
            conn: RefCell::new(conn),
            out: Notify::new(),
            close: Flag::new(),
            close_reason: RefCell::new(None),
            downloaded: Cell::new(0),
            uploaded: Cell::new(0),
            client: RefCell::new(None),
            peer_id: Cell::new(None),
            last_recv: Cell::new(now),
            last_send: Cell::new(now),
            request_times: RefCell::new(Vec::new()),
            last_have: RefCell::new(Bitfield::new(pieces)),
            rate: Cell::new(0),
            rate_mark: Cell::new(0),
            upload_queue: RefCell::new(VecDeque::new()),
            upload_notify: Notify::new(),
            drained: Notify::new(),
            last_unchoke: Cell::new(None),
            cipher: RefCell::new(Cipher::default()),
            encrypted: Cell::new(false),
            source,
            listen_port: Cell::new(None),
            holepunch: Cell::new(false),
            pex: RefCell::new(Default::default()),
            meta: RefCell::new(Default::default()),
        }
    }

    /// The address this peer is exchanged under (BEP 11): the remote address
    /// of a connection we dialled; for an incoming one, its IP with the
    /// listen port it advertised, or nothing.
    pub fn pex_addr(&self) -> Option<SocketAddr> {
        if !self.incoming {
            return Some(self.addr);
        }
        self.listen_port
            .get()
            .filter(|p| *p != 0)
            .map(|p| SocketAddr::new(self.addr.ip(), p))
    }

    /// BEP 21: tell the peer whether we are upload-only.
    pub fn send_upload_only(&self, on: bool) {
        let payload = wire::ext::upload_only_payload(on);
        if self.conn.borrow_mut().extended("upload_only", &payload) {
            self.out.notify();
        }
    }

    /// The metadata became known (BEP 9): size the connection, announce our
    /// have-state, refresh availability and interest.
    pub fn on_metadata(&self, torrent: &Rc<RefCell<Torrent>>, pieces: usize, have: &Bitfield) {
        let r = self.conn.borrow_mut().set_metadata(pieces, have.clone());
        match r {
            Ok(_) => {}
            Err(e) => {
                self.close(&format!("protocol: {e}"));
                return;
            }
        }
        let mut t = torrent.borrow_mut();
        *self.last_have.borrow_mut() = Bitfield::new(pieces);
        self.sync_availability(&mut t.picker, pieces);
        self.update_interest(&t.picker);
        self.send_upload_only(t.is_complete());
        self.out.notify();
    }

    /// Choke or unchoke (choker decision). Choking drops the upload queue;
    /// `wire` rejects the peer's queued requests when the fast extension is on.
    pub fn set_choked(&self, choke: bool, now: Instant) {
        let mut conn = self.conn.borrow_mut();
        if conn.am_choking() == choke {
            return;
        }
        conn.choke(choke);
        drop(conn);
        if choke {
            self.upload_queue.borrow_mut().clear();
        } else {
            self.last_unchoke.set(Some(now));
        }
        self.out.notify();
    }

    /// Bytes per second we receive from this peer (smoothed).
    pub fn download_rate(&self) -> u64 {
        self.rate.get()
    }

    /// Whether the peer is interested and we choke it (choker input).
    pub fn choke_state(&self) -> (bool, bool, bool) {
        let c = self.conn.borrow();
        (c.is_established(), c.peer_interested(), c.am_choking())
    }

    /// Ask the tasks to end.
    pub fn close(&self, reason: &str) {
        if self.close_reason.borrow().is_none() {
            *self.close_reason.borrow_mut() = Some(reason.to_string());
        }
        self.close.set();
    }

    pub fn is_seed(&self, pieces: usize) -> bool {
        self.conn.borrow().peer_have().is_seed(pieces)
    }

    pub fn info(&self, pieces: usize) -> PeerInfo {
        let conn = self.conn.borrow();
        let have = conn.peer_have();
        PeerInfo {
            addr: self.addr,
            source: self.source,
            peer_id: self.peer_id.get(),
            client: self.client.borrow().clone(),
            incoming: self.incoming,
            downloaded: self.downloaded.get(),
            uploaded: self.uploaded.get(),
            pieces: match have {
                PeerHave::All => pieces,
                PeerHave::Pieces(b) => b.count(),
                _ => 0,
            },
            is_seed: have.is_seed(pieces),
            peer_choking: conn.peer_choking(),
            am_interested: conn.am_interested(),
            outstanding: conn.outstanding().len(),
            encrypted: self.encrypted.get(),
            upload_only: conn.peer_upload_only() || have.is_seed(pieces),
        }
    }

    /// Interested iff the peer has a wanted piece we lack.
    pub fn update_interest(&self, picker: &Picker) {
        let mut conn = self.conn.borrow_mut();
        if !conn.is_established() {
            return;
        }
        let interested = match conn.peer_have() {
            PeerHave::All => !picker.is_complete(),
            PeerHave::Pieces(b) => b
                .iter_set()
                .any(|i| !picker.have(i) && picker.priority(i) > 0),
            _ => false,
        };
        let was = conn.am_interested();
        conn.interested(interested);
        if was != interested {
            self.out.notify();
        }
    }

    /// Bring this peer's availability contribution up to date.
    fn sync_availability(&self, picker: &mut Picker, pieces: usize) {
        let now = self.conn.borrow().peer_have().to_bitfield(pieces);
        let mut last = self.last_have.borrow_mut();
        if *last != now {
            picker.peer_left(&last);
            picker.peer_joined(&now);
            *last = now;
        }
    }

    /// Request more blocks if the pipeline has room.
    pub fn fill_requests(&self, torrent: &Rc<RefCell<Torrent>>, ctx: &Ctx) {
        let mut t = torrent.borrow_mut();
        self.fill_requests_locked(&mut t, ctx);
    }

    /// As [`PeerHandle::fill_requests`], with the torrent already borrowed.
    pub fn fill_requests_locked(&self, t: &mut Torrent, ctx: &Ctx) {
        if !t.is_running() || !t.has_metadata() || t.is_complete() {
            return;
        }
        let mut conn = self.conn.borrow_mut();
        if !conn.is_established() || !conn.am_interested() {
            return;
        }
        let choking = conn.peer_choking();
        let allowed: Vec<u32> = conn.allowed_fast().to_vec();
        if choking && allowed.is_empty() {
            return;
        }
        let depth = torrent::pipeline_depth(self.rate.get());
        let outstanding = conn.outstanding().len();
        if outstanding >= depth {
            return;
        }
        let have = conn.peer_have().clone();
        let has = |i: usize| have.has(i) && (!choking || allowed.contains(&(i as u32)));
        let blocks = torrent::pick_blocks(ctx, &mut t.picker, self.key, &has, depth - outstanding);
        if blocks.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut times = self.request_times.borrow_mut();
        for b in blocks {
            let r = Request {
                index: b.piece,
                begin: b.offset,
                length: b.length,
            };
            if conn.request(r) {
                times.push((r, now));
            } else {
                t.picker.release(self.key, &b);
            }
        }
        self.out.notify();
    }

    /// Once-a-second housekeeping: request timeouts, keep-alive, rate.
    pub fn tick(&self, t: &mut Torrent, ctx: &Ctx, now: Instant) {
        {
            let mut conn = self.conn.borrow_mut();
            let outstanding: Vec<Request> = conn.outstanding().to_vec();
            let mut times = self.request_times.borrow_mut();
            times.retain(|(r, _)| outstanding.contains(r));
            let mut timed_out = Vec::new();
            times.retain(|(r, at)| {
                if now.duration_since(*at) > REQUEST_TIMEOUT {
                    timed_out.push(*r);
                    false
                } else {
                    true
                }
            });
            for r in timed_out {
                conn.cancel(r);
                t.picker.release(
                    self.key,
                    &picker::Block {
                        piece: r.index,
                        offset: r.begin,
                        length: r.length,
                    },
                );
                self.out.notify();
            }
            if conn.is_established() && now.duration_since(self.last_send.get()) > KEEPALIVE_AFTER {
                conn.keep_alive();
                self.out.notify();
            }
        }
        let d = self.downloaded.get() - self.rate_mark.get();
        self.rate_mark.set(self.downloaded.get());
        self.rate.set((self.rate.get() * 3 + d) / 4);
        // Pieces may have been released by others; keep the pipeline full.
        self.fill_requests_locked(t, ctx);
    }
}

fn connection_params(
    ctx: &Ctx,
    t: &Torrent,
    role: Role,
    peer_ip: std::net::IpAddr,
    local_ip: std::net::IpAddr,
) -> ConnectionParams {
    ConnectionParams {
        role,
        info_hash: t.info_hash,
        our_peer_id: ctx.handshake_peer_id(t),
        profile: ctx.cfg.profile.clone(),
        piece_count: t.info.as_ref().map(|i| i.piece_count()),
        our_have: t
            .storage
            .as_ref()
            .map_or_else(|| Bitfield::new(0), |s| s.have()),
        listen_port: ctx.listen_port,
        peer_ip: Some(peer_ip),
        metadata_size: t.has_metadata().then_some(t.metadata_size),
        // Q6: `p` only when the listen family's external address matches our
        // end of this connection (v4 matches while nothing is voted).
        advertise_port: ctx.advertise_port_for(local_ip),
        private: t.private,
    }
}

/// MSE `allowed` mask for the session's policy.
fn allowed_mask(ctx: &Ctx) -> u32 {
    match ctx.cfg.encryption {
        EncryptionMode::Disabled => 0,
        EncryptionMode::Enabled => mse::allowed_mask(true, true),
        EncryptionMode::Forced => mse::allowed_mask(false, true),
    }
}

/// Run the MSE initiator over a fresh socket. `ia` is our BitTorrent
/// handshake (sent inside the crypto handshake). Returns the cipher and any
/// plaintext that followed pe4.
async fn mse_initiate(
    ctx: &Rc<Ctx>,
    stream: &TcpStream,
    info_hash: metainfo::InfoHash,
    ia: Vec<u8>,
) -> Result<(Cipher, Vec<u8>), String> {
    let mut rng = super::rng::RngRef(&ctx.rng);
    let mut init =
        mse::Initiator::new(info_hash, ctx.dh_private(), ia, allowed_mask(ctx), &mut rng);
    stream
        .send_all(Buffer::from_vec(init.take_outbound()))
        .await
        .map_err(|e| format!("send: {e}"))?;
    loop {
        let (r, buf) = stream.recv(Buffer::from_vec(vec![0u8; 4096])).await;
        match r {
            Ok(0) => return Err("closed during mse handshake".into()),
            Err(e) => return Err(format!("recv: {e}")),
            Ok(_) => {}
        }
        match init.receive(buf.as_slice(), &mut rng) {
            Ok(Some(outcome)) => {
                let out = init.take_outbound();
                if !out.is_empty() {
                    stream
                        .send_all(Buffer::from_vec(out))
                        .await
                        .map_err(|e| format!("send: {e}"))?;
                }
                return Ok((
                    Cipher {
                        enc: outcome.encrypt,
                        dec: outcome.decrypt,
                    },
                    outcome.plaintext,
                ));
            }
            Ok(None) => {
                let out = init.take_outbound();
                if !out.is_empty() {
                    stream
                        .send_all(Buffer::from_vec(out))
                        .await
                        .map_err(|e| format!("send: {e}"))?;
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Connect out to `addr` for `torrent` and run the connection.
pub async fn run_outgoing(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>, addr: SocketAddr) {
    // Outgoing connections originate from the listen address when one is
    // configured (libtorrent binds them to the listen interface).
    let local = match addr {
        SocketAddr::V4(_) => ctx
            .cfg
            .listen_v4
            .filter(|a| !a.is_unspecified())
            .map(std::net::IpAddr::V4),
        SocketAddr::V6(_) => ctx
            .cfg
            .listen_v6
            .filter(|a| !a.is_unspecified())
            .map(std::net::IpAddr::V6),
    };
    let connected = match local {
        Some(l) => uring::timeout(CONNECT_TIMEOUT, TcpStream::connect_from(l, addr)).await,
        None => uring::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await,
    };
    let (stream, use_mse) = {
        let mut t = torrent.borrow_mut();
        t.half_open = t.half_open.saturating_sub(1);
        t.connecting.remove(&addr);
        let stream = match connected {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!(%addr, "connect failed: {e}");
                t.note_disconnect(addr, Instant::now());
                return;
            }
            Err(_) => {
                tracing::debug!(%addr, "connect timed out");
                t.note_disconnect(addr, Instant::now());
                return;
            }
        };
        // Q3: "enabled" connects out in plaintext first and retries with MSE
        // after a failed attempt (libtorrent toggles `pe_support` per peer).
        let use_mse = match ctx.cfg.encryption {
            EncryptionMode::Disabled => false,
            EncryptionMode::Forced => true,
            EncryptionMode::Enabled => t.mse_retry.contains(&addr),
        };
        (stream, use_mse)
    };
    let local_addr = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(addr.ip(), 0));
    let (mut conn, info_hash) = {
        let t = torrent.borrow();
        if t.closing.is_set() || !t.is_running() || t.has_peer_ip(addr.ip()) {
            return;
        }
        (
            Connection::new(connection_params(
                &ctx,
                &t,
                Role::Initiator,
                addr.ip(),
                local_addr.ip(),
            )),
            t.info_hash,
        )
    };
    let _ = stream.set_nodelay(true);
    let mut cipher = Cipher::default();
    let mut initial = Vec::new();
    if use_mse {
        // The connection queued our handshake; it travels as IA.
        let ia = conn.take_outbound();
        match uring::timeout(
            HANDSHAKE_TIMEOUT,
            mse_initiate(&ctx, &stream, info_hash, ia),
        )
        .await
        {
            Ok(Ok((c, rest))) => {
                cipher = c;
                initial = rest;
            }
            Ok(Err(e)) => {
                tracing::debug!(%addr, "mse initiator failed: {e}");
                let mut t = torrent.borrow_mut();
                t.mse_retry.remove(&addr);
                t.note_disconnect(addr, Instant::now());
                return;
            }
            Err(_) => {
                tracing::debug!(%addr, "mse handshake timed out");
                let mut t = torrent.borrow_mut();
                t.mse_retry.remove(&addr);
                t.note_disconnect(addr, Instant::now());
                return;
            }
        }
    }
    let source = torrent.borrow().source_of(addr);
    run_connection(
        ctx, torrent, stream, conn, addr, local_addr, false, initial, cipher, source,
    )
    .await;
}

/// An accepted socket: read the handshake (plaintext, or through an MSE
/// responder handshake), find the torrent, run.
pub async fn run_incoming(ctx: Rc<Ctx>, stream: TcpStream) {
    let Ok(addr) = stream.peer_addr() else { return };
    let local_addr = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(addr.ip(), ctx.listen_port));
    let mut raw: Vec<u8> = Vec::with_capacity(wire::HANDSHAKE_LEN);
    let mut cipher = Cipher::default();
    // Read until we can tell plaintext from MSE (20 bytes), then finish the
    // respective handshake.
    let hs = loop {
        let chunk = Buffer::from_vec(vec![0u8; 4096]);
        match uring::timeout(HANDSHAKE_TIMEOUT, stream.recv(chunk)).await {
            Ok((Ok(0), _)) | Ok((Err(_), _)) | Err(_) => return,
            Ok((Ok(_), b)) => raw.extend_from_slice(b.as_slice()),
        }
        if raw.len() < 20 {
            continue;
        }
        let plaintext_head = Handshake::parse(&raw[..20.min(raw.len())]).is_ok();
        if plaintext_head {
            if ctx.cfg.encryption == EncryptionMode::Forced {
                tracing::debug!(%addr, "incoming plaintext refused (encryption forced)");
                return;
            }
            // Plain handshake: finish reading it.
            loop {
                match Handshake::parse(&raw) {
                    Ok(Some(_)) => break,
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(%addr, "incoming: {e}");
                        return;
                    }
                }
                let chunk = Buffer::from_vec(vec![0u8; 1024]);
                match uring::timeout(HANDSHAKE_TIMEOUT, stream.recv(chunk)).await {
                    Ok((Ok(0), _)) | Ok((Err(_), _)) | Err(_) => return,
                    Ok((Ok(_), b)) => raw.extend_from_slice(b.as_slice()),
                }
            }
            break match Handshake::parse(&raw) {
                Ok(Some(hs)) => hs,
                _ => return,
            };
        }
        if ctx.cfg.encryption == EncryptionMode::Disabled {
            tracing::debug!(%addr, "incoming: not a BitTorrent handshake (encryption disabled)");
            return;
        }
        // MSE responder.
        let mut rng = super::rng::RngRef(&ctx.rng);
        let mut resp = mse::Responder::new(
            ctx.dh_private(),
            allowed_mask(&ctx),
            ctx.cfg.profile.mse.prefer_rc4,
        );
        let torrents = ctx.info_hashes();
        let mut pending = std::mem::take(&mut raw);
        let outcome = loop {
            match resp.receive(&pending, &torrents, &mut rng) {
                Ok(Some(o)) => {
                    let out = resp.take_outbound();
                    if !out.is_empty() && stream.send_all(Buffer::from_vec(out)).await.is_err() {
                        return;
                    }
                    break o;
                }
                Ok(None) => {
                    let out = resp.take_outbound();
                    if !out.is_empty() && stream.send_all(Buffer::from_vec(out)).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    tracing::debug!(%addr, "incoming mse: {e}");
                    return;
                }
            }
            let chunk = Buffer::from_vec(vec![0u8; 4096]);
            match uring::timeout(HANDSHAKE_TIMEOUT, stream.recv(chunk)).await {
                Ok((Ok(0), _)) | Ok((Err(_), _)) | Err(_) => return,
                Ok((Ok(_), b)) => pending = b.as_slice().to_vec(),
            }
        };
        cipher = Cipher {
            enc: outcome.encrypt,
            dec: outcome.decrypt,
        };
        raw = outcome.plaintext;
        // The peer's handshake is (the start of) the decrypted plaintext.
        loop {
            match Handshake::parse(&raw) {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!(%addr, "incoming (mse): {e}");
                    return;
                }
            }
            let chunk = Buffer::from_vec(vec![0u8; 1024]);
            match uring::timeout(HANDSHAKE_TIMEOUT, stream.recv(chunk)).await {
                Ok((Ok(0), _)) | Ok((Err(_), _)) | Err(_) => return,
                Ok((Ok(_), mut b)) => {
                    if let Some(d) = cipher.dec.as_mut() {
                        d.apply(b.as_mut_slice());
                    }
                    raw.extend_from_slice(b.as_slice());
                }
            }
        }
        break match Handshake::parse(&raw) {
            Ok(Some(hs)) => hs,
            _ => return,
        };
    };
    let Some(torrent) = ctx.torrent_by_hash(&hs.info_hash) else {
        tracing::debug!(%addr, "incoming for unknown torrent");
        return;
    };
    let conn = {
        let t = torrent.borrow();
        if t.closing.is_set()
            || !t.is_running()
            || t.is_banned(addr.ip())
            || t.peers.len() >= ctx.cfg.max_peers
            || ctx.connection_count_except(Some(t.id)) + t.peers.len() + t.half_open
                >= ctx.cfg.max_connections
        {
            return;
        }
        Connection::new(connection_params(
            &ctx,
            &t,
            Role::Responder,
            addr.ip(),
            local_addr.ip(),
        ))
    };
    let _ = stream.set_nodelay(true);
    run_connection(
        ctx,
        torrent,
        stream,
        conn,
        addr,
        local_addr,
        true,
        raw,
        cipher,
        PeerSource::Incoming,
    )
    .await;
}

/// The connection's main loop. `initial` holds bytes already read (the
/// incoming handshake and whatever followed it).
#[allow(clippy::too_many_arguments)]
async fn run_connection(
    ctx: Rc<Ctx>,
    torrent: Rc<RefCell<Torrent>>,
    stream: TcpStream,
    conn: Connection,
    addr: SocketAddr,
    local: SocketAddr,
    incoming: bool,
    initial: Vec<u8>,
    cipher: Cipher,
    source: PeerSource,
) {
    let key = ctx.new_peer_key();
    let pieces = torrent.borrow().piece_count();
    let handle = Rc::new(PeerHandle::new(
        key, addr, local, incoming, conn, pieces, source,
    ));
    handle.encrypted.set(cipher.enc.is_some());
    *handle.cipher.borrow_mut() = cipher;
    torrent.borrow_mut().peers.insert(key, handle.clone());
    let stream = Rc::new(stream);
    uring::spawn(writer(
        ctx.clone(),
        torrent.clone(),
        stream.clone(),
        handle.clone(),
    ));
    uring::spawn(uploader(ctx.clone(), torrent.clone(), handle.clone()));

    let mut reason: Option<String> = None;
    if !initial.is_empty() {
        // `initial` is plaintext already (decrypted by the MSE handshake, or
        // a plain handshake), so bypass the cipher for it.
        reason = process_plain(&ctx, &torrent, &handle, &initial).await.err();
    }
    handle.out.notify();
    let down_limit = torrent.borrow().down_limit.clone();
    while reason.is_none() {
        // Download limits: take a grant before posting the receive and size
        // the buffer to it; refund what the read did not use.
        let grant = match select2(
            acquire_pair(&ctx.down_limit, &down_limit, RECV_SIZE),
            handle.close.wait(),
        )
        .await
        {
            Either::Left(g) => g,
            Either::Right(()) => break,
        };
        let mut buf = ctx.recv_pool.take_sized();
        if (grant as usize) < buf.len() {
            buf.truncate(grant as usize);
        }
        match select2(
            uring::timeout(INACTIVITY_TIMEOUT, stream.recv(buf)),
            handle.close.wait(),
        )
        .await
        {
            Either::Left(Ok((Ok(0), _))) => reason = Some("peer closed the connection".into()),
            Either::Left(Ok((Ok(n), buf))) => {
                refund_pair(
                    &ctx.down_limit,
                    &down_limit,
                    grant.saturating_sub(u64::from(n)),
                );
                handle.last_recv.set(Instant::now());
                if let Err(e) = process_bytes(&ctx, &torrent, &handle, buf.as_slice()).await {
                    reason = Some(e);
                }
            }
            Either::Left(Ok((Err(e), _))) => reason = Some(format!("recv: {e}")),
            Either::Left(Err(_)) => reason = Some("inactive".into()),
            Either::Right(()) => break,
        }
    }
    let reason = reason.unwrap_or_else(|| {
        handle
            .close_reason
            .borrow()
            .clone()
            .unwrap_or_else(|| "closed".into())
    });
    handle.close(&reason);
    // Cleanup: bookkeeping in the torrent, then the socket closes through the
    // ring when the last `Rc<TcpStream>` drops.
    let id = {
        let mut t = torrent.borrow_mut();
        t.peers.remove(&key);
        t.picker.peer_gone(key);
        let last = handle.last_have.borrow().clone();
        t.picker.peer_left(&last);
        *handle.last_have.borrow_mut() = Bitfield::new(t.piece_count());
        // A connection dropped as a duplicate says nothing about the address:
        // no backoff (if both ends tossed the coin the wrong way, the next
        // tick dials again).
        if reason.starts_with("duplicate") {
            t.allow_reconnect_now(addr);
        } else if !incoming && ctx.cfg.encryption == EncryptionMode::Enabled {
            // Q3: a plaintext attempt that died before the handshake completed
            // makes the next attempt to this address encrypted (and soon).
            if handle.peer_id.get().is_none() && !handle.encrypted.get() {
                t.mse_retry.insert(addr);
                t.allow_reconnect_now(addr);
            } else if handle.peer_id.get().is_none() {
                t.mse_retry.remove(&addr);
                t.note_disconnect(addr, Instant::now());
            } else {
                t.note_disconnect(addr, Instant::now());
            }
        } else {
            // Do not dial this address again right away (libtorrent's
            // `min_reconnect_time`).
            t.note_disconnect(addr, Instant::now());
        }
        t.id
    };
    tracing::debug!(%addr, torrent = id.0, "peer disconnected: {reason}");
    if handle.peer_id.get().is_some() {
        let pieces = torrent.borrow().piece_count();
        ctx.emit(Event::PeerDisconnected {
            id,
            addr,
            reason,
            info: handle.info(pieces),
        });
    }
}

/// Feed bytes to the state machine and act on every resulting event.
async fn process_bytes(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    handle: &Rc<PeerHandle>,
    bytes: &[u8],
) -> Result<(), String> {
    let events = {
        let mut cipher = handle.cipher.borrow_mut();
        let mut conn = handle.conn.borrow_mut();
        match cipher.dec.as_mut() {
            Some(d) => {
                let mut plain = bytes.to_vec();
                d.apply(&mut plain);
                conn.receive(&plain)
            }
            None => conn.receive(bytes),
        }
        .map_err(|e| format!("protocol: {e}"))?
    };
    let mut writes = Vec::new();
    let mut result = Ok(());
    for ev in events {
        match handle_event(ctx, torrent, handle, ev, &mut writes).await {
            Ok(()) => {}
            Err(e) => {
                result = Err(e);
                break;
            }
        }
        if handle.close.is_set() {
            break;
        }
    }
    if handle.conn.borrow().has_outbound() {
        handle.out.notify();
    }
    // One disk round trip for the whole buffer.
    for w in writes {
        w.finish(ctx, torrent).await;
    }
    result
}

/// Like `process_bytes` for bytes that are already plaintext.
async fn process_plain(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    handle: &Rc<PeerHandle>,
    bytes: &[u8],
) -> Result<(), String> {
    let events = handle
        .conn
        .borrow_mut()
        .receive(bytes)
        .map_err(|e| format!("protocol: {e}"))?;
    let mut writes = Vec::new();
    let mut result = Ok(());
    for ev in events {
        match handle_event(ctx, torrent, handle, ev, &mut writes).await {
            Ok(()) => {}
            Err(e) => {
                result = Err(e);
                break;
            }
        }
        if handle.close.is_set() {
            break;
        }
    }
    if handle.conn.borrow().has_outbound() {
        handle.out.notify();
    }
    for w in writes {
        w.finish(ctx, torrent).await;
    }
    result
}

async fn handle_event(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    handle: &Rc<PeerHandle>,
    ev: WireEvent,
    writes: &mut Vec<torrent::PendingWrite>,
) -> Result<(), String> {
    match ev {
        WireEvent::Handshaked { peer_id, .. } => {
            let id = {
                let t = torrent.borrow();
                // libtorrent's duplicate rules (peer_list::new_connection and
                // bt_peer_connection::on_receive), so both ends drop the same
                // connection:
                // - the same peer id on another connection: the side with the
                //   greater id is the one allowed to initiate;
                // - the same IP (one connection per IP): equal directions
                //   drop the newcomer; otherwise the side with the lower
                //   *listen* port keeps its outgoing connection; equal ports
                //   toss a coin.
                let our_id = handle.conn.borrow().params().our_peer_id;
                let same_pid = t
                    .peers
                    .values()
                    .find(|p| p.key != handle.key && p.peer_id.get() == Some(peer_id))
                    .cloned();
                if let Some(other) = same_pid {
                    if (peer_id < our_id) == !handle.incoming {
                        other.close("duplicate peer id");
                    } else {
                        return Err("duplicate peer id".into());
                    }
                }
                let same_ip = t
                    .peers
                    .values()
                    .find(|p| p.key != handle.key && p.addr.ip() == handle.addr.ip())
                    .cloned();
                if let Some(other) = same_ip {
                    if other.incoming == handle.incoming {
                        return Err("duplicate connection".into());
                    }
                    let our_port = ctx.listen_port;
                    let other_port = if handle.incoming {
                        other.addr.port()
                    } else {
                        handle.addr.port()
                    };
                    let outgoing1 = !handle.incoming;
                    let drop_this = (our_port < other_port && !outgoing1)
                        || (our_port > other_port && outgoing1)
                        || (our_port == other_port && ctx.rng.next_u64() & 1 == 1);
                    if drop_this {
                        return Err("duplicate connection".into());
                    }
                    other.close("duplicate connection");
                }
                t.id
            };
            handle.peer_id.set(Some(peer_id));
            tracing::debug!(
                addr = %handle.addr,
                peer_id = %String::from_utf8_lossy(&peer_id),
                incoming = handle.incoming,
                "peer connected"
            );
            ctx.emit(Event::PeerConnected {
                id,
                addr: handle.addr,
                incoming: handle.incoming,
            });
            // libtorrent unchokes a fresh peer right away when it has pieces
            // and a slot is free, saving the round-trip should it be
            // interested (`capture_peer_plain`: `have_all, unchoke` before
            // the peer's `interested`).
            let has_pieces = {
                let t = torrent.borrow();
                t.has_metadata() && t.picker.have_count() > 0
            };
            if has_pieces {
                super::maybe_unchoke_now(ctx, torrent, handle);
            }
        }
        WireEvent::ExtHandshake(ext) => {
            *handle.client.borrow_mut() = ext.v.clone();
            handle.listen_port.set(ext.p);
            // `yourip`: the peer's view of our address is a vote for this
            // listen family's external address (libtorrent
            // `on_extended_handshake` → `set_external_address`).
            if let Some(ip) = ext.yourip {
                ctx.cast_external_vote(
                    handle.local.ip(),
                    ip,
                    super::external_ip::Source::Peer,
                    handle.addr.ip(),
                );
            }
            handle
                .holepunch
                .set(ext.peer_id_for("ut_holepunch").is_some());
            let mut t = torrent.borrow_mut();
            // libtorrent `upload_upload_connection`: two upload-only ends
            // have nothing to exchange.
            if t.is_complete() && handle.conn.borrow().peer_upload_only() {
                return Err("both upload-only".into());
            }
            super::metadata::on_ext_handshake(&mut t, handle, ext.metadata_size, Instant::now());
        }
        WireEvent::HaveChanged => {
            let mut t = torrent.borrow_mut();
            if !t.has_metadata() {
                return Ok(());
            }
            let pieces = t.piece_count();
            handle.sync_availability(&mut t.picker, pieces);
            if t.is_complete() && handle.is_seed(pieces) {
                return Err("both seeds".into());
            }
            handle.update_interest(&t.picker);
            handle.fill_requests_locked(&mut t, ctx);
        }
        WireEvent::Unchoked | WireEvent::AllowedFast(_) | WireEvent::Suggest(_) => {
            handle.fill_requests(torrent, ctx);
        }
        WireEvent::Choked { dropped } => {
            let mut t = torrent.borrow_mut();
            for r in dropped {
                t.picker.release(
                    handle.key,
                    &picker::Block {
                        piece: r.index,
                        offset: r.begin,
                        length: r.length,
                    },
                );
            }
            handle.request_times.borrow_mut().clear();
        }
        WireEvent::Block { request, data } => {
            handle
                .request_times
                .borrow_mut()
                .retain(|(r, _)| *r != request);
            if let Some(w) = torrent::on_block(ctx, torrent, handle, request, data).await {
                writes.push(w);
            }
        }
        WireEvent::UnexpectedBlock { length, .. } => {
            torrent.borrow_mut().stats.redundant += u64::from(length);
        }
        WireEvent::Rejected(r) => {
            handle.request_times.borrow_mut().retain(|(x, _)| *x != r);
            torrent.borrow_mut().picker.release(
                handle.key,
                &picker::Block {
                    piece: r.index,
                    offset: r.begin,
                    length: r.length,
                },
            );
        }
        WireEvent::Request(r) => {
            // `wire` already checked choke state / allowed-fast and bounds.
            handle.upload_queue.borrow_mut().push_back(r);
            handle.upload_notify.notify();
        }
        WireEvent::Cancel(r) => {
            handle.upload_queue.borrow_mut().retain(|x| *x != r);
        }
        WireEvent::Interested => {
            // Free slot: unchoke right away rather than at the next round.
            super::maybe_unchoke_now(ctx, torrent, handle);
        }
        WireEvent::Extended { id, payload } => {
            let name = {
                let conn = handle.conn.borrow();
                ["ut_pex", "ut_metadata", "upload_only", "lt_donthave"]
                    .into_iter()
                    .find(|n| conn.our_ext_id(n) == Some(id))
            };
            let now = Instant::now();
            match name {
                Some("ut_pex") => {
                    let mut t = torrent.borrow_mut();
                    super::pex::on_message(ctx, &mut t, handle, &payload, now)?;
                }
                Some("ut_metadata") => {
                    super::metadata::on_message(ctx, torrent, handle, &payload, now).await?;
                }
                Some("upload_only") => {
                    let on = wire::ext::parse_upload_only(&payload)
                        .map_err(|e| format!("protocol: {e}"))?;
                    handle.conn.borrow_mut().set_peer_upload_only(on);
                    let t = torrent.borrow();
                    if on && t.is_complete() {
                        return Err("both upload-only".into());
                    }
                }
                // `lt_donthave` and anything else we advertise but do not
                // act on is dropped, as the oracle does for a disabled feature.
                _ => {}
            }
        }
        WireEvent::NotInterested | WireEvent::Port(_) | WireEvent::KeepAlive => {}
    }
    Ok(())
}

/// Take a grant from the session limiter, then narrow it through the
/// torrent's; unused session tokens go back.
async fn acquire_pair(session: &Limiter, torrent: &Limiter, want: u64) -> u64 {
    let g1 = session.acquire(want).await;
    let g2 = torrent.acquire(g1).await;
    if g2 < g1 {
        session.refund(g1 - g2);
    }
    g2
}

fn refund_pair(session: &Limiter, torrent: &Limiter, n: u64) {
    if n > 0 {
        session.refund(n);
        torrent.refund(n);
    }
}

/// Flush the connection's outbound bytes as they appear, within the upload
/// limits.
async fn writer(
    ctx: Rc<Ctx>,
    torrent: Rc<RefCell<Torrent>>,
    stream: Rc<TcpStream>,
    handle: Rc<PeerHandle>,
) {
    let up_limit = torrent.borrow().up_limit.clone();
    loop {
        let mut out = handle.conn.borrow_mut().take_outbound();
        if let Some(e) = handle.cipher.borrow_mut().enc.as_mut() {
            e.apply(&mut out);
        }
        if out.is_empty() {
            match select2(handle.out.wait(), handle.close.wait()).await {
                Either::Left(()) => continue,
                Either::Right(()) => break,
            }
        }
        let total = out.len();
        let mut offset = 0usize;
        while offset < total {
            let remaining = (total - offset) as u64;
            let grant = if ctx.up_limit.is_unlimited() && up_limit.is_unlimited() {
                remaining
            } else {
                match select2(
                    acquire_pair(&ctx.up_limit, &up_limit, remaining.min(RECV_SIZE)),
                    handle.close.wait(),
                )
                .await
                {
                    Either::Left(g) => g,
                    Either::Right(()) => return,
                }
            } as usize;
            let chunk = if offset == 0 && grant == total {
                Buffer::from_vec(out.clone())
            } else {
                Buffer::from_vec(out[offset..offset + grant].to_vec())
            };
            match select2(stream.send_all(chunk), handle.close.wait()).await {
                Either::Left(Ok(_)) => {
                    handle.last_send.set(Instant::now());
                    offset += grant;
                }
                Either::Left(Err(e)) => {
                    handle.close(&format!("send: {e}"));
                    return;
                }
                Either::Right(()) => return,
            }
        }
        handle.drained.notify();
    }
}

/// Serve the peer's requests: read from disk, hand to the connection. Waits
/// when the outbound queue is deep so a slow peer cannot make us buffer a
/// whole torrent.
async fn uploader(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>, handle: Rc<PeerHandle>) {
    loop {
        if handle.upload_queue.borrow().is_empty() {
            match select2(handle.upload_notify.wait(), handle.close.wait()).await {
                Either::Left(()) => continue,
                Either::Right(()) => break,
            }
        }
        while handle.conn.borrow().outbound_len() > UPLOAD_BACKLOG {
            match select2(handle.drained.wait(), handle.close.wait()).await {
                Either::Left(()) => {}
                Either::Right(()) => return,
            }
        }
        if handle.close.is_set() {
            break;
        }
        let storage = torrent.borrow().storage.clone();
        torrent::wait_not_moving(&torrent).await;
        // Take a batch of requests and put every read in flight on the disk
        // thread before waiting for the first: the round trips overlap.
        let batch: Vec<Request> = {
            let mut q = handle.upload_queue.borrow_mut();
            let n = q.len().min(UPLOAD_READ_BATCH);
            q.drain(..n).collect()
        };
        let mut reads = Vec::with_capacity(batch.len());
        for r in batch {
            // Cancelled or choked meanwhile? `wire` dropped it from its queue.
            if !handle.conn.borrow().incoming_requests().contains(&r) {
                continue;
            }
            let Some(storage) = storage.as_ref() else {
                handle.conn.borrow_mut().reject(r);
                handle.out.notify();
                continue;
            };
            if !storage.has_piece(r.index as usize) {
                handle.conn.borrow_mut().reject(r);
                handle.out.notify();
                continue;
            }
            reads.push((r, storage.read_block(r.index as usize, r.begin, r.length)));
        }
        for (r, read) in reads {
            match read.await {
                Ok(data) => {
                    let mut conn = handle.conn.borrow_mut();
                    if conn.incoming_requests().contains(&r) {
                        conn.piece(r, &data);
                        drop(conn);
                        let n = u64::from(r.length);
                        handle.uploaded.set(handle.uploaded.get() + n);
                        torrent.borrow_mut().stats.uploaded += n;
                        handle.out.notify();
                    }
                }
                Err(e) => {
                    tracing::warn!(addr = %handle.addr, "read for upload failed: {e}");
                    handle.conn.borrow_mut().reject(r);
                    handle.out.notify();
                }
            }
        }
    }
    let _ = &ctx;
}
