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
use uring::Buffer;

use super::transport::{Chunk, Transport, TransportKind};
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
/// Outer bound on a uTP dial (the socket itself gives up after its 3 s
/// connect timeout).
const UTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Pieces the peer suggested (BEP 6), newest last; requested first while
    /// the peer has them and we want them.
    suggested: RefCell<Vec<u32>>,
    peer_id: Cell<Option<[u8; 20]>>,
    last_recv: Cell<Instant>,
    last_send: Cell<Instant>,
    request_times: RefCell<Vec<(Request, Instant)>>,
    /// The availability this peer currently contributes to the picker.
    last_have: RefCell<Bitfield>,
    rate: Cell<u64>,
    rate_mark: Cell<u64>,
    up_rate: Cell<u64>,
    up_rate_mark: Cell<u64>,
    /// When the connection was set up.
    opened_at: Instant,
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
    /// The transport under the connection (uTP later).
    pub transport: Cell<super::transport::TransportKind>,
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
            suggested: RefCell::new(Vec::new()),
            peer_id: Cell::new(None),
            last_recv: Cell::new(now),
            last_send: Cell::new(now),
            request_times: RefCell::new(Vec::new()),
            last_have: RefCell::new(Bitfield::new(pieces)),
            rate: Cell::new(0),
            rate_mark: Cell::new(0),
            up_rate: Cell::new(0),
            up_rate_mark: Cell::new(0),
            opened_at: now,
            upload_queue: RefCell::new(VecDeque::new()),
            upload_notify: Notify::new(),
            drained: Notify::new(),
            last_unchoke: Cell::new(None),
            cipher: RefCell::new(Cipher::default()),
            encrypted: Cell::new(false),
            transport: Cell::new(super::transport::TransportKind::Tcp),
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
    pub fn on_metadata(
        &self,
        torrent: &Rc<RefCell<Torrent>>,
        pieces: usize,
        piece_length: u32,
        have: &Bitfield,
    ) {
        let r = self
            .conn
            .borrow_mut()
            .set_metadata(pieces, piece_length, have.clone());
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
            transport: self.transport.get(),
            download_rate: self.rate.get(),
            upload_rate: self.up_rate.get(),
            connected_for: Instant::now().saturating_duration_since(self.opened_at),
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
        self.set_interest(&mut conn, interested);
    }

    /// [`PeerHandle::update_interest`] after the peer announced one more
    /// piece: only that piece can change the answer from "no" to "yes".
    fn update_interest_added(&self, picker: &Picker, piece: usize) {
        let mut conn = self.conn.borrow_mut();
        if !conn.is_established() || conn.am_interested() {
            return;
        }
        if !picker.have(piece) && picker.priority(piece) > 0 {
            self.set_interest(&mut conn, true);
        }
    }

    fn set_interest(&self, conn: &mut wire::Connection, interested: bool) {
        let was = conn.am_interested();
        conn.interested(interested);
        if was != interested {
            self.out.notify();
        }
    }

    /// Bring this peer's availability contribution up to date after a
    /// wholesale change (bitfield, have-all/none, metadata).
    fn sync_availability(&self, picker: &mut Picker, pieces: usize) {
        let now = self.conn.borrow().peer_have().to_bitfield(pieces);
        let mut last = self.last_have.borrow_mut();
        if *last != now {
            picker.peer_left(&last);
            picker.peer_joined(&now);
            *last = now;
        }
    }

    /// The peer announced piece `i` (`have`): O(1) availability update.
    fn availability_added(&self, picker: &mut Picker, i: usize) {
        let mut last = self.last_have.borrow_mut();
        if i < last.len() && !last.get(i) {
            last.set(i);
            picker.peer_has(i);
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
        let preferred: Vec<usize> = self
            .suggested
            .borrow()
            .iter()
            .map(|&i| i as usize)
            .collect();
        let blocks = torrent::pick_blocks(
            ctx,
            &mut t.picker,
            self.key,
            &has,
            depth - outstanding,
            &preferred,
        );
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
        let u = self.uploaded.get() - self.up_rate_mark.get();
        self.up_rate_mark.set(self.uploaded.get());
        self.up_rate.set((self.up_rate.get() * 3 + u) / 4);
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
        piece_length: t.info.as_ref().map(|i| i.piece_length),
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
        dht_port: ctx.dht.as_ref().map(|d| d.port()),
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
    stream: &Transport,
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
    // The transport: TCP first by default, uTP for addresses whose TCP dial
    // failed (`PreferTcp`); libtorrent's order under `PreferUtp` (uTP unless
    // a uTP dial to the address failed, or it was reached over uTP before);
    // only one of them under the `*Only` policies.
    let policy = ctx.cfg.transports;
    let use_utp = {
        let t = torrent.borrow();
        let utp_possible =
            ctx.utp.is_some() && policy.utp_outgoing() && ctx.udp.supports(addr.ip());
        utp_possible
            && (!policy.tcp_outgoing()
                || if policy.utp_first() {
                    !t.utp_failed.contains(&addr) || t.utp_confirmed.contains(&addr)
                } else {
                    t.tcp_failed.contains(&addr) && !t.utp_failed.contains(&addr)
                })
    };
    if !use_utp && !policy.tcp_outgoing() {
        ctx.connection_closed();
        let mut t = torrent.borrow_mut();
        t.half_open = t.half_open.saturating_sub(1);
        t.connecting.remove(&addr);
        t.note_disconnect(addr, Instant::now());
        return;
    }
    let connected = match (&ctx.utp, use_utp) {
        (Some(h), true) => {
            uring::timeout(UTP_CONNECT_TIMEOUT, Transport::connect_utp(h, addr)).await
        }
        _ => uring::timeout(CONNECT_TIMEOUT, Transport::connect_tcp(local, addr)).await,
    };
    ctx.connection_closed(); // the dial is over; a live connection counts again below
    let (stream, use_mse) = {
        let mut t = torrent.borrow_mut();
        t.half_open = t.half_open.saturating_sub(1);
        t.connecting.remove(&addr);
        let stream = match connected {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!(%addr, utp = use_utp, "connect failed: {e}");
                dial_failed(&mut t, &ctx, addr, use_utp);
                return;
            }
            Err(_) => {
                tracing::debug!(%addr, utp = use_utp, "connect timed out");
                dial_failed(&mut t, &ctx, addr, use_utp);
                return;
            }
        };
        if use_utp {
            // Connected over uTP: the address speaks it for sure.
            t.utp_confirmed.insert(addr);
        } else {
            t.tcp_failed.remove(&addr);
        }
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
                if !use_utp
                    && e.contains("closed")
                    && tcp_closed_before_handshake(&mut t, &ctx, addr)
                {
                    // A uTP-only peer accepts and drops TCP: uTP next.
                    t.allow_reconnect_now(addr);
                } else {
                    t.note_disconnect(addr, Instant::now());
                }
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
pub async fn run_incoming(ctx: Rc<Ctx>, stream: Transport) {
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
        let mut pending = std::mem::take(&mut raw);
        let outcome = loop {
            let step = resp.receive(&pending, &*ctx.skeys.borrow(), &mut rng);
            match step {
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
            || ctx.connection_count() >= ctx.cfg.max_connections
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
    stream: Transport,
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
    handle.transport.set(stream.kind());
    *handle.cipher.borrow_mut() = cipher;
    torrent.borrow_mut().peers.insert(key, handle.clone());
    ctx.connection_opened();
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
    // One standing multishot receive into the session's provided buffers;
    // the kernel pauses the socket when the ring is empty, so a stalled
    // consumer (disk backpressure) turns into TCP backpressure.
    let mut rx = stream.receiver(&ctx.recv_ring);
    while reason.is_none() {
        let buf = match select2(
            uring::timeout(INACTIVITY_TIMEOUT, rx.next()),
            handle.close.wait(),
        )
        .await
        {
            Either::Left(Ok(Ok(Some(buf)))) => buf,
            Either::Left(Ok(Ok(None))) => {
                reason = Some("peer closed the connection".into());
                break;
            }
            Either::Left(Ok(Err(e))) => {
                reason = Some(format!("recv: {e}"));
                break;
            }
            Either::Left(Err(_)) => {
                reason = Some("inactive".into());
                break;
            }
            Either::Right(()) => break,
        };
        handle.last_recv.set(Instant::now());
        // Everything that arrived while we were busy (e.g. awaiting the disk
        // for the previous batch) is framed in one go, and the batch's
        // block writes leave for the disk ring together.
        let mut chunks = vec![buf];
        let mut eof = false;
        while chunks.len() < MAX_RECV_BATCH {
            match rx.try_next() {
                Some(Some(b)) => chunks.push(b),
                Some(None) => {
                    eof = true;
                    break;
                }
                None => break,
            }
        }
        // Download limits: the bytes are already here (the ring is bounded,
        // so a limited connection bursts at most one ring's worth); charge
        // the whole batch before processing it, which delays the next one.
        if !(ctx.down_limit.is_unlimited() && down_limit.is_unlimited()) {
            let mut left: u64 = chunks.iter().map(|c| c.len() as u64).sum();
            while left > 0 {
                match select2(
                    acquire_pair(&ctx.down_limit, &down_limit, left),
                    handle.close.wait(),
                )
                .await
                {
                    Either::Left(g) => left -= g.min(left),
                    Either::Right(()) => {
                        return finish_connection(ctx, torrent, handle, key, addr, incoming, None)
                            .await;
                    }
                }
            }
        }
        if let Err(e) = process_chunks(&ctx, &torrent, &handle, chunks).await {
            reason = Some(e);
        } else if eof {
            reason = Some("peer closed the connection".into());
        }
    }
    // uTP tells the peer why (libtorrent's close_reason_t in the FIN).
    let why = reason
        .clone()
        .or_else(|| handle.close_reason.borrow().clone());
    if let Some(r) = &why {
        let code = close_reason_code(r);
        if code != 0 {
            stream.set_close_reason(code);
        }
    }
    finish_connection(ctx, torrent, handle, key, addr, incoming, reason).await
}

/// An outgoing TCP connection died before the peer said anything. When uTP
/// is available for the address and has not failed for it, mark the
/// address for a uTP dial and say so (the caller reconnects right away).
fn tcp_closed_before_handshake(t: &mut Torrent, ctx: &Ctx, addr: SocketAddr) -> bool {
    let fallback = ctx.cfg.transports.utp_outgoing()
        && ctx.utp.is_some()
        && ctx.udp.supports(addr.ip())
        && !t.utp_failed.contains(&addr)
        && !t.tcp_failed.contains(&addr);
    if fallback {
        t.tcp_failed.insert(addr);
    }
    fallback
}

/// A dial failed. A failed uTP attempt marks the address as not speaking
/// uTP and reconnects over TCP right away (libtorrent's `fast_reconnect`);
/// a failed TCP attempt marks the address for uTP and reconnects right away
/// when uTP is available and has not failed for it too. Anything else backs
/// off as usual.
fn dial_failed(t: &mut Torrent, ctx: &Ctx, addr: SocketAddr, was_utp: bool) {
    let policy = ctx.cfg.transports;
    let retry_now = if was_utp {
        t.utp_confirmed.remove(&addr);
        t.utp_failed.insert(addr);
        policy.tcp_outgoing() && !t.tcp_failed.contains(&addr)
    } else {
        t.tcp_failed.insert(addr);
        policy.utp_outgoing()
            && ctx.utp.is_some()
            && ctx.udp.supports(addr.ip())
            && !t.utp_failed.contains(&addr)
    };
    if retry_now {
        t.allow_reconnect_now(addr);
    } else {
        t.note_disconnect(addr, Instant::now());
    }
}

/// libtorrent's `close_reason_t` for one of our disconnect reasons (0 =
/// none: the peer closed, or an I/O error).
fn close_reason_code(reason: &str) -> u16 {
    match reason {
        "duplicate peer id" | "duplicate connection" => 1,
        "torrent stopped" | "rechecking" => 2,
        "banned: repeated hash failures" => 5,
        "both seeds" => 6,
        "inactive" => 10,
        r if r.starts_with("protocol:") => 263,
        _ => 0,
    }
}

/// Batches at least this large go out zero-copy when enabled (a block plus
/// framing; smaller ones are control traffic).
const ZC_MIN_BYTES: usize = 16 * 1024;

/// A batch on its way out: owned chunks that come back after each send, or
/// chunks shared with the kernel (zero-copy).
enum Outbound {
    Plain(Option<Vec<Buffer>>),
    ZeroCopy(Rc<Vec<Buffer>>),
}

/// Chunks framed per receive batch (bounds the events handled before the
/// batch's writes go out; the ring size bounds it anyway).
const MAX_RECV_BATCH: usize = 32;

/// Suggested pieces remembered per peer (libtorrent `max_suggest_pieces`).
const MAX_SUGGESTED: usize = 16;

/// Tear a connection down: bookkeeping in the torrent, then the socket closes
/// through the ring when the last `Rc<Transport>` drops.
async fn finish_connection(
    ctx: Rc<Ctx>,
    torrent: Rc<RefCell<Torrent>>,
    handle: Rc<PeerHandle>,
    key: u32,
    addr: SocketAddr,
    incoming: bool,
    reason: Option<String>,
) {
    let reason = reason.unwrap_or_else(|| {
        handle
            .close_reason
            .borrow()
            .clone()
            .unwrap_or_else(|| "closed".into())
    });
    handle.close(&reason);
    ctx.connection_closed();
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
        let died_before_handshake = !incoming
            && handle.peer_id.get().is_none()
            && (reason == "peer closed the connection" || reason.starts_with("recv:"));
        // Q3: under `Enabled` a plaintext attempt the peer closed before the
        // handshake is retried encrypted, at once, on the same transport
        // (the peer may simply require encryption).
        let plaintext_refused = died_before_handshake
            && ctx.cfg.encryption == EncryptionMode::Enabled
            && !handle.encrypted.get();
        // Otherwise an outgoing TCP connection the peer closed before any
        // handshake (a uTP-only peer accepts and drops TCP) gets one uTP
        // attempt next, at once.
        let tcp_dead_before_handshake = died_before_handshake
            && !plaintext_refused
            && handle.transport.get() == TransportKind::Tcp
            && tcp_closed_before_handshake(&mut t, &ctx, addr);
        if reason.starts_with("duplicate") {
            t.allow_reconnect_now(addr);
        } else if plaintext_refused {
            t.mse_retry.insert(addr);
            t.allow_reconnect_now(addr);
        } else if tcp_dead_before_handshake {
            t.allow_reconnect_now(addr);
        } else if !incoming
            && ctx.cfg.encryption == EncryptionMode::Enabled
            && handle.peer_id.get().is_none()
        {
            // The encrypted retry died too: back to plaintext next time.
            t.mse_retry.remove(&addr);
            t.note_disconnect(addr, Instant::now());
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
/// Decrypt (in place) and frame a batch of received chunks, then act on
/// the events. The ring buffers go back to the kernel as soon as the framer
/// has consumed them, before any event handling awaits the disk.
async fn process_chunks(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    handle: &Rc<PeerHandle>,
    chunks: Vec<Chunk>,
) -> Result<(), String> {
    let events = {
        let mut cipher = handle.cipher.borrow_mut();
        let mut conn = handle.conn.borrow_mut();
        let mut events = Vec::new();
        for mut buf in chunks {
            if buf.is_empty() {
                continue;
            }
            if let Some(d) = cipher.dec.as_mut() {
                d.apply(buf.as_mut_slice());
            }
            let evs = conn
                .receive(buf.as_slice())
                .map_err(|e| format!("protocol: {e}"))?;
            events.extend(evs);
        }
        events
    };
    process_events(ctx, torrent, handle, events).await
}

/// Feed plaintext bytes (the handshake's leftovers) to the connection.
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
    process_events(ctx, torrent, handle, events).await
}

async fn process_events(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    handle: &Rc<PeerHandle>,
    events: Vec<WireEvent>,
) -> Result<(), String> {
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
            // BEP 20: the peer id names the client until (unless) the LTEP
            // handshake's `v` says more.
            if handle.client.borrow().is_none() {
                *handle.client.borrow_mut() = wire::identify::client_name(&peer_id);
            }
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
            if ext.v.is_some() {
                *handle.client.borrow_mut() = ext.v.clone();
            }
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
        WireEvent::HaveChanged { added } => {
            let mut t = torrent.borrow_mut();
            if !t.has_metadata() {
                return Ok(());
            }
            let pieces = t.piece_count();
            match added {
                // A single `have`: constant-time bookkeeping (a `have` per
                // peer per piece is the hottest control-plane path).
                Some(i) if handle.last_have.borrow().len() == pieces => {
                    handle.availability_added(&mut t.picker, i as usize);
                    handle.update_interest_added(&t.picker, i as usize);
                }
                _ => {
                    handle.sync_availability(&mut t.picker, pieces);
                    handle.update_interest(&t.picker);
                }
            }
            if t.is_complete() && handle.is_seed(pieces) {
                return Err("both seeds".into());
            }
            handle.fill_requests_locked(&mut t, ctx);
        }
        WireEvent::Suggest(i) => {
            // BEP 6 suggest piece: an advisory preference (libtorrent keeps
            // the last `max_suggest_pieces` = 16 per peer).
            {
                let mut s = handle.suggested.borrow_mut();
                s.retain(|&x| x != i);
                if s.len() >= MAX_SUGGESTED {
                    s.remove(0);
                }
                s.push(i);
            }
            handle.fill_requests(torrent, ctx);
        }
        WireEvent::Unchoked | WireEvent::AllowedFast(_) => {
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
        WireEvent::Port(port) => {
            // BEP 5: the peer's DHT node (libtorrent `incoming_dht_port`).
            if let Some(d) = ctx.dht.clone()
                && port != 0
            {
                d.add_node(ctx, SocketAddr::new(handle.addr.ip(), port));
            }
        }
        WireEvent::NotInterested | WireEvent::KeepAlive => {}
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

/// Flush the connection's outbound bytes as they appear, within the upload
/// limits.
async fn writer(
    ctx: Rc<Ctx>,
    torrent: Rc<RefCell<Torrent>>,
    stream: Rc<Transport>,
    handle: Rc<PeerHandle>,
) {
    let up_limit = torrent.borrow().up_limit.clone();
    loop {
        // Chunks are sent as they are (piece payloads are the block buffers
        // read from disk); the cipher runs over them in order, in place.
        let mut chunks = handle.conn.borrow_mut().take_outbound_chunks();
        if let Some(e) = handle.cipher.borrow_mut().enc.as_mut() {
            for c in &mut chunks {
                e.apply(c);
            }
        }
        if chunks.is_empty() {
            match select2(handle.out.wait(), handle.close.wait()).await {
                Either::Left(()) => continue,
                Either::Right(()) => break,
            }
        }
        // One vectored send for the whole batch (framing + block buffers),
        // or grant-sized slices of it under an upload limit. Payload-sized
        // batches go zero-copy when configured; the chunks are then shared
        // with the kernel until acknowledged.
        let total: usize = chunks.iter().map(Vec::len).sum();
        let bufs: Vec<Buffer> = chunks.into_iter().map(Buffer::from_vec).collect();
        let mut out = if ctx.send_zc && total >= ZC_MIN_BYTES {
            Outbound::ZeroCopy(Rc::new(bufs))
        } else {
            Outbound::Plain(Some(bufs))
        };
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
            let sent = match &mut out {
                Outbound::ZeroCopy(shared) => {
                    match select2(
                        stream.send_all_chunks_zc(shared.clone(), offset, grant),
                        handle.close.wait(),
                    )
                    .await
                    {
                        Either::Left(r) => r,
                        Either::Right(()) => return,
                    }
                }
                Outbound::Plain(slot) => {
                    let Some(bufs) = slot.take() else { return };
                    match select2(
                        stream.send_all_chunks(bufs, offset, grant),
                        handle.close.wait(),
                    )
                    .await
                    {
                        Either::Left(Ok(b)) => {
                            *slot = Some(b);
                            Ok(())
                        }
                        Either::Left(Err(e)) => Err(e),
                        Either::Right(()) => return,
                    }
                }
            };
            match sent {
                Ok(()) => {
                    handle.last_send.set(Instant::now());
                    offset += grant;
                }
                Err(e) => {
                    handle.close(&format!("send: {e}"));
                    return;
                }
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
                        conn.piece(r, data);
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
