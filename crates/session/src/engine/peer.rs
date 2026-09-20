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
use crate::api::{Event, PeerInfo};

/// Time allowed for an incoming peer to send its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Outgoing connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared view of one connection.
pub struct PeerHandle {
    pub key: u32,
    pub addr: SocketAddr,
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
}

/// Outbound bytes queued beyond which the uploader waits for the writer.
const UPLOAD_BACKLOG: usize = 256 * 1024;
/// Receive buffer size (and the largest download-limiter grant per read).
const RECV_SIZE: u64 = 64 * 1024;

impl PeerHandle {
    fn new(
        key: u32,
        addr: SocketAddr,
        incoming: bool,
        conn: Connection,
        pieces: usize,
    ) -> PeerHandle {
        let now = Instant::now();
        PeerHandle {
            key,
            addr,
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
        }
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
        if !t.is_running() || t.picker.is_complete() {
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
) -> ConnectionParams {
    ConnectionParams {
        role,
        info_hash: t.info.info_hash,
        our_peer_id: ctx.peer_id,
        profile: ctx.cfg.profile.clone(),
        piece_count: Some(t.info.piece_count()),
        our_have: t.storage.have(),
        listen_port: ctx.listen_port,
        peer_ip: Some(peer_ip),
        metadata_size: Some(t.metadata_size),
    }
}

/// Connect out to `addr` for `torrent` and run the connection.
pub async fn run_outgoing(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>, addr: SocketAddr) {
    let connected = uring::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await;
    let stream = {
        let mut t = torrent.borrow_mut();
        t.half_open = t.half_open.saturating_sub(1);
        t.connecting.remove(&addr);
        match connected {
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
        }
    };
    let conn = {
        let t = torrent.borrow();
        if t.closing.is_set() || !t.is_running() || t.has_peer_ip(addr.ip()) {
            return;
        }
        Connection::new(connection_params(&ctx, &t, Role::Initiator, addr.ip()))
    };
    let _ = stream.set_nodelay(true);
    run_connection(ctx, torrent, stream, conn, addr, false, Vec::new()).await;
}

/// An accepted socket: read the handshake, find the torrent, run.
pub async fn run_incoming(ctx: Rc<Ctx>, stream: TcpStream) {
    let Ok(addr) = stream.peer_addr() else { return };
    let mut buf: Vec<u8> = Vec::with_capacity(wire::HANDSHAKE_LEN);
    let hs = loop {
        let chunk = Buffer::from_vec(vec![0u8; 1024]);
        match uring::timeout(HANDSHAKE_TIMEOUT, stream.recv(chunk)).await {
            Ok((Ok(0), _)) | Ok((Err(_), _)) | Err(_) => return,
            Ok((Ok(_), b)) => buf.extend_from_slice(b.as_slice()),
        }
        match Handshake::parse(&buf) {
            Ok(Some(hs)) => break hs,
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!(%addr, "incoming: {e}");
                return;
            }
        }
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
        {
            return;
        }
        Connection::new(connection_params(&ctx, &t, Role::Responder, addr.ip()))
    };
    let _ = stream.set_nodelay(true);
    run_connection(ctx, torrent, stream, conn, addr, true, buf).await;
}

/// The connection's main loop. `initial` holds bytes already read (the
/// incoming handshake and whatever followed it).
async fn run_connection(
    ctx: Rc<Ctx>,
    torrent: Rc<RefCell<Torrent>>,
    stream: TcpStream,
    conn: Connection,
    addr: SocketAddr,
    incoming: bool,
    initial: Vec<u8>,
) {
    let key = ctx.new_peer_key();
    let pieces = torrent.borrow().info.piece_count();
    let handle = Rc::new(PeerHandle::new(key, addr, incoming, conn, pieces));
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
        reason = process_bytes(&ctx, &torrent, &handle, &initial).await.err();
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
        *handle.last_have.borrow_mut() = Bitfield::new(pieces);
        // Do not dial this address again right away (libtorrent's
        // `min_reconnect_time`).
        t.note_disconnect(addr, Instant::now());
        t.id
    };
    tracing::debug!(%addr, torrent = id.0, "peer disconnected: {reason}");
    if handle.peer_id.get().is_some() {
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
    let events = handle
        .conn
        .borrow_mut()
        .receive(bytes)
        .map_err(|e| format!("protocol: {e}"))?;
    for ev in events {
        handle_event(ctx, torrent, handle, ev).await?;
        if handle.close.is_set() {
            break;
        }
    }
    if handle.conn.borrow().has_outbound() {
        handle.out.notify();
    }
    Ok(())
}

async fn handle_event(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    handle: &Rc<PeerHandle>,
    ev: WireEvent,
) -> Result<(), String> {
    match ev {
        WireEvent::Handshaked { peer_id, .. } => {
            let id = {
                let t = torrent.borrow();
                // One connection per IP: if a second one exists, the connection
                // initiated by the side with the lower peer id survives. Both
                // ends compute the same answer, so exactly one is closed.
                let dup = t
                    .peers
                    .values()
                    .find(|p| p.key != handle.key && p.addr.ip() == handle.addr.ip())
                    .cloned();
                if let Some(other) = dup {
                    let this_survives = if handle.incoming {
                        peer_id < ctx.peer_id
                    } else {
                        ctx.peer_id < peer_id
                    };
                    if this_survives {
                        other.close("duplicate connection");
                    } else {
                        return Err("duplicate connection".into());
                    }
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
        }
        WireEvent::ExtHandshake(ext) => {
            *handle.client.borrow_mut() = ext.v.clone();
        }
        WireEvent::HaveChanged => {
            let mut t = torrent.borrow_mut();
            let pieces = t.info.piece_count();
            handle.sync_availability(&mut t.picker, pieces);
            if t.picker.is_complete() && handle.is_seed(pieces) {
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
            torrent::on_block(ctx, torrent, handle, request, data).await;
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
        WireEvent::NotInterested
        | WireEvent::Port(_)
        | WireEvent::KeepAlive
        | WireEvent::Extended { .. } => {}
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
        let out = handle.conn.borrow_mut().take_outbound();
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
        let next = handle.upload_queue.borrow_mut().pop_front();
        let Some(r) = next else {
            match select2(handle.upload_notify.wait(), handle.close.wait()).await {
                Either::Left(()) => continue,
                Either::Right(()) => break,
            }
        };
        while handle.conn.borrow().outbound_len() > UPLOAD_BACKLOG {
            match select2(handle.drained.wait(), handle.close.wait()).await {
                Either::Left(()) => {}
                Either::Right(()) => return,
            }
        }
        if handle.close.is_set() {
            break;
        }
        // Cancelled or choked meanwhile? `wire` dropped it from its queue.
        if !handle.conn.borrow().incoming_requests().contains(&r) {
            continue;
        }
        let storage = torrent.borrow().storage.clone();
        if !storage.has_piece(r.index as usize) {
            handle.conn.borrow_mut().reject(r);
            handle.out.notify();
            continue;
        }
        match storage
            .read_block(r.index as usize, r.begin, r.length)
            .await
        {
            Ok(data) => {
                let mut conn = handle.conn.borrow_mut();
                if conn.incoming_requests().contains(&r) {
                    conn.piece(r, data.as_slice());
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
    let _ = &ctx;
}
