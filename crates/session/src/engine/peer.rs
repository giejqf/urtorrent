// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! One task per peer connection. The task owns the socket, feeds received
//! bytes into the sans-IO [`wire::Connection`], acts on the events it returns,
//! and a companion writer task flushes whatever the connection queued. Both
//! end when the peer's [`Flag`] is set.

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use metainfo::Bitfield;
use picker::Picker;
use uring::{Buffer, TcpStream};
use wire::{Connection, ConnectionParams, Event as WireEvent, Handshake, PeerHave, Request, Role};

use super::Ctx;
use super::local::{Either, Flag, Notify, select2};
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
}

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
        }
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
    uring::spawn(writer(stream.clone(), handle.clone()));

    let mut reason: Option<String> = None;
    if !initial.is_empty() {
        reason = process_bytes(&ctx, &torrent, &handle, &initial).await.err();
    }
    handle.out.notify();
    while reason.is_none() {
        let buf = ctx.recv_pool.take_sized();
        match select2(
            uring::timeout(INACTIVITY_TIMEOUT, stream.recv(buf)),
            handle.close.wait(),
        )
        .await
        {
            Either::Left(Ok((Ok(0), _))) => reason = Some("peer closed the connection".into()),
            Either::Left(Ok((Ok(_), buf))) => {
                handle.last_recv.set(Instant::now());
                if let Err(e) = process_bytes(&ctx, &torrent, &handle, buf.as_slice()).await {
                    reason = Some(e);
                }
            }
            Either::Left(Ok((Err(e), _))) => reason = Some(format!("recv: {e}")),
            Either::Left(Err(_)) => reason = Some("inactive".into()),
            Either::Right(()) => {
                reason = Some(
                    handle
                        .close_reason
                        .borrow()
                        .clone()
                        .unwrap_or_else(|| "closed".into()),
                );
            }
        }
    }
    let reason = reason.unwrap_or_default();
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
            // Leech-only in M2: never unchoked anyone, so this only arrives
            // through allowed-fast (which we do not grant). Decline politely.
            handle.conn.borrow_mut().reject(r);
        }
        WireEvent::Interested
        | WireEvent::NotInterested
        | WireEvent::Cancel(_)
        | WireEvent::Port(_)
        | WireEvent::KeepAlive
        | WireEvent::Extended { .. } => {}
    }
    Ok(())
}

/// Flush the connection's outbound bytes as they appear.
async fn writer(stream: Rc<TcpStream>, handle: Rc<PeerHandle>) {
    loop {
        let out = handle.conn.borrow_mut().take_outbound();
        if out.is_empty() {
            match select2(handle.out.wait(), handle.close.wait()).await {
                Either::Left(()) => continue,
                Either::Right(()) => break,
            }
        }
        match select2(stream.send_all(Buffer::from_vec(out)), handle.close.wait()).await {
            Either::Left(Ok(_)) => handle.last_send.set(Instant::now()),
            Either::Left(Err(e)) => {
                handle.close(&format!("send: {e}"));
                break;
            }
            Either::Right(()) => break,
        }
    }
}
