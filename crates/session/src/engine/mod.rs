// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The engine proper: everything that runs on the `urt-net` ring thread.
//!
//! One [`uring::Runtime`] hosts the command loop, the TCP accept loops, and a
//! set of cooperating tasks per torrent (tracker announcer, tick, one task
//! per peer connection). Cross-thread input (API commands, hash results, DNS
//! results) arrives through a single eventfd [`uring::Notifier`]; local tasks
//! that need the command loop's attention ring the same eventfd.

mod choker;
mod dns;
mod external_ip;
mod http;
mod local;
mod lsd;
mod metadata;
mod peer;
mod pex;
mod rate;
mod rng;
mod tls;
mod torrent;
mod tracker_task;
mod transport;
mod udp;
mod webseed;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use metainfo::InfoHash;
use profile::Profile;
use storage::DiskRing;
use tokio::sync::{mpsc, oneshot};
use uring::{Notifier, NotifyHandle, Runtime, TcpListener};

use crate::Error;
use crate::api::{
    AddTorrent, Event, PeerInfo, SessionStats, TorrentId, TorrentStatus, TrackerStatus,
};
use dns::Dns;
use local::{Either, Flag, select2};
use torrent::Torrent;

/// Engine configuration (built by `SessionBuilder`).
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub listen_port: u16,
    pub listen_v4: Option<Ipv4Addr>,
    pub listen_v6: Option<Ipv6Addr>,
    pub profile: Profile,
    pub max_peers: usize,
    /// Session-wide connection limit (libtorrent `connections_limit`).
    pub max_connections: usize,
    pub max_half_open: usize,
    pub hash_threads: usize,
    pub ring_entries: u32,
    /// Session upload limit in bytes/s (0 = unlimited).
    pub upload_rate: u64,
    /// Session download limit in bytes/s (0 = unlimited).
    pub download_rate: u64,
    /// Session-wide unchoke slots.
    pub unchoke_slots: usize,
    /// Extra CA certificates (PEM bundles) trusted for HTTPS trackers.
    pub extra_roots: Vec<Vec<u8>>,
    /// MSE policy.
    pub encryption: crate::api::EncryptionMode,
    /// Peer exchange enabled.
    pub pex: bool,
    /// Local Service Discovery enabled.
    pub lsd: bool,
    /// Torrent file I/O on its own `urt-disk` ring thread (default) rather
    /// than on the network ring.
    pub disk_thread: bool,
    /// Torrents hashed (checked) at once; the rest queue (libtorrent's
    /// `active_checking`, 1).
    pub max_checking: usize,
    /// Tracker announces / scrapes in flight at once across the session.
    pub max_concurrent_announces: usize,
    /// Resume saves (each an fsync of the torrent's files) at once.
    pub max_concurrent_resume_saves: usize,
    /// Torrent files kept open at once (an LRU; libtorrent's file pool).
    pub max_open_files: usize,
    /// Finish a few recently started 4 MiB extents before rarest-first moves
    /// on (libtorrent `piece_extent_affinity`), so small pieces are written
    /// in runs rather than scattered over the file.
    pub piece_extent_affinity: bool,
    /// Provided receive buffers shared by every peer socket (a power of two)
    /// and the size of each. A connection holds no receive memory until data
    /// arrives; when all buffers are in use the kernel pauses the sockets
    /// until one is returned (TCP backpressure).
    pub recv_ring_entries: u16,
    pub recv_buf_size: usize,
    /// Send piece payloads with zero-copy `sendmsg` (`IORING_OP_SENDMSG_ZC`)
    /// when the kernel supports it. Off by default: on loopback and small
    /// payloads the notification round trip costs more than the copy it
    /// saves (`docs/perf.md`); worth trying on real NICs at high rates.
    pub zero_copy_send: bool,
}

/// Buffer group id of the peer receive ring.
const RECV_RING_GROUP: u16 = 1;

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            listen_port: 6881,
            listen_v4: Some(Ipv4Addr::UNSPECIFIED),
            listen_v6: Some(Ipv6Addr::UNSPECIFIED),
            profile: Profile::native(),
            max_peers: 50,
            max_connections: 500,
            max_half_open: 10,
            hash_threads: 2,
            ring_entries: 1024,
            upload_rate: 0,
            download_rate: 0,
            unchoke_slots: choker::DEFAULT_SLOTS,
            extra_roots: Vec::new(),
            encryption: crate::api::EncryptionMode::Enabled,
            pex: true,
            lsd: true,
            disk_thread: true,
            max_checking: 1,
            max_concurrent_announces: 32,
            max_concurrent_resume_saves: 4,
            max_open_files: 512,
            piece_extent_affinity: true,
            recv_ring_entries: 256,
            recv_buf_size: 32 * 1024,
            zero_copy_send: false,
        }
    }
}

/// Messages from `Session` handles.
pub enum Command {
    AddTorrent(Box<AddTorrent>, oneshot::Sender<Result<TorrentId, Error>>),
    /// Remove; `true` deletes the content files too.
    Remove(TorrentId, bool, oneshot::Sender<Result<(), Error>>),
    Find(InfoHash, oneshot::Sender<Option<TorrentId>>),
    Pause(TorrentId, oneshot::Sender<Result<(), Error>>),
    Resume(TorrentId, oneshot::Sender<Result<(), Error>>),
    PauseAll(oneshot::Sender<()>),
    ResumeAll(oneshot::Sender<()>),
    AddTracker(TorrentId, String, usize, oneshot::Sender<Result<(), Error>>),
    RemoveTracker(TorrentId, String, oneshot::Sender<Result<(), Error>>),
    SetMaxPeers(TorrentId, Option<usize>, oneshot::Sender<Result<(), Error>>),
    Status(TorrentId, oneshot::Sender<Result<TorrentStatus, Error>>),
    Statuses(oneshot::Sender<Vec<TorrentStatus>>),
    Peers(TorrentId, oneshot::Sender<Result<Vec<PeerInfo>, Error>>),
    Stats(oneshot::Sender<SessionStats>),
    SaveResume(TorrentId, oneshot::Sender<Result<(), Error>>),
    ForceReannounce(TorrentId, oneshot::Sender<Result<(), Error>>),
    AddPeer(TorrentId, SocketAddr, oneshot::Sender<Result<(), Error>>),
    SetFilePriorities(TorrentId, Vec<u8>, oneshot::Sender<Result<(), Error>>),
    SetSequential(TorrentId, bool, oneshot::Sender<Result<(), Error>>),
    MoveStorage(
        TorrentId,
        std::path::PathBuf,
        oneshot::Sender<Result<(), Error>>,
    ),
    ForceRecheck(TorrentId, oneshot::Sender<Result<(), Error>>),
    Scrape(
        TorrentId,
        oneshot::Sender<Result<Vec<TrackerStatus>, Error>>,
    ),
    SetRateLimits(u64, u64, oneshot::Sender<()>),
    SetTorrentRateLimits(TorrentId, u64, u64, oneshot::Sender<Result<(), Error>>),
    Subscribe(mpsc::Sender<Event>),
    Shutdown(oneshot::Sender<()>),
}

/// What `build()` learns once the engine is up.
pub struct Boot {
    pub notify: NotifyHandle,
    pub listen_port: u16,
}

struct Subscriber {
    tx: mpsc::Sender<Event>,
    dropped: u64,
}

/// Shared engine state (one per ring thread, behind an `Rc`).
pub struct Ctx {
    pub cfg: EngineConfig,
    pub peer_id: [u8; 20],
    pub listen_port: u16,
    pub families: http::Families,
    /// The disk thread (torrent file I/O and hashing).
    pub disk: Rc<DiskRing>,
    pub dns: Dns,
    pub tls: tls::TlsClient,
    pub udp: Rc<udp::UdpDemux>,
    /// Local Service Discovery sockets (`None` when disabled or unavailable).
    pub lsd: RefCell<Option<lsd::Lsd>>,
    /// External-address voters, one per listen family (`[v4, v6]`).
    pub external: RefCell<[external_ip::IpVoter; 2]>,
    pub rng: rng::Rng,
    pub kick: NotifyHandle,
    /// Provided buffers every peer socket receives into (multishot recv).
    pub recv_ring: uring::BufRing,
    /// Zero-copy sends: configured on and supported by the kernel.
    pub send_zc: bool,
    pub closing: Rc<Flag>,
    /// Session-wide rate limits.
    pub up_limit: Rc<rate::Limiter>,
    pub down_limit: Rc<rate::Limiter>,
    slots: Cell<usize>,
    optimistic: Cell<Option<u64>>,
    subscribers: RefCell<Vec<Subscriber>>,
    torrents: RefCell<HashMap<TorrentId, Rc<RefCell<Torrent>>>>,
    by_hash: RefCell<HashMap<InfoHash, TorrentId>>,
    /// MSE stream-key index over every torrent (O(1) per incoming
    /// encrypted connection).
    skeys: RefCell<mse::SkeyIndex>,
    /// Connections plus dials in progress across every torrent.
    connections: Cell<usize>,
    /// Torrents due for their once-a-second tick, earliest first.
    ticks: RefCell<std::collections::BinaryHeap<std::cmp::Reverse<(Instant, TorrentId)>>>,
    /// Concurrency gates (see `EngineConfig`).
    pub check_gate: Rc<local::Semaphore>,
    pub announce_gate: Rc<local::Semaphore>,
    pub resume_gate: Rc<local::Semaphore>,
    next_id: Cell<u64>,
    next_peer_key: Cell<u32>,
    /// Torrents still winding down during shutdown.
    stopping: Cell<usize>,
    shutdown_reply: RefCell<Vec<oneshot::Sender<()>>>,
    done: Rc<Flag>,
}

impl Ctx {
    /// Deliver an event to every subscriber, recording lag instead of blocking.
    pub fn emit(&self, ev: Event) {
        let mut subs = self.subscribers.borrow_mut();
        subs.retain_mut(|s| {
            if s.dropped > 0 {
                match s.tx.try_send(Event::Lagged { dropped: s.dropped }) {
                    Ok(()) => s.dropped = 0,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        s.dropped += 1;
                        return true;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return false,
                }
            }
            match s.tx.try_send(ev.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    s.dropped += 1;
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
    }

    pub fn torrent(&self, id: TorrentId) -> Option<Rc<RefCell<Torrent>>> {
        self.torrents.borrow().get(&id).cloned()
    }

    pub fn torrent_by_hash(&self, h: &InfoHash) -> Option<Rc<RefCell<Torrent>>> {
        let id = *self.by_hash.borrow().get(h)?;
        self.torrent(id)
    }

    pub fn new_peer_key(&self) -> u32 {
        let k = self.next_peer_key.get();
        self.next_peer_key.set(k.wrapping_add(1));
        k
    }

    /// A random 32-bit announce key.
    pub fn new_announce_key(&self) -> u32 {
        (self.rng.next_u64() >> 32) as u32
    }

    /// Put a torrent on the tick queue (spread across the second by id so a
    /// mass start does not tick everything at once).
    pub fn schedule_tick(&self, torrent: &Rc<RefCell<Torrent>>) {
        let mut t = torrent.borrow_mut();
        if t.tick_scheduled {
            return;
        }
        t.tick_scheduled = true;
        let phase = Duration::from_millis(t.id.0.wrapping_mul(0x9e37_79b9) % 1000);
        self.ticks
            .borrow_mut()
            .push(std::cmp::Reverse((Instant::now() + phase, t.id)));
    }

    /// Run every due torrent tick and requeue the ones that continue.
    fn run_due_ticks(self: &Rc<Self>, now: Instant) {
        loop {
            let next = {
                let mut q = self.ticks.borrow_mut();
                match q.peek() {
                    Some(std::cmp::Reverse((due, _))) if *due <= now => q.pop(),
                    _ => None,
                }
            };
            let Some(std::cmp::Reverse((due, id))) = next else {
                break;
            };
            let Some(t) = self.torrent(id) else { continue };
            if torrent::tick_once(self, &t, now) {
                // Keep the phase: schedule from the previous due time.
                let next_due = (due + Duration::from_secs(1)).max(now);
                self.ticks
                    .borrow_mut()
                    .push(std::cmp::Reverse((next_due, id)));
            }
        }
    }

    /// Register a torrent's info-hash (lookup by hash, MSE stream keys).
    pub fn index_torrent(&self, hash: InfoHash, id: TorrentId) {
        self.by_hash.borrow_mut().insert(hash, id);
        self.skeys.borrow_mut().insert(hash);
    }

    /// Bookkeeping for the session-wide connection limit: a connection or a
    /// dial started / ended.
    pub fn connection_opened(&self) {
        self.connections.set(self.connections.get() + 1);
    }

    /// See [`Ctx::connection_opened`].
    pub fn connection_closed(&self) {
        self.connections
            .set(self.connections.get().saturating_sub(1));
    }

    /// Connections plus dials in progress across every torrent.
    pub fn connection_count(&self) -> usize {
        self.connections.get()
    }

    /// 20 random bytes for a DH exponent.
    pub fn dh_private(&self) -> [u8; 20] {
        let mut k = [0u8; 20];
        if getrandom::fill(&mut k).is_err() {
            // Fall back to the engine RNG rather than fail the connection;
            // MSE is obfuscation, not a security boundary.
            for chunk in k.chunks_mut(8) {
                let v = self.rng.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
        k
    }

    /// The peer id for a new torrent: fresh per torrent or the session's,
    /// as the profile dictates (L1: lifetime is part of the identity).
    pub fn new_torrent_peer_id(&self) -> [u8; 20] {
        match self.cfg.profile.peer_id.lifetime {
            profile::PeerIdLifetime::PerTorrent => {
                let mut r = rng::RngRef(&self.rng);
                self.cfg.profile.peer_id.generate(&mut r)
            }
            profile::PeerIdLifetime::PerSession => self.peer_id,
        }
    }

    /// Record an external-address vote for the listen family of `local` (the
    /// connection's local address). On a change every torrent re-ranks its
    /// candidates (BEP 40 uses our external address) and an event is emitted.
    pub fn cast_external_vote(
        &self,
        local: IpAddr,
        ip: IpAddr,
        kind: external_ip::Source,
        source: IpAddr,
    ) {
        let idx = usize::from(local.is_ipv6());
        let changed = self.external.borrow_mut()[idx].cast_vote(ip, kind, source, Instant::now());
        if changed {
            tracing::info!(%ip, %source, ?kind, "external address updated");
            for t in self.torrents.borrow().values() {
                t.borrow_mut().rerank_candidates();
            }
            self.emit(Event::ExternalAddress { ip });
        }
    }

    /// Whether an outgoing connection with local address `local` may carry
    /// LTEP `p` (docs/quirks.md Q6).
    pub fn advertise_port_for(&self, local: IpAddr) -> bool {
        self.external.borrow()[usize::from(local.is_ipv6())].advertise_port_for(local)
    }

    /// Our external address for a family, if voted in.
    pub fn external_address(&self, v6: bool) -> Option<IpAddr> {
        self.external.borrow()[usize::from(v6)].external_address()
    }

    /// The peer id a new connection of `torrent` shakes hands with: the
    /// torrent's announce id, or a fresh one per connection (L1, Q19).
    pub fn handshake_peer_id(&self, torrent: &Torrent) -> [u8; 20] {
        match self.cfg.profile.peer_id.handshake {
            profile::HandshakePeerId::SameAsAnnounce => torrent.peer_id,
            profile::HandshakePeerId::PerConnection => {
                let mut r = rng::RngRef(&self.rng);
                self.cfg.profile.peer_id.generate(&mut r)
            }
        }
    }

    fn remove_torrent_entry(&self, id: TorrentId) -> Option<Rc<RefCell<Torrent>>> {
        let t = self.torrents.borrow_mut().remove(&id)?;
        let h = t.borrow().info_hash();
        self.by_hash.borrow_mut().remove(&h);
        self.skeys.borrow_mut().remove(&h);
        Some(t)
    }

    /// Called by a torrent's stop task when it has fully wound down during
    /// shutdown.
    fn torrent_stopped(&self) {
        let n = self.stopping.get().saturating_sub(1);
        self.stopping.set(n);
        if n == 0 && self.closing.is_set() {
            self.finish_shutdown();
        }
    }

    fn finish_shutdown(&self) {
        for tx in self.shutdown_reply.borrow_mut().drain(..) {
            let _ = tx.send(());
        }
        self.done.set();
        self.kick.notify();
    }
}

/// Entry point of the `urt-net` thread.
pub fn run(
    cfg: EngineConfig,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    ready: oneshot::Sender<Result<Boot, Error>>,
) {
    let rt = match Runtime::new(cfg.ring_entries) {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(e.into()));
            return;
        }
    };
    rt.block_on(async move {
        let notifier = match Notifier::new() {
            Ok(n) => Rc::new(n),
            Err(e) => {
                let _ = ready.send(Err(e.into()));
                return;
            }
        };
        let kick = notifier.handle();

        // Listen sockets: one per family, `IPV6_V6ONLY` on the v6 one.
        let mut listeners: Vec<TcpListener> = Vec::new();
        let mut port = cfg.listen_port;
        let mut bind_err: Option<uring::Error> = None;
        if let Some(v4) = cfg.listen_v4 {
            match TcpListener::bind(SocketAddr::new(IpAddr::V4(v4), port)) {
                Ok(l) => {
                    port = l.local_addr().port();
                    listeners.push(l);
                }
                Err(e) => bind_err = Some(e),
            }
        }
        if let Some(v6) = cfg.listen_v6 {
            match TcpListener::bind(SocketAddr::new(IpAddr::V6(v6), port)) {
                Ok(l) => {
                    port = l.local_addr().port();
                    listeners.push(l);
                }
                Err(e) => {
                    // A host without IPv6 is fine as long as v4 bound.
                    if listeners.is_empty() {
                        bind_err = Some(e);
                    } else {
                        tracing::warn!("ipv6 listen failed: {e}");
                    }
                }
            }
        }
        if listeners.is_empty() {
            let e = bind_err.map_or_else(
                || Error::Io("no listen address configured".into()),
                Error::from,
            );
            let _ = ready.send(Err(e));
            return;
        }
        let families = http::Families {
            v4: listeners.iter().any(|l| l.local_addr().is_ipv4()),
            v6: listeners.iter().any(|l| l.local_addr().is_ipv6()),
        };

        let mut roots = tls::TlsClient::env_roots();
        roots.extend(cfg.extra_roots.iter().cloned());
        let tls = match tls::TlsClient::new(&roots) {
            Ok(t) => t,
            Err(e) => {
                let _ = ready.send(Err(Error::Io(e)));
                return;
            }
        };
        let rng = rng::Rng::from_os();
        let peer_id = {
            let mut r = rng::RngRef(&rng);
            cfg.profile.peer_id.generate(&mut r)
        };
        // The listen port's UDP sockets (UDP trackers now; DHT/uTP demux later).
        let udp_demux = Rc::new(udp::UdpDemux::bind(
            port,
            if families.v4 { cfg.listen_v4 } else { None },
            if families.v6 { cfg.listen_v6 } else { None },
            (rng.next_u64() >> 32) as u32,
        ));
        let disk = if cfg.disk_thread {
            match DiskRing::start(cfg.hash_threads, cfg.max_open_files, kick.clone()) {
                Ok(d) => Rc::new(d),
                Err(e) => {
                    let _ = ready.send(Err(Error::Io(format!("disk thread: {e}"))));
                    return;
                }
            }
        } else {
            Rc::new(DiskRing::inline(
                cfg.hash_threads,
                cfg.max_open_files,
                kick.clone(),
            ))
        };
        let lsd = if cfg.lsd {
            lsd::Lsd::open(
                if families.v4 { cfg.listen_v4 } else { None },
                if families.v6 { cfg.listen_v6 } else { None },
                (rng.next_u64() >> 33) as u32,
            )
        } else {
            None
        };
        let now = Instant::now();
        // Peer receive buffers: one ring for every connection on this thread
        // (kernel 6.1 baseline: multishot recv + provided buffer rings).
        let recv_ring =
            match uring::BufRing::new(RECV_RING_GROUP, cfg.recv_ring_entries, cfg.recv_buf_size) {
                Ok(r) => r,
                Err(e) => {
                    let _ = ready.send(Err(Error::Io(format!("provided buffer ring: {e}"))));
                    return;
                }
            };
        let ctx = Rc::new(Ctx {
            dns: Dns::new(kick.clone()),
            tls,
            udp: udp_demux.clone(),
            lsd: RefCell::new(lsd),
            external: RefCell::new([
                external_ip::IpVoter::new(now),
                external_ip::IpVoter::new(now),
            ]),
            up_limit: rate::Limiter::new(cfg.upload_rate, now),
            down_limit: rate::Limiter::new(cfg.download_rate, now),
            slots: Cell::new(cfg.unchoke_slots),
            optimistic: Cell::new(None),
            peer_id,
            listen_port: port,
            families,
            disk,
            rng,
            kick: kick.clone(),
            recv_ring,
            send_zc: cfg.zero_copy_send && uring::probe().is_ok_and(|f| f.send_zc),
            closing: Flag::new(),
            subscribers: RefCell::new(Vec::new()),
            torrents: RefCell::new(HashMap::new()),
            by_hash: RefCell::new(HashMap::new()),
            skeys: RefCell::new(mse::SkeyIndex::new()),
            connections: Cell::new(0),
            ticks: RefCell::new(std::collections::BinaryHeap::new()),
            check_gate: local::Semaphore::new(cfg.max_checking),
            announce_gate: local::Semaphore::new(cfg.max_concurrent_announces),
            resume_gate: local::Semaphore::new(cfg.max_concurrent_resume_saves),
            next_id: Cell::new(1),
            next_peer_key: Cell::new(1),
            stopping: Cell::new(0),
            shutdown_reply: RefCell::new(Vec::new()),
            done: Flag::new(),
            cfg,
        });
        tracing::info!(
            port,
            peer_id = %String::from_utf8_lossy(&peer_id),
            profile = ctx.cfg.profile.name,
            "engine up"
        );
        let _ = ready.send(Ok(Boot {
            notify: kick.clone(),
            listen_port: port,
        }));

        for l in listeners {
            uring::spawn(accept_loop(ctx.clone(), l));
        }
        udp_demux.spawn(ctx.closing.clone());
        if let Some(l) = ctx.lsd.borrow().as_ref() {
            l.spawn(ctx.clone());
        }
        uring::spawn(ticker(ctx.clone()));

        // Command loop. The eventfd read is always in flight, so the runtime
        // never observes a stall.
        loop {
            if let Err(e) = notifier.wait().await {
                tracing::error!("notifier failed: {e}");
                break;
            }
            ctx.disk.drain();
            ctx.dns.drain();
            while let Ok(cmd) = cmd_rx.try_recv() {
                handle_command(&ctx, cmd);
            }
            if ctx.done.is_set() {
                break;
            }
        }
        // Let the remaining tasks observe `closing`, drop their operations
        // (which cancels them on the ring) and release their sockets before
        // the runtime is torn down.
        for _ in 0..3 {
            uring::sleep(std::time::Duration::from_millis(10)).await;
        }
        tracing::info!("engine down");
    });
}

async fn accept_loop(ctx: Rc<Ctx>, listener: TcpListener) {
    loop {
        match select2(listener.accept(), ctx.closing.wait()).await {
            Either::Left(Ok(stream)) => {
                uring::spawn(peer::run_incoming(
                    ctx.clone(),
                    transport::Transport::Tcp(stream),
                ));
            }
            Either::Left(Err(e)) => {
                tracing::warn!("accept failed: {e}");
                uring::sleep(std::time::Duration::from_millis(100)).await;
            }
            Either::Right(()) => break,
        }
    }
}

/// The session's 100 ms heartbeat: refills the rate limiters and runs the
/// choker every `UNCHOKE_INTERVAL` (rotating the optimistic slot every
/// `OPTIMISTIC_INTERVAL`).
async fn ticker(ctx: Rc<Ctx>) {
    let mut last_choke = Instant::now();
    let mut last_optimistic = Instant::now();
    let mut next_lsd = Instant::now() + lsd::ANNOUNCE_INTERVAL;
    let mut lsd_index = 0usize;
    loop {
        match select2(
            uring::sleep(std::time::Duration::from_millis(100)),
            ctx.closing.wait(),
        )
        .await
        {
            Either::Left(()) => {}
            Either::Right(()) => break,
        }
        let now = Instant::now();
        ctx.run_due_ticks(now);
        if now.duration_since(last_choke) >= choker::UNCHOKE_INTERVAL {
            last_choke = now;
            let rotate = now.duration_since(last_optimistic) >= choker::OPTIMISTIC_INTERVAL;
            if rotate {
                last_optimistic = now;
            }
            let torrents: Vec<Rc<RefCell<torrent::Torrent>>> =
                ctx.torrents.borrow().values().cloned().collect();
            choke_round(&ctx, &torrents, rotate, now);
        }
        // LSD: one torrent every `interval / torrents`, round-robin
        // (libtorrent `on_lsd_announce`).
        if now >= next_lsd {
            let mut ids: Vec<TorrentId> = ctx.torrents.borrow().keys().copied().collect();
            let n = ids.len().max(1);
            next_lsd = now + lsd::ANNOUNCE_INTERVAL / n as u32;
            if !ids.is_empty() {
                ids.sort();
                lsd_index %= ids.len();
                if let Some(t) = ctx.torrent(ids[lsd_index]) {
                    lsd::announce_now(&ctx, &t);
                }
                lsd_index += 1;
            }
        }
    }
}

fn peer_choke_key(torrent: TorrentId, peer: u32) -> u64 {
    (torrent.0 << 32) | u64::from(peer)
}

/// One choking round across every torrent (session-wide slot budget).
fn choke_round(ctx: &Ctx, torrents: &[Rc<RefCell<torrent::Torrent>>], rotate: bool, now: Instant) {
    let mut cands = Vec::new();
    let mut handles: HashMap<u64, Rc<peer::PeerHandle>> = HashMap::new();
    for t in torrents {
        let t = t.borrow();
        if !t.is_running() {
            continue;
        }
        let seeding = t.is_complete();
        let n = t.piece_count();
        for p in t.peers.values() {
            let (established, interested, choked) = p.choke_state();
            if !established {
                continue;
            }
            let key = peer_choke_key(t.id, p.key);
            cands.push(choker::Candidate {
                key,
                interested,
                choked,
                last_unchoke: p.last_unchoke.get(),
                download_rate: p.download_rate(),
                seeding,
                peer_is_seed: p.is_seed(n),
            });
            handles.insert(key, p.clone());
        }
    }
    let d = choker::round(&cands, ctx.slots.get(), ctx.optimistic.get(), rotate);
    for k in &d.choke {
        if let Some(p) = handles.get(k) {
            p.set_choked(true, now);
        }
    }
    for k in &d.unchoke {
        if let Some(p) = handles.get(k) {
            p.set_choked(false, now);
        }
    }
    ctx.optimistic.set(d.optimistic);
}

/// A peer just became interested: unchoke it now if a slot is free (the next
/// round may still rearrange).
pub fn maybe_unchoke_now(
    ctx: &Ctx,
    torrent: &Rc<RefCell<torrent::Torrent>>,
    handle: &peer::PeerHandle,
) {
    let unchoked: usize = ctx
        .torrents
        .borrow()
        .values()
        .map(|t| {
            t.borrow()
                .peers
                .values()
                .filter(|p| {
                    let (est, _, choked) = p.choke_state();
                    est && !choked
                })
                .count()
        })
        .sum();
    let (running, n) = {
        let t = torrent.borrow();
        (t.is_running(), t.piece_count())
    };
    if running && unchoked < ctx.slots.get() && !handle.is_seed(n) {
        handle.set_choked(false, Instant::now());
    }
}

fn handle_command(ctx: &Rc<Ctx>, cmd: Command) {
    match cmd {
        Command::AddTorrent(params, reply) => {
            if ctx.closing.is_set() {
                let _ = reply.send(Err(Error::Shutdown));
                return;
            }
            let id = TorrentId(ctx.next_id.get());
            ctx.next_id.set(ctx.next_id.get() + 1);
            let ctx2 = ctx.clone();
            uring::spawn(async move {
                let r = torrent::add(ctx2, id, *params).await;
                let _ = reply.send(r);
            });
        }
        Command::Remove(id, delete_files, reply) => match ctx.remove_torrent_entry(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    torrent::stop(&ctx2, &t, true).await;
                    let r = if delete_files {
                        torrent::delete_files(&t).await
                    } else {
                        Ok(())
                    };
                    ctx2.emit(Event::TorrentRemoved { id });
                    let _ = reply.send(r);
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::Find(hash, reply) => {
            let _ = reply.send(ctx.by_hash.borrow().get(&hash).copied());
        }
        Command::PauseAll(reply) => {
            let all: Vec<Rc<RefCell<Torrent>>> = ctx.torrents.borrow().values().cloned().collect();
            let ctx2 = ctx.clone();
            uring::spawn(async move {
                for t in all {
                    torrent::pause(&ctx2, &t).await;
                }
                let _ = reply.send(());
            });
        }
        Command::ResumeAll(reply) => {
            let all: Vec<Rc<RefCell<Torrent>>> = ctx.torrents.borrow().values().cloned().collect();
            for t in all {
                torrent::resume(ctx, &t);
            }
            let _ = reply.send(());
        }
        Command::AddTracker(id, url, tier, reply) => match ctx.torrent(id) {
            Some(t) => {
                let added = {
                    let mut t = t.borrow_mut();
                    let added = t.announcer.add_tracker(&url, tier);
                    if added {
                        t.tracker_kick.notify();
                    }
                    added
                };
                let _ = reply.send(if added {
                    Ok(())
                } else {
                    Err(Error::Io("tracker URL empty or already present".into()))
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::RemoveTracker(id, url, reply) => match ctx.torrent(id) {
            Some(t) => {
                let jobs = t.borrow_mut().announcer.remove_tracker(&url);
                match jobs {
                    Some(jobs) => {
                        torrent::announce_stopped(ctx, &t, jobs);
                        let _ = reply.send(Ok(()));
                    }
                    None => {
                        let _ = reply.send(Err(Error::Io("no such tracker".into())));
                    }
                }
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::SetMaxPeers(id, max, reply) => match ctx.torrent(id) {
            Some(t) => {
                t.borrow_mut().max_peers = max;
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::Pause(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    torrent::pause(&ctx2, &t).await;
                    let _ = reply.send(Ok(()));
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::Resume(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                torrent::resume(ctx, &t);
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::Status(id, reply) => {
            let r = ctx
                .torrent(id)
                .map(|t| t.borrow().status(Instant::now()))
                .ok_or(Error::NoSuchTorrent);
            let _ = reply.send(r);
        }
        Command::Statuses(reply) => {
            let now = Instant::now();
            let mut v: Vec<TorrentStatus> = ctx
                .torrents
                .borrow()
                .values()
                .map(|t| t.borrow().status(now))
                .collect();
            v.sort_by_key(|s| s.id);
            let _ = reply.send(v);
        }
        Command::Peers(id, reply) => {
            let r = ctx
                .torrent(id)
                .map(|t| t.borrow().peer_infos())
                .ok_or(Error::NoSuchTorrent);
            let _ = reply.send(r);
        }
        Command::Stats(reply) => {
            let torrents = ctx.torrents.borrow();
            let mut s = SessionStats {
                torrents: torrents.len(),
                external_v4: ctx.external_address(false),
                external_v6: ctx.external_address(true),
                ..Default::default()
            };
            for t in torrents.values() {
                let t = t.borrow();
                s.peers += t.peer_count();
                s.downloaded += t.stats.downloaded;
                s.uploaded += t.stats.uploaded;
                s.download_rate += t.stats.download_rate;
                s.upload_rate += t.stats.upload_rate;
            }
            s.connections = ctx.connection_count();
            let disk = ctx.disk.stats();
            s.disk_jobs_pending = disk.jobs_pending.load(std::sync::atomic::Ordering::Relaxed);
            s.hash_jobs_pending = disk.hash_pending.load(std::sync::atomic::Ordering::Relaxed);
            s.hash_readback_bytes = disk
                .readback_bytes
                .load(std::sync::atomic::Ordering::Relaxed);
            s.recv_buffers_free = ctx.recv_ring.free();
            s.recv_buffers = usize::from(ctx.cfg.recv_ring_entries);
            let _ = reply.send(s);
        }
        Command::SaveResume(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    let r = torrent::save_resume(&ctx2, &t).await;
                    let _ = reply.send(r);
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::AddPeer(id, addr, reply) => match ctx.torrent(id) {
            Some(t) => {
                t.borrow_mut()
                    .add_candidates(ctx, &[addr], crate::api::PeerSource::Manual);
                torrent::on_new_candidates(ctx, &t);
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::SetFilePriorities(id, prios, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    let r = torrent::set_file_priorities(&ctx2, &t, prios).await;
                    let _ = reply.send(r);
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::SetSequential(id, on, reply) => match ctx.torrent(id) {
            Some(t) => {
                t.borrow_mut().set_sequential(on);
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::MoveStorage(id, path, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    let r = torrent::move_storage(&ctx2, &t, path).await;
                    let _ = reply.send(r);
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::ForceReannounce(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                t.borrow_mut().force_reannounce(Instant::now());
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::ForceRecheck(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    torrent::recheck(ctx2, t).await;
                    let _ = reply.send(Ok(()));
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::Scrape(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    tracker_task::scrape_all(&ctx2, &t).await;
                    let st = t.borrow().status(Instant::now());
                    let _ = reply.send(Ok(st.trackers));
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::SetRateLimits(up, down, reply) => {
            let now = Instant::now();
            ctx.up_limit.set_rate(up, now);
            ctx.down_limit.set_rate(down, now);
            let _ = reply.send(());
        }
        Command::SetTorrentRateLimits(id, up, down, reply) => match ctx.torrent(id) {
            Some(t) => {
                let now = Instant::now();
                let t = t.borrow();
                t.up_limit.set_rate(up, now);
                t.down_limit.set_rate(down, now);
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::Subscribe(tx) => {
            ctx.subscribers
                .borrow_mut()
                .push(Subscriber { tx, dropped: 0 });
        }
        Command::Shutdown(reply) => {
            ctx.shutdown_reply.borrow_mut().push(reply);
            if ctx.closing.is_set() {
                if ctx.done.is_set() {
                    ctx.finish_shutdown();
                }
                return;
            }
            ctx.closing.set();
            let ids: Vec<TorrentId> = ctx.torrents.borrow().keys().copied().collect();
            ctx.stopping.set(ids.len());
            if ids.is_empty() {
                ctx.finish_shutdown();
                return;
            }
            for id in ids {
                if let Some(t) = ctx.remove_torrent_entry(id) {
                    let ctx2 = ctx.clone();
                    uring::spawn(async move {
                        torrent::stop(&ctx2, &t, true).await;
                        ctx2.torrent_stopped();
                    });
                }
            }
        }
    }
}
