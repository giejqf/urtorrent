// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The engine proper: everything that runs on the `urt-net` ring thread.
//!
//! One [`uring::Runtime`] hosts the command loop, the TCP accept loops, and a
//! set of cooperating tasks per torrent (tracker announcer, tick, one task
//! per peer connection). Cross-thread input (API commands, hash results, DNS
//! results) arrives through a single eventfd [`uring::Notifier`]; local tasks
//! that need the command loop's attention ring the same eventfd.

mod bridge;
mod choker;
mod dns;
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
mod udp;
mod webseed;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::Instant;

use metainfo::InfoHash;
use profile::Profile;
use storage::HashPool;
use tokio::sync::{mpsc, oneshot};
use uring::{BufferPool, Notifier, NotifyHandle, Runtime, TcpListener};

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
}

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
        }
    }
}

/// Messages from `Session` handles.
pub enum Command {
    AddTorrent(Box<AddTorrent>, oneshot::Sender<Result<TorrentId, Error>>),
    Remove(TorrentId, oneshot::Sender<Result<(), Error>>),
    Pause(TorrentId, oneshot::Sender<Result<(), Error>>),
    Resume(TorrentId, oneshot::Sender<Result<(), Error>>),
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
    pub pool: Rc<HashPool>,
    pub dns: Dns,
    pub tls: tls::TlsClient,
    pub udp: Rc<udp::UdpDemux>,
    /// Local Service Discovery sockets (`None` when disabled or unavailable).
    pub lsd: RefCell<Option<lsd::Lsd>>,
    pub rng: rng::Rng,
    pub kick: NotifyHandle,
    pub recv_pool: BufferPool,
    pub closing: Rc<Flag>,
    /// Session-wide rate limits.
    pub up_limit: Rc<rate::Limiter>,
    pub down_limit: Rc<rate::Limiter>,
    slots: Cell<usize>,
    optimistic: Cell<Option<u64>>,
    subscribers: RefCell<Vec<Subscriber>>,
    torrents: RefCell<HashMap<TorrentId, Rc<RefCell<Torrent>>>>,
    by_hash: RefCell<HashMap<InfoHash, TorrentId>>,
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

    /// Connections (plus dials in progress) across every torrent except
    /// `except` (which the caller may hold borrowed).
    pub fn connection_count_except(&self, except: Option<TorrentId>) -> usize {
        self.torrents
            .borrow()
            .iter()
            .filter(|(id, _)| Some(**id) != except)
            .map(|(_, t)| {
                let t = t.borrow();
                t.peers.len() + t.half_open
            })
            .sum()
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

    /// Every torrent we serve (for the MSE responder's stream-key lookup).
    pub fn info_hashes(&self) -> Vec<InfoHash> {
        self.by_hash.borrow().keys().copied().collect()
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
        let pool = Rc::new(HashPool::new(cfg.hash_threads));
        pool.attach_notifier(kick.clone());
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
        let ctx = Rc::new(Ctx {
            dns: Dns::new(kick.clone()),
            tls,
            udp: udp_demux.clone(),
            lsd: RefCell::new(lsd),
            up_limit: rate::Limiter::new(cfg.upload_rate, now),
            down_limit: rate::Limiter::new(cfg.download_rate, now),
            slots: Cell::new(cfg.unchoke_slots),
            optimistic: Cell::new(None),
            peer_id,
            listen_port: port,
            families,
            pool,
            rng,
            kick: kick.clone(),
            recv_pool: BufferPool::new(64 * 1024, 64),
            closing: Flag::new(),
            subscribers: RefCell::new(Vec::new()),
            torrents: RefCell::new(HashMap::new()),
            by_hash: RefCell::new(HashMap::new()),
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
            ctx.pool.drain();
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
                uring::spawn(peer::run_incoming(ctx.clone(), stream));
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
        ctx.up_limit.tick(now);
        ctx.down_limit.tick(now);
        let torrents: Vec<Rc<RefCell<torrent::Torrent>>> =
            ctx.torrents.borrow().values().cloned().collect();
        for t in &torrents {
            let t = t.borrow();
            t.up_limit.tick(now);
            t.down_limit.tick(now);
        }
        if now.duration_since(last_choke) >= choker::UNCHOKE_INTERVAL {
            last_choke = now;
            let rotate = now.duration_since(last_optimistic) >= choker::OPTIMISTIC_INTERVAL;
            if rotate {
                last_optimistic = now;
            }
            choke_round(&ctx, &torrents, rotate, now);
        }
        // LSD: one torrent every `interval / torrents`, round-robin
        // (libtorrent `on_lsd_announce`).
        if now >= next_lsd {
            let n = torrents.len().max(1);
            next_lsd = now + lsd::ANNOUNCE_INTERVAL / n as u32;
            if !torrents.is_empty() {
                let mut ids: Vec<TorrentId> = torrents.iter().map(|t| t.borrow().id).collect();
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
        Command::Remove(id, reply) => match ctx.remove_torrent_entry(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    torrent::stop(&ctx2, &t, true).await;
                    ctx2.emit(Event::TorrentRemoved { id });
                    let _ = reply.send(Ok(()));
                });
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
            let _ = reply.send(s);
        }
        Command::SaveResume(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                uring::spawn(async move {
                    let r = torrent::save_resume(&t).await;
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
