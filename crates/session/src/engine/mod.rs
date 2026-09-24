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
mod dht;
mod dns;
mod external_ip;
mod http;
mod ipranges;
mod listen;
mod local;
mod lsd;
mod metadata;
mod peer;
mod pex;
mod queue;
mod rate;
mod rng;
mod tls;
mod torrent;
mod tracker_task;
mod transport;
mod udp;
mod utp;
mod webseed;

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use metainfo::InfoHash;
use profile::Profile;
use storage::DiskRing;
use tokio::sync::{mpsc, oneshot};
use uring::{Notifier, NotifyHandle, Runtime};

use crate::Error;
use crate::api::{
    ActiveLimits, AddTorrent, Event, PeerInfo, QueueMove, SessionStats, TorrentId, TorrentStatus,
    TrackerStatus,
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
    /// Active-torrent queue limits (default unlimited).
    pub active_limits: ActiveLimits,
    /// Extra CA certificates (PEM bundles) trusted for HTTPS trackers.
    pub extra_roots: Vec<Vec<u8>>,
    /// MSE policy.
    pub encryption: crate::api::EncryptionMode,
    /// Peer exchange enabled.
    pub pex: bool,
    /// Local Service Discovery enabled.
    pub lsd: bool,
    /// Run a DHT node (BEP 5) on the listen port's UDP sockets.
    pub dht: bool,
    /// Bootstrap routers (`host:port`); `None` = the profile's defaults,
    /// `Some(empty)` = none (saved state / peers' `port` messages only).
    pub dht_bootstrap_nodes: Option<Vec<String>>,
    /// BEP 43 read-only DHT node.
    pub dht_read_only: bool,
    /// Saved DHT state to restore (`Session::dht_state`).
    pub dht_state: Option<Vec<u8>>,
    /// Peer transports and dial order (`TransportPolicy`, default TCP first).
    pub transports: crate::api::TransportPolicy,
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

/// Most addresses remembered as ours (`Ctx::note_own_ip`).
const MAX_OWN_IPS: usize = 64;

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
            active_limits: ActiveLimits::UNLIMITED,
            extra_roots: Vec::new(),
            encryption: crate::api::EncryptionMode::Enabled,
            pex: true,
            lsd: true,
            dht: true,
            dht_bootstrap_nodes: None,
            dht_read_only: false,
            dht_state: None,
            transports: crate::api::TransportPolicy::PreferTcp,
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
/// A session-wide limit changed at runtime.
#[derive(Debug, Clone, Copy)]
pub enum SessionLimit {
    Connections(usize),
    PeersPerTorrent(usize),
    UnchokeSlots(usize),
}

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
    SetMaxUploads(TorrentId, Option<usize>, oneshot::Sender<Result<(), Error>>),
    SetSessionLimits(SessionLimit, oneshot::Sender<()>),
    SetEncryption(crate::api::EncryptionMode, oneshot::Sender<()>),
    SetTransports(crate::api::TransportPolicy, oneshot::Sender<()>),
    SetPex(bool, oneshot::Sender<()>),
    SetLsd(bool, oneshot::Sender<()>),
    BanIp(IpAddr, bool, oneshot::Sender<()>),
    BannedIps(oneshot::Sender<Vec<IpAddr>>),
    BanIpRange(IpAddr, IpAddr, bool, oneshot::Sender<Result<(), Error>>),
    BannedIpRanges(oneshot::Sender<Vec<(IpAddr, IpAddr)>>),
    Settings(oneshot::Sender<crate::api::SessionSettings>),
    SetListen(
        u16,
        Option<Ipv4Addr>,
        Option<Ipv6Addr>,
        oneshot::Sender<Result<u16, Error>>,
    ),
    SetDht(bool, oneshot::Sender<Result<(), Error>>),
    SetProfile(Box<Profile>, oneshot::Sender<Result<(), Error>>),
    Files(
        TorrentId,
        oneshot::Sender<Result<Vec<crate::api::FileStatus>, Error>>,
    ),
    ResumeData(TorrentId, oneshot::Sender<Result<Vec<u8>, Error>>),
    Trackers(
        TorrentId,
        oneshot::Sender<Result<Vec<TrackerStatus>, Error>>,
    ),
    SetPiecePriorities(TorrentId, Vec<u8>, oneshot::Sender<Result<(), Error>>),
    PiecePriorities(TorrentId, oneshot::Sender<Result<Vec<u8>, Error>>),
    Pieces(
        TorrentId,
        oneshot::Sender<Result<Vec<crate::api::PieceInfo>, Error>>,
    ),
    TorrentFile(TorrentId, oneshot::Sender<Result<Option<Vec<u8>>, Error>>),
    WebSeed(TorrentId, String, bool, oneshot::Sender<Result<(), Error>>),
    RenameFile(TorrentId, usize, String, oneshot::Sender<Result<(), Error>>),
    SetActiveLimits(ActiveLimits, oneshot::Sender<()>),
    SetAutoManaged(TorrentId, bool, oneshot::Sender<Result<(), Error>>),
    ForceResume(TorrentId, oneshot::Sender<Result<(), Error>>),
    MoveInQueue(TorrentId, QueueMove, oneshot::Sender<Result<(), Error>>),
    DhtState(oneshot::Sender<Option<Vec<u8>>>),
    AddDhtNode(SocketAddr, oneshot::Sender<()>),
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
    Release(TorrentId, oneshot::Sender<Result<(), Error>>),
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
    /// The session peer id (profiles with a per-session id); regenerated
    /// by `set_profile`.
    peer_id: Cell<[u8; 20]>,
    /// The listen port in use (`set_listen` changes it).
    listen_port: Cell<u16>,
    /// The listen families in use.
    families: Cell<http::Families>,
    /// The listen addresses in use (`None` = family off).
    listen_v4: Cell<Option<Ipv4Addr>>,
    listen_v6: Cell<Option<Ipv6Addr>>,
    /// The identity profile in force (`set_profile`).
    profile: RefCell<Profile>,
    /// Set when the listen sockets are replaced: the accept loops of the
    /// old sockets exit.
    listen_gen: RefCell<Rc<Flag>>,
    /// Accept loops running (a listener's fd closes when its loop exits).
    accept_loops: Cell<usize>,
    /// Saved DHT state of a node switched off (`set_dht`), restored when
    /// it is switched on again.
    dht_saved: RefCell<Option<Vec<u8>>>,
    /// The disk thread (torrent file I/O and hashing).
    pub disk: Rc<DiskRing>,
    pub dns: Dns,
    pub tls: tls::TlsClient,
    pub udp: Rc<udp::UdpDemux>,
    /// Local Service Discovery sockets (`None` when disabled or unavailable).
    pub lsd: RefCell<Option<lsd::Lsd>>,
    /// The DHT node(s), `None` when disabled.
    dht: RefCell<Option<Rc<dht::Dht>>>,
    /// The uTP endpoint, `None` when both directions are disabled.
    utp: RefCell<Option<Rc<utp::UtpHost>>>,
    /// External-address voters, one per listen family (`[v4, v6]`).
    pub external: RefCell<[external_ip::IpVoter; 2]>,
    pub rng: Rc<rng::Rng>,
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
    /// Session-wide connection limit (`Session::set_max_connections`).
    max_connections: Cell<usize>,
    /// Default per-torrent connection cap (`Session::set_max_peers_per_torrent`).
    max_peers: Cell<usize>,
    /// Active-torrent queue limits (`Session::set_active_limits`).
    active_limits: Cell<ActiveLimits>,
    /// MSE policy (`Session::set_encryption`).
    encryption: Cell<crate::api::EncryptionMode>,
    /// Transport policy (`Session::set_transports`).
    transports: Cell<crate::api::TransportPolicy>,
    /// PEX on (`Session::set_pex`).
    pex: Cell<bool>,
    /// LSD on (`Session::set_lsd`); the sockets in `lsd` stay open once
    /// opened.
    lsd_on: Cell<bool>,
    /// Addresses banned by the caller (`Session::ban_ip`): never dialled,
    /// never accepted, for every torrent.
    banned_ips: RefCell<HashSet<IpAddr>>,
    /// Address ranges banned by the caller (`Session::ban_ip_range`).
    banned_ranges: RefCell<ipranges::IpRanges>,
    /// Next queue position handed to an added torrent.
    next_queue_position: Cell<u64>,
    /// Payload bytes copied in user space by connections since closed (live
    /// ones are summed at query time; see `SessionStats::copied_bytes`).
    copied: Cell<u64>,
    /// Addresses that proved to be ours (a self-connection came in from
    /// them): never dialled on our listen port again. Bounded.
    own_ips: RefCell<HashSet<IpAddr>>,
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

    /// The listen port in use.
    pub fn listen_port(&self) -> u16 {
        self.listen_port.get()
    }

    /// The listen families in use.
    pub fn families(&self) -> http::Families {
        self.families.get()
    }

    /// The IPv4 listen address in use.
    pub fn listen_v4(&self) -> Option<Ipv4Addr> {
        self.listen_v4.get()
    }

    /// The IPv6 listen address in use.
    pub fn listen_v6(&self) -> Option<Ipv6Addr> {
        self.listen_v6.get()
    }

    /// Where outgoing HTTP(S) connections may go and come from: the listen
    /// families and addresses in use now (they change with `set_listen`).
    pub fn outgoing(&self) -> http::Outgoing {
        http::Outgoing {
            families: self.families(),
            bind_v4: self.listen_v4().filter(|a| !a.is_unspecified()),
            bind_v6: self.listen_v6().filter(|a| !a.is_unspecified()),
        }
    }

    /// The source address for an outgoing connection to `ip`: the listen
    /// address of its family, when a specific one is in use.
    pub fn bind_addr_for(&self, ip: IpAddr) -> Option<IpAddr> {
        self.outgoing().bind_for(ip)
    }

    /// The listen address of each tracker endpoint, in the announcer's
    /// endpoint order (`Families::endpoints`).
    pub fn endpoint_addrs(&self) -> Vec<SocketAddr> {
        let port = self.listen_port();
        self.families()
            .endpoints()
            .into_iter()
            .map(|v6| {
                if v6 {
                    SocketAddr::new(
                        self.listen_v6().unwrap_or(Ipv6Addr::UNSPECIFIED).into(),
                        port,
                    )
                } else {
                    SocketAddr::new(
                        self.listen_v4().unwrap_or(Ipv4Addr::UNSPECIFIED).into(),
                        port,
                    )
                }
            })
            .collect()
    }

    /// The identity profile in force.
    pub fn profile(&self) -> Profile {
        self.profile.borrow().clone()
    }

    /// The DHT node, if one runs.
    pub fn dht(&self) -> Option<Rc<dht::Dht>> {
        self.dht.borrow().clone()
    }

    /// The uTP host, if the listen port has a UDP socket.
    pub fn utp(&self) -> Option<Rc<utp::UtpHost>> {
        self.utp.borrow().clone()
    }

    /// The flag the current accept loops watch.
    pub fn listen_gen(&self) -> Rc<Flag> {
        self.listen_gen.borrow().clone()
    }

    /// Session-wide connection limit.
    pub fn max_connections(&self) -> usize {
        self.max_connections.get()
    }

    /// Default per-torrent connection cap.
    pub fn default_max_peers(&self) -> usize {
        self.max_peers.get()
    }

    /// The active-torrent limits.
    pub fn active_limits(&self) -> ActiveLimits {
        self.active_limits.get()
    }

    /// The MSE policy in force.
    pub fn encryption(&self) -> crate::api::EncryptionMode {
        self.encryption.get()
    }

    /// The transport policy in force.
    pub fn transports(&self) -> crate::api::TransportPolicy {
        self.transports.get()
    }

    /// Whether PEX is on.
    pub fn pex(&self) -> bool {
        self.pex.get()
    }

    /// Whether LSD is on (and its sockets are open).
    pub fn lsd_on(&self) -> bool {
        self.lsd_on.get() && self.lsd.borrow().is_some()
    }

    /// Whether the caller banned `ip` (`Session::ban_ip`).
    pub fn is_banned_ip(&self, ip: IpAddr) -> bool {
        self.banned_ips.borrow().contains(&ip) || self.banned_ranges.borrow().contains(ip)
    }

    /// A fresh queue position at the back of the queue.
    pub fn next_queue_position(&self) -> u64 {
        let p = self.next_queue_position.get();
        self.next_queue_position.set(p + 1);
        p
    }

    /// Positions were renumbered `0..n`: hand out `n` next.
    pub fn reset_queue_positions(&self, n: u64) {
        self.next_queue_position.set(n);
    }

    /// A position restored from resume data: later additions go behind it.
    pub fn note_queue_position(&self, q: u64) {
        let next = self.next_queue_position.get();
        self.next_queue_position.set(next.max(q.saturating_add(1)));
    }

    /// `ip` is one of ours (see `own_ips`).
    pub fn note_own_ip(&self, ip: IpAddr) {
        let mut own = self.own_ips.borrow_mut();
        if own.len() < MAX_OWN_IPS {
            own.insert(ip);
        }
    }

    /// Whether `ip` proved to be ours.
    pub fn is_own_ip(&self, ip: IpAddr) -> bool {
        self.own_ips.borrow().contains(&ip)
    }

    /// Retire a connection's copy count (see `SessionStats::copied_bytes`).
    pub fn note_copied(&self, bytes: u64) {
        self.copied.set(self.copied.get() + bytes);
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
        let profile = self.profile.borrow();
        match profile.peer_id.lifetime {
            profile::PeerIdLifetime::PerTorrent => {
                let mut r = rng::RngRef(&self.rng);
                profile.peer_id.generate(&mut r)
            }
            profile::PeerIdLifetime::PerSession => self.peer_id.get(),
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
            self.dht_external_ip_changed(ip);
        }
    }

    /// The DHT node of that family adopts a BEP 42 id for the new address.
    fn dht_external_ip_changed(&self, ip: IpAddr) {
        if let Some(d) = self.dht() {
            d.external_ip(self, ip);
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
        let profile = self.profile.borrow();
        match profile.peer_id.handshake {
            profile::HandshakePeerId::SameAsAnnounce => torrent.peer_id,
            profile::HandshakePeerId::PerConnection => {
                let mut r = rng::RngRef(&self.rng);
                profile.peer_id.generate(&mut r)
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
        let bound = match listen::bind_tcp(cfg.listen_port, cfg.listen_v4, cfg.listen_v6) {
            Ok(b) => b,
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        };
        let listen::Bound {
            listeners,
            port,
            families,
            v4: bound_v4,
            v6: bound_v6,
        } = bound;

        let mut roots = tls::TlsClient::env_roots();
        roots.extend(cfg.extra_roots.iter().cloned());
        let tls = match tls::TlsClient::new(&roots) {
            Ok(t) => t,
            Err(e) => {
                let _ = ready.send(Err(Error::Io(e)));
                return;
            }
        };
        let rng = Rc::new(rng::Rng::from_os());
        let peer_id = {
            let mut r = rng::RngRef(&rng);
            cfg.profile.peer_id.generate(&mut r)
        };
        // The listen port's UDP sockets (UDP trackers now; DHT/uTP demux later).
        let udp_demux = Rc::new(udp::UdpDemux::bind(
            port,
            bound_v4,
            bound_v6,
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
            lsd::Lsd::open(bound_v4, bound_v6, (rng.next_u64() >> 33) as u32)
        } else {
            None
        };
        let now = Instant::now();
        let dht_service = if cfg.dht
            && (udp_demux.supports(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                || udp_demux.supports(IpAddr::V6(Ipv6Addr::UNSPECIFIED)))
        {
            Some(Rc::new(dht::Dht::new(
                &cfg.profile,
                cfg.dht_read_only,
                cfg.dht_bootstrap_nodes.as_deref(),
                udp_demux.supports(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                udp_demux.supports(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                port,
                cfg.dht_state.as_deref(),
                &rng,
                now,
            )))
        } else {
            None
        };
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
        // The uTP host exists whenever there is a UDP socket; the transport
        // policy (changeable at runtime) decides whether it is used.
        let utp_host = if udp_demux.supports(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            || udp_demux.supports(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        {
            Some(utp::UtpHost::new(
                utp::default_config(),
                udp_demux.clone(),
                rng.clone(),
                cfg.transports.utp_incoming(),
                cfg.max_connections.max(1) * 2,
            ))
        } else {
            None
        };
        let ctx = Rc::new(Ctx {
            dns: Dns::new(kick.clone()),
            tls,
            udp: udp_demux.clone(),
            lsd: RefCell::new(lsd),
            dht: RefCell::new(dht_service),
            utp: RefCell::new(utp_host),
            listen_v4: Cell::new(bound_v4),
            listen_v6: Cell::new(bound_v6),
            profile: RefCell::new(cfg.profile.clone()),
            listen_gen: RefCell::new(Flag::new()),
            accept_loops: Cell::new(0),
            dht_saved: RefCell::new(None),
            external: RefCell::new([
                external_ip::IpVoter::new(now),
                external_ip::IpVoter::new(now),
            ]),
            up_limit: rate::Limiter::new(cfg.upload_rate, now),
            down_limit: rate::Limiter::new(cfg.download_rate, now),
            slots: Cell::new(cfg.unchoke_slots),
            optimistic: Cell::new(None),
            peer_id: Cell::new(peer_id),
            listen_port: Cell::new(port),
            families: Cell::new(families),
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
            max_connections: Cell::new(cfg.max_connections),
            max_peers: Cell::new(cfg.max_peers),
            active_limits: Cell::new(cfg.active_limits),
            encryption: Cell::new(cfg.encryption),
            transports: Cell::new(cfg.transports),
            pex: Cell::new(cfg.pex),
            lsd_on: Cell::new(cfg.lsd),
            banned_ips: RefCell::new(HashSet::new()),
            banned_ranges: RefCell::new(ipranges::IpRanges::default()),
            next_queue_position: Cell::new(0),
            copied: Cell::new(0),
            own_ips: RefCell::new(HashSet::new()),
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
            profile = ctx.profile.borrow().name,
            "engine up"
        );
        let _ = ready.send(Ok(Boot {
            notify: kick.clone(),
            listen_port: port,
        }));

        let generation = ctx.listen_gen();
        for l in listeners {
            listen::spawn_accept(&ctx, l, generation.clone());
        }
        if let Some(h) = ctx.utp() {
            // uTP datagrams on the listen port; SYNs become incoming peers.
            listen::install_utp(&ctx, h);
        }
        udp_demux.spawn(ctx.closing.clone());
        // KRPC datagrams on the listen port go to the DHT node, whichever
        // runs at the time (`set_dht`).
        {
            let weak = Rc::downgrade(&ctx);
            ctx.udp.set_dht_hook(Box::new(move |from, pkt, v6| {
                if let Some(ctx) = weak.upgrade()
                    && let Some(d) = ctx.dht()
                {
                    d.incoming(&ctx, from, pkt, v6);
                }
            }));
        }
        if let Some(d) = ctx.dht() {
            let ctx2 = ctx.clone();
            uring::spawn(async move {
                d.start(&ctx2).await;
            });
        }
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

/// The session's 100 ms heartbeat: refills the rate limiters and runs the
/// choker every `UNCHOKE_INTERVAL` (rotating the optimistic slot every
/// `OPTIMISTIC_INTERVAL`).
async fn ticker(ctx: Rc<Ctx>) {
    let mut last_choke = Instant::now();
    let mut last_optimistic = Instant::now();
    let mut last_dht = Instant::now();
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
        if let Some(h) = ctx.utp() {
            h.tick(now);
        }
        if now.duration_since(last_dht) >= std::time::Duration::from_secs(1) {
            last_dht = now;
            if let Some(d) = ctx.dht() {
                d.tick(&ctx, now);
            }
            queue::recalculate(&ctx, now);
        }
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

/// A torrent's dense queue position from `queue::positions`.
fn queue_index(positions: &[(TorrentId, usize)], id: TorrentId) -> usize {
    positions
        .iter()
        .find(|(i, _)| *i == id)
        .map_or(0, |(_, p)| *p)
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
                torrent: t.id.0,
                max_uploads: t.max_uploads,
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
    let (running, n, under_cap) = {
        let t = torrent.borrow();
        let own = t
            .peers
            .values()
            .filter(|p| {
                let (est, _, choked) = p.choke_state();
                est && !choked
            })
            .count();
        (
            t.is_running(),
            t.piece_count(),
            t.max_uploads.is_none_or(|cap| own < cap),
        )
    };
    if running && under_cap && unchoked < ctx.slots.get() && !handle.is_seed(n) {
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
                    torrent::stop(&ctx2, &t, false).await;
                    let mut r = torrent::delete_resume_file(&t);
                    if delete_files && r.is_ok() {
                        r = torrent::delete_files(&t).await;
                    }
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
            for t in &all {
                t.borrow_mut().set_auto_managed(false);
            }
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
                if t.borrow().held {
                    // Held torrents are released and started too.
                    t.borrow_mut().set_auto_managed(true);
                    let ctx2 = ctx.clone();
                    uring::spawn(async move {
                        let _ = torrent::release(&ctx2, &t, true).await;
                    });
                    continue;
                }
                queue::mark_eligible(&t);
            }
            queue::recalculate(ctx, Instant::now());
            let _ = reply.send(());
        }
        Command::AddTracker(id, url, tier, reply) => match ctx.torrent(id) {
            Some(t) => {
                let added = {
                    let mut t = t.borrow_mut();
                    let added = t.announcer.add_tracker(&url, tier);
                    if added {
                        t.tracker_kick.notify();
                        // The tracker list is in the resume data (v6).
                        t.resume_dirty = true;
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
                        t.borrow_mut().resume_dirty = true;
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
        Command::DhtState(reply) => {
            let _ = reply.send(ctx.dht().map(|d| d.state()));
        }
        Command::AddDhtNode(addr, reply) => {
            if let Some(d) = ctx.dht() {
                d.add_node(ctx, addr);
            }
            let _ = reply.send(());
        }
        Command::SetMaxUploads(id, max, reply) => match ctx.torrent(id) {
            Some(t) => {
                let mut t = t.borrow_mut();
                if t.max_uploads != max {
                    t.max_uploads = max;
                    t.resume_dirty = true;
                }
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::SetSessionLimits(limit, reply) => {
            match limit {
                SessionLimit::Connections(n) => ctx.max_connections.set(n.max(1)),
                SessionLimit::PeersPerTorrent(n) => ctx.max_peers.set(n.max(1)),
                SessionLimit::UnchokeSlots(n) => ctx.slots.set(n),
            }
            let _ = reply.send(());
        }
        Command::SetEncryption(mode, reply) => {
            ctx.encryption.set(mode);
            let _ = reply.send(());
        }
        Command::SetTransports(policy, reply) => {
            ctx.transports.set(policy);
            if let Some(h) = ctx.utp() {
                h.set_incoming(policy.utp_incoming());
            }
            let _ = reply.send(());
        }
        Command::SetPex(on, reply) => {
            ctx.pex.set(on);
            let _ = reply.send(());
        }
        Command::SetLsd(on, reply) => {
            ctx.lsd_on.set(on);
            if on && ctx.lsd.borrow().is_none() {
                // Opened on first use; the sockets then stay for the session.
                let opened = lsd::Lsd::open(
                    if ctx.families().v4 {
                        ctx.listen_v4()
                    } else {
                        None
                    },
                    if ctx.families().v6 {
                        ctx.listen_v6()
                    } else {
                        None
                    },
                    (ctx.rng.next_u64() >> 33) as u32,
                );
                if let Some(l) = opened {
                    l.spawn(ctx.clone());
                    *ctx.lsd.borrow_mut() = Some(l);
                }
            }
            let _ = reply.send(());
        }
        Command::BanIp(ip, on, reply) => {
            if on {
                ctx.banned_ips.borrow_mut().insert(ip);
                // Drop what is connected from there, on every torrent.
                for t in ctx.torrents.borrow().values() {
                    let t = t.borrow();
                    for p in t.peers.values() {
                        if p.addr.ip() == ip {
                            p.close("banned");
                        }
                    }
                }
            } else {
                ctx.banned_ips.borrow_mut().remove(&ip);
            }
            let _ = reply.send(());
        }
        Command::BanIpRange(first, last, on, reply) => {
            if first.is_ipv4() != last.is_ipv4() || first > last {
                let _ = reply.send(Err(Error::InvalidArgument(format!(
                    "{first}..={last} is not a range of one family"
                ))));
                return;
            }
            if on {
                ctx.banned_ranges.borrow_mut().insert(first, last);
                for t in ctx.torrents.borrow().values() {
                    let t = t.borrow();
                    for p in t.peers.values() {
                        let ip = p.addr.ip();
                        if first <= ip && ip <= last {
                            p.close("banned");
                        }
                    }
                }
            } else {
                ctx.banned_ranges.borrow_mut().remove(first, last);
            }
            let _ = reply.send(Ok(()));
        }
        Command::BannedIpRanges(reply) => {
            let _ = reply.send(ctx.banned_ranges.borrow().ranges());
        }
        Command::BannedIps(reply) => {
            let mut v: Vec<IpAddr> = ctx.banned_ips.borrow().iter().copied().collect();
            v.sort();
            let _ = reply.send(v);
        }
        Command::SetListen(port, v4, v6, reply) => {
            let ctx2 = ctx.clone();
            uring::spawn(async move {
                let r = listen::set_listen(&ctx2, port, v4, v6).await;
                let _ = reply.send(r);
            });
        }
        Command::SetDht(on, reply) => {
            let _ = reply.send(listen::set_dht(ctx, on));
        }
        Command::SetProfile(profile, reply) => {
            let ctx2 = ctx.clone();
            uring::spawn(async move {
                let r = listen::set_profile(&ctx2, *profile).await;
                let _ = reply.send(r);
            });
        }
        Command::Settings(reply) => {
            let _ = reply.send(crate::api::SessionSettings {
                listen_port: ctx.listen_port(),
                listen_v4: ctx.listen_v4(),
                listen_v6: ctx.listen_v6(),
                profile: ctx.profile.borrow().name.to_string(),
                dht: ctx.dht().is_some(),
                upload_limit: ctx.up_limit.rate(),
                download_limit: ctx.down_limit.rate(),
                max_connections: ctx.max_connections(),
                max_peers_per_torrent: ctx.default_max_peers(),
                unchoke_slots: ctx.slots.get(),
                active_limits: ctx.active_limits(),
                encryption: ctx.encryption(),
                transports: ctx.transports(),
                pex: ctx.pex(),
                lsd: ctx.lsd_on(),
            });
        }
        Command::SetActiveLimits(limits, reply) => {
            ctx.active_limits.set(limits);
            queue::recalculate(ctx, Instant::now());
            let _ = reply.send(());
        }
        Command::SetAutoManaged(id, on, reply) => match ctx.torrent(id) {
            Some(t) => {
                queue::set_auto_managed(ctx, &t, on);
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::ForceResume(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    if t.borrow().held {
                        t.borrow_mut().set_auto_managed(false);
                        let _ = reply.send(torrent::release(&ctx2, &t, true).await);
                        return;
                    }
                    if t.borrow().error.is_some() {
                        t.borrow_mut().set_auto_managed(false);
                        t.borrow_mut().auto_paused = false;
                        let r = torrent::recover(&ctx2, &t, torrent::Recovery::Resume).await;
                        let _ = reply.send(r.map(|_| ()));
                        return;
                    }
                    t.borrow_mut().set_auto_managed(false);
                    torrent::resume(&ctx2, &t);
                    let _ = reply.send(Ok(()));
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::MoveInQueue(id, to, reply) => {
            let r = queue::move_in_queue(ctx, id, to);
            let _ = reply.send(r);
        }
        Command::SetMaxPeers(id, max, reply) => match ctx.torrent(id) {
            Some(t) => {
                let mut t = t.borrow_mut();
                if t.max_peers != max {
                    t.max_peers = max;
                    t.resume_dirty = true;
                }
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::Pause(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                // A paused auto-managed torrent would be restarted by the
                // queue: pausing takes it out of the queue's hands.
                t.borrow_mut().set_auto_managed(false);
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
                if t.borrow().held {
                    let ctx2 = ctx.clone();
                    uring::spawn(async move {
                        // Released into the queue's hands.
                        t.borrow_mut().set_auto_managed(true);
                        let _ = reply.send(torrent::release(&ctx2, &t, true).await);
                    });
                } else if t.borrow().error.is_some() {
                    let ctx2 = ctx.clone();
                    uring::spawn(async move {
                        // Back in the queue's hands, then recovered: the
                        // restart goes through the queue.
                        t.borrow_mut().set_auto_managed(true);
                        let r = torrent::recover(&ctx2, &t, torrent::Recovery::Resume).await;
                        let _ = reply.send(r.map(|_| ()));
                    });
                } else {
                    queue::set_auto_managed(ctx, &t, true);
                    let _ = reply.send(Ok(()));
                }
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::Status(id, reply) => {
            let positions = queue::positions(ctx);
            let r = ctx
                .torrent(id)
                .map(|t| {
                    t.borrow().status(
                        Instant::now(),
                        queue_index(&positions, id),
                        true,
                        &ctx.endpoint_addrs(),
                    )
                })
                .ok_or(Error::NoSuchTorrent);
            let _ = reply.send(r);
        }
        Command::Statuses(reply) => {
            let now = Instant::now();
            let positions = queue::positions(ctx);
            let mut v: Vec<TorrentStatus> = ctx
                .torrents
                .borrow()
                .values()
                .map(|t| {
                    let t = t.borrow();
                    t.status(now, queue_index(&positions, t.id), false, &[])
                })
                .collect();
            v.sort_by_key(|s| s.id);
            let _ = reply.send(v);
        }
        Command::ResumeData(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    let r = torrent::resume_data(&ctx2, &t).await;
                    let _ = reply.send(r);
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::Files(id, reply) => {
            let r = ctx
                .torrent(id)
                .map(|t| t.borrow().files())
                .ok_or(Error::NoSuchTorrent);
            let _ = reply.send(r);
        }
        Command::Trackers(id, reply) => {
            let r = ctx
                .torrent(id)
                .map(|t| t.borrow().trackers(Instant::now(), &ctx.endpoint_addrs()))
                .ok_or(Error::NoSuchTorrent);
            let _ = reply.send(r);
        }
        Command::SetPiecePriorities(id, prios, reply) => {
            let r = match ctx.torrent(id) {
                Some(t) => torrent::set_piece_priorities(ctx, &t, prios),
                None => Err(Error::NoSuchTorrent),
            };
            let _ = reply.send(r);
        }
        Command::PiecePriorities(id, reply) => {
            let r = ctx
                .torrent(id)
                .map(|t| {
                    t.borrow()
                        .pieces()
                        .into_iter()
                        .map(|p| p.priority)
                        .collect()
                })
                .ok_or(Error::NoSuchTorrent);
            let _ = reply.send(r);
        }
        Command::Pieces(id, reply) => {
            let r = ctx
                .torrent(id)
                .map(|t| t.borrow().pieces())
                .ok_or(Error::NoSuchTorrent);
            let _ = reply.send(r);
        }
        Command::TorrentFile(id, reply) => {
            let r = ctx
                .torrent(id)
                .map(|t| t.borrow().torrent_file())
                .ok_or(Error::NoSuchTorrent);
            let _ = reply.send(r);
        }
        Command::RenameFile(id, index, path, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    let r = torrent::rename_file(&ctx2, &t, index, &path).await;
                    let _ = reply.send(r);
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::WebSeed(id, url, add, reply) => match ctx.torrent(id) {
            Some(t) => {
                {
                    let mut tb = t.borrow_mut();
                    if add {
                        if !tb.web_seeds.contains(&url) {
                            tb.web_seeds.push(url);
                        }
                    } else {
                        tb.web_seeds.retain(|u| *u != url);
                    }
                    tb.resume_dirty = true;
                }
                if add {
                    webseed::start(ctx, &t);
                }
                let _ = reply.send(Ok(()));
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
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
            s.copied_bytes = ctx.copied.get();
            for t in torrents.values() {
                let t = t.borrow();
                s.peers += t.peer_count();
                s.downloaded += t.stats.downloaded;
                s.uploaded += t.stats.uploaded;
                s.download_rate += t.stats.download_rate;
                s.upload_rate += t.stats.upload_rate;
                s.copied_bytes += t.copied_bytes();
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
            if let Some(d) = ctx.dht() {
                let ds = d.stats();
                s.dht_nodes = ds.nodes;
                s.dht_lookups = ds.lookups;
                s.dht_stored_peers = ds.peers;
            }
            if let Some(h) = ctx.utp() {
                s.utp_connections = h.connections();
                s.copied_bytes += h.copied_bytes();
            }
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
                {
                    let mut tb = t.borrow_mut();
                    tb.add_candidates(ctx, &[addr], crate::api::PeerSource::Manual);
                    // An explicit request: dial now, whatever the backoff
                    // from an earlier (or still closing) connection
                    // (libtorrent `connect_peer`).
                    tb.request_dial(torrent::canonical_addr(addr));
                }
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
        Command::Release(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    let r = torrent::release(&ctx2, &t, false).await;
                    let _ = reply.send(r);
                });
            }
            None => {
                let _ = reply.send(Err(Error::NoSuchTorrent));
            }
        },
        Command::ForceRecheck(id, reply) => match ctx.torrent(id) {
            Some(t) => {
                let ctx2 = ctx.clone();
                uring::spawn(async move {
                    if t.borrow().held {
                        let _ = reply.send(torrent::release(&ctx2, &t, false).await);
                        return;
                    }
                    let r = match torrent::recover(&ctx2, &t, torrent::Recovery::Recheck).await {
                        Ok(true) => Ok(()),
                        Ok(false) => {
                            torrent::recheck(ctx2, t).await;
                            Ok(())
                        }
                        Err(e) => Err(e),
                    };
                    let _ = reply.send(r);
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
                    let st = t
                        .borrow()
                        .status(Instant::now(), 0, true, &ctx2.endpoint_addrs());
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
                let mut t = t.borrow_mut();
                if t.up_limit.rate() != up || t.down_limit.rate() != down {
                    t.resume_dirty = true;
                }
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
