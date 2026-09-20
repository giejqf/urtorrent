// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Public API types and the `Session` handle. Everything here is plain data
//! or a message to the engine thread.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use metainfo::InfoHash;
use profile::Profile;
use tokio::sync::{mpsc, oneshot};

use crate::Error;
use crate::engine::{self, Command, EngineConfig};

/// Message Stream Encryption policy (qBittorrent's "Allow" / "Require" /
/// "Disable").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    /// Plaintext only; encrypted incoming connections are refused.
    Disabled,
    /// Accept both; connect out in plaintext first and retry with MSE when
    /// that fails (libtorrent's behaviour, docs/quirks.md Q3).
    Enabled,
    /// RC4 required both ways.
    Forced,
}

/// Identifies a torrent within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TorrentId(pub u64);

/// Where a torrent comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorrentSource {
    /// The bytes of a `.torrent` file.
    Metainfo(Vec<u8>),
    /// A magnet link (BEP 9): the metadata is fetched from peers found
    /// through its trackers (and PEX / LSD).
    Magnet(String),
}

/// Parameters for [`Session::add_torrent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddTorrent {
    /// The torrent.
    pub source: TorrentSource,
    /// Directory the content is stored under.
    pub save_path: PathBuf,
    /// Directory for this torrent's resume file (`<infohash>.resume`). `None`
    /// disables resume persistence.
    pub resume_dir: Option<PathBuf>,
    /// Add without starting (no announces, no connections).
    pub paused: bool,
    /// Download pieces in order.
    pub sequential: bool,
    /// Initial file priorities, one per content file in torrent order
    /// (`0` = skip, `1..=7`; libtorrent's default is 4). `None` keeps the
    /// priorities from the resume data, or the default. For a magnet link
    /// they apply once the metadata arrives (ignored if the count differs).
    pub file_priorities: Option<Vec<u8>>,
}

impl AddTorrent {
    /// Add from `.torrent` bytes, saving under `save_path`.
    pub fn metainfo(bytes: Vec<u8>, save_path: impl Into<PathBuf>) -> AddTorrent {
        AddTorrent {
            source: TorrentSource::Metainfo(bytes),
            save_path: save_path.into(),
            resume_dir: None,
            paused: false,
            sequential: false,
            file_priorities: None,
        }
    }

    /// Add from a magnet link, saving under `save_path`.
    pub fn magnet(uri: impl Into<String>, save_path: impl Into<PathBuf>) -> AddTorrent {
        AddTorrent {
            source: TorrentSource::Magnet(uri.into()),
            save_path: save_path.into(),
            resume_dir: None,
            paused: false,
            sequential: false,
            file_priorities: None,
        }
    }

    /// Set the resume directory.
    pub fn resume_dir(mut self, dir: impl Into<PathBuf>) -> AddTorrent {
        self.resume_dir = Some(dir.into());
        self
    }

    /// Start paused.
    pub fn paused(mut self, paused: bool) -> AddTorrent {
        self.paused = paused;
        self
    }

    /// Sequential download.
    pub fn sequential(mut self, sequential: bool) -> AddTorrent {
        self.sequential = sequential;
        self
    }

    /// Initial file priorities (see the field).
    pub fn file_priorities(mut self, prios: Vec<u8>) -> AddTorrent {
        self.file_priorities = Some(prios);
        self
    }
}

/// One content file in a status snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStatus {
    /// Path relative to the save directory, `/`-separated.
    pub path: String,
    /// Length in bytes.
    pub size: u64,
    /// Priority (`0` = skipped).
    pub priority: u8,
    /// Bytes of this file covered by verified pieces.
    pub done: u64,
}

/// A torrent's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorrentState {
    /// A magnet link waiting for its metadata (BEP 9).
    FetchingMetadata,
    /// Verifying data on disk.
    Checking,
    /// Downloading (or waiting for peers).
    Downloading,
    /// Complete; announcing and accepting peers.
    Seeding,
    /// Stopped by the caller.
    Paused,
    /// Stopped by an error (see `error`).
    Error,
}

/// One tracker's state in a status snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerStatus {
    /// Announce URL.
    pub url: String,
    /// Tier index.
    pub tier: usize,
    /// The last announce succeeded.
    pub working: bool,
    /// Consecutive failures.
    pub fails: u32,
    /// Last error text.
    pub last_error: Option<String>,
    /// Seeders reported by the tracker.
    pub seeders: Option<u32>,
    /// Leechers reported by the tracker.
    pub leechers: Option<u32>,
    /// Completed downloads reported by a scrape.
    pub downloaded: Option<u32>,
    /// Time until the next scheduled announce.
    pub next_announce_in: Option<Duration>,
}

/// A copied-out snapshot of a torrent. Counters are truthful (AGENTS.md rule 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentStatus {
    /// The torrent id.
    pub id: TorrentId,
    /// Info-hash.
    pub info_hash: InfoHash,
    /// Display name.
    pub name: String,
    /// State.
    pub state: TorrentState,
    /// Error text when `state == Error`.
    pub error: Option<String>,
    /// The metadata is known (always true for a `.torrent`; false while a
    /// magnet link is fetching it).
    pub has_metadata: bool,
    /// BEP 27 private torrent (no PEX / LSD / DHT).
    pub private: bool,
    /// Verified pieces.
    pub pieces_have: usize,
    /// Total pieces.
    pub pieces_total: usize,
    /// Total content size in bytes.
    pub total_size: u64,
    /// Payload bytes downloaded (this run plus resume data).
    pub downloaded: u64,
    /// Payload bytes uploaded.
    pub uploaded: u64,
    /// Bytes still needed (the announce `left`).
    pub left: u64,
    /// Bytes that failed hash checks.
    pub corrupt: u64,
    /// Bytes received redundantly.
    pub redundant: u64,
    /// Bytes per second, smoothed.
    pub download_rate: u64,
    /// Bytes per second, smoothed.
    pub upload_rate: u64,
    /// Connected peers.
    pub peers: usize,
    /// Connected peers that are seeds.
    pub seeds: usize,
    /// Trackers.
    pub trackers: Vec<TrackerStatus>,
    /// Whether the torrent is complete (all wanted pieces).
    pub complete: bool,
    /// Web seeds (BEP 19) configured.
    pub web_seeds: usize,
    /// Content files with their priorities and progress (empty until the
    /// metadata is known).
    pub files: Vec<FileStatus>,
    /// Bytes in wanted pieces (priority > 0).
    pub total_wanted: u64,
    /// Bytes in wanted pieces already verified.
    pub total_wanted_done: u64,
    /// Where the content lives.
    pub save_path: PathBuf,
}

impl TorrentStatus {
    /// Fraction of pieces we have, 0.0..=1.0 (0.0 without metadata).
    pub fn progress(&self) -> f64 {
        if self.pieces_total == 0 {
            if self.has_metadata { 1.0 } else { 0.0 }
        } else {
            self.pieces_have as f64 / self.pieces_total as f64
        }
    }

    /// Fraction of the wanted bytes we have, 0.0..=1.0 (1.0 when nothing is
    /// wanted).
    pub fn wanted_progress(&self) -> f64 {
        if self.total_wanted == 0 {
            1.0
        } else {
            self.total_wanted_done as f64 / self.total_wanted as f64
        }
    }
}

/// Where a peer's address was learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerSource {
    /// A tracker reply.
    Tracker,
    /// [`Session::add_peer`].
    Manual,
    /// Peer exchange (BEP 11).
    Pex,
    /// Local Service Discovery (BEP 14).
    Lsd,
    /// It connected to us.
    Incoming,
}

/// A connected peer, copied out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// Remote address.
    pub addr: SocketAddr,
    /// How we learned of the peer.
    pub source: PeerSource,
    /// Peer id (after handshake).
    pub peer_id: Option<[u8; 20]>,
    /// Client name from the LTEP handshake `v`.
    pub client: Option<String>,
    /// Whether the peer connected to us.
    pub incoming: bool,
    /// Payload bytes received from this peer.
    pub downloaded: u64,
    /// Payload bytes sent to this peer.
    pub uploaded: u64,
    /// Pieces the peer has.
    pub pieces: usize,
    /// The peer has every piece.
    pub is_seed: bool,
    /// The peer is choking us.
    pub peer_choking: bool,
    /// We are interested in the peer.
    pub am_interested: bool,
    /// Outstanding requests to the peer.
    pub outstanding: usize,
    /// The connection is RC4-encrypted (MSE).
    pub encrypted: bool,
    /// The peer declared itself upload-only (BEP 21) or is a seed.
    pub upload_only: bool,
}

/// Session-wide counters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionStats {
    /// Torrents in the session.
    pub torrents: usize,
    /// Connected peers across torrents.
    pub peers: usize,
    /// Total payload downloaded this session.
    pub downloaded: u64,
    /// Total payload uploaded this session.
    pub uploaded: u64,
    /// Sum of the torrents' smoothed download rates, bytes per second.
    pub download_rate: u64,
    /// Sum of the torrents' smoothed upload rates, bytes per second.
    pub upload_rate: u64,
    /// External IPv4 address, once trackers / peers voted one in.
    pub external_v4: Option<std::net::IpAddr>,
    /// External IPv6 address, once voted in.
    pub external_v6: Option<std::net::IpAddr>,
}

/// Something that happened in the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A torrent was added.
    TorrentAdded {
        /// The torrent.
        id: TorrentId,
    },
    /// Initial check (resume validation or recheck) finished.
    Checked {
        /// The torrent.
        id: TorrentId,
        /// Verified pieces found.
        pieces_have: usize,
    },
    /// A piece was verified and written.
    PieceFinished {
        /// The torrent.
        id: TorrentId,
        /// The piece.
        piece: u32,
    },
    /// A piece failed its hash check.
    HashFailed {
        /// The torrent.
        id: TorrentId,
        /// The piece.
        piece: u32,
    },
    /// Every wanted piece is verified.
    TorrentFinished {
        /// The torrent.
        id: TorrentId,
    },
    /// A magnet link's metadata arrived and verified (BEP 9).
    MetadataReceived {
        /// The torrent.
        id: TorrentId,
    },
    /// A `ut_pex` message brought peers (BEP 11).
    PexPeers {
        /// The torrent.
        id: TorrentId,
        /// The peer that sent it.
        from: SocketAddr,
        /// New addresses (after filtering).
        added: usize,
        /// Addresses dropped.
        dropped: usize,
    },
    /// A Local Service Discovery announce for one of our torrents (BEP 14).
    LsdPeer {
        /// The torrent.
        id: TorrentId,
        /// The announcing peer.
        addr: SocketAddr,
    },
    /// Trackers / peers agreed on our external address (libtorrent's
    /// `external_ip_alert`).
    ExternalAddress {
        /// The address.
        ip: std::net::IpAddr,
    },
    /// The content was moved to a new directory (`Session::move_storage`).
    StorageMoved {
        /// The torrent.
        id: TorrentId,
        /// The new save path.
        path: PathBuf,
    },
    /// A web seed (BEP 19) request failed; the seed is retried later.
    WebSeedError {
        /// The torrent.
        id: TorrentId,
        /// The web seed URL.
        url: String,
        /// What went wrong.
        error: String,
    },
    /// A tracker answered an announce.
    TrackerReply {
        /// The torrent.
        id: TorrentId,
        /// Announce URL.
        url: String,
        /// Peers in the reply.
        peers: usize,
    },
    /// A scrape answered (BEP 48).
    ScrapeReply {
        /// The torrent.
        id: TorrentId,
        /// Scrape URL.
        url: String,
        /// Seeders.
        complete: u32,
        /// Leechers.
        incomplete: u32,
        /// Completed downloads.
        downloaded: u32,
    },
    /// A tracker announce failed.
    TrackerError {
        /// The torrent.
        id: TorrentId,
        /// Announce URL.
        url: String,
        /// What went wrong.
        error: String,
    },
    /// A peer connection completed its handshake.
    PeerConnected {
        /// The torrent.
        id: TorrentId,
        /// Remote address.
        addr: SocketAddr,
        /// Whether the peer connected to us.
        incoming: bool,
    },
    /// A peer connection ended (after a completed handshake).
    PeerDisconnected {
        /// The torrent.
        id: TorrentId,
        /// Remote address.
        addr: SocketAddr,
        /// Why.
        reason: String,
        /// Final counters and identity of the peer.
        info: PeerInfo,
    },
    /// A torrent hit an error and stopped.
    TorrentError {
        /// The torrent.
        id: TorrentId,
        /// What went wrong.
        error: String,
    },
    /// A torrent was removed.
    TorrentRemoved {
        /// The torrent.
        id: TorrentId,
    },
    /// The consumer fell behind; `dropped` events were discarded.
    Lagged {
        /// Number of events discarded.
        dropped: u64,
    },
}

/// A stream of [`Event`]s. `recv().await` on any executor, or use it as a
/// `futures_core::Stream`.
pub struct EventStream {
    rx: mpsc::Receiver<Event>,
}

impl EventStream {
    /// Next event, or `None` once the engine is gone.
    pub async fn recv(&mut self) -> Option<Event> {
        self.rx.recv().await
    }

    /// Non-blocking poll.
    pub fn try_recv(&mut self) -> Option<Event> {
        self.rx.try_recv().ok()
    }
}

impl futures_core::Stream for EventStream {
    type Item = Event;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Event>> {
        self.rx.poll_recv(cx)
    }
}

/// Configures and starts a [`Session`].
#[derive(Debug, Clone, Default)]
pub struct SessionBuilder {
    cfg: EngineConfig,
}

impl SessionBuilder {
    /// TCP listen port for both address families (0 = ephemeral).
    pub fn listen_port(mut self, port: u16) -> Self {
        self.cfg.listen_port = port;
        self
    }

    /// IPv4 listen address (`None` disables IPv4 listening).
    pub fn listen_v4(mut self, addr: Option<Ipv4Addr>) -> Self {
        self.cfg.listen_v4 = addr;
        self
    }

    /// IPv6 listen address (`None` disables IPv6 listening).
    pub fn listen_v6(mut self, addr: Option<Ipv6Addr>) -> Self {
        self.cfg.listen_v6 = addr;
        self
    }

    /// The identity profile (default: `native`).
    pub fn profile(mut self, profile: Profile) -> Self {
        self.cfg.profile = profile;
        self
    }

    /// Maximum connected peers per torrent (default 50).
    pub fn max_peers_per_torrent(mut self, n: usize) -> Self {
        self.cfg.max_peers = n.max(1);
        self
    }

    /// Maximum connections across the session (default 500, libtorrent's
    /// `connections_limit`).
    pub fn max_connections(mut self, n: usize) -> Self {
        self.cfg.max_connections = n.max(1);
        self
    }

    /// Hash pool threads.
    pub fn hash_threads(mut self, n: usize) -> Self {
        self.cfg.hash_threads = n.max(1);
        self
    }

    /// Session upload limit in bytes per second (0 = unlimited).
    pub fn upload_limit(mut self, bytes_per_sec: u64) -> Self {
        self.cfg.upload_rate = bytes_per_sec;
        self
    }

    /// Session download limit in bytes per second (0 = unlimited).
    pub fn download_limit(mut self, bytes_per_sec: u64) -> Self {
        self.cfg.download_rate = bytes_per_sec;
        self
    }

    /// Session-wide number of unchoke slots.
    pub fn unchoke_slots(mut self, n: usize) -> Self {
        self.cfg.unchoke_slots = n;
        self
    }

    /// Encryption policy (default: `Enabled`, like the oracle's default).
    pub fn encryption(mut self, mode: EncryptionMode) -> Self {
        self.cfg.encryption = mode;
        self
    }

    /// Peer exchange (BEP 11), default on. Private torrents never use it
    /// regardless.
    pub fn pex(mut self, on: bool) -> Self {
        self.cfg.pex = on;
        self
    }

    /// Local Service Discovery (BEP 14), default on. Private torrents are
    /// never announced regardless.
    pub fn lsd(mut self, on: bool) -> Self {
        self.cfg.lsd = on;
        self
    }

    /// Run torrent file I/O on a dedicated `urt-disk` io_uring thread
    /// (default) instead of the network ring. Off keeps disk latency on the
    /// network ring but saves the cross-thread hops; see `docs/perf.md`.
    pub fn disk_thread(mut self, on: bool) -> Self {
        self.cfg.disk_thread = on;
        self
    }

    /// Trust an additional CA (PEM bundle) for HTTPS trackers, on top of the
    /// Mozilla roots and `SSL_CERT_FILE`.
    pub fn root_certificate_pem(mut self, pem: Vec<u8>) -> Self {
        self.cfg.extra_roots.push(pem);
        self
    }

    /// Start the engine threads. Fails hard if io_uring is unavailable.
    pub async fn build(self) -> Result<Session, Error> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let cfg = self.cfg;
        let thread = std::thread::Builder::new()
            .name("urt-net".into())
            .spawn(move || engine::run(cfg, cmd_rx, ready_tx))
            .map_err(|e| Error::Io(e.to_string()))?;
        let boot = ready_rx.await.map_err(|_| Error::Shutdown)??;
        Ok(Session {
            inner: Arc::new(Inner {
                cmd_tx,
                notify: boot.notify,
                listen_port: boot.listen_port,
                thread: Mutex::new(Some(thread)),
            }),
        })
    }
}

struct Inner {
    cmd_tx: mpsc::UnboundedSender<Command>,
    notify: uring::NotifyHandle,
    listen_port: u16,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Last handle gone: ask the engine to stop (it sends `stopped`, flushes
        // resume data and exits on its own). Not joined here; `shutdown()` is
        // the way to wait for it.
        let (tx, _rx) = oneshot::channel();
        let _ = self.cmd_tx.send(Command::Shutdown(tx));
        self.notify.notify();
    }
}

/// A handle to a running engine. Cheap to clone; all clones share one engine.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

impl Session {
    /// Start configuring a session.
    pub fn builder() -> SessionBuilder {
        SessionBuilder::default()
    }

    fn send<T>(&self, make: impl FnOnce(oneshot::Sender<T>) -> Command) -> Reply<T> {
        let (tx, rx) = oneshot::channel();
        let ok = self.inner.cmd_tx.send(make(tx)).is_ok();
        self.inner.notify.notify();
        Reply { rx, ok }
    }

    /// The TCP port the engine listens on (useful when 0 was requested).
    pub fn listen_port(&self) -> u16 {
        self.inner.listen_port
    }

    /// Add a torrent.
    pub async fn add_torrent(&self, params: AddTorrent) -> Result<TorrentId, Error> {
        self.send(|tx| Command::AddTorrent(Box::new(params), tx))
            .await?
    }

    /// Remove a torrent (sends `stopped`, keeps the files).
    pub async fn remove_torrent(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::Remove(id, tx)).await?
    }

    /// Pause a torrent (sends `stopped`, drops peers).
    pub async fn pause(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::Pause(id, tx)).await?
    }

    /// Resume a paused torrent.
    pub async fn resume(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::Resume(id, tx)).await?
    }

    /// Status snapshot of one torrent.
    pub async fn status(&self, id: TorrentId) -> Result<TorrentStatus, Error> {
        self.send(|tx| Command::Status(id, tx)).await?
    }

    /// Status snapshots of every torrent.
    pub async fn statuses(&self) -> Result<Vec<TorrentStatus>, Error> {
        self.send(Command::Statuses).await
    }

    /// Connected peers of a torrent.
    pub async fn peers(&self, id: TorrentId) -> Result<Vec<PeerInfo>, Error> {
        self.send(|tx| Command::Peers(id, tx)).await?
    }

    /// Session-wide counters.
    pub async fn stats(&self) -> Result<SessionStats, Error> {
        self.send(Command::Stats).await
    }

    /// Write resume data now (fsyncs the content first).
    pub async fn save_resume_data(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::SaveResume(id, tx)).await?
    }

    /// Add a peer address to try (libtorrent `connect_peer`): a manual
    /// source alongside trackers, PEX and LSD.
    pub async fn add_peer(&self, id: TorrentId, addr: SocketAddr) -> Result<(), Error> {
        self.send(|tx| Command::AddPeer(id, addr, tx)).await?
    }

    /// Download pieces in order (or go back to rarest-first).
    pub async fn set_sequential(&self, id: TorrentId, sequential: bool) -> Result<(), Error> {
        self.send(|tx| Command::SetSequential(id, sequential, tx))
            .await?
    }

    /// Set file priorities (one per content file, `0` = skip, `1..=7`).
    /// Pieces straddling a skipped and a wanted file are still downloaded;
    /// their skipped bytes go to a parts file (`.<name>.parts`) rather than
    /// creating the skipped file. Resolves once storage has been adjusted.
    pub async fn set_file_priorities(&self, id: TorrentId, prios: Vec<u8>) -> Result<(), Error> {
        self.send(|tx| Command::SetFilePriorities(id, prios, tx))
            .await?
    }

    /// Move the content to `path` (rename on the same filesystem, copy
    /// otherwise). Peer I/O is held while the files move; resolves when the
    /// torrent runs from the new location.
    pub async fn move_storage(&self, id: TorrentId, path: PathBuf) -> Result<(), Error> {
        self.send(|tx| Command::MoveStorage(id, path, tx)).await?
    }

    /// Re-announce as soon as each tracker's `min interval` allows.
    pub async fn force_reannounce(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::ForceReannounce(id, tx)).await?
    }

    /// Scrape every tracker of a torrent (BEP 48, HTTP and UDP). Resolves with
    /// the updated tracker statuses once every scrape answered or failed.
    pub async fn scrape(&self, id: TorrentId) -> Result<Vec<TrackerStatus>, Error> {
        self.send(|tx| Command::Scrape(id, tx)).await?
    }

    /// Drop peers and re-hash everything on disk; the have-set is rebuilt from
    /// what verifies. Resolves when the check is done.
    pub async fn force_recheck(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::ForceRecheck(id, tx)).await?
    }

    /// Set the session-wide upload / download limits in bytes per second
    /// (0 = unlimited).
    pub async fn set_rate_limits(&self, upload: u64, download: u64) -> Result<(), Error> {
        self.send(|tx| Command::SetRateLimits(upload, download, tx))
            .await
    }

    /// Set one torrent's upload / download limits in bytes per second
    /// (0 = unlimited); the session limits still apply.
    pub async fn set_torrent_rate_limits(
        &self,
        id: TorrentId,
        upload: u64,
        download: u64,
    ) -> Result<(), Error> {
        self.send(|tx| Command::SetTorrentRateLimits(id, upload, download, tx))
            .await?
    }

    /// Subscribe to events. Events emitted before the engine processes the
    /// subscription are not delivered.
    pub fn events(&self) -> EventStream {
        let (tx, rx) = mpsc::channel(1024);
        let _ = self.inner.cmd_tx.send(Command::Subscribe(tx));
        self.inner.notify.notify();
        EventStream { rx }
    }

    /// Stop: `stopped` to trackers, flush resume data, join the engine
    /// threads. Idempotent.
    pub async fn shutdown(&self) -> Result<(), Error> {
        let r = self.send(Command::Shutdown).await;
        let handle = self.inner.thread.lock().ok().and_then(|mut g| g.take());
        if let Some(h) = handle {
            let _ = h.join();
        }
        match r {
            Ok(()) | Err(Error::Shutdown) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// A pending reply from the engine.
struct Reply<T> {
    rx: oneshot::Receiver<T>,
    ok: bool,
}

impl<T> std::future::Future for Reply<T> {
    type Output = Result<T, Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.ok {
            return Poll::Ready(Err(Error::Shutdown));
        }
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(v)) => Poll::Ready(Ok(v)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(Error::Shutdown)),
            Poll::Pending => Poll::Pending,
        }
    }
}
