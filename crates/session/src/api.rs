// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Public API types and the `Session` handle. Everything here is plain data
//! or a message to the engine thread.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use metainfo::InfoHash;
use profile::Profile;
use tokio::sync::{mpsc, oneshot};

use crate::Error;
use crate::engine::{self, Command, EngineConfig, SessionLimit};

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
    /// Download pieces in order. `None` keeps the resume data's value, else
    /// `false`.
    pub sequential: Option<bool>,
    /// Initial file priorities, one per content file in torrent order
    /// (`0` = skip, `1..=7`; libtorrent's default is 4). `None` keeps the
    /// priorities from the resume data, or the default. For a magnet link
    /// they apply once the metadata arrives (ignored if the count differs).
    pub file_priorities: Option<Vec<u8>>,
    /// Allocate every content file to its full size up front (`fallocate`)
    /// instead of writing sparse files (default off).
    pub preallocate: bool,
    /// Upload limit in bytes/s from the start (`0` = unlimited). `None`
    /// keeps the resume data's value, else unlimited;
    /// [`Session::set_torrent_rate_limits`] changes it later.
    pub upload_limit: Option<u64>,
    /// Download limit in bytes/s from the start (`0` = unlimited); `None` as
    /// for `upload_limit`.
    pub download_limit: Option<u64>,
    /// Connection cap for this torrent. `None` keeps the resume data's
    /// value, else the session's `max_peers_per_torrent`;
    /// [`Session::set_max_peers`] changes it later.
    pub max_peers: Option<usize>,
    /// Upload slot cap for this torrent. `None` keeps the resume data's
    /// value, else only the session-wide `unchoke_slots` budget applies;
    /// [`Session::set_max_uploads`] changes it later.
    pub max_uploads: Option<usize>,
    /// Whether the session's [`ActiveLimits`] queue manages this torrent
    /// (started and stopped to keep within the limits, in queue order).
    /// `None` keeps the resume data's value, else `true`. `false` is a
    /// "force start": the torrent runs regardless of the limits.
    pub auto_managed: Option<bool>,
    /// Resume data as [`Session::resume_data`] returned it, for a caller
    /// that stores the blob itself (libtorrent's `read_resume_data`). It is
    /// used instead of the `resume_dir` file, if both are given, and must
    /// belong to this torrent (the info-hash is checked).
    pub resume_data: Option<Vec<u8>>,
}

impl AddTorrent {
    /// Add from `.torrent` bytes, saving under `save_path`.
    pub fn metainfo(bytes: Vec<u8>, save_path: impl Into<PathBuf>) -> AddTorrent {
        AddTorrent {
            source: TorrentSource::Metainfo(bytes),
            save_path: save_path.into(),
            resume_dir: None,
            paused: false,
            sequential: None,
            file_priorities: None,
            preallocate: false,
            upload_limit: None,
            download_limit: None,
            max_peers: None,
            max_uploads: None,
            auto_managed: None,
            resume_data: None,
        }
    }

    /// Add from a magnet link, saving under `save_path`.
    pub fn magnet(uri: impl Into<String>, save_path: impl Into<PathBuf>) -> AddTorrent {
        AddTorrent {
            source: TorrentSource::Magnet(uri.into()),
            save_path: save_path.into(),
            resume_dir: None,
            paused: false,
            sequential: None,
            file_priorities: None,
            preallocate: false,
            upload_limit: None,
            download_limit: None,
            max_peers: None,
            max_uploads: None,
            auto_managed: None,
            resume_data: None,
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

    /// Preallocate the content files (`fallocate`) when they are created.
    pub fn preallocate(mut self, on: bool) -> AddTorrent {
        self.preallocate = on;
        self
    }

    /// Sequential download.
    pub fn sequential(mut self, sequential: bool) -> AddTorrent {
        self.sequential = Some(sequential);
        self
    }

    /// Initial file priorities (see the field).
    pub fn file_priorities(mut self, prios: Vec<u8>) -> AddTorrent {
        self.file_priorities = Some(prios);
        self
    }

    /// Upload limit in bytes/s from the start (`0` = unlimited).
    pub fn upload_limit(mut self, bytes_per_sec: u64) -> AddTorrent {
        self.upload_limit = Some(bytes_per_sec);
        self
    }

    /// Download limit in bytes/s from the start (`0` = unlimited).
    pub fn download_limit(mut self, bytes_per_sec: u64) -> AddTorrent {
        self.download_limit = Some(bytes_per_sec);
        self
    }

    /// Connection cap for this torrent.
    pub fn max_peers(mut self, n: usize) -> AddTorrent {
        self.max_peers = Some(n);
        self
    }

    /// Upload slot cap for this torrent.
    pub fn max_uploads(mut self, n: usize) -> AddTorrent {
        self.max_uploads = Some(n);
        self
    }

    /// Whether the active-torrent queue manages this torrent (see the field).
    pub fn auto_managed(mut self, on: bool) -> AddTorrent {
        self.auto_managed = Some(on);
        self
    }

    /// Resume data from an earlier run (see the field).
    pub fn resume_data(mut self, bytes: Vec<u8>) -> AddTorrent {
        self.resume_data = Some(bytes);
        self
    }
}

/// How many torrents may be active at once (libtorrent `active_downloads` /
/// `active_seeds` / `active_limit`, qBittorrent's "torrent queueing"). A
/// torrent is *active* when it is running (announcing, connecting); the
/// others wait in queue order (`TorrentState::Queued`) until a slot frees.
/// `None` means unlimited, the default for all three, so nothing is queued
/// unless a limit is set. Auto-managed torrents (`AddTorrent::auto_managed`,
/// the default) take part; force-started ones run regardless and count
/// towards the limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ActiveLimits {
    /// Torrents still downloading that may be active.
    pub downloads: Option<usize>,
    /// Complete torrents (seeds) that may be active.
    pub seeds: Option<usize>,
    /// Active torrents in total.
    pub total: Option<usize>,
    /// Count torrents that move no data towards the limits. Off (the
    /// default, libtorrent `dont_count_slow_torrents`): a running torrent
    /// whose rates have stayed below 2 KiB/s for 60 s no longer holds a
    /// slot, so stalled torrents (no peers, dead trackers) do not block the
    /// queue; it starts counting again when data flows.
    pub count_slow: bool,
}

impl ActiveLimits {
    /// No limits: every torrent runs.
    pub const UNLIMITED: ActiveLimits = ActiveLimits {
        downloads: None,
        seeds: None,
        total: None,
        count_slow: false,
    };

    /// Whether any limit is set.
    pub fn is_limited(&self) -> bool {
        self.downloads.is_some() || self.seeds.is_some() || self.total.is_some()
    }
}

/// The session's settings as they stand (`Session::settings`). The first
/// block is fixed for the session's lifetime (build a new session to change
/// it); the rest changes at runtime through the `Session::set_*` methods.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionSettings {
    /// The listen port in use (the ephemeral one if 0 was asked for).
    pub listen_port: u16,
    /// IPv4 listen address, if IPv4 is on.
    pub listen_v4: Option<Ipv4Addr>,
    /// IPv6 listen address, if IPv6 is on.
    pub listen_v6: Option<Ipv6Addr>,
    /// The identity profile's name.
    pub profile: String,
    /// Whether a DHT node runs.
    pub dht: bool,
    /// Session upload limit in bytes/s (0 = unlimited).
    pub upload_limit: u64,
    /// Session download limit in bytes/s (0 = unlimited).
    pub download_limit: u64,
    /// Session-wide connection limit.
    pub max_connections: usize,
    /// Default per-torrent connection cap.
    pub max_peers_per_torrent: usize,
    /// Session-wide unchoke slots.
    pub unchoke_slots: usize,
    /// The active-torrent queue limits.
    pub active_limits: ActiveLimits,
    /// The MSE policy.
    pub encryption: EncryptionMode,
    /// The transport policy.
    pub transports: TransportPolicy,
    /// PEX on.
    pub pex: bool,
    /// LSD on.
    pub lsd: bool,
}

/// Where to move a torrent in the queue (`Session::move_in_queue`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueMove {
    /// To the front.
    Top,
    /// One place towards the front.
    Up,
    /// One place towards the back.
    Down,
    /// To the back.
    Bottom,
}

/// A piece's standing (`Session::pieces`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceState {
    /// Not verified on disk, no download in progress.
    Missing,
    /// Blocks requested or received but not yet verified.
    Downloading,
    /// Verified and written.
    Have,
}

/// One piece in [`Session::pieces`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PieceInfo {
    /// Its standing.
    pub state: PieceState,
    /// Connected peers (and web seeds) that have it.
    pub availability: u32,
}

/// One content file in a status snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum TorrentState {
    /// A magnet link waiting for its metadata (BEP 9).
    FetchingMetadata,
    /// Waiting for a checking slot (`SessionBuilder::max_checking`).
    QueuedForChecking,
    /// Verifying data on disk.
    Checking,
    /// Downloading (or waiting for peers).
    Downloading,
    /// Complete; announcing and accepting peers.
    Seeding,
    /// Waiting for an active slot (`ActiveLimits`): auto-managed and beyond
    /// the limits, in queue order.
    Queued,
    /// Stopped by the caller.
    Paused,
    /// Stopped by an error (see `error` and `error_kind`).
    Error,
}

/// What stopped a torrent in [`TorrentState::Error`], and so what brings it
/// back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Files the resume data vouches for are gone: moved, deleted, or on a
    /// drive that is not mounted (qBittorrent's "missing files"). Nothing is
    /// created in their place. [`Session::resume`] looks again once they are
    /// back; [`Session::force_recheck`] accepts what the disk holds and
    /// downloads the rest.
    ContentMissing,
    /// Reading, writing or checking the files failed (disk full, I/O error,
    /// permissions). [`Session::resume`] restarts, downloading again the
    /// pieces that were in progress; [`Session::force_recheck`] rechecks.
    Io,
    /// The metadata cannot be used (malformed, or v2-only). Only removing
    /// the torrent helps.
    Metadata,
}

/// One tracker's state in a status snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// What kind of error, when `state == Error`.
    pub error_kind: Option<ErrorKind>,
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
    /// Payload bytes received (this run plus resume data), including the
    /// [`corrupt`](Self::corrupt) and [`redundant`](Self::redundant) ones;
    /// announces report `downloaded - corrupt - redundant`, as libtorrent
    /// does.
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
    /// Tracker states. Empty in [`Session::statuses`] (see
    /// [`Session::status`] or [`Session::trackers`]).
    pub trackers: Vec<TrackerStatus>,
    /// Whether the torrent is complete (all wanted pieces).
    pub complete: bool,
    /// Web seeds (BEP 19) configured.
    pub web_seeds: usize,
    /// The web seed URLs (`Session::add_web_seed` / `remove_web_seed`).
    pub web_seed_urls: Vec<String>,
    /// Content files with their priorities and progress. Empty until the
    /// metadata is known, and in [`Session::statuses`] (per-torrent detail
    /// comes from [`Session::status`] or [`Session::files`]).
    pub files: Vec<FileStatus>,
    /// Piece length in bytes (0 until the metadata is known).
    pub piece_length: u32,
    /// The `.torrent`'s `comment`, if it had one.
    pub comment: Option<String>,
    /// The `.torrent`'s `created by`, if present.
    pub created_by: Option<String>,
    /// The `.torrent`'s `creation date` (unix seconds), if present.
    pub creation_date: Option<i64>,
    /// This torrent's upload limit in bytes/s (0 = unlimited).
    pub upload_limit: u64,
    /// This torrent's download limit in bytes/s (0 = unlimited).
    pub download_limit: u64,
    /// Bytes in wanted pieces (priority > 0).
    pub total_wanted: u64,
    /// Bytes in wanted pieces already verified.
    pub total_wanted_done: u64,
    /// Where the content lives.
    pub save_path: PathBuf,
    /// Time the torrent has been active (not paused), over its whole life
    /// (persisted in resume data).
    pub active_time: Duration,
    /// Time the torrent has been active as a complete torrent, over its
    /// whole life (persisted in resume data).
    pub seeding_time: Duration,
    /// Per-torrent connection cap, if set (`Session::set_max_peers`).
    pub max_peers: Option<usize>,
    /// Upload slot cap set for this torrent (`None` = session budget only).
    pub max_uploads: Option<usize>,
    /// Peer addresses known for the torrent (connected or waiting to be
    /// dialled), capped at 3000 like libtorrent's `max_peerlist_size`.
    pub peer_list_size: usize,
    /// Something the resume data records has changed since it was last
    /// saved or returned (libtorrent `need_save_resume`): a caller storing
    /// blobs itself fetches [`Session::resume_data`] when this is set.
    pub needs_resume_save: bool,
    /// When the torrent was added, unix seconds (restored from resume
    /// data).
    pub added_on: u64,
    /// When the download completed, unix seconds, if it has.
    pub completed_on: Option<u64>,
    /// Whether the active-torrent queue manages this torrent.
    pub auto_managed: bool,
    /// Position in the queue (0 = first, dense across the session's
    /// torrents): the order in which auto-managed torrents get the
    /// `ActiveLimits` slots, downloads against `downloads` and seeds against
    /// `seeds`. libtorrent ranks seeds by its `seed_rank` instead; here the
    /// caller's order applies to both.
    pub queue_position: usize,
    /// Time until the earliest scheduled tracker announce, if any.
    pub next_announce_in: Option<Duration>,
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
    /// The DHT (BEP 5).
    Dht,
    /// Resume data (a peer from the previous run).
    Resume,
}

/// A connected peer, copied out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// We are choking the peer (it holds no upload slot).
    pub am_choking: bool,
    /// The peer wants our data.
    pub peer_interested: bool,
    /// We are interested in the peer.
    pub am_interested: bool,
    /// Outstanding requests to the peer.
    pub outstanding: usize,
    /// The connection is RC4-encrypted (MSE).
    pub encrypted: bool,
    /// The peer declared itself upload-only (BEP 21) or is a seed.
    pub upload_only: bool,
    /// The transport the connection runs over.
    pub transport: PeerTransport,
    /// Payload bytes per second received from this peer (smoothed).
    pub download_rate: u64,
    /// Payload bytes per second sent to this peer (smoothed).
    pub upload_rate: u64,
    /// How long the connection has been up.
    pub connected_for: Duration,
}

/// Which transports peers are reached over, and in which order.
///
/// TCP is the fast path (`docs/perf.md`); uTP (BEP 29) is the compatibility
/// transport that reaches peers only listening on UDP and yields to other
/// traffic. libtorrent dials every new peer over uTP first; this library
/// does not by default (maintainer decision: performance over that one L3
/// nuance), but [`TransportPolicy::PreferUtp`] reproduces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportPolicy {
    /// TCP only: uTP is off, incoming uTP SYNs are ignored.
    TcpOnly,
    /// The default: dial TCP first and accept both. A peer whose TCP dial
    /// fails (refused, timed out, or closed before the handshake) gets one
    /// uTP attempt right away and is dialled over uTP from then on while
    /// that keeps working.
    #[default]
    PreferTcp,
    /// libtorrent's behaviour: dial uTP first (every peer is assumed to
    /// speak it), fall back to TCP at once when the uTP attempt fails and
    /// remember; accept both.
    PreferUtp,
    /// uTP only (qBittorrent's "μTP only"): every dial is uTP, accepted TCP
    /// connections are dropped.
    UtpOnly,
}

impl TransportPolicy {
    /// Whether TCP connections are accepted.
    pub fn tcp_incoming(self) -> bool {
        !matches!(self, TransportPolicy::UtpOnly)
    }

    /// Whether peers are ever dialled over TCP.
    pub fn tcp_outgoing(self) -> bool {
        !matches!(self, TransportPolicy::UtpOnly)
    }

    /// Whether uTP SYNs are accepted.
    pub fn utp_incoming(self) -> bool {
        !matches!(self, TransportPolicy::TcpOnly)
    }

    /// Whether peers are ever dialled over uTP.
    pub fn utp_outgoing(self) -> bool {
        !matches!(self, TransportPolicy::TcpOnly)
    }

    /// Whether the first dial to a fresh address is uTP.
    pub fn utp_first(self) -> bool {
        matches!(self, TransportPolicy::PreferUtp | TransportPolicy::UtpOnly)
    }
}

/// The byte transport under a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerTransport {
    /// Plain TCP.
    Tcp,
    /// uTP (BEP 29) over the listen port's UDP socket.
    Utp,
}

/// Session-wide counters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
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
    /// Peer connections plus dials in progress, across torrents.
    pub connections: usize,
    /// Storage jobs submitted to the disk ring and not finished.
    pub disk_jobs_pending: usize,
    /// Hash jobs handed to the SHA-1 workers and not finished.
    pub hash_jobs_pending: usize,
    /// Bytes re-read from disk to hash blocks that arrived out of order.
    pub hash_readback_bytes: u64,
    /// Receive buffers of the peer ring not currently holding data.
    pub recv_buffers_free: usize,
    /// Receive buffers of the peer ring in total.
    pub recv_buffers: usize,
    /// Live nodes in the DHT routing tables (0 when the DHT is off).
    pub dht_nodes: usize,
    /// DHT lookups in progress.
    pub dht_lookups: usize,
    /// Peers other nodes announced to us and we store for them.
    pub dht_stored_peers: usize,
    /// Live uTP connections, including ones finishing their close handshake.
    pub utp_connections: usize,
    /// Payload bytes copied in user space on the data path since the session
    /// started: peer-wire frames cut by a receive boundary, block payloads
    /// lifted out of the receive ring, uTP's receive and send queues, and
    /// rate-limited partial sends. The budget is documented and gated in
    /// `docs/perf.md`: a TCP download costs one copy per byte, a TCP upload
    /// none, a uTP transfer two each way.
    pub copied_bytes: u64,
}

/// Something that happened in the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The DHT bootstrap lookup finished.
    DhtBootstrapped {
        /// Live nodes in the routing table afterwards.
        nodes: usize,
    },
    /// A DHT lookup returned peers for a torrent.
    DhtPeers {
        /// The torrent.
        id: TorrentId,
        /// Peers in the reply.
        peers: usize,
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
        /// What kind of error (what brings the torrent back).
        kind: ErrorKind,
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

    /// IPv4 listen address (`None` disables IPv4: no listen socket, no
    /// announce for the family, and IPv4 peers learned from any source are
    /// not dialled).
    pub fn listen_v4(mut self, addr: Option<Ipv4Addr>) -> Self {
        self.cfg.listen_v4 = addr;
        self
    }

    /// IPv6 listen address (`None` disables IPv6: no listen socket, no
    /// announce for the family, and IPv6 peers learned from any source are
    /// not dialled).
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

    /// How many torrents may be active at once (see [`ActiveLimits`];
    /// default unlimited).
    pub fn active_limits(mut self, limits: ActiveLimits) -> Self {
        self.cfg.active_limits = limits;
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

    /// The DHT (BEP 5), default on: one node per listen family on the listen
    /// port's UDP sockets. Private torrents are never announced or looked up
    /// regardless.
    pub fn dht(mut self, on: bool) -> Self {
        self.cfg.dht = on;
        self
    }

    /// Bootstrap routers (`host:port`) instead of the profile's defaults; an
    /// empty list means none (only saved state and peers' `port` messages
    /// seed the table). Tests must set this: the defaults are on the public
    /// internet.
    pub fn dht_bootstrap_nodes(mut self, nodes: Vec<String>) -> Self {
        self.cfg.dht_bootstrap_nodes = Some(nodes);
        self
    }

    /// Run the DHT node read-only (BEP 43): it answers no queries and marks
    /// its own `ro`.
    pub fn dht_read_only(mut self, on: bool) -> Self {
        self.cfg.dht_read_only = on;
        self
    }

    /// Which peer transports to use and in which order (default
    /// [`TransportPolicy::PreferTcp`]). The transport a peer ended up on
    /// shows in [`PeerInfo::transport`].
    pub fn transports(mut self, policy: TransportPolicy) -> Self {
        self.cfg.transports = policy;
        self
    }

    /// Restore DHT state saved by [`Session::dht_state`] (node ids and
    /// routing-table nodes), so the node comes up without a cold bootstrap.
    pub fn dht_state(mut self, state: Vec<u8>) -> Self {
        self.cfg.dht_state = Some(state);
        self
    }

    /// How many torrents are hashed (checked) at once; the others queue
    /// (default 1, like libtorrent's `active_checking`).
    pub fn max_checking(mut self, n: usize) -> Self {
        self.cfg.max_checking = n.max(1);
        self
    }

    /// Torrent files kept open at once across the session (default 512, an
    /// LRU like libtorrent's file pool); handles are reopened on demand.
    pub fn max_open_files(mut self, n: usize) -> Self {
        self.cfg.max_open_files = n.max(1);
        self
    }

    /// Prefer finishing a few recently started 4 MiB extents before
    /// rarest-first picks elsewhere (default on; libtorrent's
    /// `piece_extent_affinity`, off there). With small pieces this turns
    /// scattered 16 KiB writes into runs the kernel can write back
    /// efficiently; piece order within a swarm is otherwise unchanged.
    pub fn piece_extent_affinity(mut self, on: bool) -> Self {
        self.cfg.piece_extent_affinity = on;
        self
    }

    /// The provided receive buffers every peer socket shares: `entries`
    /// buffers (a power of two, default 256) of `buf_size` bytes (default
    /// 32 KiB). A connection holds no receive memory while idle; when every
    /// buffer is in use the kernel pauses the sockets until one returns.
    pub fn recv_ring(mut self, entries: u16, buf_size: usize) -> Self {
        self.cfg.recv_ring_entries = entries.clamp(1, 1 << 15).next_power_of_two();
        self.cfg.recv_buf_size = buf_size.clamp(4096, 1 << 20);
        self
    }

    /// Send piece payloads with zero-copy `sendmsg` when the kernel supports
    /// it (default off; see `docs/perf.md` for when it pays).
    pub fn zero_copy_send(mut self, on: bool) -> Self {
        self.cfg.zero_copy_send = on;
        self
    }

    /// Tracker requests in flight at once across the session (default 32):
    /// bounds the announce storm when thousands of torrents start together.
    pub fn max_concurrent_announces(mut self, n: usize) -> Self {
        self.cfg.max_concurrent_announces = n.max(1);
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
                listen_port: std::sync::atomic::AtomicU16::new(boot.listen_port),
                thread: Mutex::new(Some(thread)),
            }),
        })
    }
}

struct Inner {
    cmd_tx: mpsc::UnboundedSender<Command>,
    notify: uring::NotifyHandle,
    /// The port in use, kept current by `set_listen` (shared by every
    /// clone of the handle).
    listen_port: std::sync::atomic::AtomicU16,
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

    /// The TCP (and UDP) port the engine listens on (useful when 0 was
    /// requested); kept current across [`Session::set_listen`].
    pub fn listen_port(&self) -> u16 {
        self.inner
            .listen_port
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Replace the listen sockets: `port` (0 = ephemeral) on `v4` / `v6`
    /// (`None` = that family off, as for the builder). The new sockets are
    /// bound first; if that fails the error is returned and nothing
    /// changes. Otherwise every running torrent announces `stopped` on the
    /// old sockets and `started` on the new ones (trackers see the new
    /// port), the DHT node carries on over the new UDP sockets, LSD rejoins
    /// its groups, established TCP connections stay, uTP connections (bound
    /// to the old UDP sockets) drop, and peers of a family that went away
    /// are disconnected. Returns the port in use.
    pub async fn set_listen(
        &self,
        port: u16,
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
    ) -> Result<u16, Error> {
        let port = self
            .send(|tx| Command::SetListen(port, v4, v6, tx))
            .await??;
        self.inner
            .listen_port
            .store(port, std::sync::atomic::Ordering::Relaxed);
        Ok(port)
    }

    /// Start or stop the DHT node (`SessionBuilder::dht`). Starting restores
    /// the tables of a node stopped earlier in the session (or the
    /// builder's `dht_state`); stopping keeps them for the next start and
    /// ends all DHT traffic. Fails when the listen port has no UDP socket.
    pub async fn set_dht(&self, on: bool) -> Result<(), Error> {
        self.send(|tx| Command::SetDht(on, tx)).await?
    }

    /// Replace the identity profile (`SessionBuilder::profile`): connections
    /// made from now on carry the new identity (connections already
    /// handshaked keep theirs), every torrent gets a fresh announce peer id
    /// and key, trackers hear `stopped` under the old identity and
    /// `started` under the new, and the DHT node restarts with its tables
    /// under the new version tag.
    pub async fn set_profile(&self, profile: Profile) -> Result<(), Error> {
        self.send(|tx| Command::SetProfile(Box::new(profile), tx))
            .await?
    }

    /// Add a torrent.
    pub async fn add_torrent(&self, params: AddTorrent) -> Result<TorrentId, Error> {
        self.send(|tx| Command::AddTorrent(Box::new(params), tx))
            .await?
    }

    /// Remove a torrent (sends `stopped`, keeps the files).
    pub async fn remove_torrent(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::Remove(id, false, tx)).await?
    }

    /// Remove a torrent and delete its content files, its parts file and
    /// the directories that became empty (the resume file too).
    pub async fn remove_torrent_with_files(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::Remove(id, true, tx)).await?
    }

    /// The torrent with this info-hash, if present.
    pub async fn find_torrent(&self, info_hash: InfoHash) -> Option<TorrentId> {
        self.send(|tx| Command::Find(info_hash, tx)).await.ok()?
    }

    /// Pause every torrent (each sends `stopped`).
    pub async fn pause_all(&self) -> Result<(), Error> {
        self.send(Command::PauseAll).await
    }

    /// Resume every paused torrent.
    pub async fn resume_all(&self) -> Result<(), Error> {
        self.send(Command::ResumeAll).await
    }

    /// Add a tracker to `tier` (a tier past the end appends a new one). It
    /// is announced to at once if the torrent is running.
    pub async fn add_tracker(&self, id: TorrentId, url: String, tier: usize) -> Result<(), Error> {
        self.send(|tx| Command::AddTracker(id, url, tier, tx))
            .await?
    }

    /// Remove a tracker (it gets `stopped` if it had `started`).
    pub async fn remove_tracker(&self, id: TorrentId, url: String) -> Result<(), Error> {
        self.send(|tx| Command::RemoveTracker(id, url, tx)).await?
    }

    /// Cap this torrent's connections (`None` restores the session default,
    /// `SessionBuilder::max_peers_per_torrent`). Existing connections above
    /// the cap are kept; no new ones are made.
    pub async fn set_max_peers(&self, id: TorrentId, max: Option<usize>) -> Result<(), Error> {
        self.send(|tx| Command::SetMaxPeers(id, max, tx)).await?
    }

    /// Cap this torrent's upload slots (`None` = only the session-wide
    /// budget applies). Takes effect at the next choking round.
    pub async fn set_max_uploads(&self, id: TorrentId, max: Option<usize>) -> Result<(), Error> {
        self.send(|tx| Command::SetMaxUploads(id, max, tx)).await?
    }

    /// Change the session-wide connection limit
    /// (`SessionBuilder::max_connections`). Existing connections above the
    /// limit are kept; no new ones are made until below it.
    pub async fn set_max_connections(&self, n: usize) -> Result<(), Error> {
        self.send(|tx| Command::SetSessionLimits(SessionLimit::Connections(n), tx))
            .await
    }

    /// Change the default per-torrent connection cap
    /// (`SessionBuilder::max_peers_per_torrent`) for torrents without a cap
    /// of their own.
    pub async fn set_max_peers_per_torrent(&self, n: usize) -> Result<(), Error> {
        self.send(|tx| Command::SetSessionLimits(SessionLimit::PeersPerTorrent(n), tx))
            .await
    }

    /// Change the session-wide unchoke slot budget
    /// (`SessionBuilder::unchoke_slots`); applied at the next choking round.
    pub async fn set_unchoke_slots(&self, n: usize) -> Result<(), Error> {
        self.send(|tx| Command::SetSessionLimits(SessionLimit::UnchokeSlots(n), tx))
            .await
    }

    /// Change the active-torrent limits (`SessionBuilder::active_limits`);
    /// the queue is re-evaluated at once.
    pub async fn set_active_limits(&self, limits: ActiveLimits) -> Result<(), Error> {
        self.send(|tx| Command::SetActiveLimits(limits, tx)).await
    }

    /// Change the MSE policy (`SessionBuilder::encryption`) for connections
    /// made or accepted from now on; existing ones are kept.
    pub async fn set_encryption(&self, mode: EncryptionMode) -> Result<(), Error> {
        self.send(|tx| Command::SetEncryption(mode, tx)).await
    }

    /// Change the transport policy (`SessionBuilder::transports`) for
    /// connections made or accepted from now on.
    pub async fn set_transports(&self, policy: TransportPolicy) -> Result<(), Error> {
        self.send(|tx| Command::SetTransports(policy, tx)).await
    }

    /// Turn peer exchange on or off (`SessionBuilder::pex`). Off: PEX
    /// messages are neither sent nor acted on from now on.
    pub async fn set_pex(&self, on: bool) -> Result<(), Error> {
        self.send(|tx| Command::SetPex(on, tx)).await
    }

    /// Turn Local Service Discovery on or off (`SessionBuilder::lsd`). The
    /// multicast sockets open on first use and stay for the session.
    pub async fn set_lsd(&self, on: bool) -> Result<(), Error> {
        self.send(|tx| Command::SetLsd(on, tx)).await
    }

    /// The torrent's resume data as bytes (libtorrent's
    /// `write_resume_data_buf`), after syncing its files so everything the
    /// data claims is on disk: verified pieces, the written ranges of
    /// unfinished pieces, counters and times, the tracker list and web seeds
    /// as they stand, per-torrent settings, renamed files, queue standing,
    /// and up to 100 peers to try first. Store it and pass it back through
    /// [`AddTorrent::resume_data`] on the next run; `resume_dir` is not
    /// needed for that. Clears [`TorrentStatus::needs_resume_save`]. Fails
    /// while a magnet link's metadata is unknown.
    pub async fn resume_data(&self, id: TorrentId) -> Result<Vec<u8>, Error> {
        self.send(|tx| Command::ResumeData(id, tx)).await?
    }

    /// The per-file status of a torrent (empty until the metadata is known).
    pub async fn files(&self, id: TorrentId) -> Result<Vec<FileStatus>, Error> {
        self.send(|tx| Command::Files(id, tx)).await?
    }

    /// The tracker list of a torrent with each tracker's state.
    pub async fn trackers(&self, id: TorrentId) -> Result<Vec<TrackerStatus>, Error> {
        self.send(|tx| Command::Trackers(id, tx)).await?
    }

    /// Every piece's state and availability (empty until the metadata is
    /// known); the piece bar of a UI.
    pub async fn pieces(&self, id: TorrentId) -> Result<Vec<PieceInfo>, Error> {
        self.send(|tx| Command::Pieces(id, tx)).await?
    }

    /// The torrent as a `.torrent` file: the info dictionary as received
    /// (byte-exact, so the info-hash matches), the current trackers as
    /// `announce` / `announce-list`, the web seeds as `url-list`, and the
    /// original `comment` / `created by` / `creation date`. `None` for a
    /// magnet link whose metadata has not arrived. What a daemon stores to
    /// re-add the torrent after a restart.
    pub async fn torrent_file(&self, id: TorrentId) -> Result<Option<Vec<u8>>, Error> {
        self.send(|tx| Command::TorrentFile(id, tx)).await?
    }

    /// Rename (move within the save path) content file `index` (as numbered
    /// in [`TorrentStatus::files`]) to `path`, `/`-separated and relative to
    /// the save path, sanitised like a `.torrent` path (no `..`, no absolute
    /// paths). The file on disk is renamed if it exists; the new path is
    /// used from then on and persisted in the resume data.
    pub async fn rename_file(
        &self,
        id: TorrentId,
        index: usize,
        path: String,
    ) -> Result<(), Error> {
        self.send(|tx| Command::RenameFile(id, index, path, tx))
            .await?
    }

    /// Add a web seed (BEP 19 `url-list`) URL; it is used once the torrent
    /// runs and has something left to download.
    pub async fn add_web_seed(&self, id: TorrentId, url: String) -> Result<(), Error> {
        self.send(|tx| Command::WebSeed(id, url, true, tx)).await?
    }

    /// Remove a web seed URL; a running request for it ends.
    pub async fn remove_web_seed(&self, id: TorrentId, url: String) -> Result<(), Error> {
        self.send(|tx| Command::WebSeed(id, url, false, tx)).await?
    }

    /// The settings in force.
    pub async fn settings(&self) -> Result<SessionSettings, Error> {
        self.send(Command::Settings).await
    }

    /// Ban an address for the session: its connections on every torrent are
    /// dropped, and it is neither dialled nor accepted until unbanned.
    pub async fn ban_ip(&self, ip: IpAddr) -> Result<(), Error> {
        self.send(|tx| Command::BanIp(ip, true, tx)).await
    }

    /// Lift a [`Session::ban_ip`].
    pub async fn unban_ip(&self, ip: IpAddr) -> Result<(), Error> {
        self.send(|tx| Command::BanIp(ip, false, tx)).await
    }

    /// The addresses banned with [`Session::ban_ip`].
    pub async fn banned_ips(&self) -> Result<Vec<IpAddr>, Error> {
        self.send(Command::BannedIps).await
    }

    /// Hand a torrent to the queue (`true`: it runs when the
    /// [`ActiveLimits`] allow, in queue order, and waits as
    /// `TorrentState::Queued` otherwise) or take it out (`false`: it keeps
    /// its current running / paused state and is never started or stopped
    /// by the queue; a running one still counts towards the limits).
    pub async fn set_auto_managed(&self, id: TorrentId, on: bool) -> Result<(), Error> {
        self.send(|tx| Command::SetAutoManaged(id, on, tx)).await?
    }

    /// Start a torrent regardless of the active limits ("force start"):
    /// takes it out of the queue's hands and resumes it. An errored torrent
    /// is recovered as [`Session::resume`] describes.
    pub async fn force_resume(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::ForceResume(id, tx)).await?
    }

    /// Move a torrent in the queue (`TorrentStatus::queue_position`).
    pub async fn move_in_queue(&self, id: TorrentId, to: QueueMove) -> Result<(), Error> {
        self.send(|tx| Command::MoveInQueue(id, to, tx)).await?
    }

    /// The DHT's persistable state (node ids and routing-table nodes) for
    /// [`SessionBuilder::dht_state`]; `None` when the DHT is off. Save it at
    /// shutdown.
    pub async fn dht_state(&self) -> Result<Option<Vec<u8>>, Error> {
        self.send(Command::DhtState).await
    }

    /// Tell the DHT about a node (it is probed and, if it answers, joins the
    /// routing table).
    pub async fn add_dht_node(&self, addr: SocketAddr) -> Result<(), Error> {
        self.send(|tx| Command::AddDhtNode(addr, tx)).await
    }

    /// Pause a torrent (sends `stopped`, drops peers). The torrent leaves
    /// the queue's hands (`auto_managed = false`) so it stays paused until
    /// resumed.
    pub async fn pause(&self, id: TorrentId) -> Result<(), Error> {
        self.send(|tx| Command::Pause(id, tx)).await?
    }

    /// Resume a paused torrent under the queue (`auto_managed = true`): it
    /// starts when the [`ActiveLimits`] allow, else waits as
    /// `TorrentState::Queued`. [`Session::force_resume`] bypasses the queue.
    ///
    /// An errored torrent is recovered first, by [`ErrorKind`]:
    /// `ContentMissing` looks for the files again (and stays errored while
    /// they are still gone), `Io` restarts and downloads again the pieces
    /// that were in progress (a torrent that failed while checking is
    /// rechecked), `Metadata` is refused with [`Error::Busy`].
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
    /// source alongside trackers, PEX and LSD, dialled at the next tick
    /// even if an earlier attempt put the address in reconnect backoff.
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
    /// what verifies. Resolves when the check is done. An errored torrent
    /// (other than [`ErrorKind::Metadata`], refused with [`Error::Busy`]) has
    /// its error cleared and its files created where missing first, so a
    /// torrent whose content went missing starts over from what the disk
    /// holds.
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
