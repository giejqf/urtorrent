// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Per-torrent state and lifecycle: add (parse, storage, resume/recheck),
//! the one-second tick (connections, request timeouts, keep-alives, rates,
//! periodic resume saves), piece verification, completion, pause/stop.
//!
//! All counters are truthful (AGENTS.md rule 1): `downloaded` counts payload
//! bytes that arrived in `piece` messages we asked for, `uploaded` payload we
//! sent, `corrupt` bytes of pieces that failed their hash, `redundant` bytes we
//! received but did not need. `left` is derived from the verified have-set.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use metainfo::{Bitfield, InfoHash, Torrent as Metainfo};
use picker::{Picker, Received};
use storage::{DiskStore, ResumeData};
use tracker::{AnnounceJob, Announcer};
use wire::Request;

use super::Ctx;
use super::local::{Flag, Notify};
use super::peer::PeerHandle;
use super::rate::Limiter;
use super::rng::RngRef;
use crate::Error;
use crate::api::{
    AddTorrent, Event, PeerInfo, PeerSource, TorrentId, TorrentSource, TorrentState, TorrentStatus,
    TrackerStatus,
};

/// Outstanding requests older than this are cancelled and re-picked
/// (libtorrent `request_timeout`).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Send a keep-alive after this much outbound silence (libtorrent sends every
/// 2 minutes; peers time out at ~2 minutes of silence, so stay well under).
pub const KEEPALIVE_AFTER: Duration = Duration::from_secs(100);
/// Drop a peer after this much inbound silence.
pub const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(180);
/// Trust points (libtorrent `torrent_peer::trust_points`): a peer is banned
/// when its score drops to `BAN_AT`. A failed piece it supplied alone
/// costs `SOLE_FAIL_COST` (an immediate ban, libtorrent's `known_bad_peer`);
/// a failed piece shared with others costs `SHARED_FAIL_COST`; a verified
/// piece earns 1 (capped at `TRUST_CAP`).
const BAN_AT: i32 = -7;
const SOLE_FAIL_COST: i32 = 7;
const SHARED_FAIL_COST: i32 = 2;
const TRUST_CAP: i32 = 8;
/// Periodic resume save cadence.
const RESUME_SAVE_EVERY: Duration = Duration::from_secs(60);
/// Do not reconnect to an address that failed for this long.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(60);
/// The picker key under which blocks restored from resume data are
/// recorded (no live peer has it: keys start at 1).
const RESUME_PEER_KEY: u32 = 0;

/// Wall-clock seconds since the epoch (timestamps in resume data).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Most peer addresses kept per torrent (libtorrent `max_peerlist_size`):
/// a tracker, PEX peer or DHT reply handing out endless unique addresses
/// cannot grow the session without bound.
pub const MAX_PEER_LIST: usize = 3000;

/// Truthful transfer counters.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub downloaded: u64,
    pub uploaded: u64,
    pub corrupt: u64,
    pub redundant: u64,
    pub download_rate: u64,
    pub upload_rate: u64,
    last_downloaded: u64,
    last_uploaded: u64,
}

/// One torrent.
pub struct Torrent {
    pub id: TorrentId,
    pub info_hash: InfoHash,
    /// Display name (`info.name`, or the magnet's `dn` / hex hash until then).
    pub name: String,
    /// BEP 27. `false` until the metadata says otherwise; once `true` the
    /// torrent never again takes part in PEX or LSD (rule 2).
    pub private: bool,
    /// The metadata, once known (`None` while a magnet link fetches it).
    pub info: Option<Arc<metainfo::Info>>,
    pub storage: Option<Rc<DiskStore>>,
    /// The raw bencoded info dictionary, served over `ut_metadata`.
    pub raw_info: Option<Rc<Vec<u8>>>,
    /// Empty (zero pieces) until the metadata is known.
    pub picker: Picker,
    /// BEP 9 fetch state (magnet links).
    pub metadata: super::metadata::Fetch,
    /// BEP 11 state.
    pub pex: super::pex::State,
    /// BEP 19 web seeds (`url-list`).
    pub web_seeds: Vec<String>,
    /// Unix seconds when the torrent was added (from resume data when it
    /// carries one) and when the download completed.
    pub added_time: u64,
    pub completed_time: Option<u64>,
    /// A resume blob given at add time (`AddTorrent::resume_data`), taking
    /// precedence over the resume directory's file.
    pub resume_blob: Option<Vec<u8>>,
    /// `.torrent` extras kept for `Session::torrent_file` and the status:
    /// `comment`, `created by`, `creation date`.
    pub comment: Option<String>,
    pub created_by: Option<String>,
    pub creation_date: Option<i64>,
    pub webseed: super::webseed::State,
    pub save_path: PathBuf,
    sequential: bool,
    /// Requested file priorities (content-file order) until the metadata
    /// exists; afterwards the live ones are in `storage`.
    pending_priorities: Option<Vec<u8>>,
    /// BEP 53 `so=` from a magnet link: content-file indices to download;
    /// applied when the metadata arrives unless explicit priorities were
    /// given. Indices past the end are ignored.
    select_only: Option<Vec<u32>>,

    /// `move_storage` in progress: block writes/reads wait on `move_gate`.
    pub moving: bool,
    pub move_gate: Rc<Notify>,
    /// Disk writes in flight (drained before a move).
    pub writes_in_flight: usize,
    /// The tracker / tick tasks are running.
    pub tasks_running: bool,
    /// An entry for this torrent sits in the session's tick queue.
    pub tick_scheduled: bool,
    /// A periodic resume save is in flight.
    pub resume_saving: bool,
    pub announcer: Announcer,
    pub announce_key: u32,
    /// The peer id used for this torrent's announces and handshakes (per
    /// torrent or the session's, per the profile).
    pub peer_id: [u8; 20],
    /// Stopped by the caller.
    pub paused: bool,
    /// Paused by the active-torrent queue, not the caller
    /// (`TorrentState::Queued`); implies `paused`.
    pub auto_paused: bool,
    /// Bumped whenever the piece bookkeeping is replaced wholesale (a
    /// recheck's verdict, metadata arriving): a task that started before
    /// and comes back after must not apply what it computed against the
    /// old picture.
    pub epoch: u64,
    /// A pause is winding the torrent down (`stopped` announces in flight);
    /// a resume meanwhile only clears `paused`, and the pause restarts the
    /// tasks when it is done.
    pub stopping: bool,
    /// The queue may start and stop this torrent.
    pub auto_managed: bool,
    /// `auto_managed` came from `AddTorrent` (not to be overridden by the
    /// resume data).
    pub auto_managed_explicit: bool,
    /// Which per-torrent settings came from `AddTorrent` (the resume data's
    /// values apply to the others).
    pub settings_explicit: SettingsExplicit,
    /// Order in the queue (lower first; dense positions are computed for
    /// status).
    pub queue_position: u64,
    /// Since when both rates have been below the queue's inactivity
    /// thresholds while running.
    pub slow_since: Option<Instant>,
    /// Per-torrent upload slot cap (`None` = session budget only).
    pub max_uploads: Option<usize>,
    /// Per-torrent connection cap (`None` = the session default).
    pub max_peers: Option<usize>,
    /// Preallocate files when creating them (`fallocate`).
    pub preallocate: bool,
    /// Time spent active (not paused / stopped), excluding the current run.
    pub active_time: Duration,
    /// When the current run began, while running.
    pub active_since: Option<Instant>,
    /// Time spent active as a complete torrent, excluding the current run.
    pub seeding_time: Duration,
    /// When the current seeding run began, while running and complete.
    pub seeding_since: Option<Instant>,
    /// A check (initial or forced) is running or queued.
    pub checking: bool,
    /// The check waits for a slot (`max_checking`).
    pub check_queued: bool,
    pub error: Option<String>,
    pub stats: Stats,
    /// Per-torrent rate limits (0 = unlimited; the session limits apply too).
    pub up_limit: Rc<Limiter>,
    pub down_limit: Rc<Limiter>,
    pub peers: HashMap<u32, Rc<PeerHandle>>,
    /// Addresses learned from trackers, not yet tried.
    candidates: VecDeque<SocketAddr>,
    /// New candidates arrived; re-rank before the next dial.
    candidates_dirty: bool,
    /// Addresses whose uTP dial failed (libtorrent's `supports_utp` gone
    /// false); a PEX uTP flag clears the mark again.
    pub utp_failed: HashSet<SocketAddr>,
    /// Addresses whose TCP dial failed or was closed before the handshake:
    /// under `TransportPolicy::PreferTcp` they are dialled over uTP next.
    pub tcp_failed: HashSet<SocketAddr>,
    /// Addresses we connected to over uTP (`confirmed_supports_utp`).
    pub utp_confirmed: HashSet<SocketAddr>,
    known: HashSet<SocketAddr>,
    sources: HashMap<SocketAddr, PeerSource>,
    failed: HashMap<SocketAddr, Instant>,
    /// Addresses with a connect in progress.
    pub connecting: HashSet<SocketAddr>,
    /// Our peer id on every outgoing connection in progress or established
    /// (libtorrent `m_outgoing_pids`): an incoming handshake carrying one of
    /// them is ourselves, however we learned our own address (a tracker
    /// handing back the other family's listen address, for one).
    pub outgoing_pids: HashSet<[u8; 20]>,
    /// Addresses whose next outgoing attempt uses MSE (Q3 toggle).
    pub mse_retry: HashSet<SocketAddr>,
    /// Addresses that already used their one immediate retry
    /// (`take_fast_retry`).
    fast_retried: HashSet<SocketAddr>,
    pub half_open: usize,
    /// Set when the torrent is stopping; every task of the torrent exits.
    pub closing: Rc<Flag>,
    /// Wakes the tracker task (completed / forced / paused).
    pub tracker_kick: Rc<Notify>,
    /// Peers that supplied blocks of a piece (key, address), for blame.
    suppliers: HashMap<u32, Vec<(u32, IpAddr)>>,
    /// Trust points per address (see `BAN_AT`).
    trust: HashMap<IpAddr, i32>,
    banned: HashSet<IpAddr>,
    resume_path: Option<PathBuf>,
    pub resume_dirty: bool,
    last_resume_save: Instant,
    /// Pieces whose hash is being computed.
    verifying: HashSet<u32>,
    finished_emitted: bool,
    /// Tracker announce jobs in flight (so stop can wait for them).
    pub announces_in_flight: usize,
    /// Size of the raw info dictionary (LTEP `metadata_size`).
    pub metadata_size: u32,
}

impl Torrent {
    pub fn info_hash(&self) -> InfoHash {
        self.info_hash
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// The piece bookkeeping is about to be replaced: work in flight
    /// against the old picture is void (`epoch`), including the verifies
    /// whose pieces are being re-examined.
    pub fn new_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.verifying.clear();
    }

    /// Payload bytes the live connections copied in user space.
    pub fn copied_bytes(&self) -> u64 {
        self.peers
            .values()
            .map(|p| p.conn.borrow().copied_in())
            .sum()
    }

    /// Whether the metadata is known.
    pub fn has_metadata(&self) -> bool {
        self.info.is_some()
    }

    /// Connection cap for this torrent.
    pub fn max_peers(&self, ctx: &Ctx) -> usize {
        self.max_peers.unwrap_or(ctx.default_max_peers())
    }

    /// Total active / seeding time including the current run.
    pub fn times(&self, now: Instant) -> (Duration, Duration) {
        let run = |since: Option<Instant>| {
            since.map_or(Duration::ZERO, |t| now.saturating_duration_since(t))
        };
        (
            self.active_time + run(self.active_since),
            self.seeding_time + run(self.seeding_since),
        )
    }

    /// Fold the current run into the totals (a run ends).
    fn fold_times(&mut self, now: Instant) {
        let (a, s) = self.times(now);
        self.active_time = a;
        self.seeding_time = s;
        self.active_since = None;
        self.seeding_since = None;
    }

    /// The seeding clock follows completeness while running.
    fn sync_seeding_clock(&mut self, now: Instant) {
        if self.active_since.is_none() {
            return;
        }
        match (self.is_complete(), self.seeding_since) {
            (true, None) => self.seeding_since = Some(now),
            (false, Some(since)) => {
                self.seeding_time += now.saturating_duration_since(since);
                self.seeding_since = None;
            }
            _ => {}
        }
    }

    /// Pieces in the torrent (0 before the metadata is known).
    pub fn piece_count(&self) -> usize {
        self.info.as_ref().map_or(0, |i| i.piece_count())
    }

    /// Every wanted piece is verified (never true without metadata).
    pub fn is_complete(&self) -> bool {
        self.info.is_some() && self.picker.is_complete()
    }

    /// PEX and LSD are allowed for this torrent (rule 2).
    pub fn discovery_allowed(&self) -> bool {
        !self.private
    }

    /// The lifecycle state as reported to callers.
    pub fn state(&self) -> TorrentState {
        if self.error.is_some() {
            TorrentState::Error
        } else if self.checking {
            if self.check_queued {
                TorrentState::QueuedForChecking
            } else {
                TorrentState::Checking
            }
        } else if self.paused {
            if self.auto_paused {
                TorrentState::Queued
            } else {
                TorrentState::Paused
            }
        } else if self.info.is_none() {
            TorrentState::FetchingMetadata
        } else if self.picker.is_complete() {
            TorrentState::Seeding
        } else {
            TorrentState::Downloading
        }
    }

    /// Peers may be connected and served.
    pub fn is_running(&self) -> bool {
        !self.paused && !self.checking && self.error.is_none()
    }

    /// Running for a while and moving no data (the queue's slow-torrent
    /// exemption, libtorrent `dont_count_slow_torrents`).
    pub fn is_inactive(&self, now: Instant) -> bool {
        let started = self
            .active_since
            .is_some_and(|s| now.duration_since(s) >= super::queue::INACTIVE_AFTER);
        started
            && self
                .slow_since
                .is_some_and(|s| now.duration_since(s) >= super::queue::INACTIVE_AFTER)
    }

    /// The tick / tracker tasks keep running (checking included).
    pub fn is_active(&self) -> bool {
        !self.paused && self.error.is_none()
    }

    /// Bytes still needed (from the verified have-set). Without metadata the
    /// size is unknown; libtorrent announces 16 KiB then (docs/quirks.md Q12)
    /// and so do we: the value is not a claim about data we hold.
    pub fn left(&self) -> u64 {
        if self.info.is_none() {
            return 16 * 1024;
        }
        self.picker.bytes_left()
    }

    /// The status snapshot. `detailed` fills the per-file and per-tracker
    /// vectors (`Session::status`); `Session::statuses` leaves them empty.
    pub fn status(&self, now: Instant, queue_position: usize, detailed: bool) -> TorrentStatus {
        let trackers = if detailed {
            self.trackers(now)
        } else {
            Vec::new()
        };
        let files = if detailed { self.files() } else { Vec::new() };
        self.status_with(now, queue_position, files, trackers)
    }

    /// The tracker list as a status snapshot.
    pub fn trackers(&self, now: Instant) -> Vec<TrackerStatus> {
        self.announcer
            .snapshot()
            .into_iter()
            .map(|t| TrackerStatus {
                url: t.url,
                tier: t.tier,
                working: t.working,
                fails: t.fails,
                last_error: t.last_error,
                seeders: t.complete,
                leechers: t.incomplete,
                downloaded: t.downloaded,
                next_announce_in: t.next_announce.map(|a| a.saturating_duration_since(now)),
            })
            .collect()
    }

    /// The per-file status list.
    pub fn files(&self) -> Vec<crate::api::FileStatus> {
        self.file_statuses()
    }

    /// The torrent as `.torrent` bytes (`Session::torrent_file`): the raw
    /// info dictionary spliced in verbatim so the info-hash is preserved
    /// whatever its original encoding; everything else re-encoded from the
    /// current state.
    pub fn torrent_file(&self) -> Option<Vec<u8>> {
        use bencode::Value;
        let raw = self.raw_info.as_ref()?;
        let mut tiers: Vec<Vec<String>> = Vec::new();
        for t in self.announcer.snapshot() {
            while tiers.len() <= t.tier {
                tiers.push(Vec::new());
            }
            tiers[t.tier].push(t.url);
        }
        tiers.retain(|t| !t.is_empty());
        let mut out = Vec::new();
        let key = |out: &mut Vec<u8>, k: &str| {
            out.extend_from_slice(k.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(k.as_bytes());
        };
        // Keys in sorted order (canonical bencode).
        out.push(b'd');
        if let Some(first) = tiers.first().and_then(|t| t.first()) {
            key(&mut out, "announce");
            out.extend_from_slice(&bencode::to_bytes(&Value::Bytes(first.as_bytes())));
        }
        if tiers.iter().map(Vec::len).sum::<usize>() > 1 || tiers.len() > 1 {
            key(&mut out, "announce-list");
            let items: Vec<Value<'_>> = tiers
                .iter()
                .map(|t| Value::List {
                    items: t.iter().map(|u| Value::Bytes(u.as_bytes())).collect(),
                    raw: &[],
                })
                .collect();
            out.extend_from_slice(&bencode::to_bytes(&Value::List { items, raw: &[] }));
        }
        if let Some(c) = &self.comment {
            key(&mut out, "comment");
            out.extend_from_slice(&bencode::to_bytes(&Value::Bytes(c.as_bytes())));
        }
        if let Some(c) = &self.created_by {
            key(&mut out, "created by");
            out.extend_from_slice(&bencode::to_bytes(&Value::Bytes(c.as_bytes())));
        }
        if let Some(d) = self.creation_date {
            key(&mut out, "creation date");
            out.extend_from_slice(&bencode::to_bytes(&Value::Int(d)));
        }
        key(&mut out, "info");
        out.extend_from_slice(raw);
        if !self.web_seeds.is_empty() {
            key(&mut out, "url-list");
            let items: Vec<Value<'_>> = self
                .web_seeds
                .iter()
                .map(|u| Value::Bytes(u.as_bytes()))
                .collect();
            out.extend_from_slice(&bencode::to_bytes(&Value::List { items, raw: &[] }));
        }
        out.push(b'e');
        Some(out)
    }

    /// The per-piece state and availability (`Session::pieces`).
    pub fn pieces(&self) -> Vec<crate::api::PieceInfo> {
        use crate::api::{PieceInfo, PieceState};
        let n = self.piece_count();
        let mut v: Vec<PieceInfo> = (0..n)
            .map(|i| PieceInfo {
                state: if self.picker.have(i) {
                    PieceState::Have
                } else {
                    PieceState::Missing
                },
                availability: self.picker.availability(i),
            })
            .collect();
        for i in self.picker.open_piece_indices() {
            if let Some(p) = v.get_mut(i)
                && p.state == PieceState::Missing
            {
                p.state = PieceState::Downloading;
            }
        }
        v
    }

    fn status_with(
        &self,
        now: Instant,
        queue_position: usize,
        files: Vec<crate::api::FileStatus>,
        trackers: Vec<TrackerStatus>,
    ) -> TorrentStatus {
        let n = self.piece_count();
        let seeds = self.peers.values().filter(|p| p.is_seed(n)).count();
        TorrentStatus {
            id: self.id,
            info_hash: self.info_hash,
            name: self.name.clone(),
            state: self.state(),
            error: self.error.clone(),
            has_metadata: self.info.is_some(),
            private: self.private,
            pieces_have: self.picker.have_count(),
            pieces_total: n,
            total_size: self.info.as_ref().map_or(0, |i| i.total_length),
            downloaded: self.stats.downloaded,
            uploaded: self.stats.uploaded,
            left: self.left(),
            corrupt: self.stats.corrupt,
            redundant: self.stats.redundant,
            download_rate: self.stats.download_rate,
            upload_rate: self.stats.upload_rate,
            peers: self.peers.len(),
            seeds,
            trackers,
            complete: self.is_complete(),
            web_seeds: self.web_seeds.len(),
            web_seed_urls: self.web_seeds.clone(),
            files,
            piece_length: self.info.as_ref().map_or(0, |i| i.piece_length),
            comment: self.comment.clone(),
            created_by: self.created_by.clone(),
            creation_date: self.creation_date,
            upload_limit: self.up_limit.rate(),
            download_limit: self.down_limit.rate(),
            total_wanted: self.wanted().0,
            total_wanted_done: self.wanted().1,
            save_path: self.save_path.clone(),
            active_time: self.times(now).0,
            seeding_time: self.times(now).1,
            max_peers: self.max_peers,
            max_uploads: self.max_uploads,
            peer_list_size: self.known.len(),
            needs_resume_save: self.resume_dirty,
            added_on: self.added_time,
            completed_on: self.completed_time,
            auto_managed: self.auto_managed,
            queue_position,
            next_announce_in: self
                .announcer
                .snapshot()
                .into_iter()
                .filter_map(|t| t.next_announce)
                .min()
                .map(|a| a.saturating_duration_since(now)),
        }
    }

    /// `(total_wanted, total_wanted_done)`: bytes of the files with a
    /// non-zero priority, and those of them covered by verified pieces
    /// (libtorrent's definition, per file rather than per piece).
    fn wanted(&self) -> (u64, u64) {
        let (Some(info), Some(storage)) = (&self.info, &self.storage) else {
            return (0, 0);
        };
        let prios = storage.file_priorities();
        let mut total = 0u64;
        let mut done = 0u64;
        for (i, f) in info.files.iter().enumerate() {
            if f.is_padding() || prios.get(i).copied().unwrap_or(0) == 0 {
                continue;
            }
            total += f.length;
            done += storage.file_done(i);
        }
        (total, done)
    }

    /// Content files with priority and progress.
    fn file_statuses(&self) -> Vec<crate::api::FileStatus> {
        let (Some(info), Some(storage)) = (&self.info, &self.storage) else {
            return Vec::new();
        };
        let prios = storage.file_priorities();
        info.files
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.is_padding())
            .map(|(i, f)| crate::api::FileStatus {
                path: storage
                    .rel_path(i)
                    .unwrap_or_else(|| f.path.clone())
                    .components()
                    .join("/"),
                size: f.length,
                priority: prios.get(i).copied().unwrap_or(0),
                done: storage.file_done(i),
            })
            .collect()
    }

    /// Indices into `info.files` of the content (non-padding) files, in
    /// order: the public API numbers files this way.
    fn content_indices(info: &metainfo::Info) -> Vec<usize> {
        info.files
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.is_padding())
            .map(|(i, _)| i)
            .collect()
    }

    pub fn peer_infos(&self) -> Vec<PeerInfo> {
        let n = self.piece_count();
        let mut v: Vec<PeerInfo> = self.peers.values().map(|p| p.info(n)).collect();
        v.sort_by_key(|p| p.addr);
        v
    }

    pub fn force_reannounce(&mut self, now: Instant) {
        self.announcer.force_reannounce(now);
        self.tracker_kick.notify();
    }

    /// Add peers learned from `source`, filtering what AGENTS.md 5.5 says to
    /// drop. PEX / LSD peers are refused for private torrents (rule 2).
    pub fn add_candidates(&mut self, ctx: &Ctx, peers: &[SocketAddr], source: PeerSource) -> usize {
        if self.private && matches!(source, PeerSource::Pex | PeerSource::Lsd) {
            return 0;
        }
        let mut added = 0;
        for &p in peers {
            if self.known.len() >= MAX_PEER_LIST && !self.evict_candidate() {
                // Full of connected peers: nothing to make room with.
                break;
            }
            // Normalise on ingress (AGENTS.md 5.5): a v4-mapped v6 address
            // (`::ffff:a.b.c.d`, as some trackers put in `peers6` and some
            // clients in PEX `added6`) is the IPv4 peer it names.
            let p = canonical_addr(p);
            if !usable_peer_addr(ctx, p)
                || self.banned.contains(&p.ip())
                || ctx.is_banned_ip(p.ip())
            {
                continue;
            }
            if self.known.insert(p) {
                self.sources.insert(p, source);
                self.candidates.push_back(p);
                added += 1;
            }
        }
        if added > 0 {
            self.candidates_dirty = true;
        }
        added
    }

    /// Make room in a full peer list (libtorrent `peer_list::erase_peers`):
    /// drop the candidate that has waited longest and is not connected or
    /// being dialled. `false` when every entry is in use.
    fn evict_candidate(&mut self) -> bool {
        let victim = self
            .candidates
            .iter()
            .position(|a| !self.has_peer_ip(a.ip()) && !self.connecting.contains(a));
        let Some(i) = victim else {
            return false;
        };
        if let Some(a) = self.candidates.remove(i) {
            self.known.remove(&a);
            self.sources.remove(&a);
            self.failed.remove(&a);
            self.fast_retried.remove(&a);
        }
        true
    }

    /// Forget expired reconnect backoffs (the map would otherwise grow with
    /// every address ever tried).
    pub fn prune_failed(&mut self, now: Instant) {
        if self.failed.len() > MAX_PEER_LIST {
            self.failed
                .retain(|_, t| now.duration_since(*t) < RECONNECT_BACKOFF);
        }
    }

    /// Our external address changed: BEP 40 ranks depend on it.
    pub fn rerank_candidates(&mut self) {
        self.candidates_dirty = true;
    }

    /// Toggle sequential download (applies to future picks).
    pub fn set_sequential(&mut self, on: bool) {
        self.sequential = on;
        self.picker.set_sequential(on);
    }

    /// Where an address was learned (for `PeerInfo::source`).
    pub fn source_of(&self, addr: SocketAddr) -> PeerSource {
        self.sources
            .get(&addr)
            .copied()
            .unwrap_or(PeerSource::Incoming)
    }

    /// Whether we already have (or are opening) a connection to this IP.
    pub fn has_peer_ip(&self, ip: IpAddr) -> bool {
        self.peers.values().any(|p| p.addr.ip() == ip)
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.banned.contains(&ip)
    }

    /// A connect failed or a connection ended: back this address off for
    /// `RECONNECT_BACKOFF` from `attempted` (the time the connection was
    /// made or tried).
    pub fn note_disconnect(&mut self, addr: SocketAddr, attempted: Instant) {
        self.failed.insert(addr, attempted);
    }

    /// Let the next tick dial `addr` again immediately (libtorrent's
    /// `fast_reconnect` after a plaintext attempt that needs MSE).
    pub fn allow_reconnect_now(&mut self, addr: SocketAddr) {
        self.failed.remove(&addr);
    }

    /// One immediate retry per address whose first connection died before
    /// the handshake (libtorrent's `fast_reconnect`): a peer that was not
    /// ready — still checking its files, just restarted — costs a
    /// round trip, not the full `min_reconnect_time`. Returns whether this
    /// retry is the one.
    pub fn take_fast_retry(&mut self, addr: SocketAddr) -> bool {
        if self.fast_retried.contains(&addr) {
            return false;
        }
        if self.fast_retried.len() < MAX_PEER_LIST {
            self.fast_retried.insert(addr);
        }
        true
    }

    /// Record who supplied a block (for blame).
    pub fn note_supplier(&mut self, piece: u32, key: u32, ip: IpAddr) {
        let v = self.suppliers.entry(piece).or_default();
        if !v.iter().any(|(k, _)| *k == key) && v.len() < 64 {
            v.push((key, ip));
        }
    }

    /// Adjust a peer's trust; ban (and drop) it when it falls to `BAN_AT`.
    /// Web seeds (blamed under the unspecified address) are not tracked by
    /// address; a failed piece drops the seed instead (`verify_piece`).
    fn adjust_trust(&mut self, ip: IpAddr, delta: i32) -> Vec<u32> {
        if ip.is_unspecified() {
            return Vec::new();
        }
        let t = self.trust.entry(ip).or_insert(0);
        *t = (*t + delta).min(TRUST_CAP);
        if *t > BAN_AT {
            return Vec::new();
        }
        let fresh = self.banned.insert(ip);
        for p in self.peers.values() {
            if p.addr.ip() == ip {
                p.close("banned: repeated hash failures");
            }
        }
        if !fresh {
            return Vec::new();
        }
        // Everything it sent into pieces still in progress is suspect:
        // those pieces start over, so its corrupt blocks cannot drag an
        // honest peer down with them later.
        let tainted: Vec<u32> = self
            .suppliers
            .iter()
            .filter(|(piece, who)| {
                !self.picker.have(**piece as usize) && who.iter().any(|(_, sup)| *sup == ip)
            })
            .map(|(piece, _)| *piece)
            .collect();
        for piece in &tainted {
            self.suppliers.remove(piece);
            self.picker.piece_failed(*piece as usize);
        }
        tainted
    }

    /// Drop `addr` from the candidates (an address that turned out to be
    /// ours; `Ctx::note_own_ip` keeps it out of every torrent from now on).
    pub fn forget_candidate(&mut self, addr: SocketAddr) {
        self.known.remove(&addr);
        self.candidates.retain(|a| *a != addr);
    }

    /// Everyone must know when we gain a piece; once complete, connections to
    /// other seeds are pointless on both sides and are closed.
    fn broadcast_have(&self, piece: u32) {
        let complete = self.is_complete();
        let n = self.piece_count();
        for p in self.peers.values() {
            p.conn.borrow_mut().have(piece);
            p.out.notify();
            if complete && p.is_seed(n) {
                p.close("both seeds");
            }
        }
    }

    /// Re-evaluate interest in every peer after our have-set changed
    /// wholesale (priorities, recheck).
    fn refresh_interest(&self) {
        for p in self.peers.values() {
            p.update_interest(&self.picker);
        }
    }

    /// Re-evaluate interest after we gained `piece`: only a peer we are
    /// interested in and that has this piece can become uninteresting
    /// (libtorrent `torrent::we_have`).
    fn refresh_interest_after(&self, piece: u32) {
        for p in self.peers.values() {
            let conn = p.conn.borrow();
            if !conn.am_interested() || !conn.peer_have().has(piece as usize) {
                continue;
            }
            drop(conn);
            p.update_interest(&self.picker);
        }
    }
}

/// Peer address filtering (AGENTS.md 5.5): drop unspecified, multicast,
/// link-local, port 0, and our own listen endpoint.
/// Which of a torrent's settings the caller gave explicitly at add time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SettingsExplicit {
    pub sequential: bool,
    pub upload_limit: bool,
    pub download_limit: bool,
    pub max_peers: bool,
    pub max_uploads: bool,
}

/// A v4-mapped v6 socket address as the IPv4 address it names; anything
/// else unchanged.
pub fn canonical_addr(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        IpAddr::V4(_) => a,
    }
}

/// Whether a peer address is worth dialling: not a placeholder, not one we
/// could not reach (no listen socket of that family, so no route and no
/// source address to dial from), not ourselves. Callers canonicalise
/// first; a v4-mapped address that slipped through is refused.
fn usable_peer_addr(ctx: &Ctx, a: SocketAddr) -> bool {
    if a.port() == 0 {
        return false;
    }
    let ip = a.ip();
    let bad = match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified() || v4.is_multicast() || v4.is_link_local() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.to_ipv4_mapped().is_some()
        }
    };
    if bad || !ctx.families().allows(ip) {
        return false;
    }
    let own = match ip {
        IpAddr::V4(v4) => ctx.listen_v4() == Some(v4) && !v4.is_unspecified(),
        IpAddr::V6(v6) => ctx.listen_v6() == Some(v6) && !v6.is_unspecified(),
    } || ctx.is_own_ip(ip);
    !(own && a.port() == ctx.listen_port())
}

fn resume_file(dir: &std::path::Path, h: &InfoHash) -> PathBuf {
    dir.join(format!("{}.resume", bencode::hex(h)))
}

/// `Session::add_torrent`.
pub async fn add(ctx: Rc<Ctx>, id: TorrentId, params: AddTorrent) -> Result<TorrentId, Error> {
    let now = Instant::now();
    let mut extras: (Option<String>, Option<String>, Option<i64>) = (None, None, None);
    let (info_hash, name, tiers, web_seeds, parsed) = match &params.source {
        TorrentSource::Metainfo(bytes) => {
            let meta = Metainfo::parse(bytes).map_err(|e| Error::Metainfo(e.to_string()))?;
            extras = (
                meta.comment.clone(),
                meta.created_by.clone(),
                meta.creation_date,
            );
            if meta.info.has_v2 && meta.info.piece_hashes.is_empty() {
                return Err(Error::Unsupported("v2-only torrents (BEP 52) are deferred"));
            }
            let raw = bencode::from_bytes(bytes)
                .ok()
                .and_then(|v| v.get_str("info").and_then(|i| i.raw()).map(|r| r.to_vec()))
                .ok_or_else(|| Error::Metainfo("no raw info dictionary".into()))?;
            (
                meta.info.info_hash,
                meta.info.name.clone(),
                meta.tiers(),
                meta.url_list.clone(),
                Some((meta.info.clone(), raw)),
            )
        }
        TorrentSource::Magnet(uri) => {
            let m = metainfo::MagnetLink::parse(uri).map_err(|e| Error::Metainfo(e.to_string()))?;
            let name = m.name.clone().unwrap_or_else(|| bencode::hex(&m.info_hash));
            (m.info_hash, name, m.tiers(), m.web_seeds.clone(), None)
        }
    };
    let magnet = match &params.source {
        TorrentSource::Magnet(uri) => metainfo::MagnetLink::parse(uri).ok(),
        TorrentSource::Metainfo(_) => None,
    };
    if ctx.closing.is_set() {
        // The session started shutting down while this add was in flight:
        // it would never be stopped (the shutdown took its snapshot).
        return Err(Error::Shutdown);
    }
    if ctx.by_hash.borrow().contains_key(&info_hash) {
        return Err(Error::Duplicate);
    }
    let resume_path = params
        .resume_dir
        .as_deref()
        .map(|d| resume_file(d, &info_hash));
    if let Some(dir) = &params.resume_dir {
        std::fs::create_dir_all(dir)?;
    }
    let announcer = Announcer::new(tiers, ctx.families().endpoints().len());
    let torrent = Rc::new(RefCell::new(Torrent {
        id,
        info_hash,
        name,
        private: false,
        info: None,
        storage: None,
        raw_info: None,
        picker: Picker::new(0, 0, 0),
        metadata: super::metadata::Fetch::default(),
        pex: super::pex::State::default(),
        web_seeds,
        added_time: unix_now(),
        completed_time: None,
        resume_blob: params.resume_data.clone(),
        comment: extras.0,
        created_by: extras.1,
        creation_date: extras.2,
        webseed: super::webseed::State::default(),
        save_path: params.save_path.clone(),
        sequential: params.sequential.unwrap_or(false),
        settings_explicit: SettingsExplicit {
            sequential: params.sequential.is_some(),
            upload_limit: params.upload_limit.is_some(),
            download_limit: params.download_limit.is_some(),
            max_peers: params.max_peers.is_some(),
            max_uploads: params.max_uploads.is_some(),
        },
        pending_priorities: params.file_priorities.clone(),
        select_only: magnet.as_ref().and_then(|m| m.select_only.clone()),
        moving: false,
        move_gate: Notify::new(),
        writes_in_flight: 0,
        tasks_running: false,
        tick_scheduled: false,
        resume_saving: false,
        announcer,
        announce_key: ctx.new_announce_key(),
        peer_id: ctx.new_torrent_peer_id(),
        paused: params.paused,
        epoch: 0,
        auto_paused: false,
        stopping: false,
        // Resume data may say otherwise (`load_resume`); the caller wins.
        auto_managed: params.auto_managed.unwrap_or(true),
        auto_managed_explicit: params.auto_managed.is_some(),
        queue_position: ctx.next_queue_position(),
        slow_since: None,
        max_uploads: params.max_uploads,
        max_peers: params.max_peers,
        preallocate: params.preallocate,
        active_time: Duration::ZERO,
        active_since: None,
        seeding_time: Duration::ZERO,
        seeding_since: None,
        checking: parsed.is_some(),
        check_queued: false,
        error: None,
        stats: Stats::default(),
        up_limit: Limiter::new(params.upload_limit.unwrap_or(0), now),
        down_limit: Limiter::new(params.download_limit.unwrap_or(0), now),
        peers: HashMap::new(),
        candidates: VecDeque::new(),
        candidates_dirty: false,
        utp_failed: HashSet::new(),
        tcp_failed: HashSet::new(),
        utp_confirmed: HashSet::new(),
        known: HashSet::new(),
        sources: HashMap::new(),
        failed: HashMap::new(),
        connecting: HashSet::new(),
        outgoing_pids: HashSet::new(),
        mse_retry: HashSet::new(),
        fast_retried: HashSet::new(),
        half_open: 0,
        closing: Flag::new(),
        tracker_kick: Notify::new(),
        suppliers: HashMap::new(),
        trust: HashMap::new(),
        banned: HashSet::new(),
        resume_path,
        resume_dirty: false,
        last_resume_save: now,
        verifying: HashSet::new(),
        finished_emitted: false,
        announces_in_flight: 0,
        metadata_size: 0,
    }));
    ctx.torrents.borrow_mut().insert(id, torrent.clone());
    ctx.index_torrent(info_hash, id);
    ctx.emit(Event::TorrentAdded { id });
    match parsed {
        Some((info, raw)) => {
            let resume = load_resume(&ctx, &torrent);
            if let Err(e) = attach_metadata(&ctx, &torrent, info, raw, resume.as_ref()) {
                ctx.remove_torrent_entry(id);
                return Err(e);
            }
            // Before any file is created: does the disk still hold what the
            // resume data describes?
            let files_present = wanted_files_present(&torrent);
            if let Err(e) = create_files(&torrent).await {
                ctx.remove_torrent_entry(id);
                return Err(e);
            }
            uring::spawn(initial_check(
                ctx.clone(),
                torrent.clone(),
                files_present,
                resume,
            ));
        }
        None => {
            // A magnet: nothing to check yet; announce and find peers to
            // fetch the metadata from. BEP 9 `x.pe` peers are dialled right
            // away (host names through the DNS helper).
            if !params.paused {
                super::queue::activate(&ctx, &torrent);
            }
            if let Some(m) = &magnet {
                for peer in m.peers.clone() {
                    let ctx2 = ctx.clone();
                    let torrent2 = torrent.clone();
                    uring::spawn(async move {
                        let Some((host, port)) = split_host_port(&peer) else {
                            return;
                        };
                        match ctx2.dns.resolve(&host, port).await {
                            Ok(addrs) => {
                                let mut t = torrent2.borrow_mut();
                                let n =
                                    t.add_candidates(&ctx2, &addrs, crate::api::PeerSource::Manual);
                                if n > 0 {
                                    t.tracker_kick.notify();
                                }
                            }
                            Err(e) => tracing::debug!(peer, "magnet x.pe: {e}"),
                        }
                    });
                }
            }
        }
    }
    Ok(id)
}

/// Whether every wanted content file exists on disk. Evaluated before any
/// file is created, to decide whether resume data still describes the disk;
/// skipped files are never created, so they do not count.
fn wanted_files_present(torrent: &Rc<RefCell<Torrent>>) -> bool {
    let t = torrent.borrow();
    let (Some(info), Some(storage)) = (&t.info, &t.storage) else {
        return false;
    };
    let prios = storage.file_priorities();
    info.files
        .iter()
        .enumerate()
        .filter(|(i, f)| !f.is_padding() && prios.get(*i).copied().unwrap_or(0) > 0)
        .all(|(i, _)| {
            storage
                .file_path(i)
                .is_some_and(|p| std::fs::metadata(p).is_ok())
        })
}

/// Load the resume file, if any (unreadable data is ignored with a warning).
fn load_resume(ctx: &Ctx, torrent: &Rc<RefCell<Torrent>>) -> Option<ResumeData> {
    let blob = torrent.borrow_mut().resume_blob.take();
    let r = match blob {
        Some(bytes) => match ResumeData::decode(&bytes) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("ignoring unreadable resume data blob: {e}");
                return None;
            }
        },
        None => {
            let path = torrent.borrow().resume_path.clone()?;
            ResumeData::load(&path).unwrap_or_else(|e| {
                tracing::warn!("ignoring unreadable resume data {}: {e}", path.display());
                None
            })?
        }
    };
    if r.info_hash != torrent.borrow().info_hash {
        tracing::warn!("ignoring resume data for another torrent");
        return None;
    }
    // The queue fields: the caller's `AddTorrent::auto_managed` wins over the
    // file's; the saved order is restored (positions are dense per session,
    // so a restored key only orders the torrent among the others restored).
    {
        let mut t = torrent.borrow_mut();
        if !t.auto_managed_explicit {
            t.auto_managed = r.auto_managed;
        }
        if let Some(q) = r.queue_position {
            t.queue_position = q;
            ctx.note_queue_position(q);
        }
        // Per-torrent settings (v5), unless the caller set them.
        let now = Instant::now();
        let e = t.settings_explicit;
        if !e.sequential {
            t.sequential = r.sequential;
            t.picker.set_sequential(r.sequential);
        }
        if !e.upload_limit {
            t.up_limit.set_rate(r.upload_limit, now);
        }
        if !e.download_limit {
            t.down_limit.set_rate(r.download_limit, now);
        }
        if !e.max_peers {
            t.max_peers = r.max_peers.map(|m| m as usize);
        }
        if !e.max_uploads {
            t.max_uploads = r.max_uploads.map(|m| m as usize);
        }
        // v6: the tracker list and web seeds as they stood replace the
        // metainfo's (libtorrent's resume trackers), the timestamps come
        // back, the last peers are the first candidates.
        if !r.trackers.is_empty() {
            let endpoints = t.announcer.endpoints();
            t.announcer = Announcer::new(r.trackers.clone(), endpoints);
        }
        if !r.web_seeds.is_empty() {
            t.web_seeds = r.web_seeds.clone();
        }
        if r.added_time > 0 {
            t.added_time = r.added_time;
        }
        t.completed_time = r.completed_time;
        if !r.peers.is_empty() {
            t.add_candidates(ctx, &r.peers, PeerSource::Resume);
        }
    }
    Some(r)
}

/// Expand content-file priorities to one entry per `info.files` (padding
/// files get 0). `None` when the count does not match.
fn expand_priorities(info: &metainfo::Info, prios: &[u8]) -> Option<Vec<u8>> {
    let idx = Torrent::content_indices(info);
    if idx.len() != prios.len() {
        return None;
    }
    let mut out = vec![0u8; info.files.len()];
    for (k, i) in idx.into_iter().enumerate() {
        out[i] = prios[k].min(storage::MAX_PRIORITY);
    }
    Some(out)
}

/// Install the metadata: the info dictionary, storage (with the initial file
/// priorities: the caller's, else the resume data's, else the default),
/// picker, privacy.
fn attach_metadata(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    info: metainfo::Info,
    raw: Vec<u8>,
    resume: Option<&ResumeData>,
) -> Result<(), Error> {
    let mut t = torrent.borrow_mut();
    let info = Arc::new(info);
    let requested = t.pending_priorities.take().or_else(|| {
        // BEP 53: only the selected content files, the rest skipped.
        let so = t.select_only.take()?;
        let n = Torrent::content_indices(&info).len();
        let mut prios = vec![0u8; n];
        for i in so {
            if let Some(p) = prios.get_mut(i as usize) {
                *p = storage::DEFAULT_PRIORITY;
            }
        }
        Some(prios)
    });
    let initial: Option<Vec<u8>> = match requested {
        Some(p) => match expand_priorities(&info, &p) {
            Some(e) => Some(e),
            None => {
                tracing::warn!(
                    torrent = t.id.0,
                    "file priority count {} does not match {} files; ignored",
                    p.len(),
                    Torrent::content_indices(&info).len()
                );
                None
            }
        },
        None => resume
            .filter(|r| r.matches(&info) && r.file_priorities.len() == info.files.len())
            .map(|r| r.file_priorities.clone()),
    };
    // Renamed paths from the resume data (v5), validated like any path.
    let mapped: Vec<Option<metainfo::SafePath>> = resume
        .filter(|r| r.matches(&info) && r.mapped_files.len() == info.files.len())
        .map(|r| {
            r.mapped_files
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    if m.is_empty() {
                        return None;
                    }
                    let comps: Vec<&[u8]> = m.split('/').map(str::as_bytes).collect();
                    metainfo::SafePath::from_components(&comps, i).ok()
                })
                .collect()
        })
        .unwrap_or_default();
    let storage = Rc::new(
        ctx.disk
            .open_mapped(info.clone(), t.save_path.clone(), initial, mapped),
    );
    let mut picker = Picker::new(info.piece_count(), info.piece_length, info.total_length);
    picker.set_sequential(t.sequential);
    picker.set_extent_affinity(ctx.cfg.piece_extent_affinity);
    for (i, p) in storage.piece_priorities().into_iter().enumerate() {
        picker.set_priority(i, p);
    }
    t.new_epoch();
    t.metadata_size = raw.len().min(u32::MAX as usize) as u32;
    t.name = info.name.clone();
    t.private = info.private;
    t.picker = picker;
    t.storage = Some(storage);
    t.raw_info = Some(Rc::new(raw));
    t.info = Some(info);
    Ok(())
}

async fn create_files(torrent: &Rc<RefCell<Torrent>>) -> Result<(), Error> {
    let (storage, preallocate) = {
        let t = torrent.borrow();
        (t.storage.clone(), t.preallocate)
    };
    if let Some(s) = storage {
        s.create_files(preallocate).await?;
    }
    Ok(())
}

/// The metadata arrived over `ut_metadata` (BEP 9): install it, tell every
/// connected peer, and check the disk before downloading.
pub async fn on_metadata(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, raw: Vec<u8>) {
    let info = match metainfo::Info::from_info_dict(&raw) {
        Ok(i) => i,
        Err(e) => {
            fail_torrent(ctx, torrent, format!("metadata unusable: {e}"));
            return;
        }
    };
    if info.has_v2 && info.piece_hashes.is_empty() {
        fail_torrent(ctx, torrent, "v2-only metadata (BEP 52) is deferred".into());
        return;
    }
    let resume = load_resume(ctx, torrent);
    if let Err(e) = attach_metadata(ctx, torrent, info, raw, resume.as_ref()) {
        fail_torrent(ctx, torrent, e.to_string());
        return;
    }
    let files_present = wanted_files_present(torrent);
    if let Err(e) = create_files(torrent).await {
        fail_torrent(ctx, torrent, e.to_string());
        return;
    }
    let (id, private, peers) = {
        let mut t = torrent.borrow_mut();
        t.checking = true;
        let peers: Vec<Rc<PeerHandle>> = t.peers.values().cloned().collect();
        if t.private {
            // Rule 2: a private torrent takes no part in PEX from the moment
            // we know. Connections learned through PEX stay (they were legal
            // when made); nothing more is exchanged.
            t.pex = super::pex::State::default();
        }
        (t.id, t.private, peers)
    };
    tracing::info!(torrent = id.0, private, "metadata received");
    ctx.emit(Event::MetadataReceived { id });
    let (n, plen, have) = {
        let t = torrent.borrow();
        (
            t.piece_count(),
            t.info.as_ref().map_or(0, |i| i.piece_length),
            Bitfield::new(t.piece_count()),
        )
    };
    for p in peers {
        p.on_metadata(torrent, n, plen, &have);
    }
    uring::spawn(initial_check(
        ctx.clone(),
        torrent.clone(),
        files_present,
        resume,
    ));
}

/// Resume data or recheck, then start. A resume file only ever records pieces
/// that were verified and fsynced, so it is trusted when it matches the
/// torrent and every content file is still present; otherwise, if any content
/// exists on disk, it is rechecked (AGENTS.md 5.4: when unsure, recheck).
async fn initial_check(
    ctx: Rc<Ctx>,
    torrent: Rc<RefCell<Torrent>>,
    files_present: bool,
    resume: Option<ResumeData>,
) {
    let (storage, info) = {
        let t = torrent.borrow();
        let (Some(s), Some(i)) = (t.storage.clone(), t.info.clone()) else {
            return;
        };
        (s, i)
    };
    let mut have = Bitfield::new(info.piece_count());
    let mut carried: Option<(u64, u64)> = None;
    let mut unfinished: Vec<(u32, Vec<(u32, u32)>)> = Vec::new();
    match resume {
        Some(r) if r.matches(&info) && files_present => {
            have = r.have.clone();
            carried = Some((r.downloaded, r.uploaded));
            unfinished = r.unfinished.clone();
            let mut t = torrent.borrow_mut();
            t.active_time = Duration::from_secs(r.active_time);
            t.seeding_time = Duration::from_secs(r.seeding_time);
        }
        _ => {
            let any_data = (0..info.files.len()).any(|i| {
                storage
                    .file_path(i)
                    .is_some_and(|p| std::fs::metadata(p).is_ok_and(|m| m.len() > 0))
            }) || std::fs::metadata(storage.parts_path()).is_ok_and(|m| m.len() > 0);
            if any_data {
                let result = checked(&ctx, &torrent, storage.check_all()).await;
                match result {
                    Some(Ok(h)) => have = h,
                    Some(Err(e)) => {
                        fail_torrent(&ctx, &torrent, format!("check failed: {e}"));
                        return;
                    }
                    None => return,
                }
            }
        }
    }
    {
        let t = torrent.borrow();
        if let Some(s) = &t.storage {
            s.set_have(have.clone());
        }
    }
    // (The initial check: nothing was received into the picker yet.)
    let _ = torrent.borrow_mut().picker.set_have(&have);
    let restores = begin_restore(&torrent, &storage, &have, unfinished);
    finish_check(&ctx, &torrent, have, carried);
    finish_restore(&ctx, &torrent, &storage, restores).await;
}

/// A partly written piece being brought back from resume data.
struct Restore {
    piece: usize,
    /// Its blocks are all there: verify once restored.
    complete: bool,
    /// The picture the restore belongs to (a recheck meanwhile voids it).
    epoch: u64,
    /// The storage job, queued already.
    job: std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), storage::Error>>>>,
}

/// Bring back the pieces that were partly written when the resume data was
/// saved: their synced ranges become downloaded blocks (not requested
/// again) and the storage's hash cursor reads them back as it advances.
/// This half runs before the torrent starts: the picker learns the blocks
/// and the disk jobs are queued, so a peer is never asked for a restored
/// block (had it sent one, the disk would no longer count among the
/// piece's suppliers and a torn write would get the peer banned alone),
/// and every write a peer causes runs behind the restore on the disk
/// thread.
fn begin_restore(
    torrent: &Rc<RefCell<Torrent>>,
    storage: &Rc<DiskStore>,
    have: &Bitfield,
    unfinished: Vec<(u32, Vec<(u32, u32)>)>,
) -> Vec<Restore> {
    const BLOCK: u32 = 16 * 1024;
    let mut t = torrent.borrow_mut();
    let piece_count = t.piece_count();
    let mut restored = 0u64;
    let mut restores = Vec::new();
    for (piece, ranges) in unfinished {
        let piece = piece as usize;
        if piece >= piece_count || have.get(piece) {
            continue;
        }
        let piece_size = t.picker.piece_size(piece);
        let mut complete = false;
        let mut piece_restored = 0u64;
        for &(s, e) in &ranges {
            let e = e.min(piece_size);
            // Whole blocks only; a partial block is downloaded again.
            let mut b = s.div_ceil(BLOCK) * BLOCK;
            while b < e {
                let len = BLOCK.min(piece_size - b);
                if b + len > e {
                    break;
                }
                let block = picker::Block {
                    piece: piece as u32,
                    offset: b,
                    length: len,
                };
                if let picker::Received::Accepted { piece_complete, .. } =
                    t.picker.block_received(RESUME_PEER_KEY, &block)
                {
                    piece_restored += u64::from(len);
                    complete |= piece_complete;
                }
                b += BLOCK;
            }
        }
        restored += piece_restored;
        if piece_restored > 0 {
            // The disk is a supplier of this piece too: should the piece
            // fail its hash, the peers that send the rest are not the sole
            // suspects (a torn write is as likely).
            t.note_supplier(
                piece as u32,
                RESUME_PEER_KEY,
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            );
        }
        if complete {
            t.verifying.insert(piece as u32);
        }
        restores.push(Restore {
            piece,
            complete,
            epoch: t.epoch,
            job: Box::pin(storage.restore_unfinished(piece, ranges)),
        });
    }
    if restored > 0 {
        tracing::info!(
            torrent = t.id.0,
            bytes = restored,
            "unfinished pieces restored from resume data"
        );
    }
    restores
}

/// The other half of [`begin_restore`], once the torrent runs: wait for the
/// storage jobs, verify the pieces whose blocks are all there, and start
/// over a piece the storage could not restore.
async fn finish_restore(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    storage: &Rc<DiskStore>,
    restores: Vec<Restore>,
) {
    for r in restores {
        let result = r.job.await;
        if torrent.borrow().epoch != r.epoch {
            continue;
        }
        if let Err(e) = result {
            tracing::warn!(piece = r.piece, "unfinished piece not restored: {e}");
            {
                let mut t = torrent.borrow_mut();
                t.verifying.remove(&(r.piece as u32));
                t.suppliers.remove(&(r.piece as u32));
                t.picker.piece_failed(r.piece);
            }
            let _ = storage.discard_piece(r.piece).await;
            continue;
        }
        if r.complete {
            uring::spawn(verify_piece(
                ctx.clone(),
                torrent.clone(),
                r.piece as u32,
                r.epoch,
            ));
        }
    }
}

/// Run a hash check behind the session's checking gate (`max_checking`),
/// marking the torrent queued while it waits. `None` when the torrent was
/// removed / errored meanwhile.
async fn checked<F>(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    check: F,
) -> Option<Result<Bitfield, storage::Error>>
where
    F: std::future::Future<Output = Result<Bitfield, storage::Error>>,
{
    if ctx.check_gate.available() == 0 {
        torrent.borrow_mut().check_queued = true;
    }
    let permit = ctx.check_gate.acquire().await;
    {
        let mut t = torrent.borrow_mut();
        t.check_queued = false;
        if t.error.is_some() {
            return None;
        }
    }
    let r = check.await;
    drop(permit);
    Some(r)
}

/// Start after the initial check (unless paused), the have-set already
/// applied. When the tasks are already running (metadata arrived on a
/// running magnet torrent) they are refreshed instead.
fn finish_check(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    have: Bitfield,
    carried: Option<(u64, u64)>,
) {
    let (id, start, running, kick) = {
        let mut t = torrent.borrow_mut();
        if let Some((d, u)) = carried {
            t.stats.downloaded = d;
            t.stats.uploaded = u;
        }
        t.checking = false;
        t.finished_emitted = t.is_complete();
        // Addresses backed off during the check may be dialled again.
        t.failed.clear();
        let running = t.tasks_running && !t.closing.is_set();
        (
            t.id,
            !t.paused && t.error.is_none() && !running,
            running,
            t.tracker_kick.clone(),
        )
    };
    ctx.emit(Event::Checked {
        id,
        pieces_have: have.count(),
    });
    if start {
        super::queue::activate(ctx, torrent);
    } else if running {
        // Peers connected during the metadata fetch learn our have-set and
        // get requests; trackers hear the real `left`.
        let peers: Vec<Rc<PeerHandle>> = torrent.borrow().peers.values().cloned().collect();
        let (n, plen) = {
            let t = torrent.borrow();
            (
                t.piece_count(),
                t.info.as_ref().map_or(0, |i| i.piece_length),
            )
        };
        for p in &peers {
            p.on_metadata(torrent, n, plen, &have);
        }
        kick.notify();
        on_new_candidates(ctx, torrent);
        super::webseed::start(ctx, torrent);
    }
}

/// `Session::force_recheck`: drop peers, re-hash everything on disk, rebuild
/// the have-set from what verifies.
pub async fn recheck(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>) {
    let storage = {
        let mut t = torrent.borrow_mut();
        if t.checking || t.error.is_some() {
            return;
        }
        t.checking = true;
        for p in t.peers.values() {
            p.close("rechecking");
        }
        let Some(storage) = t.storage.clone() else {
            t.checking = false;
            return;
        };
        storage
    };
    let Some(result) = checked(&ctx, &torrent, storage.check_all()).await else {
        return;
    };
    match result {
        Ok(have) => {
            let mut t = torrent.borrow_mut();
            t.resume_dirty = true;
            drop(t);
            finish_check_after_recheck(&ctx, &torrent, have);
        }
        Err(e) => {
            torrent.borrow_mut().checking = false;
            fail_torrent(&ctx, &torrent, format!("recheck failed: {e}"));
        }
    }
}

fn finish_check_after_recheck(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, have: Bitfield) {
    let tasks_running = {
        let t = torrent.borrow();
        !t.closing.is_set() && !t.paused
    };
    let (id, kick) = {
        let mut t = torrent.borrow_mut();
        // The disk is the truth again: verifies and writes started against
        // the old picture must not apply.
        t.new_epoch();
        if let Some(s) = &t.storage {
            s.set_have(have.clone());
        }
        // Blocks received into pieces the check did not find are wasted
        // bytes: they were downloaded and are being thrown away, so the
        // accounting says so (`downloaded - corrupt - redundant` stays the
        // torrent's size).
        let discarded = t.picker.set_have(&have);
        t.stats.redundant += discarded;
        t.checking = false;
        t.finished_emitted = t.is_complete();
        t.failed.clear();
        (t.id, t.tracker_kick.clone())
    };
    ctx.emit(Event::Checked {
        id,
        pieces_have: have.count(),
    });
    if tasks_running {
        // Tasks kept running through the check; just refresh.
        kick.notify();
        on_new_candidates(ctx, torrent);
    } else if !torrent.borrow().paused {
        super::queue::activate(ctx, torrent);
    }
}

/// Start the tracker and tick tasks (after add / resume).
fn start_tasks(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) {
    {
        let mut t = torrent.borrow_mut();
        t.closing = Flag::new();
        t.paused = false;
        t.tasks_running = true;
        t.announcer.start();
        let now = Instant::now();
        t.active_since = Some(now);
        t.sync_seeding_clock(now);
    }
    uring::spawn(super::tracker_task::run(ctx.clone(), torrent.clone()));
    ctx.schedule_tick(torrent);
    super::lsd::announce_now(ctx, torrent);
    super::webseed::start(ctx, torrent);
    if let Some(d) = ctx.dht() {
        let t = torrent.borrow();
        if !t.private {
            d.announce_soon(t.id);
        }
    }
}

/// `Session::resume`.
pub fn resume(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) {
    {
        let mut t = torrent.borrow_mut();
        if !t.paused || t.error.is_some() {
            return;
        }
        t.auto_paused = false;
        if t.checking || t.stopping {
            // `finish_check` (or the pause winding down) starts the tasks
            // once it completes.
            t.paused = false;
            return;
        }
    }
    start_tasks(ctx, torrent);
}

/// `Session::pause`: stop announcing (with `stopped`), drop peers, keep state.
pub async fn pause(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) {
    {
        let mut t = torrent.borrow_mut();
        if t.paused || t.stopping {
            return;
        }
        t.paused = true;
        t.stopping = true;
    }
    stop(ctx, torrent, false).await;
    let restart = {
        let mut t = torrent.borrow_mut();
        t.stopping = false;
        // Resumed while winding down: start again now that it is over.
        !t.paused && !t.checking && t.error.is_none()
    };
    if restart {
        start_tasks(ctx, torrent);
    }
}

/// Wind a torrent down: send `stopped` to every started tracker, close every
/// peer, save resume data. Used by pause, remove and shutdown.
pub async fn stop(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, _final: bool) {
    {
        let t = torrent.borrow();
        t.closing.set();
        t.tracker_kick.notify();
    }
    // An announce in flight (typically `started`) must land before we decide
    // which trackers get `stopped`, or a tracker would be left with a ghost.
    for _ in 0..100 {
        if torrent.borrow().announces_in_flight == 0 {
            break;
        }
        uring::sleep(Duration::from_millis(50)).await;
    }
    let (closing, jobs, peers) = {
        let mut t = torrent.borrow_mut();
        t.tasks_running = false;
        t.fold_times(Instant::now());
        let jobs = t.announcer.stop();
        let peers: Vec<Rc<PeerHandle>> = t.peers.values().cloned().collect();
        (t.closing.clone(), jobs, peers)
    };
    closing.set();
    for p in &peers {
        p.close("torrent stopped");
    }
    // `stopped` announces, concurrently, each bounded.
    let mut handles = Vec::new();
    for job in jobs {
        let ctx2 = ctx.clone();
        let t2 = torrent.clone();
        handles.push(uring::spawn(async move {
            let _ = uring::timeout(
                Duration::from_secs(10),
                super::tracker_task::announce_once(&ctx2, &t2, job),
            )
            .await;
        }));
    }
    for h in handles {
        h.await;
    }
    // Blocks accepted just before the peers went away may still be on
    // their way to the disk: let them land, so the resume data describes
    // the files and a `remove_torrent_with_files` cannot be overtaken by a
    // write that recreates one.
    // Blocks accepted just before the peers went away may still be on
    // their way to the disk: let them land, so the resume data describes
    // the files and a `remove_torrent_with_files` cannot be overtaken by a
    // write that recreates one.
    for _ in 0..100 {
        if torrent.borrow().writes_in_flight == 0 {
            break;
        }
        uring::sleep(Duration::from_millis(20)).await;
    }
    if let Err(e) = save_resume(ctx, torrent).await {
        tracing::warn!("saving resume data failed: {e}");
    }
    // Give peer tasks a moment to observe the flag and release their sockets.
    for _ in 0..50 {
        if torrent.borrow().peers.is_empty() {
            break;
        }
        uring::sleep(Duration::from_millis(20)).await;
    }
}

/// Fire the `stopped` announces a removed tracker is owed (bounded, in the
/// background).
pub fn announce_stopped(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, jobs: Vec<AnnounceJob>) {
    for job in jobs {
        let ctx2 = ctx.clone();
        let t2 = torrent.clone();
        uring::spawn(async move {
            let _ = uring::timeout(
                Duration::from_secs(10),
                super::tracker_task::announce_once(&ctx2, &t2, job),
            )
            .await;
        });
    }
}

/// Delete a removed torrent's content (files, parts file, emptied
/// directories) and its resume file.
pub async fn delete_files(torrent: &Rc<RefCell<Torrent>>) -> Result<(), Error> {
    let (storage, resume_path) = {
        let t = torrent.borrow();
        (t.storage.clone(), t.resume_path.clone())
    };
    if let Some(s) = storage {
        s.delete_files().await?;
    }
    if let Some(p) = resume_path
        && let Err(e) = std::fs::remove_file(&p)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(format!("removing {}: {e}", p.display())));
    }
    Ok(())
}

/// Persist resume data: fsync content first so the have-set never claims data
/// the disk does not hold.
pub async fn save_resume(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) -> Result<(), Error> {
    let Some(path) = torrent.borrow().resume_path.clone() else {
        return Ok(());
    };
    let Some(data) = build_resume(ctx, torrent).await? else {
        return Ok(());
    };
    data.save(&path)?;
    Ok(())
}

/// `Session::resume_data`: the resume blob, bytes.
pub async fn resume_data(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) -> Result<Vec<u8>, Error> {
    match build_resume(ctx, torrent).await? {
        Some(d) => Ok(d.encode()),
        None => Err(Error::Busy("metadata not known yet")),
    }
}

/// Assemble the resume data after syncing the content files, so everything
/// it claims (verified pieces, written ranges of unfinished pieces) is on
/// disk (AGENTS.md 5.4). `None` while the metadata is unknown. Clears the
/// dirty flag.
async fn build_resume(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
) -> Result<Option<ResumeData>, Error> {
    let (storage, info) = {
        let t = torrent.borrow();
        let (Some(storage), Some(info)) = (t.storage.clone(), t.info.clone()) else {
            // Nothing verified yet (metadata pending): nothing to persist.
            return Ok(None);
        };
        (storage, info)
    };
    // Bounded concurrency: each save fsyncs the torrent's files.
    let _permit = ctx.resume_gate.acquire().await;
    let started = Instant::now();
    storage.sync_all().await?;
    tracing::debug!(
        torrent = torrent.borrow().id.0,
        sync_ms = started.elapsed().as_millis() as u64,
        "resume save: content synced"
    );
    let unfinished: Vec<(u32, Vec<(u32, u32)>)> = storage
        .unfinished()
        .await?
        .into_iter()
        .filter_map(|(p, r)| u32::try_from(p).ok().map(|p| (p, r)))
        .collect();
    let have = storage.have();
    let mut t = torrent.borrow_mut();
    let times = t.times(Instant::now());
    // Peers worth trying first next time: connected ones by their listen
    // address (incoming peers only when their LTEP handshake named a
    // port), then the freshest candidates.
    let mut peers: Vec<SocketAddr> = t
        .peers
        .values()
        .filter_map(|p| {
            if p.incoming {
                p.listen_port
                    .get()
                    .map(|port| SocketAddr::new(p.addr.ip(), port))
            } else {
                Some(p.addr)
            }
        })
        .collect();
    for c in t.candidates.iter().rev() {
        if peers.len() >= storage::MAX_RESUME_PEERS {
            break;
        }
        if !peers.contains(c) {
            peers.push(*c);
        }
    }
    peers.truncate(storage::MAX_RESUME_PEERS);
    let mut tiers: Vec<Vec<String>> = Vec::new();
    for tr in t.announcer.snapshot() {
        while tiers.len() <= tr.tier {
            tiers.push(Vec::new());
        }
        tiers[tr.tier].push(tr.url);
    }
    tiers.retain(|tier| !tier.is_empty());
    let data = ResumeData {
        format_version: storage::FORMAT_VERSION,
        info_hash: info.info_hash,
        piece_length: info.piece_length,
        total_length: info.total_length,
        have,
        uploaded: t.stats.uploaded,
        downloaded: t.stats.downloaded,
        file_priorities: storage.file_priorities(),
        active_time: times.0.as_secs(),
        seeding_time: times.1.as_secs(),
        auto_managed: t.auto_managed,
        queue_position: Some(t.queue_position),
        sequential: t.sequential,
        upload_limit: t.up_limit.rate(),
        download_limit: t.down_limit.rate(),
        max_peers: t.max_peers.map(|m| m.min(u32::MAX as usize) as u32),
        max_uploads: t.max_uploads.map(|m| m.min(u32::MAX as usize) as u32),
        mapped_files: {
            let mapped = storage.mapped_files();
            if mapped.iter().all(Option::is_none) {
                Vec::new()
            } else {
                mapped
                    .iter()
                    .map(|m| {
                        m.as_ref()
                            .map_or(String::new(), |p| p.components().join("/"))
                    })
                    .collect()
            }
        },
        trackers: tiers,
        web_seeds: t.web_seeds.clone(),
        added_time: t.added_time,
        completed_time: t.completed_time,
        peers,
        unfinished,
    };
    t.resume_dirty = false;
    t.last_resume_save = Instant::now();
    Ok(Some(data))
}

/// One torrent's once-a-second housekeeping, driven by the session ticker's
/// due-queue (one timer for the whole session instead of one per torrent):
/// rates, per-peer timeouts and keep-alives, PEX and metadata steps, dialling,
/// and a periodic resume save (bounded by the resume gate). Returns whether
/// the torrent wants to be ticked again.
pub fn tick_once(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, now: Instant) -> bool {
    let save = {
        let mut t = torrent.borrow_mut();
        if !t.is_active() || !t.tasks_running || t.closing.is_set() {
            t.tick_scheduled = false;
            return false;
        }
        // Rates: exponential moving average over 1 s samples.
        let d = t.stats.downloaded - t.stats.last_downloaded;
        let u = t.stats.uploaded - t.stats.last_uploaded;
        t.stats.last_downloaded = t.stats.downloaded;
        t.stats.last_uploaded = t.stats.uploaded;
        t.stats.download_rate = (t.stats.download_rate * 3 + d) / 4;
        t.stats.upload_rate = (t.stats.upload_rate * 3 + u) / 4;
        // The queue's inactivity clock (`ActiveLimits::count_slow`).
        if t.stats.download_rate < super::queue::INACTIVE_RATE
            && t.stats.upload_rate < super::queue::INACTIVE_RATE
        {
            t.slow_since.get_or_insert(now);
        } else {
            t.slow_since = None;
        }

        // Per-peer housekeeping.
        let peers: Vec<Rc<PeerHandle>> = t.peers.values().cloned().collect();
        for p in &peers {
            p.tick(&mut t, ctx, now);
        }
        super::pex::tick(ctx, &mut t, now);
        super::metadata::tick(&mut t, now);
        t.prune_failed(now);
        connect_more(ctx, torrent, &mut t, now);
        let save = t.resume_dirty
            && !t.resume_saving
            && now.duration_since(t.last_resume_save) > RESUME_SAVE_EVERY;
        if save {
            t.resume_saving = true;
        }
        save
    };
    if save {
        let ctx = ctx.clone();
        let torrent = torrent.clone();
        uring::spawn(async move {
            if let Err(e) = save_resume(&ctx, &torrent).await {
                tracing::warn!("periodic resume save failed: {e}");
            }
            torrent.borrow_mut().resume_saving = false;
        });
    }
    true
}

/// Open connections up to the limits. Candidates are ranked by BEP 40
/// canonical priority (libtorrent `peer_list` order, highest first) and
/// rotate through the queue so an address that is busy, backed off or
/// connected now is retried later.
fn connect_more(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, t: &mut Torrent, now: Instant) {
    if !t.is_running() {
        return;
    }
    let max_peers = t.max_peers(ctx);
    let max_half_open = ctx.cfg.max_half_open;
    if t.candidates_dirty {
        t.candidates_dirty = false;
        // Rank against our external address when known (libtorrent
        // `torrent_peer::rank` uses `external_address(peer)`), else the
        // listen address.
        let ours_v4 = SocketAddr::new(
            ctx.external_address(false).unwrap_or(IpAddr::V4(
                ctx.listen_v4().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
            )),
            ctx.listen_port(),
        );
        let ours_v6 = SocketAddr::new(
            ctx.external_address(true).unwrap_or(IpAddr::V6(
                ctx.listen_v6().unwrap_or(std::net::Ipv6Addr::UNSPECIFIED),
            )),
            ctx.listen_port(),
        );
        let mut v: Vec<SocketAddr> = t.candidates.drain(..).collect();
        v.sort_by_key(|a| {
            let ours = if a.is_ipv4() { ours_v4 } else { ours_v6 };
            std::cmp::Reverse(wire::peer_priority(ours, *a).unwrap_or(0))
        });
        t.candidates.extend(v);
    }
    for _ in 0..t.candidates.len() {
        if t.peers.len() + t.half_open >= max_peers
            || t.half_open >= max_half_open
            || ctx.connection_count() >= ctx.max_connections()
        {
            break;
        }
        let Some(addr) = t.candidates.pop_front() else {
            break;
        };
        t.candidates.push_back(addr);
        if t.banned.contains(&addr.ip())
            || ctx.is_banned_ip(addr.ip())
            || !ctx.families().allows(addr.ip()) // a family switched off since
            || t.has_peer_ip(addr.ip()) // one connection per IP, as the oracle
            || t.connecting.contains(&addr)
            || t.failed
                .get(&addr)
                .is_some_and(|f| now.duration_since(*f) < RECONNECT_BACKOFF)
        {
            continue;
        }
        t.half_open += 1;
        ctx.connection_opened();
        t.connecting.insert(addr);
        uring::spawn(super::peer::run_outgoing(
            ctx.clone(),
            torrent.clone(),
            addr,
        ));
    }
}

/// Called when a tracker reply brought peers: try to connect right away.
pub fn on_new_candidates(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) {
    let mut t = torrent.borrow_mut();
    if t.is_running() {
        connect_more(ctx, torrent, &mut t, Instant::now());
    }
}

/// The pending disk write of one block: queued on the disk thread already,
/// awaited by the caller when convenient (`PendingWrite::finish`).
pub struct PendingWrite {
    fut: std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), storage::Error>>>>,
}

impl PendingWrite {
    /// Wait for the write; a failure puts the torrent into the error state.
    pub async fn finish(self, ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) {
        let r = self.fut.await;
        torrent.borrow_mut().writes_in_flight -= 1;
        if let Err(e) = r {
            fail_torrent(ctx, torrent, format!("disk write failed: {e}"));
        }
    }
}

/// A block we requested arrived from a peer: account, hand to the picker,
/// queue the write, and start a verify when the piece is complete. Returns
/// the pending write for the caller to await (peers batch the writes of one
/// receive buffer, then wait for all of them: one disk round trip per buffer
/// instead of one per block, with the buffer as the backpressure unit).
pub async fn on_block(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    peer: &Rc<PeerHandle>,
    request: Request,
    data: wire::Block,
) -> Option<PendingWrite> {
    peer.downloaded
        .set(peer.downloaded.get() + u64::from(request.length));
    let w = on_block_from(ctx, torrent, peer.key, Some(peer.addr.ip()), request, data).await;
    peer.fill_requests(torrent, ctx);
    w
}

/// [`on_block`] for any supplier (`key`): a peer with its address for blame,
/// or a web seed (`None`; blamed by key, see `verify_piece`).
pub async fn on_block_from(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    key: u32,
    ip: Option<IpAddr>,
    request: Request,
    data: wire::Block,
) -> Option<PendingWrite> {
    let block = picker::Block {
        piece: request.index,
        offset: request.begin,
        length: request.length,
    };
    let (storage, outcome) = {
        let mut t = torrent.borrow_mut();
        t.stats.downloaded += u64::from(request.length);
        if t.checking {
            // A recheck is replacing the picture. Its disk read runs behind
            // the writes queued before it, not this one: accepted now, the
            // block would land after the check looked, the check would void
            // its piece as wasted bytes, and a later check could find the
            // piece whole on disk — bytes counted both wasted and present.
            // The block came off the wire and goes nowhere.
            t.stats.redundant += u64::from(request.length);
            return None;
        }
        let outcome = t.picker.block_received(key, &block);
        if let Received::Accepted { cancel, .. } = &outcome {
            for k in cancel {
                if let Some(other) = t.peers.get(k) {
                    other.conn.borrow_mut().cancel(request);
                    other.out.notify();
                }
            }
            t.note_supplier(
                request.index,
                key,
                ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            );
        } else {
            t.stats.redundant += u64::from(request.length);
        }
        (t.storage.clone(), outcome)
    };
    let Received::Accepted { piece_complete, .. } = outcome else {
        return None;
    };
    let storage = storage?;
    wait_not_moving(torrent).await;
    // Queued on the disk thread now; a verify submitted after it is ordered
    // behind it (the disk thread's barrier), whenever the write is awaited.
    torrent.borrow_mut().writes_in_flight += 1;
    // The block stays in the buffer it arrived in (a whole peer-wire frame
    // when it fit in one receive chunk): the disk thread writes and hashes
    // the range in place.
    let (buf, start) = data.into_parts();
    let write = storage.write_block_from(request.index as usize, request.begin, buf, start);
    if piece_complete {
        let epoch = {
            let mut t = torrent.borrow_mut();
            t.verifying.insert(request.index).then_some(t.epoch)
        };
        if let Some(epoch) = epoch {
            uring::spawn(verify_piece(
                ctx.clone(),
                torrent.clone(),
                request.index,
                epoch,
            ));
        }
    }
    Some(PendingWrite {
        fut: Box::pin(write),
    })
}

/// Hash a completed piece and act on the result.
async fn verify_piece(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>, piece: u32, epoch: u64) {
    let Some(storage) = torrent.borrow().storage.clone() else {
        return;
    };
    wait_not_moving(&torrent).await;
    let result = storage.verify_piece(piece as usize).await;
    let now = Instant::now();
    let finished = {
        let mut t = torrent.borrow_mut();
        t.verifying.remove(&piece);
        if t.epoch != epoch {
            // A recheck (or new metadata) replaced the picture while this
            // verify ran: its verdict describes a world that is gone.
            tracing::debug!(torrent = t.id.0, piece, "stale verify dropped");
            return;
        }
        let id = t.id;
        match result {
            Ok(true) => {
                t.picker.piece_verified(piece as usize);
                for (_, ip) in t.suppliers.remove(&piece).unwrap_or_default() {
                    let _ = t.adjust_trust(ip, 1);
                }
                t.resume_dirty = true;
                t.broadcast_have(piece);
                t.refresh_interest_after(piece);
                ctx.emit(Event::PieceFinished { id, piece });
                maybe_finished(&ctx, &mut t, now)
            }
            Ok(false) => {
                let size = t.picker.piece_size(piece as usize);
                t.stats.corrupt += u64::from(size);
                t.picker.piece_failed(piece as usize);
                let blamed = t.suppliers.remove(&piece).unwrap_or_default();
                tracing::warn!(torrent = id.0, piece, ?blamed, "hash check failed");
                // A web seed that supplied a failed piece is dropped outright.
                for (k, ip) in blamed.iter().filter(|(_, ip)| ip.is_unspecified()) {
                    let urls: Vec<String> = t.webseed.running_urls_for(*k).into_iter().collect();
                    for u in urls {
                        t.webseed.abandon(&u);
                    }
                    let _ = ip;
                }
                // Suppliers already banned are the likely culprits; the
                // others are not charged for what those sent.
                let banned_in = blamed.iter().any(|(_, ip)| t.banned.contains(ip));
                let mut tainted: Vec<u32> = Vec::new();
                if blamed.len() == 1 {
                    // One supplier: it is the culprit.
                    tainted.extend(t.adjust_trust(blamed[0].1, -SOLE_FAIL_COST));
                } else if banned_in {
                    // A banned peer was in it: nobody else is charged.
                } else if !blamed.is_empty() {
                    // Several suppliers: everyone loses some trust, and the
                    // piece is re-downloaded from the least trusted one that
                    // is still connected, so the next verdict is unambiguous.
                    for (_, ip) in &blamed {
                        tainted.extend(t.adjust_trust(*ip, -SHARED_FAIL_COST));
                    }
                    let suspect = blamed
                        .iter()
                        .filter(|(k, ip)| t.peers.contains_key(k) && !t.banned.contains(ip))
                        .min_by_key(|(_, ip)| t.trust.get(ip).copied().unwrap_or(0))
                        .map(|(k, _)| *k);
                    if let Some(k) = suspect {
                        t.picker.set_exclusive(piece as usize, k);
                    }
                }
                ctx.emit(Event::HashFailed { id, piece });
                // Pieces a just-banned peer had blocks in start over on
                // disk too.
                if !tainted.is_empty()
                    && let Some(s) = t.storage.clone()
                {
                    for p in tainted {
                        let s = s.clone();
                        uring::spawn(async move {
                            let _ = s.discard_piece(p as usize).await;
                        });
                    }
                }
                // Re-request the piece from whoever is available.
                for p in t.peers.values().cloned().collect::<Vec<_>>() {
                    p.fill_requests_locked(&mut t, &ctx);
                }
                false
            }
            Err(e) => {
                drop(t);
                fail_torrent(&ctx, &torrent, format!("disk read failed: {e}"));
                false
            }
        }
    };
    if finished && let Err(e) = save_resume(&ctx, &torrent).await {
        tracing::warn!("resume save after completion failed: {e}");
    }
}

/// Every wanted piece is verified: emit `TorrentFinished` once per
/// completion, tell peers we are upload-only (BEP 21), and announce
/// `completed` when we are a full seed (libtorrent only does so for a seed,
/// not for a finished selective download). Returns whether it fired.
fn maybe_finished(ctx: &Ctx, t: &mut Torrent, now: Instant) -> bool {
    if !t.is_complete() || t.finished_emitted {
        return false;
    }
    t.finished_emitted = true;
    t.sync_seeding_clock(now);
    if t.completed_time.is_none() {
        t.completed_time = Some(unix_now());
        t.resume_dirty = true;
    }
    if t.picker.is_seed() {
        t.announcer.completed(now);
        t.tracker_kick.notify();
        // The oracle re-announces to the DHT as a seed right after finishing.
        if let Some(d) = ctx.dht()
            && !t.private
        {
            d.announce_soon(t.id);
        }
    }
    tracing::info!(
        torrent = t.id.0,
        seed = t.picker.is_seed(),
        "download finished"
    );
    ctx.emit(Event::TorrentFinished { id: t.id });
    for p in t.peers.values() {
        p.send_upload_only(true);
    }
    super::webseed::stop_all(t);
    true
}

/// `Session::set_file_priorities`.
pub async fn set_file_priorities(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    prios: Vec<u8>,
) -> Result<(), Error> {
    if prios.iter().any(|p| *p > storage::MAX_PRIORITY) {
        return Err(Error::InvalidArgument(format!(
            "file priorities must be 0..={}",
            storage::MAX_PRIORITY
        )));
    }
    let (storage, expanded) = {
        let mut t = torrent.borrow_mut();
        let (Some(info), Some(storage)) = (t.info.clone(), t.storage.clone()) else {
            // No metadata yet: remember for when it arrives.
            t.pending_priorities = Some(prios);
            return Ok(());
        };
        let expanded = expand_priorities(&info, &prios).ok_or_else(|| {
            Error::InvalidArgument(format!(
                "expected {} file priorities, got {}",
                Torrent::content_indices(&info).len(),
                prios.len()
            ))
        })?;
        if t.moving {
            return Err(Error::Busy("storage is being moved"));
        }
        (storage, expanded)
    };
    storage.set_file_priorities(&expanded).await?;
    let mut t = torrent.borrow_mut();
    for (i, p) in storage.piece_priorities().into_iter().enumerate() {
        t.picker.set_priority(i, p);
    }
    t.resume_dirty = true;
    let now = Instant::now();
    if !t.is_complete() {
        // More to download: a later completion fires `TorrentFinished` again,
        // peers hear we are no longer upload-only, and seeds we parted from
        // as "both seeds" may be dialled again right away.
        t.finished_emitted = false;
        t.sync_seeding_clock(Instant::now());
        for p in t.peers.values() {
            p.send_upload_only(false);
        }
        t.failed.clear();
    }
    t.refresh_interest();
    let peers: Vec<Rc<PeerHandle>> = t.peers.values().cloned().collect();
    for p in &peers {
        p.fill_requests_locked(&mut t, ctx);
    }
    maybe_finished(ctx, &mut t, now);
    let running = t.is_running();
    if running {
        connect_more(ctx, torrent, &mut t, now);
    }
    drop(t);
    if running {
        super::webseed::start(ctx, torrent);
    }
    Ok(())
}

/// `Session::move_storage`: hold disk I/O, wait for in-flight writes and
/// hash checks to drain, move the files, resume.
pub async fn move_storage(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    path: PathBuf,
) -> Result<(), Error> {
    let storage = {
        let mut t = torrent.borrow_mut();
        let Some(storage) = t.storage.clone() else {
            // No files yet: just change where they will go.
            t.save_path = path.clone();
            ctx.emit(Event::StorageMoved { id: t.id, path });
            return Ok(());
        };
        if t.moving {
            return Err(Error::Busy("storage is already being moved"));
        }
        if t.checking {
            return Err(Error::Busy("torrent is checking"));
        }
        t.moving = true;
        storage
    };
    // Drain: no write may be mid-flight and no piece mid-hash.
    for _ in 0..600 {
        let quiet = {
            let t = torrent.borrow();
            t.writes_in_flight == 0 && t.verifying.is_empty()
        };
        if quiet {
            break;
        }
        uring::sleep(Duration::from_millis(50)).await;
    }
    let result = storage.move_to(path.clone()).await;
    let (id, gate) = {
        let mut t = torrent.borrow_mut();
        t.moving = false;
        if result.is_ok() {
            t.save_path = path.clone();
            t.resume_dirty = true;
        }
        (t.id, t.move_gate.clone())
    };
    gate.notify();
    match result {
        Ok(()) => {
            tracing::info!(torrent = id.0, path = %path.display(), "storage moved");
            ctx.emit(Event::StorageMoved { id, path });
            Ok(())
        }
        Err(e) => Err(Error::Io(format!("move storage: {e}"))),
    }
}

/// `Session::rename_file`: `index` counts content files (the public
/// numbering); the storage move happens under the same quiescing as a
/// storage move, as a disk-ring barrier.
pub async fn rename_file(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    index: usize,
    path: &str,
) -> Result<(), Error> {
    let components: Vec<&[u8]> = path
        .split('/')
        .filter(|c| !c.is_empty())
        .map(str::as_bytes)
        .collect();
    let safe = metainfo::SafePath::from_components(&components, index)
        .map_err(|e| Error::InvalidArgument(format!("path: {e}")))?;
    let (storage, file_index) = {
        let mut t = torrent.borrow_mut();
        let (Some(storage), Some(info)) = (t.storage.clone(), t.info.clone()) else {
            return Err(Error::Busy("metadata not known yet"));
        };
        let file_index = *Torrent::content_indices(&info)
            .get(index)
            .ok_or_else(|| Error::InvalidArgument(format!("no file {index}")))?;
        if t.moving {
            return Err(Error::Busy("storage is being moved"));
        }
        if t.checking {
            return Err(Error::Busy("torrent is checking"));
        }
        t.moving = true;
        (storage, file_index)
    };
    for _ in 0..600 {
        let quiet = {
            let t = torrent.borrow();
            t.writes_in_flight == 0 && t.verifying.is_empty()
        };
        if quiet {
            break;
        }
        uring::sleep(Duration::from_millis(50)).await;
    }
    let result = storage.rename_file(file_index, safe).await;
    let gate = {
        let mut t = torrent.borrow_mut();
        t.moving = false;
        if result.is_ok() {
            t.resume_dirty = true;
        }
        t.move_gate.clone()
    };
    gate.notify();
    let _ = ctx;
    result.map_err(|e| Error::Io(format!("rename file: {e}")))
}

/// Wait while a storage move is in progress (disk I/O callers).
pub async fn wait_not_moving(torrent: &Rc<RefCell<Torrent>>) {
    loop {
        let gate = {
            let t = torrent.borrow();
            if !t.moving {
                return;
            }
            t.move_gate.clone()
        };
        super::local::select2(gate.wait(), uring::sleep(Duration::from_millis(100))).await;
    }
}

/// Put the torrent into the error state and stop its activity.
pub fn fail_torrent(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, error: String) {
    let id = {
        let mut t = torrent.borrow_mut();
        if t.error.is_some() {
            return;
        }
        tracing::error!(torrent = t.id.0, "{error}");
        t.error = Some(error.clone());
        t.id
    };
    ctx.emit(Event::TorrentError { id, error });
    let ctx2 = ctx.clone();
    let t2 = torrent.clone();
    uring::spawn(async move {
        stop(&ctx2, &t2, false).await;
    });
}

/// Most requests in flight towards one peer (4 MiB of blocks).
pub const MAX_PIPELINE: usize = 256;

/// Pipeline depth for a peer: ~3 seconds of its current rate in 16 KiB
/// blocks, within sane bounds (libtorrent-style, L3). The peer's own
/// slow-start (`desired_queue`) raises this while it keeps up.
pub fn pipeline_depth(rate_bytes_per_sec: u64) -> usize {
    let by_rate = (rate_bytes_per_sec * 3 / u64::from(picker::BLOCK_SIZE)) as usize;
    by_rate.clamp(8, MAX_PIPELINE)
}

/// Pick with the engine's RNG.
pub fn pick_blocks(
    ctx: &Ctx,
    picker: &mut Picker,
    peer: u32,
    has: &dyn Fn(usize) -> bool,
    want: usize,
    preferred: &[usize],
) -> Vec<picker::Block> {
    let mut rng = RngRef(&ctx.rng);
    if preferred.is_empty() {
        picker.pick(peer, has, want, &mut rng)
    } else {
        picker.pick_preferring(peer, has, want, preferred, &mut rng)
    }
}

/// Pick contiguous blocks (web seeds).
pub fn pick_contiguous(
    ctx: &Ctx,
    picker: &mut Picker,
    peer: u32,
    want: usize,
) -> Vec<picker::Block> {
    let mut rng = RngRef(&ctx.rng);
    picker.pick_contiguous(peer, &|_| true, want, &mut rng)
}

/// `host:port`, `ipv4:port` or `[ipv6]:port` (BEP 9 `x.pe`).
fn split_host_port(s: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = s.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_split_handles_both_literals_and_names() {
        assert_eq!(
            split_host_port("[fd77::1]:6881"),
            Some(("fd77::1".to_string(), 6881))
        );
        assert_eq!(
            split_host_port("10.1.2.3:51413"),
            Some(("10.1.2.3".to_string(), 51413))
        );
        assert_eq!(
            split_host_port("seed.example:1"),
            Some(("seed.example".to_string(), 1))
        );
        // A bare IPv6 literal is ambiguous without brackets; no port at all;
        // a port out of range.
        assert_eq!(split_host_port("fd77::1:6881"), None);
        assert_eq!(split_host_port("seed.example"), None);
        assert_eq!(split_host_port("[fd77::1]:70000"), None);
        assert_eq!(split_host_port(":6881"), None);
    }

    #[test]
    fn v4_mapped_addresses_become_ipv4() {
        let mapped: SocketAddr = "[::ffff:10.1.2.3]:6881".parse().unwrap();
        assert_eq!(
            canonical_addr(mapped),
            "10.1.2.3:6881".parse::<SocketAddr>().unwrap()
        );
        for a in ["[fd77::1]:6881", "[::1]:1", "10.0.0.1:2"] {
            let a: SocketAddr = a.parse().unwrap();
            assert_eq!(canonical_addr(a), a);
        }
        // `::ffff:0:0/96` only: the deprecated v4-compatible form is left
        // alone (it names nothing routable and is dropped later anyway).
        let compat: SocketAddr = "[::10.1.2.3]:6881".parse().unwrap();
        assert_eq!(canonical_addr(compat), compat);
    }
}
