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
use tracker::Announcer;
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
/// Trust points: a peer is banned when its score drops to this. A failed
/// piece it supplied alone costs `SOLE_FAIL_COST`; a failed piece shared with
/// others costs 1; a verified piece earns 1 (capped at `TRUST_CAP`).
const BAN_AT: i32 = -3;
const SOLE_FAIL_COST: i32 = 3;
const TRUST_CAP: i32 = 8;
/// Periodic resume save cadence.
const RESUME_SAVE_EVERY: Duration = Duration::from_secs(60);
/// Do not reconnect to an address that failed for this long.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(60);

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
    pub webseed: super::webseed::State,
    pub save_path: PathBuf,
    sequential: bool,
    /// Requested file priorities (content-file order) until the metadata
    /// exists; afterwards the live ones are in `storage`.
    pending_priorities: Option<Vec<u8>>,
    /// `move_storage` in progress: block writes/reads wait on `move_gate`.
    pub moving: bool,
    pub move_gate: Rc<Notify>,
    /// Disk writes in flight (drained before a move).
    pub writes_in_flight: usize,
    /// The tracker / tick tasks are running.
    pub tasks_running: bool,
    pub announcer: Announcer,
    pub announce_key: u32,
    /// The peer id used for this torrent's announces and handshakes (per
    /// torrent or the session's, per the profile).
    pub peer_id: [u8; 20],
    /// Stopped by the caller.
    pub paused: bool,
    /// A check (initial or forced) is running.
    pub checking: bool,
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
    known: HashSet<SocketAddr>,
    sources: HashMap<SocketAddr, PeerSource>,
    failed: HashMap<SocketAddr, Instant>,
    /// Addresses with a connect in progress.
    pub connecting: HashSet<SocketAddr>,
    /// Addresses whose next outgoing attempt uses MSE (Q3 toggle).
    pub mse_retry: HashSet<SocketAddr>,
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
    resume_dirty: bool,
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

    /// Whether the metadata is known.
    pub fn has_metadata(&self) -> bool {
        self.info.is_some()
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
            TorrentState::Checking
        } else if self.paused {
            TorrentState::Paused
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

    pub fn status(&self, now: Instant) -> TorrentStatus {
        let trackers = self
            .announcer
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
            .collect();
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
            files: self.file_statuses(),
            total_wanted: self.wanted().0,
            total_wanted_done: self.wanted().1,
            save_path: self.save_path.clone(),
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
                path: f.path.components().join("/"),
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
            if !usable_peer_addr(ctx, p) || self.banned.contains(&p.ip()) {
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

    /// A connect failed or a connection ended: back this address off.
    pub fn note_disconnect(&mut self, addr: SocketAddr, now: Instant) {
        self.failed.insert(addr, now);
    }

    /// Let the next tick dial `addr` again immediately (libtorrent's
    /// `fast_reconnect` after a plaintext attempt that needs MSE).
    pub fn allow_reconnect_now(&mut self, addr: SocketAddr) {
        self.failed.remove(&addr);
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
    fn adjust_trust(&mut self, ip: IpAddr, delta: i32) {
        if ip.is_unspecified() {
            return;
        }
        let t = self.trust.entry(ip).or_insert(0);
        *t = (*t + delta).min(TRUST_CAP);
        if *t <= BAN_AT {
            self.banned.insert(ip);
            for p in self.peers.values() {
                if p.addr.ip() == ip {
                    p.close("banned: repeated hash failures");
                }
            }
        }
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

    /// Re-evaluate interest in every peer after our have-set changed.
    fn refresh_interest(&self) {
        for p in self.peers.values() {
            p.update_interest(&self.picker);
        }
    }
}

/// Peer address filtering (AGENTS.md 5.5): drop unspecified, multicast,
/// link-local, port 0, and our own listen endpoint.
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
    if bad {
        return false;
    }
    let own = match ip {
        IpAddr::V4(v4) => ctx.cfg.listen_v4 == Some(v4) && !v4.is_unspecified(),
        IpAddr::V6(v6) => ctx.cfg.listen_v6 == Some(v6) && !v6.is_unspecified(),
    };
    !(own && a.port() == ctx.listen_port)
}

fn resume_file(dir: &std::path::Path, h: &InfoHash) -> PathBuf {
    dir.join(format!("{}.resume", bencode::hex(h)))
}

/// `Session::add_torrent`.
pub async fn add(ctx: Rc<Ctx>, id: TorrentId, params: AddTorrent) -> Result<TorrentId, Error> {
    let now = Instant::now();
    let (info_hash, name, tiers, web_seeds, parsed) = match &params.source {
        TorrentSource::Metainfo(bytes) => {
            let meta = Metainfo::parse(bytes).map_err(|e| Error::Metainfo(e.to_string()))?;
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
            (m.info_hash, name, m.tiers(), Vec::new(), None)
        }
    };
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
    let announcer = Announcer::new(tiers, ctx.families.endpoints().len());
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
        webseed: super::webseed::State::default(),
        save_path: params.save_path.clone(),
        sequential: params.sequential,
        pending_priorities: params.file_priorities.clone(),
        moving: false,
        move_gate: Notify::new(),
        writes_in_flight: 0,
        tasks_running: false,
        announcer,
        announce_key: ctx.new_announce_key(),
        peer_id: ctx.new_torrent_peer_id(),
        paused: params.paused,
        checking: parsed.is_some(),
        error: None,
        stats: Stats::default(),
        up_limit: Limiter::new(0, now),
        down_limit: Limiter::new(0, now),
        peers: HashMap::new(),
        candidates: VecDeque::new(),
        candidates_dirty: false,
        known: HashSet::new(),
        sources: HashMap::new(),
        failed: HashMap::new(),
        connecting: HashSet::new(),
        mse_retry: HashSet::new(),
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
    ctx.by_hash.borrow_mut().insert(info_hash, id);
    ctx.emit(Event::TorrentAdded { id });
    match parsed {
        Some((info, raw)) => {
            let resume = load_resume(&torrent);
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
            // fetch the metadata from.
            if !params.paused {
                start_tasks(&ctx, &torrent);
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
        .all(|(_, f)| std::fs::metadata(f.path.to_path(&t.save_path)).is_ok())
}

/// Load the resume file, if any (unreadable data is ignored with a warning).
fn load_resume(torrent: &Rc<RefCell<Torrent>>) -> Option<ResumeData> {
    let path = torrent.borrow().resume_path.clone()?;
    ResumeData::load(&path).unwrap_or_else(|e| {
        tracing::warn!("ignoring unreadable resume data {}: {e}", path.display());
        None
    })
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
    let requested = t.pending_priorities.take();
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
    let storage = Rc::new(ctx.disk.open(info.clone(), t.save_path.clone(), initial));
    let mut picker = Picker::new(info.piece_count(), info.piece_length, info.total_length);
    picker.set_sequential(t.sequential);
    for (i, p) in storage.piece_priorities().into_iter().enumerate() {
        picker.set_priority(i, p);
    }
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
    let storage = torrent.borrow().storage.clone();
    if let Some(s) = storage {
        s.create_files().await?;
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
    let resume = load_resume(torrent);
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
    let (n, have) = {
        let t = torrent.borrow();
        (t.piece_count(), Bitfield::new(t.piece_count()))
    };
    for p in peers {
        p.on_metadata(torrent, n, &have);
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
    let (storage, info, save_path) = {
        let t = torrent.borrow();
        let (Some(s), Some(i)) = (t.storage.clone(), t.info.clone()) else {
            return;
        };
        (s, i, t.save_path.clone())
    };
    let mut have = Bitfield::new(info.piece_count());
    let mut carried: Option<(u64, u64)> = None;
    match resume {
        Some(r) if r.matches(&info) && files_present => {
            have = r.have.clone();
            carried = Some((r.downloaded, r.uploaded));
        }
        _ => {
            let any_data = info
                .content_files()
                .any(|f| std::fs::metadata(f.path.to_path(&save_path)).is_ok_and(|m| m.len() > 0))
                || std::fs::metadata(storage.parts_path()).is_ok_and(|m| m.len() > 0);
            if any_data {
                match storage.check_all().await {
                    Ok(h) => have = h,
                    Err(e) => {
                        fail_torrent(&ctx, &torrent, format!("check failed: {e}"));
                        return;
                    }
                }
            }
        }
    }
    finish_check(&ctx, &torrent, have, carried);
}

/// Apply a check result and start (unless paused). When the tasks are already
/// running (metadata arrived on a running magnet torrent) they are refreshed
/// instead.
fn finish_check(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    have: Bitfield,
    carried: Option<(u64, u64)>,
) {
    let (id, start, running, kick) = {
        let mut t = torrent.borrow_mut();
        if let Some(s) = &t.storage {
            s.set_have(have.clone());
        }
        t.picker.set_have(&have);
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
        start_tasks(ctx, torrent);
    } else if running {
        // Peers connected during the metadata fetch learn our have-set and
        // get requests; trackers hear the real `left`.
        let peers: Vec<Rc<PeerHandle>> = torrent.borrow().peers.values().cloned().collect();
        let n = torrent.borrow().piece_count();
        for p in &peers {
            p.on_metadata(torrent, n, &have);
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
    match storage.check_all().await {
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
        if let Some(s) = &t.storage {
            s.set_have(have.clone());
        }
        t.picker.set_have(&have);
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
        start_tasks(ctx, torrent);
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
    }
    uring::spawn(super::tracker_task::run(ctx.clone(), torrent.clone()));
    uring::spawn(tick(ctx.clone(), torrent.clone()));
    super::lsd::announce_now(ctx, torrent);
    super::webseed::start(ctx, torrent);
}

/// `Session::resume`.
pub fn resume(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) {
    {
        let mut t = torrent.borrow_mut();
        if !t.paused || t.error.is_some() {
            return;
        }
        if t.checking {
            // `finish_check` starts the tasks once the check completes.
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
        if t.paused {
            return;
        }
        t.paused = true;
    }
    stop(ctx, torrent, false).await;
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
    if let Err(e) = save_resume(torrent).await {
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

/// Persist resume data: fsync content first so the have-set never claims data
/// the disk does not hold.
pub async fn save_resume(torrent: &Rc<RefCell<Torrent>>) -> Result<(), Error> {
    let (storage, path, have, downloaded, uploaded, info) = {
        let t = torrent.borrow();
        let Some(path) = t.resume_path.clone() else {
            return Ok(());
        };
        let (Some(storage), Some(info)) = (t.storage.clone(), t.info.clone()) else {
            // Nothing verified yet (metadata pending): nothing to persist.
            return Ok(());
        };
        let have = storage.have();
        (
            storage,
            path,
            have,
            t.stats.downloaded,
            t.stats.uploaded,
            info,
        )
    };
    storage.sync_all().await?;
    let data = ResumeData {
        format_version: storage::FORMAT_VERSION,
        info_hash: info.info_hash,
        piece_length: info.piece_length,
        total_length: info.total_length,
        have,
        uploaded,
        downloaded,
        file_priorities: storage.file_priorities(),
    };
    data.save(&path)?;
    let mut t = torrent.borrow_mut();
    t.resume_dirty = false;
    t.last_resume_save = Instant::now();
    Ok(())
}

/// The one-second tick.
async fn tick(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>) {
    let closing = torrent.borrow().closing.clone();
    loop {
        match super::local::select2(uring::sleep(Duration::from_secs(1)), closing.wait()).await {
            super::local::Either::Left(()) => {}
            super::local::Either::Right(()) => break,
        }
        let now = Instant::now();
        let save = {
            let mut t = torrent.borrow_mut();
            if !t.is_active() {
                break;
            }
            // Rates: exponential moving average over 1 s samples.
            let d = t.stats.downloaded - t.stats.last_downloaded;
            let u = t.stats.uploaded - t.stats.last_uploaded;
            t.stats.last_downloaded = t.stats.downloaded;
            t.stats.last_uploaded = t.stats.uploaded;
            t.stats.download_rate = (t.stats.download_rate * 3 + d) / 4;
            t.stats.upload_rate = (t.stats.upload_rate * 3 + u) / 4;

            // Per-peer housekeeping.
            let peers: Vec<Rc<PeerHandle>> = t.peers.values().cloned().collect();
            for p in &peers {
                p.tick(&mut t, &ctx, now);
            }
            super::pex::tick(&ctx, &mut t, now);
            super::metadata::tick(&mut t, now);
            connect_more(&ctx, &torrent, &mut t, now);
            t.resume_dirty && now.duration_since(t.last_resume_save) > RESUME_SAVE_EVERY
        };
        if save && let Err(e) = save_resume(&torrent).await {
            tracing::warn!("periodic resume save failed: {e}");
        }
    }
}

/// Open connections up to the limits. Candidates are ranked by BEP 40
/// canonical priority (libtorrent `peer_list` order, highest first) and
/// rotate through the queue so an address that is busy, backed off or
/// connected now is retried later.
fn connect_more(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, t: &mut Torrent, now: Instant) {
    if !t.is_running() {
        return;
    }
    let max_peers = ctx.cfg.max_peers;
    let max_half_open = ctx.cfg.max_half_open;
    if t.candidates_dirty {
        t.candidates_dirty = false;
        // Rank against our external address when known (libtorrent
        // `torrent_peer::rank` uses `external_address(peer)`), else the
        // listen address.
        let ours_v4 = SocketAddr::new(
            ctx.external_address(false).unwrap_or(IpAddr::V4(
                ctx.cfg.listen_v4.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
            )),
            ctx.listen_port,
        );
        let ours_v6 = SocketAddr::new(
            ctx.external_address(true).unwrap_or(IpAddr::V6(
                ctx.cfg.listen_v6.unwrap_or(std::net::Ipv6Addr::UNSPECIFIED),
            )),
            ctx.listen_port,
        );
        let mut v: Vec<SocketAddr> = t.candidates.drain(..).collect();
        v.sort_by_key(|a| {
            let ours = if a.is_ipv4() { ours_v4 } else { ours_v6 };
            std::cmp::Reverse(wire::peer_priority(ours, *a).unwrap_or(0))
        });
        t.candidates.extend(v);
    }
    // Session-wide limit: the other torrents' connections plus ours.
    let others = ctx.connection_count_except(Some(t.id));
    for _ in 0..t.candidates.len() {
        if t.peers.len() + t.half_open >= max_peers
            || t.half_open >= max_half_open
            || others + t.peers.len() + t.half_open >= ctx.cfg.max_connections
        {
            break;
        }
        let Some(addr) = t.candidates.pop_front() else {
            break;
        };
        t.candidates.push_back(addr);
        if t.banned.contains(&addr.ip())
            || t.has_peer_ip(addr.ip()) // one connection per IP, as the oracle
            || t.connecting.contains(&addr)
            || t.failed
                .get(&addr)
                .is_some_and(|f| now.duration_since(*f) < RECONNECT_BACKOFF)
        {
            continue;
        }
        t.half_open += 1;
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
    data: Vec<u8>,
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
    data: Vec<u8>,
) -> Option<PendingWrite> {
    let block = picker::Block {
        piece: request.index,
        offset: request.begin,
        length: request.length,
    };
    let (storage, outcome) = {
        let mut t = torrent.borrow_mut();
        t.stats.downloaded += u64::from(request.length);
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
    let write = storage.write_block(request.index as usize, request.begin, data);
    if piece_complete {
        let already = !torrent.borrow_mut().verifying.insert(request.index);
        if !already {
            uring::spawn(verify_piece(ctx.clone(), torrent.clone(), request.index));
        }
    }
    Some(PendingWrite {
        fut: Box::pin(write),
    })
}

/// Hash a completed piece and act on the result.
async fn verify_piece(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>, piece: u32) {
    let Some(storage) = torrent.borrow().storage.clone() else {
        return;
    };
    wait_not_moving(&torrent).await;
    let result = storage.verify_piece(piece as usize).await;
    let now = Instant::now();
    let finished = {
        let mut t = torrent.borrow_mut();
        t.verifying.remove(&piece);
        let id = t.id;
        match result {
            Ok(true) => {
                t.picker.piece_verified(piece as usize);
                for (_, ip) in t.suppliers.remove(&piece).unwrap_or_default() {
                    t.adjust_trust(ip, 1);
                }
                t.resume_dirty = true;
                t.broadcast_have(piece);
                t.refresh_interest();
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
                if blamed.len() == 1 {
                    // One supplier: it is the culprit.
                    t.adjust_trust(blamed[0].1, -SOLE_FAIL_COST);
                } else if !blamed.is_empty() {
                    // Several suppliers: everyone loses a little trust, and the
                    // piece is re-downloaded from the least trusted one that
                    // is still connected, so the next verdict is unambiguous.
                    for (_, ip) in &blamed {
                        t.adjust_trust(*ip, -1);
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
    if finished && let Err(e) = save_resume(&torrent).await {
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
    if t.picker.is_seed() {
        t.announcer.completed(now);
        t.tracker_kick.notify();
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

/// Pipeline depth for a peer: ~3 seconds of its current rate in 16 KiB
/// blocks, within sane bounds (libtorrent-style, L3).
pub fn pipeline_depth(rate_bytes_per_sec: u64) -> usize {
    let by_rate = (rate_bytes_per_sec * 3 / u64::from(picker::BLOCK_SIZE)) as usize;
    by_rate.clamp(8, 256)
}

/// Pick with the engine's RNG.
pub fn pick_blocks(
    ctx: &Ctx,
    picker: &mut Picker,
    peer: u32,
    has: &dyn Fn(usize) -> bool,
    want: usize,
) -> Vec<picker::Block> {
    let mut rng = RngRef(&ctx.rng);
    picker.pick(peer, has, want, &mut rng)
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
