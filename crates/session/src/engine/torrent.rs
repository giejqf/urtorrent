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
use std::time::{Duration, Instant};

use metainfo::{Bitfield, InfoHash, Torrent as Metainfo};
use picker::{Picker, Received};
use storage::{ResumeData, Storage};
use tracker::Announcer;
use wire::Request;

use super::Ctx;
use super::local::{Flag, Notify};
use super::peer::PeerHandle;
use super::rate::Limiter;
use super::rng::RngRef;
use crate::Error;
use crate::api::{
    AddTorrent, Event, PeerInfo, TorrentId, TorrentSource, TorrentState, TorrentStatus,
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
    pub info: Rc<metainfo::Info>,
    pub storage: Rc<Storage>,
    pub picker: Picker,
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
    known: HashSet<SocketAddr>,
    failed: HashMap<SocketAddr, Instant>,
    /// Addresses with a connect in progress.
    pub connecting: HashSet<SocketAddr>,
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
        self.info.info_hash
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// The lifecycle state as reported to callers.
    pub fn state(&self) -> TorrentState {
        if self.error.is_some() {
            TorrentState::Error
        } else if self.checking {
            TorrentState::Checking
        } else if self.paused {
            TorrentState::Paused
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

    /// Bytes still needed (from the verified have-set).
    pub fn left(&self) -> u64 {
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
        let seeds = self
            .peers
            .values()
            .filter(|p| p.is_seed(self.info.piece_count()))
            .count();
        TorrentStatus {
            id: self.id,
            info_hash: self.info.info_hash,
            name: self.info.name.clone(),
            state: self.state(),
            error: self.error.clone(),
            pieces_have: self.picker.have_count(),
            pieces_total: self.info.piece_count(),
            total_size: self.info.total_length,
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
            complete: self.picker.is_complete(),
        }
    }

    pub fn peer_infos(&self) -> Vec<PeerInfo> {
        let n = self.info.piece_count();
        let mut v: Vec<PeerInfo> = self.peers.values().map(|p| p.info(n)).collect();
        v.sort_by_key(|p| p.addr);
        v
    }

    pub fn force_reannounce(&mut self, now: Instant) {
        self.announcer.force_reannounce(now);
        self.tracker_kick.notify();
    }

    /// Add tracker-supplied peers, filtering what AGENTS.md 5.5 says to drop.
    pub fn add_candidates(&mut self, ctx: &Ctx, peers: &[SocketAddr]) -> usize {
        let mut added = 0;
        for &p in peers {
            if !usable_peer_addr(ctx, p) || self.banned.contains(&p.ip()) {
                continue;
            }
            if self.known.insert(p) {
                self.candidates.push_back(p);
                added += 1;
            }
        }
        added
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

    /// Record who supplied a block (for blame).
    pub fn note_supplier(&mut self, piece: u32, key: u32, ip: IpAddr) {
        let v = self.suppliers.entry(piece).or_default();
        if !v.iter().any(|(k, _)| *k == key) && v.len() < 64 {
            v.push((key, ip));
        }
    }

    /// Adjust a peer's trust; ban (and drop) it when it falls to `BAN_AT`.
    fn adjust_trust(&mut self, ip: IpAddr, delta: i32) {
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
        let complete = self.picker.is_complete();
        let n = self.info.piece_count();
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
    let (meta, metadata_size) = match &params.source {
        TorrentSource::Metainfo(bytes) => {
            let meta = Metainfo::parse(bytes).map_err(|e| Error::Metainfo(e.to_string()))?;
            let size = bencode::from_bytes(bytes)
                .ok()
                .and_then(|v| v.get_str("info").and_then(|i| i.raw()).map(|r| r.len()))
                .unwrap_or(0)
                .min(u32::MAX as usize) as u32;
            (meta, size)
        }
        TorrentSource::Magnet(_) => {
            return Err(Error::Unsupported(
                "magnet links need ut_metadata (BEP 9), which lands in M6",
            ));
        }
    };
    if meta.info.has_v2 && meta.info.piece_hashes.is_empty() {
        return Err(Error::Unsupported("v2-only torrents (BEP 52) are deferred"));
    }
    if ctx.by_hash.borrow().contains_key(&meta.info.info_hash) {
        return Err(Error::Duplicate);
    }
    let info = Rc::new(meta.info.clone());
    let storage = Rc::new(Storage::new(
        info.clone(),
        params.save_path.clone(),
        ctx.pool.clone(),
    ));
    // Before any file is created: does the resume data still describe what
    // is on disk?
    let files_present = info
        .content_files()
        .all(|f| std::fs::metadata(f.path.to_path(&params.save_path)).is_ok());
    storage.create_files()?;
    let resume_path = params
        .resume_dir
        .as_deref()
        .map(|d| resume_file(d, &info.info_hash));
    if let Some(dir) = &params.resume_dir {
        std::fs::create_dir_all(dir)?;
    }

    let mut picker = Picker::new(info.piece_count(), info.piece_length, info.total_length);
    picker.set_sequential(params.sequential);
    let now = Instant::now();
    let announcer = Announcer::new(meta.tiers());
    let torrent = Rc::new(RefCell::new(Torrent {
        id,
        info: info.clone(),
        storage,
        picker,
        announcer,
        announce_key: ctx.new_announce_key(),
        peer_id: ctx.new_torrent_peer_id(),
        paused: params.paused,
        checking: true,
        error: None,
        stats: Stats::default(),
        up_limit: Limiter::new(0, now),
        down_limit: Limiter::new(0, now),
        peers: HashMap::new(),
        candidates: VecDeque::new(),
        known: HashSet::new(),
        failed: HashMap::new(),
        connecting: HashSet::new(),
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
        metadata_size,
    }));
    ctx.torrents.borrow_mut().insert(id, torrent.clone());
    ctx.by_hash.borrow_mut().insert(info.info_hash, id);
    ctx.emit(Event::TorrentAdded { id });
    uring::spawn(initial_check(
        ctx.clone(),
        torrent.clone(),
        files_present,
        params.save_path,
    ));
    Ok(id)
}

/// Resume data or recheck, then start. A resume file only ever records pieces
/// that were verified and fsynced, so it is trusted when it matches the
/// torrent and every content file is still present; otherwise, if any content
/// exists on disk, it is rechecked (AGENTS.md 5.4: when unsure, recheck).
async fn initial_check(
    ctx: Rc<Ctx>,
    torrent: Rc<RefCell<Torrent>>,
    files_present: bool,
    save_path: PathBuf,
) {
    let (storage, info, resume_path) = {
        let t = torrent.borrow();
        (t.storage.clone(), t.info.clone(), t.resume_path.clone())
    };
    let resume = match &resume_path {
        Some(p) => ResumeData::load(p).unwrap_or_else(|e| {
            tracing::warn!("ignoring unreadable resume data {}: {e}", p.display());
            None
        }),
        None => None,
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
                .any(|f| std::fs::metadata(f.path.to_path(&save_path)).is_ok_and(|m| m.len() > 0));
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

/// Apply a check result and start (unless paused).
fn finish_check(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    have: Bitfield,
    carried: Option<(u64, u64)>,
) {
    let (id, start) = {
        let mut t = torrent.borrow_mut();
        t.storage.set_have(have.clone());
        t.picker.set_have(&have);
        if let Some((d, u)) = carried {
            t.stats.downloaded = d;
            t.stats.uploaded = u;
        }
        t.checking = false;
        t.finished_emitted = t.picker.is_complete();
        // Addresses backed off during the check may be dialled again.
        t.failed.clear();
        (t.id, !t.paused && t.error.is_none())
    };
    ctx.emit(Event::Checked {
        id,
        pieces_have: have.count(),
    });
    if start {
        start_tasks(ctx, torrent);
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
        t.storage.clone()
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
        t.storage.set_have(have.clone());
        t.picker.set_have(&have);
        t.checking = false;
        t.finished_emitted = t.picker.is_complete();
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
        t.announcer.start();
    }
    uring::spawn(super::tracker_task::run(ctx.clone(), torrent.clone()));
    uring::spawn(tick(ctx.clone(), torrent.clone()));
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
        (
            t.storage.clone(),
            path,
            t.storage.have(),
            t.stats.downloaded,
            t.stats.uploaded,
            t.info.clone(),
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
            connect_more(&ctx, &torrent, &mut t, now);
            t.resume_dirty && now.duration_since(t.last_resume_save) > RESUME_SAVE_EVERY
        };
        if save && let Err(e) = save_resume(&torrent).await {
            tracing::warn!("periodic resume save failed: {e}");
        }
    }
}

/// Open connections up to the limits. Candidates rotate through the queue so
/// an address that is busy, backed off or connected now is retried later.
fn connect_more(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, t: &mut Torrent, now: Instant) {
    if !t.is_running() {
        return;
    }
    let max_peers = ctx.cfg.max_peers;
    let max_half_open = ctx.cfg.max_half_open;
    for _ in 0..t.candidates.len() {
        if t.peers.len() + t.half_open >= max_peers || t.half_open >= max_half_open {
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

/// A block we requested arrived: account, hand to the picker, write, and
/// verify when the piece is complete.
pub async fn on_block(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    peer: &Rc<PeerHandle>,
    request: Request,
    data: Vec<u8>,
) {
    let block = picker::Block {
        piece: request.index,
        offset: request.begin,
        length: request.length,
    };
    let (storage, outcome) = {
        let mut t = torrent.borrow_mut();
        t.stats.downloaded += u64::from(request.length);
        peer.downloaded
            .set(peer.downloaded.get() + u64::from(request.length));
        let outcome = t.picker.block_received(peer.key, &block);
        if let Received::Accepted { cancel, .. } = &outcome {
            for k in cancel {
                if let Some(other) = t.peers.get(k) {
                    other.conn.borrow_mut().cancel(request);
                    other.out.notify();
                }
            }
            t.note_supplier(request.index, peer.key, peer.addr.ip());
        } else {
            t.stats.redundant += u64::from(request.length);
        }
        (t.storage.clone(), outcome)
    };
    let Received::Accepted { piece_complete, .. } = outcome else {
        return;
    };
    let write = storage
        .write_block(
            request.index as usize,
            request.begin,
            uring::Buffer::from_vec(data),
        )
        .await;
    if let Err(e) = write {
        fail_torrent(ctx, torrent, format!("disk write failed: {e}"));
        return;
    }
    if piece_complete {
        let already = !torrent.borrow_mut().verifying.insert(request.index);
        if !already {
            uring::spawn(verify_piece(ctx.clone(), torrent.clone(), request.index));
        }
    }
    peer.fill_requests(torrent, ctx);
}

/// Hash a completed piece and act on the result.
async fn verify_piece(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>, piece: u32) {
    let storage = torrent.borrow().storage.clone();
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
                if t.picker.is_complete() && !t.finished_emitted {
                    t.finished_emitted = true;
                    t.announcer.completed(now);
                    t.tracker_kick.notify();
                    tracing::info!(torrent = id.0, "download complete");
                    ctx.emit(Event::TorrentFinished { id });
                    true
                } else {
                    false
                }
            }
            Ok(false) => {
                let size = t.picker.piece_size(piece as usize);
                t.stats.corrupt += u64::from(size);
                t.picker.piece_failed(piece as usize);
                let blamed = t.suppliers.remove(&piece).unwrap_or_default();
                tracing::warn!(torrent = id.0, piece, ?blamed, "hash check failed");
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
