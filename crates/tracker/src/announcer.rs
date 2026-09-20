// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Tier/backoff semantics follow libtorrent-rasterbar (BSD-3-Clause),
// Copyright (c) Arvid Norberg and contributors; see NOTICE.

//! Per-torrent announce scheduling: multi-tracker tiers with libtorrent's
//! semantics (`announce_to_all_tiers = true`, `announce_to_all_trackers =
//! false`, as qBittorrent runs it), **one announce state per listen socket**
//! ("endpoint": the oracle announces to the same tracker once over IPv4 and
//! once over IPv6, each with its own `started` / `completed` / `stopped`;
//! `testkit/golden/capture_tracker_dual`), event sequencing (`started` once
//! per endpoint, `completed` exactly once per started endpoint, `stopped` on
//! stop for every started endpoint), interval clamping and failure backoff.
//!
//! Sans-IO: the caller drives it with `Instant`s and performs the announces
//! that [`Announcer::poll`] hands out. Timing constants are libtorrent's
//! defaults (AGENTS.md 6, L3: good defaults, not mimicry targets).
//!
//! Tier semantics, per endpoint, per tier and in tracker order: a tracker
//! that is currently announcing, or that is *working* (its last announce
//! succeeded) but not yet due, satisfies the tier and the rest of the tier is
//! skipped; a tracker that is due is announced to and satisfies the tier; a
//! failed tracker in backoff is skipped so the next one in the tier gets its
//! turn. Endpoints the caller disabled (a listen socket that cannot reach the
//! tracker's address family) are skipped silently.

use std::time::{Duration, Instant};

use crate::announce::{AnnounceEvent, AnnounceResponse};

/// Never announce more often than this, whatever the tracker says
/// (libtorrent `min_announce_interval`, docs/quirks.md Q4).
pub const MIN_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);
/// Backoff floor after a failure (libtorrent `tracker_retry_delay_min`).
const RETRY_DELAY_MIN: u64 = 5;
/// Backoff ceiling (libtorrent `tracker_retry_delay_max`).
const RETRY_DELAY_MAX: u64 = 60 * 60;
/// Backoff growth in percent (libtorrent `tracker_backoff`).
const TRACKER_BACKOFF: u64 = 250;

/// One announce the caller must perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceJob {
    /// Tier index.
    pub tier: usize,
    /// Tracker index within the tier.
    pub index: usize,
    /// Listen-socket (endpoint) index.
    pub endpoint: usize,
    /// The announce URL.
    pub url: String,
    /// The event to send.
    pub event: AnnounceEvent,
    /// `tracker id` to echo, if the tracker gave one.
    pub tracker_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Endpoint {
    enabled: bool,
    fails: u32,
    /// `None` = never announced, due immediately.
    next_announce: Option<Instant>,
    /// Earliest time a forced re-announce may happen.
    min_announce: Option<Instant>,
    updating: bool,
    start_sent: bool,
    complete_sent: bool,
    complete_pending: bool,
    ever_succeeded: bool,
    last_error: Option<String>,
    complete: Option<u32>,
    incomplete: Option<u32>,
    interval: Option<u32>,
}

impl Endpoint {
    fn new() -> Endpoint {
        Endpoint {
            enabled: true,
            fails: 0,
            next_announce: None,
            min_announce: None,
            updating: false,
            start_sent: false,
            complete_sent: false,
            complete_pending: false,
            ever_succeeded: false,
            last_error: None,
            complete: None,
            incomplete: None,
            interval: None,
        }
    }

    fn is_working(&self) -> bool {
        self.ever_succeeded && self.fails == 0
    }

    fn is_due(&self, now: Instant) -> bool {
        self.enabled && !self.updating && self.next_announce.is_none_or(|t| t <= now)
    }
}

#[derive(Debug, Clone)]
struct Tracker {
    url: String,
    tracker_id: Option<Vec<u8>>,
    /// Completed downloads from a scrape.
    downloaded: Option<u32>,
    endpoints: Vec<Endpoint>,
}

/// Read-only view of one tracker (aggregated over its endpoints) for status
/// reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerSnapshot {
    /// Announce URL.
    pub url: String,
    /// Tier index.
    pub tier: usize,
    /// Fewest consecutive failures over the enabled endpoints.
    pub fails: u32,
    /// Whether any endpoint's last announce succeeded.
    pub working: bool,
    /// Whether an announce is in flight on any endpoint.
    pub updating: bool,
    /// Earliest next scheduled announce over the endpoints.
    pub next_announce: Option<Instant>,
    /// Last error message (any endpoint).
    pub last_error: Option<String>,
    /// Seeders reported.
    pub complete: Option<u32>,
    /// Leechers reported.
    pub incomplete: Option<u32>,
    /// Completed downloads reported (scrape).
    pub downloaded: Option<u32>,
    /// Per-endpoint `(enabled, working, start_sent)`.
    pub endpoints: Vec<(bool, bool, bool)>,
}

/// The announce scheduler for one torrent.
#[derive(Debug, Clone)]
pub struct Announcer {
    tiers: Vec<Vec<Tracker>>,
    endpoints: usize,
    running: bool,
    /// The download has finished (so endpoints first contacted from now on
    /// never need a `completed`).
    finished: bool,
}

impl Announcer {
    /// Create a scheduler for `tiers` (BEP 12 order) over `endpoints` listen
    /// sockets (at least one). Empty URLs are dropped.
    pub fn new(tiers: Vec<Vec<String>>, endpoints: usize) -> Announcer {
        let endpoints = endpoints.max(1);
        Announcer {
            tiers: tiers
                .into_iter()
                .map(|t| {
                    t.into_iter()
                        .filter(|u| !u.trim().is_empty())
                        .map(|url| Tracker {
                            url,
                            tracker_id: None,
                            downloaded: None,
                            endpoints: (0..endpoints).map(|_| Endpoint::new()).collect(),
                        })
                        .collect()
                })
                .filter(|t: &Vec<Tracker>| !t.is_empty())
                .collect(),
            endpoints,
            running: false,
            finished: false,
        }
    }

    /// Number of endpoints.
    pub fn endpoints(&self) -> usize {
        self.endpoints
    }

    /// Whether there is any tracker at all.
    pub fn has_trackers(&self) -> bool {
        !self.tiers.is_empty()
    }

    /// Whether announcing is active (between `start` and `stop`).
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Begin (or resume) announcing. Every endpoint becomes due immediately,
    /// whatever schedule an earlier `stopped` reply left behind.
    pub fn start(&mut self) {
        self.running = true;
        for t in self.tiers.iter_mut().flatten() {
            for e in &mut t.endpoints {
                e.next_announce = None;
                e.updating = false;
            }
        }
    }

    /// Stop announcing. Returns the `stopped` announces to perform: one per
    /// endpoint that received `started`. No further jobs are produced.
    pub fn stop(&mut self) -> Vec<AnnounceJob> {
        self.running = false;
        let mut jobs = Vec::new();
        for (ti, tier) in self.tiers.iter_mut().enumerate() {
            for (i, t) in tier.iter_mut().enumerate() {
                for (ei, e) in t.endpoints.iter_mut().enumerate() {
                    e.updating = false;
                    if e.start_sent {
                        jobs.push(AnnounceJob {
                            tier: ti,
                            index: i,
                            endpoint: ei,
                            url: t.url.clone(),
                            event: AnnounceEvent::Stopped,
                            tracker_id: t.tracker_id.clone(),
                        });
                    }
                }
            }
        }
        jobs
    }

    /// The download finished: queue `completed` for every endpoint that got
    /// `started` and make it due now. Endpoints never started will send
    /// `started` (with `left=0`) when their turn comes.
    pub fn completed(&mut self, now: Instant) {
        self.finished = true;
        for t in self.tiers.iter_mut().flatten() {
            for e in &mut t.endpoints {
                if e.start_sent && !e.complete_sent {
                    e.complete_pending = true;
                    e.next_announce = Some(now);
                }
            }
        }
    }

    /// Force a re-announce as soon as each endpoint's `min interval` allows.
    pub fn force_reannounce(&mut self, now: Instant) {
        for t in self.tiers.iter_mut().flatten() {
            for e in &mut t.endpoints {
                let earliest = e.min_announce.unwrap_or(now).max(now);
                e.next_announce = Some(earliest);
            }
        }
    }

    /// Disable one endpoint of one tracker (its listen socket cannot reach
    /// the tracker, e.g. an IPv4 literal from the IPv6 socket). Disabled
    /// endpoints produce no jobs and no errors.
    pub fn disable_endpoint(&mut self, tier: usize, index: usize, endpoint: usize) {
        if let Some(e) = self
            .tiers
            .get_mut(tier)
            .and_then(|t| t.get_mut(index))
            .and_then(|t| t.endpoints.get_mut(endpoint))
        {
            e.enabled = false;
            e.updating = false;
        }
    }

    /// Announces that should be performed right now, at most one per tier
    /// per endpoint.
    pub fn poll(&mut self, now: Instant) -> Vec<AnnounceJob> {
        if !self.running {
            return Vec::new();
        }
        let mut jobs = Vec::new();
        for ei in 0..self.endpoints {
            for (ti, tier) in self.tiers.iter_mut().enumerate() {
                for (i, t) in tier.iter_mut().enumerate() {
                    let Some(e) = t.endpoints.get_mut(ei) else {
                        continue;
                    };
                    if !e.enabled {
                        continue;
                    }
                    if e.updating {
                        break; // this tier is being handled on this endpoint
                    }
                    if e.is_due(now) {
                        let event = if e.complete_pending && e.start_sent {
                            AnnounceEvent::Completed
                        } else if !e.start_sent {
                            AnnounceEvent::Started
                        } else {
                            AnnounceEvent::None
                        };
                        e.updating = true;
                        jobs.push(AnnounceJob {
                            tier: ti,
                            index: i,
                            endpoint: ei,
                            url: t.url.clone(),
                            event,
                            tracker_id: t.tracker_id.clone(),
                        });
                        break;
                    }
                    if e.is_working() {
                        break; // a working tracker satisfies the tier until it is due
                    }
                    // failed and in backoff: let the next tracker in the tier try
                }
            }
        }
        jobs
    }

    /// The earliest instant at which `poll` may produce a job, if any.
    pub fn next_due(&self, now: Instant) -> Option<Instant> {
        if !self.running {
            return None;
        }
        let mut best: Option<Instant> = None;
        for ei in 0..self.endpoints {
            for tier in &self.tiers {
                for t in tier {
                    let Some(e) = t.endpoints.get(ei) else {
                        continue;
                    };
                    if !e.enabled {
                        continue;
                    }
                    if e.updating {
                        break;
                    }
                    let due = e.next_announce.unwrap_or(now).max(now);
                    best = Some(best.map_or(due, |b| b.min(due)));
                    if e.is_working() || e.is_due(now) {
                        break;
                    }
                }
            }
        }
        best
    }

    fn endpoint_mut(&mut self, job: &AnnounceJob) -> Option<(&mut Tracker, usize)> {
        let t = self.tiers.get_mut(job.tier)?.get_mut(job.index)?;
        if job.endpoint < t.endpoints.len() {
            Some((t, job.endpoint))
        } else {
            None
        }
    }

    /// A job succeeded. Schedules the next regular announce at
    /// `max(interval, MIN_ANNOUNCE_INTERVAL)` and records the tracker's reply.
    pub fn on_success(&mut self, job: &AnnounceJob, resp: &AnnounceResponse, now: Instant) {
        let finished = self.finished;
        let Some((t, ei)) = self.endpoint_mut(job) else {
            return;
        };
        if let Some(id) = &resp.tracker_id {
            t.tracker_id = Some(id.clone());
        }
        let e = &mut t.endpoints[ei];
        e.updating = false;
        e.fails = 0;
        e.ever_succeeded = true;
        e.last_error = None;
        e.start_sent = true;
        if job.event == AnnounceEvent::Completed
            || (job.event == AnnounceEvent::Started && finished)
        {
            // Either we just said `completed`, or this endpoint first heard
            // from us after the download finished (`left=0`): it never needs
            // a `completed`.
            e.complete_sent = true;
            e.complete_pending = false;
        }
        if job.event == AnnounceEvent::Stopped {
            e.start_sent = false;
        }
        let interval = Duration::from_secs(u64::from(resp.interval)).max(MIN_ANNOUNCE_INTERVAL);
        e.interval = Some(resp.interval);
        e.next_announce = Some(now + interval);
        e.min_announce = Some(now + Duration::from_secs(u64::from(resp.min_interval.unwrap_or(0))));
        e.complete = resp.complete;
        e.incomplete = resp.incomplete;
    }

    /// A job failed (transport error, HTTP error, `failure reason`, timeout).
    /// Backs the endpoint off: `min(5 + fails² · 5 · 2.5, 1h)` seconds, never
    /// less than the tracker's own interval.
    pub fn on_failure(&mut self, job: &AnnounceJob, error: String, now: Instant) {
        let Some((t, ei)) = self.endpoint_mut(job) else {
            return;
        };
        let e = &mut t.endpoints[ei];
        e.updating = false;
        e.fails = e.fails.saturating_add(1);
        e.last_error = Some(error);
        let fails = u64::from(e.fails.min(1000));
        let delay = (RETRY_DELAY_MIN + fails * fails * RETRY_DELAY_MIN * TRACKER_BACKOFF / 100)
            .min(RETRY_DELAY_MAX)
            .max(u64::from(e.interval.unwrap_or(0)));
        e.next_announce = Some(now + Duration::from_secs(delay));
    }

    /// Every tracker URL, tier by tier (for scrapes).
    pub fn urls(&self) -> Vec<String> {
        self.tiers.iter().flatten().map(|t| t.url.clone()).collect()
    }

    /// Record a scrape result for `url`.
    pub fn record_scrape(&mut self, url: &str, complete: u32, incomplete: u32, downloaded: u32) {
        for t in self.tiers.iter_mut().flatten() {
            if t.url == url {
                t.downloaded = Some(downloaded);
                for e in &mut t.endpoints {
                    e.complete = Some(complete);
                    e.incomplete = Some(incomplete);
                }
            }
        }
    }

    /// Snapshot of every tracker, tier by tier.
    pub fn snapshot(&self) -> Vec<TrackerSnapshot> {
        let mut v = Vec::new();
        for (ti, tier) in self.tiers.iter().enumerate() {
            for t in tier {
                let enabled: Vec<&Endpoint> = t.endpoints.iter().filter(|e| e.enabled).collect();
                let latest = enabled
                    .iter()
                    .filter(|e| e.ever_succeeded)
                    .max_by_key(|e| e.next_announce);
                v.push(TrackerSnapshot {
                    url: t.url.clone(),
                    tier: ti,
                    fails: enabled.iter().map(|e| e.fails).min().unwrap_or(0),
                    working: enabled.iter().any(|e| e.is_working()),
                    updating: enabled.iter().any(|e| e.updating),
                    next_announce: enabled.iter().filter_map(|e| e.next_announce).min(),
                    last_error: enabled.iter().find_map(|e| e.last_error.clone()),
                    complete: latest.and_then(|e| e.complete),
                    incomplete: latest.and_then(|e| e.incomplete),
                    downloaded: t.downloaded,
                    endpoints: t
                        .endpoints
                        .iter()
                        .map(|e| (e.enabled, e.is_working(), e.start_sent))
                        .collect(),
                });
            }
        }
        v
    }

    /// Whether `completed` has been sent on every endpoint that got `started`
    /// (used by tests to assert "exactly once").
    pub fn all_completed_sent(&self) -> bool {
        self.tiers
            .iter()
            .flatten()
            .flat_map(|t| t.endpoints.iter())
            .filter(|e| e.start_sent)
            .all(|e| e.complete_sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(interval: u32) -> AnnounceResponse {
        AnnounceResponse {
            interval,
            ..Default::default()
        }
    }

    fn urls(tiers: &[&[&str]]) -> Vec<Vec<String>> {
        tiers
            .iter()
            .map(|t| t.iter().map(|s| s.to_string()).collect())
            .collect()
    }

    #[test]
    fn started_then_regular_then_completed_then_stopped() {
        let t0 = Instant::now();
        let mut a = Announcer::new(urls(&[&["http://a/announce"]]), 1);
        assert!(a.poll(t0).is_empty(), "not running yet");
        a.start();
        let jobs = a.poll(t0);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].event, AnnounceEvent::Started);
        assert!(a.poll(t0).is_empty(), "in flight: no duplicate");
        a.on_success(&jobs[0], &resp(30), t0);
        // Clamped to 5 minutes (Q4).
        assert_eq!(a.next_due(t0), Some(t0 + MIN_ANNOUNCE_INTERVAL));
        assert!(a.poll(t0 + Duration::from_secs(299)).is_empty());
        let jobs = a.poll(t0 + Duration::from_secs(300));
        assert_eq!(jobs[0].event, AnnounceEvent::None);
        a.on_success(&jobs[0], &resp(1800), t0 + Duration::from_secs(300));
        // Completed: due immediately, exactly once.
        let t1 = t0 + Duration::from_secs(400);
        a.completed(t1);
        let jobs = a.poll(t1);
        assert_eq!(jobs[0].event, AnnounceEvent::Completed);
        a.on_success(&jobs[0], &resp(1800), t1);
        assert!(a.all_completed_sent());
        a.completed(t1 + Duration::from_secs(1));
        assert!(
            a.poll(t1 + Duration::from_secs(1)).is_empty(),
            "no second completed"
        );
        // Stop: one stopped for the started tracker; nothing afterwards.
        let stopped = a.stop();
        assert_eq!(stopped.len(), 1);
        assert_eq!(stopped[0].event, AnnounceEvent::Stopped);
        assert!(a.poll(t1 + Duration::from_secs(9999)).is_empty());
    }

    #[test]
    fn tier_failover_and_backoff() {
        let t0 = Instant::now();
        let mut a = Announcer::new(urls(&[&["http://a/", "http://b/"], &["http://c/"]]), 1);
        a.start();
        let jobs = a.poll(t0);
        // One per tier: a (tier 0) and c (tier 1).
        assert_eq!(
            jobs.iter().map(|j| j.url.as_str()).collect::<Vec<_>>(),
            vec!["http://a/", "http://c/"]
        );
        a.on_failure(&jobs[0], "refused".into(), t0);
        a.on_success(&jobs[1], &resp(1800), t0);
        // a failed -> b gets its turn immediately.
        let jobs = a.poll(t0);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].url, "http://b/");
        assert_eq!(jobs[0].event, AnnounceEvent::Started);
        a.on_success(&jobs[0], &resp(1800), t0);
        // Nothing due now; a is in backoff (5 + 1*5*2.5 = 17s).
        assert!(a.poll(t0 + Duration::from_secs(1)).is_empty());
        let snap = a.snapshot();
        assert_eq!(snap[0].fails, 1);
        assert_eq!(snap[0].next_announce, Some(t0 + Duration::from_secs(17)));
        assert!(snap[1].working && snap[2].working);
        // When a comes due it is retried (first in tier), b is skipped.
        let jobs = a.poll(t0 + Duration::from_secs(17));
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].url, "http://a/");
        a.on_failure(&jobs[0], "refused".into(), t0 + Duration::from_secs(17));
        // fails = 2: 5 + 2*2*5*250/100 = 55 s.
        assert_eq!(
            a.snapshot()[0].next_announce,
            Some(t0 + Duration::from_secs(17 + 55))
        );
        // b is working and not due: tier satisfied, nothing to do.
        assert!(a.poll(t0 + Duration::from_secs(18)).is_empty());
        // stop: started trackers only (b, c).
        let stopped = a.stop();
        assert_eq!(
            stopped.iter().map(|j| j.url.as_str()).collect::<Vec<_>>(),
            vec!["http://b/", "http://c/"]
        );
    }

    #[test]
    fn two_endpoints_announce_independently() {
        let t0 = Instant::now();
        let mut a = Announcer::new(urls(&[&["http://a/"]]), 2);
        a.start();
        let jobs = a.poll(t0);
        assert_eq!(jobs.len(), 2, "one started per endpoint");
        assert_eq!(
            jobs.iter().map(|j| j.endpoint).collect::<Vec<_>>(),
            vec![0, 1]
        );
        a.on_success(&jobs[0], &resp(1800), t0);
        a.on_failure(&jobs[1], "unreachable".into(), t0);
        // Endpoint 1 retries on its own schedule; endpoint 0 is fine.
        let snap = a.snapshot();
        assert!(snap[0].working);
        assert_eq!(
            snap[0].endpoints,
            vec![(true, true, true), (true, false, false)]
        );
        a.completed(t0 + Duration::from_secs(1));
        let jobs = a.poll(t0 + Duration::from_secs(1));
        assert_eq!(jobs.len(), 1, "completed only where started");
        assert_eq!(
            (jobs[0].endpoint, jobs[0].event),
            (0, AnnounceEvent::Completed)
        );
        a.on_success(&jobs[0], &resp(1800), t0 + Duration::from_secs(1));
        // Disabling the failing endpoint silences it.
        a.disable_endpoint(0, 0, 1);
        assert!(a.poll(t0 + Duration::from_secs(1000)).is_empty());
        let stopped = a.stop();
        assert_eq!(stopped.len(), 1);
        assert_eq!(stopped[0].endpoint, 0);
    }

    #[test]
    fn backoff_is_capped_and_respects_interval() {
        let t0 = Instant::now();
        let mut a = Announcer::new(urls(&[&["http://a/"]]), 1);
        a.start();
        let job = a.poll(t0).remove(0);
        a.on_success(&job, &resp(1000), t0);
        let mut now = t0 + Duration::from_secs(1000);
        for _ in 0..50 {
            let job = a.poll(now).remove(0);
            a.on_failure(&job, "x".into(), now);
            let next = a.snapshot()[0].next_announce.unwrap();
            let delay = next - now;
            assert!(
                delay >= Duration::from_secs(1000),
                "never below the interval"
            );
            assert!(delay <= Duration::from_secs(3600), "capped at an hour");
            now = next;
        }
    }

    #[test]
    fn force_reannounce_honours_min_interval() {
        let t0 = Instant::now();
        let mut a = Announcer::new(urls(&[&["http://a/"]]), 1);
        a.start();
        let job = a.poll(t0).remove(0);
        a.on_success(
            &job,
            &AnnounceResponse {
                interval: 1800,
                min_interval: Some(60),
                ..Default::default()
            },
            t0,
        );
        a.force_reannounce(t0 + Duration::from_secs(10));
        assert!(a.poll(t0 + Duration::from_secs(10)).is_empty());
        assert_eq!(
            a.next_due(t0 + Duration::from_secs(10)),
            Some(t0 + Duration::from_secs(60))
        );
        assert_eq!(a.poll(t0 + Duration::from_secs(60)).len(), 1);
    }

    #[test]
    fn completed_before_started_becomes_started() {
        let t0 = Instant::now();
        let mut a = Announcer::new(urls(&[&["http://a/"]]), 1);
        a.start();
        a.completed(t0);
        let job = a.poll(t0).remove(0);
        assert_eq!(job.event, AnnounceEvent::Started);
        a.on_success(&job, &resp(1800), t0);
        // Never downloaded through this tracker: no completed ever.
        assert!(a.poll(t0 + Duration::from_secs(1)).is_empty());
        assert!(a.all_completed_sent());
    }

    #[test]
    fn tracker_id_is_echoed() {
        let t0 = Instant::now();
        let mut a = Announcer::new(urls(&[&["http://a/"]]), 1);
        a.start();
        let job = a.poll(t0).remove(0);
        assert_eq!(job.tracker_id, None);
        a.on_success(
            &job,
            &AnnounceResponse {
                interval: 1,
                tracker_id: Some(b"tid".to_vec()),
                ..Default::default()
            },
            t0,
        );
        let job = a.poll(t0 + MIN_ANNOUNCE_INTERVAL).remove(0);
        assert_eq!(job.tracker_id, Some(b"tid".to_vec()));
    }

    #[test]
    fn restart_after_stop_announces_started_again() {
        let t0 = Instant::now();
        let mut a = Announcer::new(urls(&[&["http://a/"]]), 1);
        a.start();
        let job = a.poll(t0).remove(0);
        a.on_success(&job, &resp(1800), t0);
        let stopped = a.stop().remove(0);
        assert_eq!(stopped.event, AnnounceEvent::Stopped);
        a.on_success(&stopped, &resp(1800), t0);
        // Resume a second later: due now, and `started` again.
        a.start();
        let t1 = t0 + Duration::from_secs(1);
        let job = a.poll(t1).remove(0);
        assert_eq!(job.event, AnnounceEvent::Started);
        a.on_success(&job, &resp(1800), t1);
        assert_eq!(a.stop().len(), 1);
    }

    #[test]
    fn empty_and_trackerless() {
        let mut a = Announcer::new(vec![vec![], vec!["".into()]], 2);
        assert!(!a.has_trackers());
        a.start();
        assert!(a.poll(Instant::now()).is_empty());
        assert!(a.stop().is_empty());
    }
}
