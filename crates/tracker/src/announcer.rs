// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Per-torrent announce scheduling: multi-tracker tiers with libtorrent's
//! semantics (`announce_to_all_tiers = true`, `announce_to_all_trackers =
//! false`, as qBittorrent runs it), event sequencing (`started` once per
//! tracker, `completed` exactly once per started tracker, `stopped` on stop
//! for every started tracker), interval clamping and failure backoff.
//!
//! Sans-IO: the caller drives it with `Instant`s and performs the announces
//! that [`Announcer::poll`] hands out. Timing constants are libtorrent's
//! defaults (AGENTS.md 6, L3: good defaults, not mimicry targets).
//!
//! Tier semantics, per tier and in tracker order: a tracker that is currently
//! announcing, or that is *working* (its last announce succeeded) but not yet
//! due, satisfies the tier and the rest of the tier is skipped; a tracker that
//! is due is announced to and satisfies the tier; a failed tracker in backoff
//! is skipped so the next one in the tier gets its turn.

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
    /// The announce URL.
    pub url: String,
    /// The event to send.
    pub event: AnnounceEvent,
    /// `tracker id` to echo, if the tracker gave one.
    pub tracker_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Tracker {
    url: String,
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
    tracker_id: Option<Vec<u8>>,
    last_error: Option<String>,
    complete: Option<u32>,
    incomplete: Option<u32>,
    interval: Option<u32>,
}

impl Tracker {
    fn new(url: String) -> Tracker {
        Tracker {
            url,
            fails: 0,
            next_announce: None,
            min_announce: None,
            updating: false,
            start_sent: false,
            complete_sent: false,
            complete_pending: false,
            ever_succeeded: false,
            tracker_id: None,
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
        !self.updating && self.next_announce.is_none_or(|t| t <= now)
    }
}

/// Read-only view of one tracker for status reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerSnapshot {
    /// Announce URL.
    pub url: String,
    /// Tier index.
    pub tier: usize,
    /// Consecutive failures.
    pub fails: u32,
    /// Whether the last announce succeeded.
    pub working: bool,
    /// Whether an announce is in flight.
    pub updating: bool,
    /// Next scheduled announce.
    pub next_announce: Option<Instant>,
    /// Last error message.
    pub last_error: Option<String>,
    /// Seeders reported.
    pub complete: Option<u32>,
    /// Leechers reported.
    pub incomplete: Option<u32>,
}

/// The announce scheduler for one torrent.
#[derive(Debug, Clone)]
pub struct Announcer {
    tiers: Vec<Vec<Tracker>>,
    running: bool,
    /// The download has finished (so trackers first contacted from now on
    /// never need a `completed`).
    finished: bool,
}

impl Announcer {
    /// Create a scheduler for `tiers` (BEP 12 order). Empty URLs are dropped.
    pub fn new(tiers: Vec<Vec<String>>) -> Announcer {
        Announcer {
            tiers: tiers
                .into_iter()
                .map(|t| {
                    t.into_iter()
                        .filter(|u| !u.trim().is_empty())
                        .map(Tracker::new)
                        .collect()
                })
                .filter(|t: &Vec<Tracker>| !t.is_empty())
                .collect(),
            running: false,
            finished: false,
        }
    }

    /// Whether there is any tracker at all.
    pub fn has_trackers(&self) -> bool {
        !self.tiers.is_empty()
    }

    /// Whether announcing is active (between `start` and `stop`).
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Begin announcing. Every tracker becomes due; `poll` hands out jobs.
    pub fn start(&mut self) {
        self.running = true;
    }

    /// Stop announcing. Returns the `stopped` announces to perform: one per
    /// tracker that received `started`. No further jobs are produced.
    pub fn stop(&mut self) -> Vec<AnnounceJob> {
        self.running = false;
        let mut jobs = Vec::new();
        for (ti, tier) in self.tiers.iter_mut().enumerate() {
            for (i, t) in tier.iter_mut().enumerate() {
                t.updating = false;
                if t.start_sent {
                    jobs.push(AnnounceJob {
                        tier: ti,
                        index: i,
                        url: t.url.clone(),
                        event: AnnounceEvent::Stopped,
                        tracker_id: t.tracker_id.clone(),
                    });
                }
            }
        }
        jobs
    }

    /// The download finished: queue `completed` for every tracker that got
    /// `started` and make it due now. Trackers never started will send
    /// `started` (with `left=0`) when their turn comes.
    pub fn completed(&mut self, now: Instant) {
        self.finished = true;
        for t in self.tiers.iter_mut().flatten() {
            if t.start_sent && !t.complete_sent {
                t.complete_pending = true;
                t.next_announce = Some(now);
            }
        }
    }

    /// Force a re-announce as soon as each tracker's `min interval` allows.
    pub fn force_reannounce(&mut self, now: Instant) {
        for t in self.tiers.iter_mut().flatten() {
            let earliest = t.min_announce.unwrap_or(now).max(now);
            t.next_announce = Some(earliest);
        }
    }

    /// Announces that should be performed right now, at most one per tier.
    pub fn poll(&mut self, now: Instant) -> Vec<AnnounceJob> {
        if !self.running {
            return Vec::new();
        }
        let mut jobs = Vec::new();
        for (ti, tier) in self.tiers.iter_mut().enumerate() {
            for (i, t) in tier.iter_mut().enumerate() {
                if t.updating {
                    break; // this tier is being handled
                }
                if t.is_due(now) {
                    let event = if t.complete_pending && t.start_sent {
                        AnnounceEvent::Completed
                    } else if !t.start_sent {
                        AnnounceEvent::Started
                    } else {
                        AnnounceEvent::None
                    };
                    t.updating = true;
                    jobs.push(AnnounceJob {
                        tier: ti,
                        index: i,
                        url: t.url.clone(),
                        event,
                        tracker_id: t.tracker_id.clone(),
                    });
                    break;
                }
                if t.is_working() {
                    break; // a working tracker satisfies the tier until it is due
                }
                // failed and in backoff: let the next tracker in the tier try
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
        for tier in &self.tiers {
            for t in tier {
                if t.updating {
                    break;
                }
                let due = t.next_announce.unwrap_or(now).max(now);
                best = Some(best.map_or(due, |b| b.min(due)));
                if t.is_working() || t.is_due(now) {
                    break;
                }
            }
        }
        best
    }

    fn tracker_mut(&mut self, job: &AnnounceJob) -> Option<&mut Tracker> {
        self.tiers.get_mut(job.tier)?.get_mut(job.index)
    }

    /// A job succeeded. Schedules the next regular announce at
    /// `max(interval, MIN_ANNOUNCE_INTERVAL)` and records the tracker's reply.
    pub fn on_success(&mut self, job: &AnnounceJob, resp: &AnnounceResponse, now: Instant) {
        let finished = self.finished;
        let Some(t) = self.tracker_mut(job) else {
            return;
        };
        t.updating = false;
        t.fails = 0;
        t.ever_succeeded = true;
        t.last_error = None;
        t.start_sent = true;
        if job.event == AnnounceEvent::Completed
            || (job.event == AnnounceEvent::Started && finished)
        {
            // Either we just said `completed`, or this tracker first heard
            // from us after the download finished (`left=0`): it never needs
            // a `completed`.
            t.complete_sent = true;
            t.complete_pending = false;
        }
        if job.event == AnnounceEvent::Stopped {
            t.start_sent = false;
        }
        let interval = Duration::from_secs(u64::from(resp.interval)).max(MIN_ANNOUNCE_INTERVAL);
        t.interval = Some(resp.interval);
        t.next_announce = Some(now + interval);
        t.min_announce = Some(now + Duration::from_secs(u64::from(resp.min_interval.unwrap_or(0))));
        if let Some(id) = &resp.tracker_id {
            t.tracker_id = Some(id.clone());
        }
        t.complete = resp.complete;
        t.incomplete = resp.incomplete;
    }

    /// A job failed (transport error, HTTP error, `failure reason`, timeout).
    /// Backs the tracker off: `min(5 + fails² · 5 · 2.5, 1h)` seconds, never
    /// less than the tracker's own interval.
    pub fn on_failure(&mut self, job: &AnnounceJob, error: String, now: Instant) {
        let Some(t) = self.tracker_mut(job) else {
            return;
        };
        t.updating = false;
        t.fails = t.fails.saturating_add(1);
        t.last_error = Some(error);
        let fails = u64::from(t.fails.min(1000));
        let delay = (RETRY_DELAY_MIN + fails * fails * RETRY_DELAY_MIN * TRACKER_BACKOFF / 100)
            .min(RETRY_DELAY_MAX)
            .max(u64::from(t.interval.unwrap_or(0)));
        t.next_announce = Some(now + Duration::from_secs(delay));
    }

    /// Snapshot of every tracker, tier by tier.
    pub fn snapshot(&self) -> Vec<TrackerSnapshot> {
        let mut v = Vec::new();
        for (ti, tier) in self.tiers.iter().enumerate() {
            for t in tier {
                v.push(TrackerSnapshot {
                    url: t.url.clone(),
                    tier: ti,
                    fails: t.fails,
                    working: t.is_working(),
                    updating: t.updating,
                    next_announce: t.next_announce,
                    last_error: t.last_error.clone(),
                    complete: t.complete,
                    incomplete: t.incomplete,
                });
            }
        }
        v
    }

    /// Whether `completed` has been sent to every tracker that got `started`
    /// (used by tests to assert "exactly once").
    pub fn all_completed_sent(&self) -> bool {
        self.tiers
            .iter()
            .flatten()
            .filter(|t| t.start_sent)
            .all(|t| t.complete_sent)
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
        let mut a = Announcer::new(urls(&[&["http://a/announce"]]));
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
        let mut a = Announcer::new(urls(&[&["http://a/", "http://b/"], &["http://c/"]]));
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
    fn backoff_is_capped_and_respects_interval() {
        let t0 = Instant::now();
        let mut a = Announcer::new(urls(&[&["http://a/"]]));
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
        let mut a = Announcer::new(urls(&[&["http://a/"]]));
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
        let mut a = Announcer::new(urls(&[&["http://a/"]]));
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
        let mut a = Announcer::new(urls(&[&["http://a/"]]));
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
    fn empty_and_trackerless() {
        let mut a = Announcer::new(vec![vec![], vec!["".into()]]);
        assert!(!a.has_trackers());
        a.start();
        assert!(a.poll(Instant::now()).is_empty());
        assert!(a.stop().is_empty());
    }
}
