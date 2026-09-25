// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// The active-torrent limits and the slow-torrent exemption follow
// libtorrent-rasterbar (BSD-3-Clause), Copyright (c) Arvid Norberg and
// contributors (`session_impl::recalculate_auto_managed_torrents`); see NOTICE.

//! The active-torrent queue (`ActiveLimits`, libtorrent's auto-managed
//! torrents): auto-managed torrents are started in queue order while the
//! limits allow and stopped (`TorrentState::Queued`) beyond them, once a
//! second and whenever a limit or a torrent's standing changes. A running
//! torrent that has moved no data for a while does not hold a slot
//! (`ActiveLimits::count_slow`), so stalled torrents never block the queue.
//! Force-started torrents (`auto_managed = false`) are left alone but count.
//!
//! The decision is a pure function of a snapshot ([`plan`]), so it is unit
//! tested without an engine.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::api::{ActiveLimits, QueueMove, TorrentId};

use super::torrent::{self, Torrent};
use super::{Ctx, Error};

/// Rates below which a torrent counts as inactive (libtorrent
/// `inactive_down_rate` / `inactive_up_rate`: 2 KiB/s).
pub const INACTIVE_RATE: u64 = 2048;
/// How long a torrent must have run, and been slow, before it stops
/// counting (libtorrent `auto_manage_startup`).
pub const INACTIVE_AFTER: Duration = Duration::from_secs(60);

/// One torrent as the planner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: TorrentId,
    /// Queue order key (lower first).
    pub position: u64,
    /// Complete: counts against `seeds`, else against `downloads`.
    pub seed: bool,
    /// Currently running (not paused by anyone).
    pub running: bool,
    /// The queue may start or stop it.
    pub auto_managed: bool,
    /// Eligible at all: not paused by the caller, not errored, not being
    /// checked (checking has its own gate).
    pub eligible: bool,
    /// Running but moving no data (see `count_slow`).
    pub inactive: bool,
}

/// What to do after a planning round.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub start: Vec<TorrentId>,
    pub stop: Vec<TorrentId>,
}

/// Decide which eligible torrents run: walk them in queue order, handing
/// out `downloads` / `seeds` slots within `total`. Force-started torrents
/// take slots first (they run regardless); a slow running torrent takes
/// none unless `count_slow`.
pub fn plan(entries: &[Entry], limits: ActiveLimits) -> Plan {
    let mut plan = Plan::default();
    let mut order: Vec<&Entry> = entries.iter().filter(|e| e.eligible).collect();
    // Forced torrents first so they are charged before the queue's own.
    order.sort_by_key(|e| (e.auto_managed, e.position));
    let mut downloads = limits.downloads;
    let mut seeds = limits.seeds;
    let mut total = limits.total;
    let take = |slot: &mut Option<usize>| -> bool {
        match slot {
            None => true,
            Some(0) => false,
            Some(n) => {
                *n -= 1;
                true
            }
        }
    };
    let fits = |kind: &Option<usize>, total: &Option<usize>| -> bool {
        kind.is_none_or(|n| n > 0) && total.is_none_or(|n| n > 0)
    };
    for e in order {
        if e.running && e.inactive && !limits.count_slow {
            // Holds no slot; keeps running (libtorrent
            // `dont_count_slow_torrents`).
            continue;
        }
        let kind = if e.seed { &mut seeds } else { &mut downloads };
        if !e.auto_managed {
            // Runs (or stays paused) whatever the limits say, but a running
            // one is charged.
            if e.running {
                take(kind);
                take(&mut total);
            }
            continue;
        }
        if fits(kind, &total) {
            take(kind);
            take(&mut total);
            if !e.running {
                plan.start.push(e.id);
            }
        } else if e.running {
            plan.stop.push(e.id);
        }
    }
    plan
}

fn entry(t: &Torrent, now: Instant) -> Entry {
    Entry {
        id: t.id,
        position: t.queue_position,
        seed: t.is_complete(),
        running: !t.paused,
        auto_managed: t.auto_managed,
        eligible: t.error.is_none() && !t.checking && !t.held && (!t.paused || t.auto_paused),
        inactive: t.is_inactive(now),
    }
}

/// Re-evaluate the queue: start and stop torrents as [`plan`] says.
pub fn recalculate(ctx: &Rc<Ctx>, now: Instant) {
    let limits = ctx.active_limits();
    let torrents: Vec<Rc<RefCell<Torrent>>> = ctx.torrents.borrow().values().cloned().collect();
    let entries: Vec<Entry> = torrents.iter().map(|t| entry(&t.borrow(), now)).collect();
    if !limits.is_limited() && entries.iter().all(|e| e.running || !e.eligible) {
        return;
    }
    let p = plan(&entries, limits);
    for t in &torrents {
        let id = t.borrow().id;
        if p.start.contains(&id) {
            {
                let mut tb = t.borrow_mut();
                tb.auto_paused = false;
                tb.slow_since = None;
            }
            tracing::debug!(torrent = id.0, "queue: start");
            torrent::resume(ctx, t);
        } else if p.stop.contains(&id) {
            {
                let mut tb = t.borrow_mut();
                if tb.paused {
                    continue;
                }
                tb.auto_paused = true;
            }
            tracing::debug!(torrent = id.0, "queue: stop (beyond the active limits)");
            let ctx2 = ctx.clone();
            let t2 = t.clone();
            uring::spawn(async move {
                torrent::pause(&ctx2, &t2).await;
            });
        }
    }
}

/// A caller-paused torrent handed (back) to the queue: eligible, waiting
/// for the next round to start it if the limits allow.
pub fn mark_eligible(t: &Rc<RefCell<Torrent>>) {
    let mut tb = t.borrow_mut();
    tb.set_auto_managed(true);
    if tb.paused && tb.error.is_none() && !tb.held {
        tb.auto_paused = true;
    }
}

/// `Session::set_auto_managed` / `Session::resume`.
pub fn set_auto_managed(ctx: &Rc<Ctx>, t: &Rc<RefCell<Torrent>>, on: bool) {
    if on {
        mark_eligible(t);
        recalculate(ctx, Instant::now());
    } else {
        let mut tb = t.borrow_mut();
        tb.set_auto_managed(false);
        // A queued torrent becomes a plainly paused one.
        tb.auto_paused = false;
    }
}

/// A torrent has just become ready to run (added, checked, metadata
/// received): hand it to the queue, or start it outright when it is not
/// auto-managed.
pub fn activate(ctx: &Rc<Ctx>, t: &Rc<RefCell<Torrent>>) {
    let managed = {
        let mut tb = t.borrow_mut();
        if tb.auto_managed {
            tb.paused = true;
            tb.auto_paused = true;
        }
        tb.auto_managed
    };
    if managed {
        recalculate(ctx, Instant::now());
    } else {
        torrent::resume(ctx, t);
    }
}

/// Dense queue positions (0 = first) by torrent, in queue order.
pub fn positions(ctx: &Ctx) -> Vec<(TorrentId, usize)> {
    let mut v: Vec<(TorrentId, u64)> = ctx
        .torrents
        .borrow()
        .values()
        .map(|t| {
            let t = t.borrow();
            (t.id, t.queue_position)
        })
        .collect();
    v.sort_by_key(|(_, p)| *p);
    v.into_iter()
        .enumerate()
        .map(|(i, (id, _))| (id, i))
        .collect()
}

/// `Session::move_in_queue`.
pub fn move_in_queue(ctx: &Rc<Ctx>, id: TorrentId, to: QueueMove) -> Result<(), Error> {
    place(ctx, id, |idx, rest| match to {
        QueueMove::Top => 0,
        QueueMove::Up => idx.saturating_sub(1),
        QueueMove::Down => (idx + 1).min(rest),
        QueueMove::Bottom => rest,
    })
}

/// `Session::set_queue_position`: past the end is last.
pub fn set_queue_position(ctx: &Rc<Ctx>, id: TorrentId, position: usize) -> Result<(), Error> {
    place(ctx, id, |_, rest| position.min(rest))
}

/// Take `id` out of the queue order and insert it where `at(current index,
/// number of the others)` says, then renumber and re-plan once.
fn place(
    ctx: &Rc<Ctx>,
    id: TorrentId,
    at: impl FnOnce(usize, usize) -> usize,
) -> Result<(), Error> {
    let order = positions(ctx);
    let Some(idx) = order.iter().position(|(i, _)| *i == id) else {
        return Err(Error::NoSuchTorrent);
    };
    let mut ids: Vec<TorrentId> = order.into_iter().map(|(i, _)| i).collect();
    let moved = ids.remove(idx);
    let at = at(idx, ids.len());
    ids.insert(at, moved);
    // Renumber densely, keeping the allocator ahead of every position;
    // each torrent whose key changes has its resume data marked.
    for (i, tid) in ids.iter().enumerate() {
        if let Some(t) = ctx.torrent(*tid) {
            t.borrow_mut().set_queue_position(i as u64);
        }
    }
    ctx.reset_queue_positions(ids.len() as u64);
    recalculate(ctx, Instant::now());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(id: u64, position: u64, seed: bool, running: bool) -> Entry {
        Entry {
            id: TorrentId(id),
            position,
            seed,
            running,
            auto_managed: true,
            eligible: true,
            inactive: false,
        }
    }

    fn limits(
        downloads: Option<usize>,
        seeds: Option<usize>,
        total: Option<usize>,
    ) -> ActiveLimits {
        ActiveLimits {
            downloads,
            seeds,
            total,
            count_slow: false,
        }
    }

    #[test]
    fn unlimited_starts_everything_eligible() {
        let p = plan(
            &[
                e(1, 0, false, false),
                e(2, 1, true, false),
                e(3, 2, false, true),
            ],
            ActiveLimits::UNLIMITED,
        );
        assert_eq!(p.start, vec![TorrentId(1), TorrentId(2)]);
        assert!(p.stop.is_empty());
    }

    #[test]
    fn queue_order_decides_and_the_rest_is_stopped() {
        // Two download slots, three downloads: positions 0 and 1 run.
        let p = plan(
            &[
                e(1, 2, false, true),
                e(2, 0, false, false),
                e(3, 1, false, true),
            ],
            limits(Some(2), None, None),
        );
        assert_eq!(p.start, vec![TorrentId(2)]);
        assert_eq!(p.stop, vec![TorrentId(1)]);
    }

    #[test]
    fn seeds_and_downloads_have_their_own_slots_within_the_total() {
        let entries = [
            e(1, 0, false, false),
            e(2, 1, true, false),
            e(3, 2, true, false),
            e(4, 3, false, false),
        ];
        let p = plan(&entries, limits(Some(1), Some(1), None));
        assert_eq!(p.start, vec![TorrentId(1), TorrentId(2)]);
        let p = plan(&entries, limits(Some(5), Some(5), Some(3)));
        assert_eq!(p.start, vec![TorrentId(1), TorrentId(2), TorrentId(3)]);
        let p = plan(&entries, limits(None, Some(0), None));
        assert_eq!(p.start, vec![TorrentId(1), TorrentId(4)]);
    }

    #[test]
    fn forced_torrents_are_charged_first_and_never_stopped() {
        let mut forced = e(9, 5, false, true);
        forced.auto_managed = false;
        let p = plan(
            &[e(1, 0, false, true), forced.clone()],
            limits(Some(1), None, None),
        );
        // The forced one holds the only slot; the queued one stops.
        assert_eq!(p.stop, vec![TorrentId(1)]);
        assert!(p.start.is_empty());
        // A forced paused torrent is never started by the queue.
        forced.running = false;
        let p = plan(&[forced], limits(None, None, None));
        assert!(p.start.is_empty());
    }

    #[test]
    fn slow_torrents_hold_no_slot_unless_counted() {
        let mut slow = e(1, 0, false, true);
        slow.inactive = true;
        let entries = [slow, e(2, 1, false, false)];
        let p = plan(&entries, limits(Some(1), None, None));
        assert_eq!(p.start, vec![TorrentId(2)]);
        assert!(p.stop.is_empty(), "the slow one keeps running");
        let mut counted = limits(Some(1), None, None);
        counted.count_slow = true;
        let p = plan(&entries, counted);
        assert!(p.start.is_empty());
    }

    #[test]
    fn ineligible_torrents_are_ignored() {
        let mut paused = e(1, 0, false, false);
        paused.eligible = false;
        let p = plan(
            &[paused, e(2, 1, false, false)],
            limits(Some(1), None, None),
        );
        assert_eq!(p.start, vec![TorrentId(2)]);
    }
}
