# ADR 0009: The active-torrent queue lives in the library

Date: 2026-09-21 (0.7.0)

## Context

A client managing many torrents needs to bound how many are active at once:
"max active downloads / seeds / torrents" in qBittorrent, `active_downloads`
/ `active_seeds` / `active_limit` in libtorrent, where the mechanism lives
inside the library (auto-managed torrents). A frontend could emulate it with
`pause` / `resume`, but the decision needs engine facts at engine cadence: a
torrent's real state (checking, downloading, complete), whether it is moving
data (the slow-torrent exemption, without which one dead tracker blocks the
queue for good), and it must not race the engine's own transitions (a
torrent completing frees a download slot in the same tick). The maintainer's
review of missing configuration (docs/config.md) put it on the library side.

## Decision

- `ActiveLimits { downloads, seeds, total, count_slow }` on the session
  (`SessionBuilder::active_limits`, `Session::set_active_limits`), default
  unlimited so existing behaviour is unchanged until a limit is set.
- Per torrent: `auto_managed` (default true, persisted), a queue position
  (dense per session, persisted as the ordering key, restored on re-add),
  `TorrentState::Queued` for a torrent the queue stopped.
- `engine/queue.rs`: a pure planner (`plan`) over a snapshot of every
  torrent, walked in queue order, charging force-started torrents first,
  skipping slow running ones unless `count_slow`; the engine applies the
  plan (start = `torrent::resume`, stop = `torrent::pause` marked
  `auto_paused`). Runs once a second from the session ticker and at once on
  limit changes, moves, `resume`, `set_auto_managed`.
- Semantics of the public operations follow qBittorrent's use of libtorrent:
  `pause` takes the torrent out of the queue (else the queue would restart
  it), `resume` hands it back (it may end up `Queued`), `force_resume`
  bypasses the queue, `move_in_queue` reorders.
- A resume during a pause's wind-down is safe: `Torrent::stopping` makes the
  pause restart the tasks when its `stopped` announces are done, instead of
  two lifecycles overlapping.

## Consequences

- Seeds are ordered by queue position (libtorrent: `seed_rank`); documented
  as Q26. A frontend implementing ratio-based seed policies moves torrents
  or takes them out of the queue.
- Resume data format 4 (adds `auto_managed`, `queue_position`; older files
  load as managed, appended).
- `crates/session/tests/queue.rs` gates order, moves, force start, pause /
  resume interplay, the seed limit, persistence, and the per-torrent /
  session limits added alongside (`max_uploads`, add-time limits, runtime
  `set_unchoke_slots` / `set_max_connections` / `set_max_peers_per_torrent`).
