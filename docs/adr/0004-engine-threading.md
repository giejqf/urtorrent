# ADR 0004: Engine threading and cross-thread wakeups

- Status: accepted (2026-09-20)
- Relates to: AGENTS.md 5.3, 5.6; ADR 0001

## Context

The `session` engine must run peers, trackers, disk I/O and timers on io_uring
(rule 4) while exposing a tokio-native API (5.6) whose callers live on other
threads, and while SHA-1 hashing and DNS run on helper threads. Three things
need to cross into the ring thread: API commands, hash results and DNS results.
The `uring` executor's wakers are `Rc`-based and thread-local; calling one from
another thread would be unsound, and the runtime's park step is
`io_uring_enter(GETEVENTS)`, which only a CQE can end.

## Decision

1. **One `urt-net` thread hosts one `uring::Runtime`** with the command loop,
   the TCP accept loops and, per torrent, cooperating tasks: a tracker task,
   a one-second tick, and one task (plus a writer sub-task) per peer
   connection. Tasks share state through `Rc<RefCell<..>>`; no borrow is held
   across an `await`.
2. **A single eventfd (`uring::Notifier`) is the only way in.** Other threads
   push into a `Mutex` queue and `write(2)` the eventfd; the ring thread keeps
   one `IORING_OP_READ` on it in flight, and on completion drains the API
   command channel (`tokio::sync::mpsc`, `try_recv`), `HashPool::drain()` and
   `Dns::drain()`, which complete ring-local futures and wake their wakers *on
   the ring thread*. Local tasks that need the command loop use the same
   eventfd (a `write(2)` on the same thread), so the loop never drops its
   notifier future mid-flight and no wakeup can be lost.
3. **Hashing overlaps I/O.** `HashPool::verify_async` / `update_async` hand
   bytes to a worker and resolve through the eventfd; the blocking `verify`
   remains for callers without a reactor. The worker never touches a waker.
   Since 2026-09-20 pieces are hashed as they are written (a per-piece
   cursor advanced with `update_async` over each contiguous run) rather than
   read back once complete; the have-bit is still set only after every write
   of the piece completed.
4. **Disk I/O runs on its own ring (`urt-disk`), through a job queue.**
   (Amended 2026-09-20; M2–0.1.0 ran torrent file I/O on the network ring.)
   `storage::DiskRing` owns a second `uring::Runtime` thread that hosts every
   `storage::Storage` and the SHA-1 `HashPool` (whose completions it drains).
   The engine holds a `storage::DiskStore` per torrent: its async methods
   queue a job (`Mutex<VecDeque>` + the disk thread's eventfd) and resolve on
   the engine ring through a `uring::Bridge` ticket, rung by the engine's
   eventfd; the same rule as (2), in both directions. Ordering on the disk
   side is per piece (a verify waits for earlier writes to its piece and
   holds later ones) with full barriers for check / priorities / move / sync,
   so reads and writes of different pieces overlap. Peers batch the writes
   of one receive buffer and wait once; the uploader keeps several reads in
   flight. `SessionBuilder::disk_thread(false)` runs the same machinery
   inline on the network ring (no thread hop, same-thread completion slots)
   for hosts without a spare core. Measured on the 2-vCPU dev VM the two
   are within run-to-run noise of each other and of the old single-ring
   design (`docs/perf.md`); the split pays off where disk latency would
   otherwise stall peer sockets.
5. **Teardown cancels, never waits.** `Runtime::drop` issues `ASYNC_CANCEL`
   for every in-flight op and reaps with bounded waits, so abandoned `accept`s
   and timers cannot hang a shutting-down engine; buffers stay owned by the
   reactor until their CQE lands (leaked, never freed, if the kernel never
   answers).

6. **Choking and rate limiting live in a 100 ms session ticker.** The
   choker is a pure function over peer snapshots (`engine/choker.rs`) run
   every 15 s with a session-wide slot budget; token-bucket limiters
   (`engine/rate.rs`) are refilled by the same ticker and consulted by each
   peer's reader (before posting a receive, sizing the buffer to the grant)
   and writer (chunking sends to grants).

## Consequences

- `Session` handles are `Arc` around the command sender and a `NotifyHandle`;
  `build().await` completes on a `tokio::sync::oneshot` sent by the ring
  thread once the listeners are bound (no runtime feature of tokio is used).
- The `xtask check` tokio audit uses `cargo tree -p <lib>` per library crate,
  which resolves features for that crate alone: `testkit` may enable tokio's
  `rt`/`macros`/`time` for `urt-client` without them leaking into the audited
  graph, and none of those features pulls in `mio`.
- The one-connection-per-IP rule is decided symmetrically: of two connections
  between the same pair, the one initiated by the side with the lower peer id
  survives, so both ends close the same one.
