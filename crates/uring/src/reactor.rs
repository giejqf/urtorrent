// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The reactor: owns the `io_uring`, a slab of in-flight operations, and the
//! [`Op`] future that submits an SQE and resolves on its CQE.
//!
//! Buffer-ownership invariant (see crate docs): the resources an operation
//! hands to the kernel (buffers, sockaddrs, timespecs) live in the slab slot,
//! not in the future. They are dropped only when the CQE arrives — even if the
//! future was dropped first — so the kernel never touches freed memory.

use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use io_uring::{IoUring, opcode, squeue, types};

/// `user_data` reserved for internal cancel SQEs, whose CQEs we ignore. Slab
/// keys are small, so `u64::MAX` never collides with a real op.
const CANCEL_UD: u64 = u64::MAX;

thread_local! {
    static REACTOR: RefCell<Option<Rc<RefCell<Reactor>>>> = const { RefCell::new(None) };
}

/// Install `reactor` as the current thread's reactor for the duration of `f`.
pub(crate) fn scope<T>(reactor: &Rc<RefCell<Reactor>>, f: impl FnOnce() -> T) -> T {
    REACTOR.with(|slot| *slot.borrow_mut() = Some(reactor.clone()));
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            REACTOR.with(|slot| *slot.borrow_mut() = None);
        }
    }
    let _g = Guard;
    f()
}

/// The current thread's reactor, if one is installed.
pub(crate) fn try_current() -> Option<Rc<RefCell<Reactor>>> {
    REACTOR.with(|slot| slot.borrow().clone())
}

/// The current thread's reactor. Panics if called outside a [`Runtime`] — an
/// internal invariant (public APIs only reach here from inside `Runtime::run`).
pub(crate) fn current() -> Rc<RefCell<Reactor>> {
    try_current().expect("uring operation used outside a Runtime")
}

/// Submit a fire-and-forget `close(fd)` through the ring (used by `Drop`), or
/// fall back to a blocking `close` if no reactor is installed on this thread.
pub(crate) fn close_fd_detached(fd: i32) {
    match try_current() {
        Some(reactor) => reactor
            .borrow_mut()
            .submit_detached(|ud| opcode::Close::new(types::Fd(fd)).build().user_data(ud)),
        None => {
            // SAFETY: `fd` is owned by the caller (a Drop impl) and closed once.
            unsafe { libc::close(fd) };
        }
    }
}

enum Lifecycle {
    /// Submitted, no waker registered yet.
    Submitted,
    /// A task is parked on this op.
    Waiting(Waker),
    /// The CQE arrived with this result; the future has not taken it yet.
    Completed(i32),
    /// The future was dropped; free the slot (and resources) when the last
    /// CQE lands.
    Ignored,
    /// A multishot operation: completions queue up until the consumer takes
    /// them; `finished` once a CQE without `IORING_CQE_F_MORE` arrived.
    Multi {
        queue: VecDeque<(i32, u32)>,
        waker: Option<Waker>,
        finished: bool,
    },
}

/// Hook for resources that must react to completions the reactor discards
/// (an abandoned multishot recv whose CQEs still carry provided buffers).
pub(crate) trait Recycle {
    /// A discarded CQE with these flags arrived for the op owning `self`.
    fn recycle(&self, flags: u32);
}

struct Slot {
    lifecycle: Lifecycle,
    /// Resources the kernel is using; boxed so their address is stable.
    resources: Option<Box<dyn Any>>,
    /// Called for CQEs nobody will look at (see [`Recycle`]).
    recycler: Option<Rc<dyn Recycle>>,
    /// A CQE with `IORING_CQE_F_MORE` arrived for a single-shot op (a
    /// zero-copy send's result; its notification follows): the resources
    /// stay in the slot until that final CQE even after the result is taken.
    more_pending: bool,
}

/// A very small slab: a `Vec<Option<Slot>>` with a free list. Keys are indices.
#[derive(Default)]
struct Slab {
    entries: Vec<Option<Slot>>,
    free: Vec<usize>,
}

impl Slab {
    fn insert(&mut self, slot: Slot) -> usize {
        if let Some(key) = self.free.pop() {
            self.entries[key] = Some(slot);
            key
        } else {
            self.entries.push(Some(slot));
            self.entries.len() - 1
        }
    }
    fn get_mut(&mut self, key: usize) -> Option<&mut Slot> {
        self.entries.get_mut(key).and_then(Option::as_mut)
    }
    fn remove(&mut self, key: usize) -> Option<Slot> {
        let slot = self.entries.get_mut(key)?.take();
        if slot.is_some() {
            self.free.push(key);
        }
        slot
    }
}

/// The reactor state.
pub(crate) struct Reactor {
    ring: IoUring,
    slab: Slab,
    /// SQEs that did not fit in the submission queue yet.
    backlog: VecDeque<squeue::Entry>,
    /// Operations awaiting a CQE (excludes untracked cancel SQEs).
    in_flight: usize,
}

impl Reactor {
    pub(crate) fn new(entries: u32) -> io::Result<Reactor> {
        // One thread owns each ring and is the only submitter and waiter, so
        // completion work can be deferred to our own `io_uring_enter` calls
        // (`SINGLE_ISSUER` + `DEFER_TASKRUN`, 6.1) instead of interrupting
        // the thread with task work: fewer context switches per completion.
        // Both flags exist since 6.0/6.1, inside the kernel baseline.
        let ring = IoUring::builder()
            .setup_single_issuer()
            .setup_defer_taskrun()
            .build(entries)
            .or_else(|_| IoUring::builder().setup_coop_taskrun().build(entries))
            .or_else(|_| IoUring::new(entries))?;
        Ok(Reactor {
            ring,
            slab: Slab::default(),
            backlog: VecDeque::new(),
            in_flight: 0,
        })
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Submit an operation. `resources` are moved into the slab (stable
    /// address); `build` receives `&mut T` and the assigned `user_data` and
    /// returns the SQE. Returns the slab key the [`Op`] future watches.
    fn submit<T: 'static>(
        &mut self,
        resources: T,
        build: impl FnOnce(&mut T, u64) -> squeue::Entry,
    ) -> usize {
        let key = self.slab.insert(Slot {
            lifecycle: Lifecycle::Submitted,
            resources: Some(Box::new(resources)),
            recycler: None,
            more_pending: false,
        });
        let entry = {
            let slot = self.slab.get_mut(key).expect("just inserted");
            let res = slot
                .resources
                .as_mut()
                .expect("just set")
                .downcast_mut::<T>()
                .expect("type matches");
            build(res, key as u64)
        };
        self.push(entry);
        self.in_flight += 1;
        key
    }

    /// Submit an operation whose completion nobody awaits (e.g. a `close` from
    /// a `Drop`). The slot is created already-`Ignored`, so the CQE just frees
    /// it. No resources are held.
    fn submit_detached(&mut self, build: impl FnOnce(u64) -> squeue::Entry) {
        let key = self.slab.insert(Slot {
            lifecycle: Lifecycle::Ignored,
            resources: None,
            recycler: None,
            more_pending: false,
        });
        let entry = build(key as u64);
        self.push(entry);
        self.in_flight += 1;
    }

    /// Submit a multishot operation: its CQEs queue in the slot until
    /// [`MultiOp::poll_next`] takes them. `recycler` sees the CQEs that
    /// arrive after the consumer is gone.
    fn submit_multi(
        &mut self,
        recycler: Rc<dyn Recycle>,
        build: impl FnOnce(u64) -> squeue::Entry,
    ) -> usize {
        let key = self.slab.insert(Slot {
            lifecycle: Lifecycle::Multi {
                queue: VecDeque::new(),
                waker: None,
                finished: false,
            },
            resources: None,
            recycler: Some(recycler),
            more_pending: false,
        });
        let entry = build(key as u64);
        self.push(entry);
        self.in_flight += 1;
        key
    }

    /// Register a provided-buffer ring (`IORING_REGISTER_PBUF_RING`).
    ///
    /// # Safety
    /// `ring_addr` must point at `entries` page-aligned `io_uring_buf`
    /// entries that stay mapped until `unregister_buf_ring`.
    pub(crate) unsafe fn register_buf_ring(
        &self,
        ring_addr: u64,
        entries: u16,
        bgid: u16,
    ) -> io::Result<()> {
        // SAFETY: forwarded to the caller's contract.
        unsafe {
            self.ring
                .submitter()
                .register_buf_ring_with_flags(ring_addr, entries, bgid, 0)
        }
    }

    pub(crate) fn unregister_buf_ring(&self, bgid: u16) -> io::Result<()> {
        self.ring.submitter().unregister_buf_ring(bgid)
    }

    /// Enqueue an SQE, spilling to the backlog if the submission queue is full.
    fn push(&mut self, entry: squeue::Entry) {
        // SAFETY: every pointer referenced by `entry` (buffer / sockaddr /
        // timespec) lives in a slab slot keyed by the entry's `user_data`, and
        // that slot is only freed when the CQE arrives (see `reap`). The entry
        // therefore refers to memory that outlives the kernel's use of it.
        let full = unsafe { self.ring.submission().push(&entry).is_err() };
        if full {
            self.backlog.push_back(entry);
        }
    }

    /// Move backlogged SQEs into the submission queue where they fit.
    fn flush_backlog(&mut self) {
        while let Some(entry) = self.backlog.front().cloned() {
            // SAFETY: as in `push` — the referenced memory is owned by a slab
            // slot that outlives the operation.
            let ok = unsafe { self.ring.submission().push(&entry).is_ok() };
            if ok {
                self.backlog.pop_front();
            } else {
                break;
            }
        }
    }

    /// Reap all available completions: record results and collect wakers.
    /// Wakers are returned so the caller can wake them without holding the
    /// reactor borrow (waking may poll a task that submits more ops).
    fn reap(&mut self, wakers: &mut Vec<Waker>) {
        self.ring.completion().sync();
        // Collect first; `completion()` borrows the ring mutably.
        let mut done: Vec<(u64, i32, u32)> = Vec::new();
        {
            let cq = self.ring.completion();
            for cqe in cq {
                done.push((cqe.user_data(), cqe.result(), cqe.flags()));
            }
        }
        for (ud, res, flags) in done {
            if ud == CANCEL_UD {
                continue; // untracked cancel CQE
            }
            let key = ud as usize;
            // The op is over unless the kernel promised more CQEs.
            let last = !io_uring::cqueue::more(flags);
            let mut remove = false;
            if let Some(slot) = self.slab.get_mut(key) {
                match &mut slot.lifecycle {
                    Lifecycle::Multi {
                        queue,
                        waker,
                        finished,
                    } => {
                        queue.push_back((res, flags));
                        *finished |= last;
                        if let Some(w) = waker.take() {
                            wakers.push(w);
                        }
                    }
                    Lifecycle::Ignored => {
                        if let Some(r) = &slot.recycler {
                            r.recycle(flags);
                        }
                        remove = last;
                    }
                    Lifecycle::Completed(_) => {
                        // The notification of a zero-copy send whose result
                        // was already recorded but not yet taken: the
                        // buffers may now go when the future takes it.
                        slot.more_pending = false;
                    }
                    lc => {
                        if let Lifecycle::Waiting(w) =
                            std::mem::replace(lc, Lifecycle::Completed(res))
                        {
                            wakers.push(w);
                        }
                        slot.more_pending = !last;
                    }
                }
            }
            if remove {
                self.slab.remove(key); // drops resources now that the kernel is done
            }
            if last {
                self.in_flight = self.in_flight.saturating_sub(1);
            }
        }
    }

    /// Cancel every operation still in flight (used at teardown): each slot is
    /// marked ignored and an `ASYNC_CANCEL` is queued, so the kernel completes
    /// it promptly (with `-ECANCELED` or its natural result) and the slot's
    /// resources are freed when that CQE lands. The displaced wakers are
    /// returned so the caller drops them after releasing the reactor borrow
    /// (dropping a waker can drop a task whose future abandons another op).
    pub(crate) fn cancel_all(&mut self) -> Vec<Waker> {
        let mut wakers = Vec::new();
        let keys: Vec<usize> = self
            .slab
            .entries
            .iter()
            .enumerate()
            .filter_map(|(k, s)| {
                s.as_ref()
                    .filter(|s| {
                        matches!(
                            s.lifecycle,
                            Lifecycle::Submitted
                                | Lifecycle::Waiting(_)
                                | Lifecycle::Multi {
                                    finished: false,
                                    ..
                                }
                        )
                    })
                    .map(|_| k)
            })
            .collect();
        for key in keys {
            if let Some(slot) = self.slab.get_mut(key) {
                match std::mem::replace(&mut slot.lifecycle, Lifecycle::Ignored) {
                    Lifecycle::Waiting(w) => wakers.push(w),
                    Lifecycle::Multi {
                        queue,
                        waker: Some(w),
                        ..
                    } => {
                        wakers.push(w);
                        // Queued-but-untaken completions still own buffers.
                        if let Some(r) = &slot.recycler {
                            for (_, flags) in queue {
                                r.recycle(flags);
                            }
                        }
                    }
                    Lifecycle::Multi { queue, .. } => {
                        if let Some(r) = &slot.recycler {
                            for (_, flags) in queue {
                                r.recycle(flags);
                            }
                        }
                    }
                    _ => {}
                }
            }
            let cancel = opcode::AsyncCancel::new(key as u64)
                .build()
                .user_data(CANCEL_UD);
            self.push(cancel);
        }
        wakers
    }

    /// Forget the resources of every slot still in flight (teardown fallback
    /// when the kernel never completed them): leaking is the only safe option.
    pub(crate) fn leak_in_flight(&mut self) {
        for slot in self.slab.entries.iter_mut().flatten() {
            if let Some(res) = slot.resources.take() {
                std::mem::forget(res);
            }
        }
    }

    /// Like `tick(true)` but never blocks longer than `timeout` (teardown
    /// safety net: a kernel that does not complete a cancelled op must not
    /// hang the thread forever).
    pub(crate) fn tick_timeout(&mut self, timeout: std::time::Duration) -> Vec<Waker> {
        self.flush_backlog();
        let ts = types::Timespec::new()
            .sec(timeout.as_secs())
            .nsec(timeout.subsec_nanos());
        let args = types::SubmitArgs::new().timespec(&ts);
        let want = if self.in_flight > 0 { 1 } else { 0 };
        match self.ring.submitter().submit_with_args(want, &args) {
            Ok(_) => {}
            Err(ref e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EBUSY) | Some(libc::ETIME) | Some(libc::EINTR)
                ) => {}
            Err(e) => tracing::error!("io_uring submit failed: {e}"),
        }
        let mut wakers = Vec::new();
        self.reap(&mut wakers);
        wakers
    }

    /// Flush pending SQEs and, if `wait` and there is something to wait for,
    /// block for at least one completion. Then reap. Returns woken wakers.
    pub(crate) fn tick(&mut self, wait: bool) -> Vec<Waker> {
        self.flush_backlog();
        let want = if wait && self.in_flight > 0 { 1 } else { 0 };
        match self.ring.submit_and_wait(want) {
            Ok(_) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EBUSY) => {
                // CQ overflow / not enough room: reap and retry next tick.
            }
            Err(e) => tracing::error!("io_uring submit failed: {e}"),
        }
        let mut wakers = Vec::new();
        self.reap(&mut wakers);
        wakers
    }

    /// Register (or replace) the waker for op `key`, or take its result.
    fn poll(&mut self, key: usize, cx: &mut Context<'_>) -> Poll<(i32, Box<dyn Any>)> {
        let Some(slot) = self.slab.get_mut(key) else {
            return Poll::Pending;
        };
        match &mut slot.lifecycle {
            Lifecycle::Completed(res) => {
                let res = *res;
                let removed = self.slab.remove(key).expect("present");
                Poll::Ready((res, removed.resources.expect("resources present")))
            }
            lc => {
                *lc = Lifecycle::Waiting(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Next completion of multishot op `key`: `Ready(Some)` with a queued
    /// `(result, flags)`, `Ready(None)` once the op finished and the queue is
    /// drained (the slot is freed), `Pending` otherwise.
    fn poll_multi(&mut self, key: usize, cx: &mut Context<'_>) -> Poll<Option<(i32, u32)>> {
        let Some(slot) = self.slab.get_mut(key) else {
            return Poll::Ready(None);
        };
        let Lifecycle::Multi {
            queue,
            waker,
            finished,
        } = &mut slot.lifecycle
        else {
            return Poll::Ready(None);
        };
        if let Some(c) = queue.pop_front() {
            return Poll::Ready(Some(c));
        }
        if *finished {
            self.slab.remove(key);
            return Poll::Ready(None);
        }
        *waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// A queued completion of multishot op `key` if one is waiting (no waker
    /// registered): `Some(Some)` a completion, `Some(None)` the op finished
    /// and is drained (slot freed), `None` nothing yet.
    fn try_take_multi(&mut self, key: usize) -> Option<Option<(i32, u32)>> {
        let Some(slot) = self.slab.get_mut(key) else {
            return Some(None);
        };
        let Lifecycle::Multi {
            queue, finished, ..
        } = &mut slot.lifecycle
        else {
            return Some(None);
        };
        if let Some(c) = queue.pop_front() {
            return Some(Some(c));
        }
        if *finished {
            self.slab.remove(key);
            return Some(None);
        }
        None
    }

    /// The consumer of multishot op `key` is gone: recycle what it never
    /// took, and cancel the op if the kernel still runs it.
    fn abandon_multi(&mut self, key: usize) {
        let Some(slot) = self.slab.get_mut(key) else {
            return;
        };
        let Lifecycle::Multi {
            queue, finished, ..
        } = std::mem::replace(&mut slot.lifecycle, Lifecycle::Ignored)
        else {
            return;
        };
        if let Some(r) = &slot.recycler {
            for (_, flags) in queue {
                r.recycle(flags);
            }
        }
        if finished {
            self.slab.remove(key);
            return;
        }
        let cancel = opcode::AsyncCancel::new(key as u64)
            .build()
            .user_data(CANCEL_UD);
        self.push(cancel);
    }

    /// Like [`Reactor::poll`] for an op whose resources never come back to
    /// the future (a zero-copy send): the result is handed out at the first
    /// CQE, and the slot keeps the buffers until the kernel's notification
    /// CQE says it is done with them.
    fn poll_result_only(&mut self, key: usize, cx: &mut Context<'_>) -> Poll<i32> {
        let Some(slot) = self.slab.get_mut(key) else {
            return Poll::Pending;
        };
        match &mut slot.lifecycle {
            Lifecycle::Completed(res) => {
                let res = *res;
                if slot.more_pending {
                    slot.lifecycle = Lifecycle::Ignored;
                } else {
                    self.slab.remove(key);
                }
                Poll::Ready(res)
            }
            lc => {
                *lc = Lifecycle::Waiting(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Mark op `key` abandoned (its future was dropped) and submit a cancel.
    fn abandon(&mut self, key: usize) {
        let (already_done, more_pending) = match self.slab.get_mut(key) {
            Some(slot) => (
                matches!(slot.lifecycle, Lifecycle::Completed(_)),
                slot.more_pending,
            ),
            None => (true, false),
        };
        if already_done {
            if more_pending {
                // A zero-copy send's result is in but its notification is
                // not: keep the buffers until it lands.
                if let Some(slot) = self.slab.get_mut(key) {
                    slot.lifecycle = Lifecycle::Ignored;
                }
                return;
            }
            // Result already here (or slot gone); just drop it.
            self.slab.remove(key);
            return;
        }
        if let Some(slot) = self.slab.get_mut(key) {
            slot.lifecycle = Lifecycle::Ignored;
        }
        // Ask the kernel to cancel; the original op's CQE will free the slot.
        let cancel = opcode::AsyncCancel::new(key as u64)
            .build()
            .user_data(CANCEL_UD);
        self.push(cancel);
    }
}

/// A future over one io_uring operation, resolving to `(result, resources)`.
/// `result` is the raw CQE value (>= 0 on success, negative errno on failure).
pub(crate) struct Op<T: 'static> {
    reactor: Rc<RefCell<Reactor>>,
    key: usize,
    done: bool,
    _marker: std::marker::PhantomData<T>,
}

impl<T: 'static> Op<T> {
    /// Submit an operation onto the current thread's reactor.
    pub(crate) fn submit(resources: T, build: impl FnOnce(&mut T, u64) -> squeue::Entry) -> Op<T> {
        let reactor = current();
        let key = reactor.borrow_mut().submit(resources, build);
        Op {
            reactor,
            key,
            done: false,
            _marker: std::marker::PhantomData,
        }
    }
}

// `Op<T>` never pins a `T` (resources live in the slab, not the future), so it
// is always `Unpin` regardless of `T`.
impl<T: 'static> Unpin for Op<T> {}

impl<T: 'static> Future for Op<T> {
    type Output = (i32, T);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let poll = this.reactor.borrow_mut().poll(this.key, cx);
        match poll {
            Poll::Ready((res, resources)) => {
                this.done = true;
                let typed = resources.downcast::<T>().expect("resource type matches op");
                Poll::Ready((res, *typed))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: 'static> Drop for Op<T> {
    fn drop(&mut self) {
        if !this_done(self) {
            self.reactor.borrow_mut().abandon(self.key);
        }
    }
}

fn this_done<T: 'static>(op: &Op<T>) -> bool {
    op.done
}

/// A one-result operation whose resources stay with the reactor until the
/// kernel's last CQE (zero-copy sends): resolves to the raw CQE result.
pub(crate) struct ResultOp {
    reactor: Rc<RefCell<Reactor>>,
    key: usize,
    done: bool,
}

impl ResultOp {
    pub(crate) fn submit<T: 'static>(
        resources: T,
        build: impl FnOnce(&mut T, u64) -> squeue::Entry,
    ) -> ResultOp {
        let reactor = current();
        let key = reactor.borrow_mut().submit(resources, build);
        ResultOp {
            reactor,
            key,
            done: false,
        }
    }
}

impl Future for ResultOp {
    type Output = i32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<i32> {
        let this = self.get_mut();
        let p = this.reactor.borrow_mut().poll_result_only(this.key, cx);
        if p.is_ready() {
            this.done = true;
        }
        p
    }
}

impl Drop for ResultOp {
    fn drop(&mut self) {
        if !self.done {
            self.reactor.borrow_mut().abandon(self.key);
        }
    }
}

/// A multishot io_uring operation: a stream of `(result, flags)` completions
/// ending with the CQE that lacks `IORING_CQE_F_MORE`.
pub(crate) struct MultiOp {
    reactor: Rc<RefCell<Reactor>>,
    key: usize,
    ended: bool,
}

impl MultiOp {
    /// Submit a multishot operation on the current thread's reactor.
    pub(crate) fn submit(
        recycler: Rc<dyn Recycle>,
        build: impl FnOnce(u64) -> squeue::Entry,
    ) -> MultiOp {
        let reactor = current();
        let key = reactor.borrow_mut().submit_multi(recycler, build);
        MultiOp {
            reactor,
            key,
            ended: false,
        }
    }

    /// Wait for the next completion; `None` once the operation is over.
    pub(crate) fn next(&mut self) -> impl Future<Output = Option<(i32, u32)>> + '_ {
        std::future::poll_fn(move |cx| {
            if self.ended {
                return Poll::Ready(None);
            }
            let p = self.reactor.borrow_mut().poll_multi(self.key, cx);
            if let Poll::Ready(None) = p {
                self.ended = true;
            }
            p
        })
    }
}

impl MultiOp {
    /// A completion already delivered, without waiting: `Some(Some)` one,
    /// `Some(None)` the operation is over, `None` nothing queued.
    pub(crate) fn try_next(&mut self) -> Option<Option<(i32, u32)>> {
        if self.ended {
            return Some(None);
        }
        let r = self.reactor.borrow_mut().try_take_multi(self.key);
        if let Some(None) = r {
            self.ended = true;
        }
        r
    }
}

impl Drop for MultiOp {
    fn drop(&mut self) {
        if !self.ended {
            self.reactor.borrow_mut().abandon_multi(self.key);
        }
    }
}

/// Map a CQE result to an `io::Result<u32>` (>= 0 is the byte count / fd).
pub(crate) fn cqe_result(res: i32) -> io::Result<u32> {
    if res < 0 {
        Err(io::Error::from_raw_os_error(-res))
    } else {
        Ok(res as u32)
    }
}

// --- opcode wrappers used by net/fs/timer ---

pub(crate) use ops::*;

mod ops {
    use super::*;
    use crate::bufpool::Buffer;

    /// `nop` — used only by tests to prove the reactor round-trips a CQE.
    #[cfg(test)]
    pub(crate) async fn nop() -> i32 {
        Op::submit((), |_, ud| opcode::Nop::new().build().user_data(ud))
            .await
            .0
    }

    /// `send` all-in-one: kernel reads from `buf`.
    pub(crate) async fn send(fd: i32, buf: Buffer) -> (io::Result<u32>, Buffer) {
        let len = buf.len();
        send_range(fd, buf, 0, len).await
    }

    /// `send` of `buf[start..start + len]` without copying: the whole buffer
    /// stays in the slab slot, the SQE points into it.
    pub(crate) async fn send_range(
        fd: i32,
        buf: Buffer,
        start: usize,
        len: usize,
    ) -> (io::Result<u32>, Buffer) {
        debug_assert!(start + len <= buf.len());
        let (res, buf) = Op::submit(buf, |b, ud| {
            // SAFETY: `start + len <= b.len()`, so the pointer stays inside
            // the buffer's initialised bytes, which the slab keeps alive
            // until the CQE.
            let ptr = unsafe { b.as_ptr().add(start) };
            opcode::Send::new(types::Fd(fd), ptr, len as u32)
                .build()
                .user_data(ud)
        })
        .await;
        (cqe_result(res), buf)
    }

    /// `recv`: kernel writes into `buf` (sized to its length); returns filled bytes.
    pub(crate) async fn recv(fd: i32, mut buf: Buffer) -> (io::Result<u32>, Buffer) {
        let (res, mut buf) = Op::submit(
            std::mem::replace(&mut buf, Buffer::from_vec(Vec::new())),
            |b, ud| {
                let len = b.len() as u32;
                opcode::Recv::new(types::Fd(fd), b.as_mut_ptr(), len)
                    .build()
                    .user_data(ud)
            },
        )
        .await;
        let r = cqe_result(res);
        if let Ok(n) = r {
            buf.truncate(n as usize);
        }
        (r, buf)
    }

    /// Resources for an unconnected UDP `sendmsg`/`recvmsg`: the buffer, the
    /// sockaddr storage, the iovec and the msghdr all live in the slab slot
    /// for the op's lifetime.
    pub(crate) struct MsgRes {
        pub buf: Buffer,
        pub addr: crate::net::RawSockAddr,
        pub iov: libc::iovec,
        pub hdr: libc::msghdr,
    }

    impl MsgRes {
        fn new(buf: Buffer, addr: crate::net::RawSockAddr) -> Box<MsgRes> {
            // SAFETY: zeroed iovec/msghdr are valid all-zero PODs; they are
            // filled in by `wire_up` once the box has a stable address.
            let (iov, hdr) = unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
            Box::new(MsgRes {
                buf,
                addr,
                iov,
                hdr,
            })
        }

        /// Point the msghdr at this struct's own buffer and address. Must be
        /// called on the boxed (address-stable) value.
        fn wire_up(&mut self) {
            self.iov.iov_base = self.buf.as_mut_ptr() as *mut libc::c_void;
            self.iov.iov_len = self.buf.len();
            self.hdr.msg_name = self.addr.as_mut_ptr() as *mut libc::c_void;
            self.hdr.msg_namelen = self.addr.capacity();
            self.hdr.msg_iov = &mut self.iov;
            self.hdr.msg_iovlen = 1;
        }
    }

    /// Resources for a vectored `sendmsg` on a connected socket: the chunks,
    /// the iovec array over the byte range being sent, and the msghdr.
    pub(crate) struct VecMsgRes {
        pub bufs: Vec<Buffer>,
        pub iovs: Vec<libc::iovec>,
        pub hdr: libc::msghdr,
    }

    impl VecMsgRes {
        fn new(bufs: Vec<Buffer>) -> Box<VecMsgRes> {
            // SAFETY: an all-zero msghdr is a valid POD; `wire_up` fills it.
            let hdr = unsafe { std::mem::zeroed() };
            Box::new(VecMsgRes {
                bufs,
                iovs: Vec::new(),
                hdr,
            })
        }

        /// Point the iovecs at bytes `[start, start + len)` of the chunks'
        /// concatenation (at most `max_iov` entries) and the msghdr at them.
        /// Must be called on the boxed (address-stable) value. Returns the
        /// number of bytes covered.
        fn wire_up(&mut self, start: usize, len: usize, max_iov: usize) -> usize {
            self.iovs.clear();
            let mut skip = start;
            let mut left = len;
            for b in &self.bufs {
                if left == 0 || self.iovs.len() == max_iov {
                    break;
                }
                let n = b.len();
                if skip >= n {
                    skip -= n;
                    continue;
                }
                let take = (n - skip).min(left);
                // SAFETY: `skip < n`, so the pointer is inside the buffer,
                // which the slab keeps alive until the CQE.
                let base = unsafe { b.as_ptr().add(skip) } as *mut libc::c_void;
                self.iovs.push(libc::iovec {
                    iov_base: base,
                    iov_len: take,
                });
                left -= take;
                skip = 0;
            }
            self.hdr.msg_iov = self.iovs.as_mut_ptr();
            self.hdr.msg_iovlen = self.iovs.len();
            len - left
        }
    }

    /// One `sendmsg` of bytes `[start, start + len)` of `bufs` (as many
    /// iovecs as fit); returns the CQE result and the chunks.
    pub(crate) async fn send_chunks(
        fd: i32,
        bufs: Vec<Buffer>,
        start: usize,
        len: usize,
    ) -> (io::Result<u32>, Vec<Buffer>) {
        const MAX_IOV: usize = 64;
        let mut res = VecMsgRes::new(bufs);
        let covered = res.wire_up(start, len, MAX_IOV);
        if covered == 0 {
            return (Ok(0), res.bufs);
        }
        let (r, res) = Op::submit(res, |b, ud| {
            opcode::SendMsg::new(types::Fd(fd), &b.hdr as *const libc::msghdr)
                .flags(libc::MSG_NOSIGNAL as u32)
                .build()
                .user_data(ud)
        })
        .await;
        (cqe_result(r), res.bufs)
    }

    /// Zero-copy `sendmsg` (`IORING_OP_SENDMSG_ZC`) of bytes `[start, start +
    /// len)` of `bufs`: the kernel maps the buffers instead of copying them
    /// into socket memory and references them until the data is acknowledged,
    /// so `bufs` is shared with the slot (an `Rc`) and freed when both the
    /// caller and the notification CQE are done with it.
    pub(crate) async fn send_chunks_zc(
        fd: i32,
        bufs: Rc<Vec<Buffer>>,
        start: usize,
        len: usize,
    ) -> io::Result<u32> {
        const MAX_IOV: usize = 64;
        let mut res = ZcMsgRes::new(bufs);
        let covered = res.wire_up(start, len, MAX_IOV);
        if covered == 0 {
            return Ok(0);
        }
        let r = ResultOp::submit(res, |b, ud| {
            opcode::SendMsgZc::new(types::Fd(fd), &b.hdr as *const libc::msghdr)
                .flags(libc::MSG_NOSIGNAL as u32)
                .build()
                .user_data(ud)
        })
        .await;
        cqe_result(r)
    }

    /// Resources of a zero-copy vectored send: shared chunks plus this op's
    /// own iovec array and msghdr.
    pub(crate) struct ZcMsgRes {
        pub bufs: Rc<Vec<Buffer>>,
        pub iovs: Vec<libc::iovec>,
        pub hdr: libc::msghdr,
    }

    impl ZcMsgRes {
        fn new(bufs: Rc<Vec<Buffer>>) -> Box<ZcMsgRes> {
            // SAFETY: an all-zero msghdr is a valid POD; `wire_up` fills it.
            let hdr = unsafe { std::mem::zeroed() };
            Box::new(ZcMsgRes {
                bufs,
                iovs: Vec::new(),
                hdr,
            })
        }

        fn wire_up(&mut self, start: usize, len: usize, max_iov: usize) -> usize {
            self.iovs.clear();
            let mut skip = start;
            let mut left = len;
            for b in self.bufs.iter() {
                if left == 0 || self.iovs.len() == max_iov {
                    break;
                }
                let n = b.len();
                if skip >= n {
                    skip -= n;
                    continue;
                }
                let take = (n - skip).min(left);
                // SAFETY: `skip < n`; the chunks live as long as the slot
                // holds the `Rc` (until the notification CQE).
                let base = unsafe { b.as_ptr().add(skip) } as *mut libc::c_void;
                self.iovs.push(libc::iovec {
                    iov_base: base,
                    iov_len: take,
                });
                left -= take;
                skip = 0;
            }
            self.hdr.msg_iov = self.iovs.as_mut_ptr();
            self.hdr.msg_iovlen = self.iovs.len();
            len - left
        }
    }

    /// `sendmsg` of `buf` to `addr` on an unconnected socket.
    pub(crate) async fn send_to(
        fd: i32,
        buf: Buffer,
        addr: crate::net::RawSockAddr,
    ) -> (io::Result<u32>, Buffer) {
        let mut res = MsgRes::new(buf, addr);
        res.wire_up();
        res.hdr.msg_namelen = res.addr.len();
        let (r, res) = Op::submit(res, |b, ud| {
            opcode::SendMsg::new(types::Fd(fd), &b.hdr as *const libc::msghdr)
                .build()
                .user_data(ud)
        })
        .await;
        (cqe_result(r), res.buf)
    }

    /// `recvmsg` into `buf` (sized to its length); returns the filled buffer
    /// and the sender's address.
    pub(crate) async fn recv_from(
        fd: i32,
        mut buf: Buffer,
    ) -> (io::Result<u32>, Buffer, Option<std::net::SocketAddr>) {
        let taken = std::mem::replace(&mut buf, Buffer::from_vec(Vec::new()));
        let mut res = MsgRes::new(taken, crate::net::RawSockAddr::empty());
        res.wire_up();
        let (r, mut res) = Op::submit(res, |b, ud| {
            opcode::RecvMsg::new(types::Fd(fd), &mut b.hdr as *mut libc::msghdr)
                .build()
                .user_data(ud)
        })
        .await;
        let result = cqe_result(r);
        let from = match &result {
            Ok(_) => res.addr.to_std(res.hdr.msg_namelen),
            Err(_) => None,
        };
        if let Ok(n) = result {
            res.buf.truncate(n as usize);
        }
        (result, res.buf, from)
    }

    /// `connect` to a prepared sockaddr.
    pub(crate) async fn connect(fd: i32, addr: crate::net::RawSockAddr) -> io::Result<()> {
        let (res, _addr) = Op::submit(addr, |a, ud| {
            opcode::Connect::new(types::Fd(fd), a.as_ptr(), a.len())
                .build()
                .user_data(ud)
        })
        .await;
        cqe_result(res).map(|_| ())
    }

    /// `accept`: returns the new connection fd.
    pub(crate) async fn accept(fd: i32) -> io::Result<i32> {
        let (res, ()) = Op::submit((), |_, ud| {
            opcode::Accept::new(types::Fd(fd), std::ptr::null_mut(), std::ptr::null_mut())
                .build()
                .user_data(ud)
        })
        .await;
        cqe_result(res).map(|fd| fd as i32)
    }

    /// `read` at `offset`: kernel writes into `buf`; returns filled bytes.
    pub(crate) async fn read_at(
        fd: i32,
        offset: u64,
        mut buf: Buffer,
    ) -> (io::Result<u32>, Buffer) {
        let (res, mut buf) = Op::submit(
            std::mem::replace(&mut buf, Buffer::from_vec(Vec::new())),
            |b, ud| {
                let len = b.len() as u32;
                opcode::Read::new(types::Fd(fd), b.as_mut_ptr(), len)
                    .offset(offset)
                    .build()
                    .user_data(ud)
            },
        )
        .await;
        let r = cqe_result(res);
        if let Ok(n) = r {
            buf.truncate(n as usize);
        }
        (r, buf)
    }

    /// `write` at `offset`: kernel reads from `buf`; returns bytes written.
    pub(crate) async fn write_at(fd: i32, offset: u64, buf: Buffer) -> (io::Result<u32>, Buffer) {
        let len = buf.len();
        write_range_at(fd, offset, buf, 0, len).await
    }

    /// `write` of `buf[start..start + len]` at `offset` without copying.
    pub(crate) async fn write_range_at(
        fd: i32,
        offset: u64,
        buf: Buffer,
        start: usize,
        len: usize,
    ) -> (io::Result<u32>, Buffer) {
        debug_assert!(start + len <= buf.len());
        let (res, buf) = Op::submit(buf, |b, ud| {
            // SAFETY: `start + len <= b.len()`; the slab keeps `b` alive
            // until the CQE.
            let ptr = unsafe { b.as_ptr().add(start) };
            opcode::Write::new(types::Fd(fd), ptr, len as u32)
                .offset(offset)
                .build()
                .user_data(ud)
        })
        .await;
        (cqe_result(res), buf)
    }

    /// `read` at `offset` into `buf[start..start + len]` without a temporary
    /// buffer; returns the bytes read (the caller tracks the fill).
    pub(crate) async fn read_range_at(
        fd: i32,
        offset: u64,
        buf: Buffer,
        start: usize,
        len: usize,
    ) -> (io::Result<u32>, Buffer) {
        debug_assert!(start + len <= buf.len());
        let (res, buf) = Op::submit(buf, |b, ud| {
            // SAFETY: as above; the kernel writes at most `len` bytes from
            // `start`, inside the buffer's length.
            let ptr = unsafe { b.as_mut_ptr().add(start) };
            opcode::Read::new(types::Fd(fd), ptr, len as u32)
                .offset(offset)
                .build()
                .user_data(ud)
        })
        .await;
        (cqe_result(res), buf)
    }

    /// `fsync` (or fdatasync when `data_only`).
    pub(crate) async fn fsync(fd: i32, data_only: bool) -> io::Result<()> {
        let flags = if data_only {
            types::FsyncFlags::DATASYNC
        } else {
            types::FsyncFlags::empty()
        };
        let (res, ()) = Op::submit((), |_, ud| {
            opcode::Fsync::new(types::Fd(fd))
                .flags(flags)
                .build()
                .user_data(ud)
        })
        .await;
        cqe_result(res).map(|_| ())
    }

    /// `fallocate` `len` bytes from `offset`.
    pub(crate) async fn fallocate(fd: i32, offset: u64, len: u64) -> io::Result<()> {
        let (res, ()) = Op::submit((), |_, ud| {
            opcode::Fallocate::new(types::Fd(fd), len)
                .offset(offset)
                .build()
                .user_data(ud)
        })
        .await;
        cqe_result(res).map(|_| ())
    }

    /// `openat` relative to the cwd (`AT_FDCWD`): the path lives in the op's
    /// resources until the CQE. Returns the new fd.
    pub(crate) async fn openat(
        path: std::ffi::CString,
        flags: i32,
        mode: libc::mode_t,
    ) -> io::Result<i32> {
        let (res, _path) = Op::submit(Box::new(path), |p, ud| {
            opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), p.as_ptr())
                .flags(flags)
                .mode(mode)
                .build()
                .user_data(ud)
        })
        .await;
        cqe_result(res).map(|fd| fd as i32)
    }

    /// `close`.
    pub(crate) async fn close(fd: i32) -> io::Result<()> {
        let (res, ()) = Op::submit((), |_, ud| {
            opcode::Close::new(types::Fd(fd)).build().user_data(ud)
        })
        .await;
        cqe_result(res).map(|_| ())
    }

    /// A standalone `timeout` that fires after `ts`. Resolves to the CQE result
    /// (`-ETIME` when it elapses normally).
    pub(crate) async fn timeout(ts: types::Timespec) -> i32 {
        Op::submit(Box::new(ts), |b, ud| {
            opcode::Timeout::new(&**b as *const types::Timespec)
                .build()
                .user_data(ud)
        })
        .await
        .0
    }
}
