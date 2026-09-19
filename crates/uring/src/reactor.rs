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
    /// The future was dropped; free the slot (and resources) when the CQE lands.
    Ignored,
}

struct Slot {
    lifecycle: Lifecycle,
    /// Resources the kernel is using; boxed so their address is stable.
    resources: Option<Box<dyn Any>>,
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
        let ring = IoUring::new(entries)?;
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
        });
        let entry = build(key as u64);
        self.push(entry);
        self.in_flight += 1;
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
        let mut done: Vec<(u64, i32)> = Vec::new();
        {
            let cq = self.ring.completion();
            for cqe in cq {
                done.push((cqe.user_data(), cqe.result()));
            }
        }
        for (ud, res) in done {
            if ud == CANCEL_UD {
                continue; // untracked cancel CQE
            }
            let key = ud as usize;
            let mut remove = false;
            if let Some(slot) = self.slab.get_mut(key) {
                match std::mem::replace(&mut slot.lifecycle, Lifecycle::Completed(res)) {
                    Lifecycle::Waiting(w) => wakers.push(w),
                    Lifecycle::Ignored => remove = true,
                    _ => {}
                }
            }
            if remove {
                self.slab.remove(key); // drops resources now that the kernel is done
            }
            self.in_flight = self.in_flight.saturating_sub(1);
        }
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

    /// Mark op `key` abandoned (its future was dropped) and submit a cancel.
    fn abandon(&mut self, key: usize) {
        let already_done = match self.slab.get_mut(key) {
            Some(slot) => matches!(slot.lifecycle, Lifecycle::Completed(_)),
            None => true,
        };
        if already_done {
            // Result already here (or slot gone); just drop it.
            self.slab.remove(key);
            self.in_flight = self.in_flight.saturating_sub(1);
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
        let (res, buf) = Op::submit(buf, |b, ud| {
            let len = b.len() as u32;
            opcode::Send::new(types::Fd(fd), b.as_ptr(), len)
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
        let (res, buf) = Op::submit(buf, |b, ud| {
            let len = b.len() as u32;
            opcode::Write::new(types::Fd(fd), b.as_ptr(), len)
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
