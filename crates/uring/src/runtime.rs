// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The single-threaded executor that drives the reactor. It is deliberately
//! tiny: a ready queue of tasks plus a park step that submits SQEs and waits
//! for at least one CQE. The executor thread *is* the reactor thread (ADR
//! 0001); the caller's tokio runtime never polls these futures.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::error::{Error, Result};
use crate::reactor::{self, Reactor};

type BoxFuture = Pin<Box<dyn Future<Output = ()>>>;

struct Task {
    future: RefCell<Option<BoxFuture>>,
    exec: Weak<Executor>,
    queued: Cell<bool>,
}

struct Executor {
    ready: RefCell<VecDeque<Rc<Task>>>,
}

impl Executor {
    fn new() -> Rc<Executor> {
        Rc::new(Executor {
            ready: RefCell::new(VecDeque::new()),
        })
    }

    fn schedule(&self, task: Rc<Task>) {
        if !task.queued.replace(true) {
            self.ready.borrow_mut().push_back(task);
        }
    }

    fn pop(&self) -> Option<Rc<Task>> {
        let t = self.ready.borrow_mut().pop_front();
        if let Some(t) = &t {
            t.queued.set(false);
        }
        t
    }
}

thread_local! {
    static EXECUTOR: RefCell<Option<Rc<Executor>>> = const { RefCell::new(None) };
}

fn current_executor() -> Rc<Executor> {
    EXECUTOR
        .with(|e| e.borrow().clone())
        .expect("spawn used outside a Runtime")
}

// --- Waker built from Rc<Task> ---

fn task_waker(task: Rc<Task>) -> Waker {
    let ptr = Rc::into_raw(task) as *const ();
    // SAFETY: the vtable functions below uphold the RawWaker contract: `clone`
    // increments the `Rc` refcount, `wake`/`wake_by_ref` consume/borrow it, and
    // `drop` decrements it, so the `Rc<Task>` refcount stays balanced.
    unsafe { Waker::from_raw(RawWaker::new(ptr, &VTABLE)) }
}

static VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

unsafe fn waker_clone(ptr: *const ()) -> RawWaker {
    // SAFETY: `ptr` came from `Rc::into_raw`; bump the count and forget so the
    // original raw pointer stays valid.
    let rc = unsafe { Rc::from_raw(ptr as *const Task) };
    let _clone = rc.clone();
    std::mem::forget(rc);
    std::mem::forget(_clone);
    RawWaker::new(ptr, &VTABLE)
}

unsafe fn waker_wake(ptr: *const ()) {
    // SAFETY: consumes one refcount (the one this waker owned).
    let task = unsafe { Rc::from_raw(ptr as *const Task) };
    if let Some(exec) = task.exec.upgrade() {
        exec.schedule(task);
    }
}

unsafe fn waker_wake_by_ref(ptr: *const ()) {
    // SAFETY: borrow without consuming; reconstruct, use, forget.
    let task = unsafe { Rc::from_raw(ptr as *const Task) };
    if let Some(exec) = task.exec.upgrade() {
        exec.schedule(task.clone());
    }
    std::mem::forget(task);
}

unsafe fn waker_drop(ptr: *const ()) {
    // SAFETY: drops the refcount this waker owned.
    drop(unsafe { Rc::from_raw(ptr as *const Task) });
}

fn poll_task(task: &Rc<Task>) {
    let mut fut_slot = task.future.borrow_mut();
    let Some(mut fut) = fut_slot.take() else {
        return;
    };
    let waker = task_waker(task.clone());
    let mut cx = Context::from_waker(&waker);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(()) => {} // done: leave the slot empty, drop the future
        Poll::Pending => *fut_slot = Some(fut),
    }
}

/// A handle to a spawned task's result. Awaiting it yields the task's output.
/// Dropping it detaches the task (it keeps running).
pub struct JoinHandle<T> {
    state: Rc<RefCell<JoinState<T>>>,
}

struct JoinState<T> {
    output: Option<T>,
    waker: Option<Waker>,
}

impl<T> Future for JoinHandle<T> {
    type Output = T;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let mut st = self.state.borrow_mut();
        match st.output.take() {
            Some(v) => Poll::Ready(v),
            None => {
                st.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// Spawn `future` onto the current thread's runtime. Must be called from within
/// [`Runtime::block_on`].
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + 'static,
{
    let exec = current_executor();
    let state = Rc::new(RefCell::new(JoinState {
        output: None,
        waker: None,
    }));
    let state2 = state.clone();
    let wrapped = async move {
        let out = future.await;
        let mut st = state2.borrow_mut();
        st.output = Some(out);
        if let Some(w) = st.waker.take() {
            w.wake();
        }
    };
    let task = Rc::new(Task {
        future: RefCell::new(Some(Box::pin(wrapped))),
        exec: Rc::downgrade(&exec),
        queued: Cell::new(false),
    });
    exec.schedule(task);
    JoinHandle { state }
}

/// The engine's io_uring runtime: one ring, one executor, on this thread.
///
/// `!Send`/`!Sync` — a runtime belongs to the thread that created it. The
/// engine (in the `session` crate) creates one per ring thread.
pub struct Runtime {
    reactor: Rc<RefCell<Reactor>>,
    exec: Rc<Executor>,
}

impl Runtime {
    /// Create a runtime with a ring of `entries` submission slots. Fails hard
    /// (no fallback) if io_uring is unavailable or a required opcode is
    /// missing.
    pub fn new(entries: u32) -> Result<Runtime> {
        crate::probe::probe()?.require_baseline()?;
        let reactor = Reactor::new(entries)
            .map_err(|e| Error::Unavailable(format!("io_uring_setup: {e}")))?;
        Ok(Runtime {
            reactor: Rc::new(RefCell::new(reactor)),
            exec: Executor::new(),
        })
    }

    /// Create a runtime with a default ring size (256 entries).
    pub fn with_defaults() -> Result<Runtime> {
        Runtime::new(256)
    }

    /// Run `future` to completion, driving the reactor and any spawned tasks.
    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        EXECUTOR.with(|e| *e.borrow_mut() = Some(self.exec.clone()));
        struct ExecGuard;
        impl Drop for ExecGuard {
            fn drop(&mut self) {
                EXECUTOR.with(|e| *e.borrow_mut() = None);
            }
        }
        let _eg = ExecGuard;

        let out: Rc<RefCell<Option<F::Output>>> = Rc::new(RefCell::new(None));
        let out2 = out.clone();
        let root = async move {
            let v = future.await;
            *out2.borrow_mut() = Some(v);
        };
        let root_task = Rc::new(Task {
            future: RefCell::new(Some(Box::pin(root))),
            exec: Rc::downgrade(&self.exec),
            queued: Cell::new(false),
        });
        self.exec.schedule(root_task);

        reactor::scope(&self.reactor, || {
            loop {
                // Run every currently-ready task.
                while let Some(task) = self.exec.pop() {
                    poll_task(&task);
                    if out.borrow().is_some() {
                        return;
                    }
                }
                if out.borrow().is_some() {
                    return;
                }
                // Nothing ready: park on the ring until a completion arrives.
                let in_flight = self.reactor.borrow().in_flight();
                if in_flight == 0 {
                    // No ready tasks and no I/O in flight, yet the root is not
                    // done: nothing can ever wake us. This is a bug in the
                    // future being run (a stall), not a normal condition.
                    panic!(
                        "uring runtime stalled: root future is pending with no ready tasks and no in-flight I/O"
                    );
                }
                let wakers = self.reactor.borrow_mut().tick(true);
                for w in wakers {
                    w.wake();
                }
            }
        });

        out.borrow_mut().take().expect("root future completed")
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // Best-effort drain: reap any completions still owed to abandoned ops
        // so their resources are freed before the ring is torn down.
        let mut guard = 0;
        while self.reactor.borrow().in_flight() > 0 && guard < 1024 {
            // Bind the returned wakers to a local so the `RefMut` from
            // `borrow_mut()` is released at the end of this statement. Dropping
            // the wakers may drop tasks whose pending futures abandon in-flight
            // ops (which re-borrows the reactor), so that must happen after the
            // borrow ends — never while it is still held.
            let wakers = self.reactor.borrow_mut().tick(true);
            drop(wakers);
            guard += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nop_roundtrips() {
        let rt = Runtime::with_defaults().unwrap();
        let r = rt.block_on(async { crate::reactor::nop().await });
        assert_eq!(r, 0);
    }

    #[test]
    fn spawn_and_join() {
        let rt = Runtime::with_defaults().unwrap();
        let sum = rt.block_on(async {
            let a = spawn(async {
                crate::reactor::nop().await;
                20
            });
            let b = spawn(async {
                crate::reactor::nop().await;
                22
            });
            a.await + b.await
        });
        assert_eq!(sum, 42);
    }

    #[test]
    fn many_concurrent_nops() {
        let rt = Runtime::with_defaults().unwrap();
        let n = rt.block_on(async {
            let handles: Vec<_> = (0..1000)
                .map(|_| spawn(async { crate::reactor::nop().await }))
                .collect();
            let mut total = 0i64;
            for h in handles {
                total += i64::from(h.await);
            }
            total
        });
        assert_eq!(n, 0);
    }
}
