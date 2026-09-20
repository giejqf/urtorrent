// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Thread-local async primitives for tasks sharing the ring thread: an edge
//! notify, a sticky flag, and a two-way select. None of them touch the ring;
//! they only park and wake tasks of the single-threaded executor.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::rc::Rc;
use std::task::{Poll, Waker};

/// Wakes waiters once per `notify` (coalesced while nobody waits).
#[derive(Default)]
pub struct Notify {
    pending: Cell<bool>,
    wakers: RefCell<Vec<Waker>>,
}

impl Notify {
    /// A new notify.
    pub fn new() -> Rc<Notify> {
        Rc::new(Notify::default())
    }

    /// Signal. Wakes every current waiter; a later `wait` returns immediately
    /// if nobody was waiting.
    pub fn notify(&self) {
        self.pending.set(true);
        for w in self.wakers.borrow_mut().drain(..) {
            w.wake();
        }
    }

    /// Wait for the next signal (consumes it).
    pub fn wait(&self) -> impl Future<Output = ()> + '_ {
        std::future::poll_fn(move |cx| {
            if self.pending.replace(false) {
                Poll::Ready(())
            } else {
                let mut w = self.wakers.borrow_mut();
                if !w.iter().any(|x| x.will_wake(cx.waker())) {
                    w.push(cx.waker().clone());
                }
                Poll::Pending
            }
        })
    }
}

/// A one-way switch: once set, every `wait` resolves immediately.
#[derive(Default)]
pub struct Flag {
    set: Cell<bool>,
    wakers: RefCell<Vec<Waker>>,
}

impl Flag {
    /// A new, unset flag.
    pub fn new() -> Rc<Flag> {
        Rc::new(Flag::default())
    }

    /// Set the flag and wake waiters.
    pub fn set(&self) {
        self.set.set(true);
        for w in self.wakers.borrow_mut().drain(..) {
            w.wake();
        }
    }

    /// Whether it is set.
    pub fn is_set(&self) -> bool {
        self.set.get()
    }

    /// Wait until set.
    pub fn wait(&self) -> impl Future<Output = ()> + '_ {
        std::future::poll_fn(move |cx| {
            if self.set.get() {
                Poll::Ready(())
            } else {
                let mut w = self.wakers.borrow_mut();
                if !w.iter().any(|x| x.will_wake(cx.waker())) {
                    w.push(cx.waker().clone());
                }
                Poll::Pending
            }
        })
    }
}

/// Which side of a [`select2`] won.
pub enum Either<A, B> {
    /// The first future finished first.
    Left(A),
    /// The second future finished first.
    Right(B),
}

/// Run two futures until one completes; the other is dropped (cancelling any
/// in-flight ring operation it owned — the reactor keeps the buffer until the
/// CQE arrives).
pub async fn select2<A: Future, B: Future>(a: A, b: B) -> Either<A::Output, B::Output> {
    let mut a = std::pin::pin!(a);
    let mut b = std::pin::pin!(b);
    std::future::poll_fn(move |cx| {
        if let Poll::Ready(v) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::Left(v));
        }
        if let Poll::Ready(v) = b.as_mut().poll(cx) {
            return Poll::Ready(Either::Right(v));
        }
        Poll::Pending
    })
    .await
}

/// A counting semaphore for the ring thread: bounds how many of something run
/// at once (checks, announces, resume saves). Waiters are woken in no
/// particular order; fairness is not needed for these uses.
pub struct Semaphore {
    free: Cell<usize>,
    notify: Rc<Notify>,
}

/// A held permit; dropping it releases the slot.
pub struct Permit {
    sem: Rc<Semaphore>,
}

impl Semaphore {
    /// `n` permits.
    pub fn new(n: usize) -> Rc<Semaphore> {
        Rc::new(Semaphore {
            free: Cell::new(n.max(1)),
            notify: Notify::new(),
        })
    }

    /// Wait for a permit.
    pub async fn acquire(self: &Rc<Self>) -> Permit {
        loop {
            let free = self.free.get();
            if free > 0 {
                self.free.set(free - 1);
                return Permit { sem: self.clone() };
            }
            self.notify.wait().await;
        }
    }

    /// Permits available right now.
    pub fn available(&self) -> usize {
        self.free.get()
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.sem.free.set(self.sem.free.get() + 1);
        self.sem.notify.notify();
    }
}

#[cfg(test)]
mod semaphore_tests {
    use super::*;

    #[test]
    fn permits_bound_concurrency_and_come_back_on_drop() {
        let rt = uring::Runtime::with_defaults().unwrap();
        rt.block_on(async {
            let sem = Semaphore::new(2);
            let a = sem.acquire().await;
            let _b = sem.acquire().await;
            assert_eq!(sem.available(), 0);
            // A third acquire waits until one permit is dropped.
            let sem2 = sem.clone();
            let waiter = uring::spawn(async move {
                let _c = sem2.acquire().await;
                sem2.available()
            });
            uring::sleep(std::time::Duration::from_millis(20)).await;
            drop(a);
            let avail_inside = waiter.await;
            assert_eq!(avail_inside, 0, "the waiter took the released permit");
            assert_eq!(sem.available(), 1);
        });
    }
}
