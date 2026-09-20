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
