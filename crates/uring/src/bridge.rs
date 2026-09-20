// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Completing ring-thread futures from helper threads. A helper thread gets a
//! [`Completer`]; when it calls `complete(value)` the value is queued and the
//! ring's eventfd is rung. The ring thread calls [`Bridge::drain`] on wakeup,
//! which hands values to their futures and wakes them locally. Executor wakers
//! never cross a thread.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use crate::NotifyHandle;

struct Slot<T> {
    value: Option<T>,
    waker: Option<Waker>,
}

struct Shared<T> {
    done: Mutex<Vec<(u64, T)>>,
    notify: NotifyHandle,
}

/// Ring-thread side.
pub struct Bridge<T> {
    shared: Arc<Shared<T>>,
    pending: RefCell<HashMap<u64, Rc<RefCell<Slot<T>>>>>,
    next: RefCell<u64>,
}

/// Helper-thread side of one ticket.
pub struct Completer<T> {
    id: u64,
    shared: Arc<Shared<T>>,
}

/// The future half of a ticket.
pub struct Ticket<T> {
    slot: Rc<RefCell<Slot<T>>>,
}

impl<T: Send + 'static> Bridge<T> {
    /// A bridge that rings `notify` on every completion.
    pub fn new(notify: NotifyHandle) -> Bridge<T> {
        Bridge {
            shared: Arc::new(Shared {
                done: Mutex::new(Vec::new()),
                notify,
            }),
            pending: RefCell::new(HashMap::new()),
            next: RefCell::new(1),
        }
    }

    /// Create a ticket: a future for the ring thread and a completer to hand
    /// to a helper thread.
    pub fn ticket(&self) -> (Ticket<T>, Completer<T>) {
        let id = {
            let mut n = self.next.borrow_mut();
            let v = *n;
            *n = n.wrapping_add(1).max(1);
            v
        };
        let slot = Rc::new(RefCell::new(Slot {
            value: None,
            waker: None,
        }));
        self.pending.borrow_mut().insert(id, slot.clone());
        (
            Ticket { slot },
            Completer {
                id,
                shared: self.shared.clone(),
            },
        )
    }

    /// Deliver every queued completion. Call when the notifier fires.
    pub fn drain(&self) -> usize {
        let done = match self.shared.done.lock() {
            Ok(mut q) => std::mem::take(&mut *q),
            Err(_) => Vec::new(),
        };
        let mut n = 0;
        for (id, value) in done {
            if let Some(slot) = self.pending.borrow_mut().remove(&id) {
                let waker = {
                    let mut s = slot.borrow_mut();
                    s.value = Some(value);
                    s.waker.take()
                };
                if let Some(w) = waker {
                    w.wake();
                }
                n += 1;
            }
        }
        n
    }
}

impl<T: Send + 'static> Completer<T> {
    /// Deliver the value (from any thread). The eventfd is rung only when
    /// the queue was empty: the ring drains everything on one wakeup, so
    /// back-to-back completions coalesce into one notification.
    pub fn complete(self, value: T) {
        let was_empty = match self.shared.done.lock() {
            Ok(mut q) => {
                let e = q.is_empty();
                q.push((self.id, value));
                e
            }
            Err(_) => true,
        };
        if was_empty {
            self.shared.notify.notify();
        }
    }
}

impl<T> Future for Ticket<T> {
    type Output = T;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let mut s = self.slot.borrow_mut();
        match s.value.take() {
            Some(v) => Poll::Ready(v),
            None => {
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}
