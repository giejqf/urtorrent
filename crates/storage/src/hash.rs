// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The hashing pipeline. SHA-1 (and later SHA-256) of piece data is CPU work,
//! not I/O, so it runs on a small dedicated thread pool off the reactor thread
//! (AGENTS.md 5.3).
//!
//! Two bridges back to the caller exist:
//!
//! - [`HashPool::hash`] / [`HashPool::verify`] block the caller until a worker
//!   finishes (simple; used by tests and by callers without a reactor).
//! - [`HashPool::verify_async`] returns a future. Workers push the result into a
//!   shared queue and ring the attached [`uring::NotifyHandle`]; the ring
//!   thread calls [`HashPool::drain`] when its notifier fires, which completes
//!   the futures and wakes their (thread-local) wakers. Without an attached
//!   notifier the future resolves synchronously, so behaviour is always
//!   correct and never deadlocks — only the overlap with disk I/O is lost.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;

use sha1::{Digest, Sha1};
use uring::NotifyHandle;

/// `(job id, digest, buffer)` returned from a worker.
type HashReply = (u64, [u8; 20], Vec<u8>);

/// Compute the SHA-1 of `data` (used directly for one-off hashing).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

enum Reply {
    /// Blocking caller waiting on a channel.
    Sync(Sender<HashReply>),
    /// Async caller: push into the shared queue and notify the ring.
    Async,
}

struct Job {
    id: u64,
    data: Vec<u8>,
    reply: Reply,
}

/// State shared between workers and the ring thread.
struct Shared {
    completions: Mutex<Vec<HashReply>>,
    notify: Mutex<Option<NotifyHandle>>,
}

/// Ring-thread side of one in-flight async verification.
struct Slot {
    result: Option<([u8; 20], Vec<u8>)>,
    waker: Option<Waker>,
}

/// A pool of worker threads computing SHA-1.
pub struct HashPool {
    tx: Option<Sender<Job>>,
    workers: Vec<JoinHandle<()>>,
    shared: Arc<Shared>,
    /// Async jobs awaiting completion, keyed by job id (ring thread only).
    pending: RefCell<HashMap<u64, Rc<RefCell<Slot>>>>,
    next_id: RefCell<u64>,
}

impl HashPool {
    /// Start a pool with `threads` workers (at least 1).
    pub fn new(threads: usize) -> HashPool {
        let threads = threads.max(1);
        let (tx, rx) = channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        let shared = Arc::new(Shared {
            completions: Mutex::new(Vec::new()),
            notify: Mutex::new(None),
        });
        let mut workers = Vec::with_capacity(threads);
        for i in 0..threads {
            let rx = rx.clone();
            let shared = shared.clone();
            let handle = std::thread::Builder::new()
                .name(format!("urt-hash-{i}"))
                .spawn(move || {
                    loop {
                        // A poisoned mutex or a closed channel both mean shut down.
                        let job = match rx.lock() {
                            Ok(guard) => guard.recv(),
                            Err(_) => break,
                        };
                        let Ok(job) = job else { break };
                        let digest = sha1(&job.data);
                        match job.reply {
                            Reply::Sync(tx) => {
                                let _ = tx.send((job.id, digest, job.data));
                            }
                            Reply::Async => {
                                if let Ok(mut q) = shared.completions.lock() {
                                    q.push((job.id, digest, job.data));
                                }
                                if let Ok(n) = shared.notify.lock()
                                    && let Some(n) = n.as_ref()
                                {
                                    n.notify();
                                }
                            }
                        }
                    }
                })
                .ok();
            if let Some(handle) = handle {
                workers.push(handle);
            }
        }
        HashPool {
            tx: Some(tx),
            workers,
            shared,
            pending: RefCell::new(HashMap::new()),
            next_id: RefCell::new(1),
        }
    }

    /// A pool sized to the machine (capped), a reasonable default.
    pub fn with_defaults() -> HashPool {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .min(4);
        HashPool::new(n)
    }

    /// Attach the ring thread's notifier: from now on `verify_async` completes
    /// asynchronously and the owner must call [`HashPool::drain`] whenever the
    /// notifier fires.
    pub fn attach_notifier(&self, handle: NotifyHandle) {
        if let Ok(mut n) = self.shared.notify.lock() {
            *n = Some(handle);
        }
    }

    fn alloc_id(&self) -> u64 {
        let mut id = self.next_id.borrow_mut();
        let v = *id;
        *id = id.wrapping_add(1).max(1);
        v
    }

    /// Hash `data` on the pool, returning `(digest, data)` (the buffer is handed
    /// back for reuse). Blocks the caller until the worker finishes.
    pub fn hash(&self, data: Vec<u8>) -> ([u8; 20], Vec<u8>) {
        let (reply, rx) = channel::<HashReply>();
        if let Some(tx) = &self.tx
            && tx
                .send(Job {
                    id: self.alloc_id(),
                    data: data.clone(),
                    reply: Reply::Sync(reply),
                })
                .is_ok()
            && let Ok((_, digest, buf)) = rx.recv()
        {
            return (digest, buf);
        }
        // Pool gone (shutting down) or worker exited: hash inline so the result
        // is still correct (accounting must be truthful, AGENTS.md rule 1) and
        // callers never deadlock.
        let digest = sha1(&data);
        (digest, data)
    }

    /// Verify `data` against `expected`, returning whether it matches and the
    /// buffer. Blocking.
    pub fn verify(&self, data: Vec<u8>, expected: &[u8; 20]) -> (bool, Vec<u8>) {
        let (digest, buf) = self.hash(data);
        (&digest == expected, buf)
    }

    /// Verify asynchronously (see the module docs). The future resolves to
    /// `(matches, data)`.
    pub fn verify_async(&self, data: Vec<u8>, expected: [u8; 20]) -> VerifyFuture {
        let attached = self
            .shared
            .notify
            .lock()
            .map(|n| n.is_some())
            .unwrap_or(false);
        let slot = Rc::new(RefCell::new(Slot {
            result: None,
            waker: None,
        }));
        if attached && let Some(tx) = &self.tx {
            let id = self.alloc_id();
            self.pending.borrow_mut().insert(id, slot.clone());
            if tx
                .send(Job {
                    id,
                    data: data.clone(),
                    reply: Reply::Async,
                })
                .is_ok()
            {
                return VerifyFuture { slot, expected };
            }
            self.pending.borrow_mut().remove(&id);
        }
        // No notifier (or pool gone): resolve now.
        let (digest, buf) = self.hash(data);
        slot.borrow_mut().result = Some((digest, buf));
        VerifyFuture { slot, expected }
    }

    /// Complete every finished async job. Call from the ring thread when the
    /// attached notifier fires. Returns how many futures were completed.
    pub fn drain(&self) -> usize {
        let done: Vec<HashReply> = match self.shared.completions.lock() {
            Ok(mut q) => std::mem::take(&mut *q),
            Err(_) => Vec::new(),
        };
        let mut n = 0;
        for (id, digest, data) in done {
            if let Some(slot) = self.pending.borrow_mut().remove(&id) {
                let waker = {
                    let mut s = slot.borrow_mut();
                    s.result = Some((digest, data));
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

    /// Async verifications not yet completed.
    pub fn pending(&self) -> usize {
        self.pending.borrow().len()
    }
}

/// The result of [`HashPool::verify_async`].
pub struct VerifyFuture {
    slot: Rc<RefCell<Slot>>,
    expected: [u8; 20],
}

impl Future for VerifyFuture {
    type Output = (bool, Vec<u8>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut s = self.slot.borrow_mut();
        match s.result.take() {
            Some((digest, data)) => Poll::Ready((digest == self.expected, data)),
            None => {
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl Drop for HashPool {
    fn drop(&mut self) {
        self.tx.take(); // close the channel so workers exit
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let d = sha1(b"abc");
        assert_eq!(bencode::hex(&d), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn pool_hashes_on_workers() {
        let pool = HashPool::new(2);
        let (digest, buf) = pool.hash(b"abc".to_vec());
        assert_eq!(
            bencode::hex(&digest),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(buf, b"abc");
        let (ok, _) = pool.verify(b"abc".to_vec(), &sha1(b"abc"));
        assert!(ok);
        let (bad, _) = pool.verify(b"abd".to_vec(), &sha1(b"abc"));
        assert!(!bad);
    }

    #[test]
    fn async_without_notifier_resolves_immediately() {
        let pool = HashPool::new(1);
        let rt = uring::Runtime::with_defaults().unwrap();
        let pool = Rc::new(pool);
        let p2 = pool.clone();
        let (ok, data) =
            rt.block_on(async move { p2.verify_async(b"abc".to_vec(), sha1(b"abc")).await });
        assert!(ok);
        assert_eq!(data, b"abc");
        assert_eq!(pool.pending(), 0);
    }

    #[test]
    fn async_with_notifier_completes_via_drain() {
        let rt = uring::Runtime::with_defaults().unwrap();
        let pool = Rc::new(HashPool::new(2));
        let notifier = Rc::new(uring::Notifier::new().unwrap());
        pool.attach_notifier(notifier.handle());
        let p = pool.clone();
        let n = notifier.clone();
        let results = rt.block_on(async move {
            let futs: Vec<_> = (0..8u8)
                .map(|i| {
                    let data = vec![i; 100_000];
                    p.verify_async(data.clone(), sha1(&data))
                })
                .collect();
            assert_eq!(p.pending(), 8);
            // Drive: wait on the notifier and drain until every future is done.
            let mut done = Vec::new();
            let mut futs: Vec<Pin<Box<VerifyFuture>>> = futs.into_iter().map(Box::pin).collect();
            while !futs.is_empty() {
                n.wait().await.unwrap();
                p.drain();
                let mut remaining = Vec::new();
                for mut f in futs {
                    let waker = std::task::Waker::noop();
                    let mut cx = Context::from_waker(waker);
                    match f.as_mut().poll(&mut cx) {
                        Poll::Ready((ok, data)) => done.push((ok, data.len())),
                        Poll::Pending => remaining.push(f),
                    }
                }
                futs = remaining;
            }
            done
        });
        assert_eq!(results.len(), 8);
        assert!(results.iter().all(|(ok, len)| *ok && *len == 100_000));
        assert_eq!(pool.pending(), 0);
    }
}
