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
//! - [`HashPool::verify_async`] and [`HashPool::update_async`] return futures.
//!   Workers push the result into a shared queue and ring the attached
//!   [`uring::NotifyHandle`]; the ring thread calls [`HashPool::drain`] when
//!   its notifier fires, which completes the futures and wakes their
//!   (thread-local) wakers. Without an attached notifier the future resolves
//!   synchronously, so behaviour is always correct and never deadlocks — only
//!   the overlap with disk I/O is lost.
//!
//! `update_async` feeds a running [`HashState`] with a batch of chunks (and
//! optionally finalises it): the piece store hashes blocks as they are
//! written instead of reading the piece back afterwards.

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

/// A running SHA-1 (opaque; created by [`HashState::new`], advanced on the
/// pool by [`HashPool::update_async`]).
#[derive(Clone, Debug, Default)]
pub struct HashState(Sha1);

impl HashState {
    /// A fresh state.
    pub fn new() -> HashState {
        HashState(Sha1::new())
    }
}

/// What a worker computed for one job.
enum Outcome {
    /// Whole-buffer digest and the buffer back.
    Digest([u8; 20], Vec<u8>),
    /// Advanced state, the chunks back, and the digest when finalised.
    Update(HashState, Vec<(Vec<u8>, usize)>, Option<[u8; 20]>),
}

/// `(job id, outcome)` returned from a worker.
type HashReply = (u64, Outcome);

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

enum Work {
    Digest(Vec<u8>),
    Update {
        state: HashState,
        /// `(buffer, start)`: the bytes to hash are `buffer[start..]`.
        chunks: Vec<(Vec<u8>, usize)>,
        finish: bool,
    },
}

struct Job {
    id: u64,
    work: Work,
    reply: Reply,
}

fn run_work(work: Work) -> Outcome {
    match work {
        Work::Digest(data) => {
            let digest = sha1(&data);
            Outcome::Digest(digest, data)
        }
        Work::Update {
            mut state,
            chunks,
            finish,
        } => {
            for (c, start) in &chunks {
                state.0.update(&c[(*start).min(c.len())..]);
            }
            let digest = finish.then(|| state.0.clone().finalize().into());
            Outcome::Update(state, chunks, digest)
        }
    }
}

/// State shared between workers and the ring thread.
struct Shared {
    completions: Mutex<Vec<HashReply>>,
    notify: Mutex<Option<NotifyHandle>>,
}

/// Ring-thread side of one in-flight async job.
struct Slot {
    result: Option<Outcome>,
    waker: Option<Waker>,
}

/// A pool of worker threads computing SHA-1.
pub struct HashPool {
    tx: Option<Sender<Job>>,
    workers: Vec<JoinHandle<()>>,
    shared: Arc<Shared>,
    /// Jobs handed to workers and not yet finished (readable from any
    /// thread: the session's stats).
    outstanding: Arc<std::sync::atomic::AtomicUsize>,
    /// Async jobs awaiting completion, keyed by job id (ring thread only).
    pending: RefCell<HashMap<u64, Rc<RefCell<Slot>>>>,
    next_id: RefCell<u64>,
}

impl HashPool {
    /// Start a pool with `threads` workers (at least 1).
    pub fn new(threads: usize) -> HashPool {
        Self::with_counter(threads, Arc::new(std::sync::atomic::AtomicUsize::new(0)))
    }

    /// [`HashPool::new`] counting in-flight jobs in `outstanding` (shared
    /// with whoever reports them).
    pub fn with_counter(
        threads: usize,
        outstanding: Arc<std::sync::atomic::AtomicUsize>,
    ) -> HashPool {
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
            let outstanding = outstanding.clone();
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
                        let outcome = run_work(job.work);
                        outstanding.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        match job.reply {
                            Reply::Sync(tx) => {
                                let _ = tx.send((job.id, outcome));
                            }
                            Reply::Async => {
                                // Ring the eventfd only when the queue was
                                // empty: the ring drains all completions at
                                // once, so a burst coalesces into one wakeup.
                                let was_empty = match shared.completions.lock() {
                                    Ok(mut q) => {
                                        let e = q.is_empty();
                                        q.push((job.id, outcome));
                                        e
                                    }
                                    Err(_) => true,
                                };
                                if was_empty
                                    && let Ok(n) = shared.notify.lock()
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
            outstanding,
            pending: RefCell::new(HashMap::new()),
            next_id: RefCell::new(1),
        }
    }

    /// Jobs handed to the workers and not finished yet.
    pub fn outstanding(&self) -> usize {
        self.outstanding.load(std::sync::atomic::Ordering::Relaxed)
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
        self.outstanding
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let data = match &self.tx {
            Some(tx) => match tx.send(Job {
                id: self.alloc_id(),
                work: Work::Digest(data),
                reply: Reply::Sync(reply),
            }) {
                Ok(()) => match rx.recv() {
                    Ok((_, Outcome::Digest(digest, buf))) => return (digest, buf),
                    Ok((_, Outcome::Update(_, mut chunks, digest))) => {
                        // Not what was asked; cannot happen, but stay truthful.
                        let buf = chunks.pop().unwrap_or_default().0;
                        return (digest.unwrap_or_else(|| sha1(&buf)), buf);
                    }
                    Err(_) => {
                        // Worker gone with the buffer: impossible while the
                        // pool owns its workers (they exit only on drop).
                        unreachable_worker();
                        Vec::new()
                    }
                },
                // Pool gone (shutting down): take the buffer back.
                Err(std::sync::mpsc::SendError(job)) => match job.work {
                    Work::Digest(d) => d,
                    Work::Update { mut chunks, .. } => chunks.pop().unwrap_or_default().0,
                },
            },
            None => data,
        };
        // Hash inline so the result is still correct (accounting must be
        // truthful, AGENTS.md rule 1) and callers never deadlock.
        self.outstanding
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let digest = sha1(&data);
        (digest, data)
    }

    /// Verify `data` against `expected`, returning whether it matches and the
    /// buffer. Blocking.
    pub fn verify(&self, data: Vec<u8>, expected: &[u8; 20]) -> (bool, Vec<u8>) {
        let (digest, buf) = self.hash(data);
        (&digest == expected, buf)
    }

    fn attached(&self) -> bool {
        self.shared
            .notify
            .lock()
            .map(|n| n.is_some())
            .unwrap_or(false)
    }

    /// Submit `work` asynchronously; on any failure (no notifier, pool gone)
    /// the work is done inline and the slot is filled at once.
    fn submit(&self, work: Work) -> Rc<RefCell<Slot>> {
        let slot = Rc::new(RefCell::new(Slot {
            result: None,
            waker: None,
        }));
        let mut work = work;
        if self.attached()
            && let Some(tx) = &self.tx
        {
            let id = self.alloc_id();
            self.pending.borrow_mut().insert(id, slot.clone());
            self.outstanding
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            match tx.send(Job {
                id,
                work,
                reply: Reply::Async,
            }) {
                Ok(()) => return slot,
                Err(std::sync::mpsc::SendError(job)) => {
                    self.outstanding
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    self.pending.borrow_mut().remove(&id);
                    work = job.work;
                }
            }
        }
        slot.borrow_mut().result = Some(run_work(work));
        slot
    }

    /// Verify asynchronously (see the module docs). The future resolves to
    /// `(matches, data)`.
    pub fn verify_async(&self, data: Vec<u8>, expected: [u8; 20]) -> VerifyFuture {
        let slot = self.submit(Work::Digest(data));
        VerifyFuture { slot, expected }
    }

    /// Advance `state` with `chunks` (in order) on the pool; with `finish`
    /// the digest is produced too. Resolves to `(state, chunks, digest)`.
    pub fn update_async(
        &self,
        state: HashState,
        chunks: Vec<(Vec<u8>, usize)>,
        finish: bool,
    ) -> UpdateFuture {
        let slot = self.submit(Work::Update {
            state,
            chunks,
            finish,
        });
        UpdateFuture { slot }
    }

    /// Complete every finished async job. Call from the ring thread when the
    /// attached notifier fires. Returns how many futures were completed.
    pub fn drain(&self) -> usize {
        let done: Vec<HashReply> = match self.shared.completions.lock() {
            Ok(mut q) => std::mem::take(&mut *q),
            Err(_) => Vec::new(),
        };
        let mut n = 0;
        for (id, outcome) in done {
            if let Some(slot) = self.pending.borrow_mut().remove(&id) {
                let waker = {
                    let mut s = slot.borrow_mut();
                    s.result = Some(outcome);
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
            Some(Outcome::Digest(digest, data)) => Poll::Ready((digest == self.expected, data)),
            Some(Outcome::Update(_, mut chunks, digest)) => {
                // Not expected for this future; stay truthful anyway.
                let data = chunks.pop().unwrap_or_default().0;
                Poll::Ready((digest == Some(self.expected), data))
            }
            None => {
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// The result of [`HashPool::update_async`].
pub struct UpdateFuture {
    slot: Rc<RefCell<Slot>>,
}

impl Future for UpdateFuture {
    type Output = (HashState, Vec<(Vec<u8>, usize)>, Option<[u8; 20]>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut s = self.slot.borrow_mut();
        match s.result.take() {
            Some(Outcome::Update(state, chunks, digest)) => Poll::Ready((state, chunks, digest)),
            Some(Outcome::Digest(digest, data)) => {
                // Not expected for this future.
                Poll::Ready((HashState::new(), vec![(data, 0)], Some(digest)))
            }
            None => {
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// A worker vanished while holding a job: impossible while the pool owns its
/// workers (they only exit when the channel closes on drop). Logged, not
/// panicked, so a caller never dies on a hashing hiccup; the caller hashes
/// inline instead.
fn unreachable_worker() {
    tracing::error!("hash worker exited while holding a job");
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
