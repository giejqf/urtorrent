// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The hashing pipeline. SHA-1 (and later SHA-256) of piece data is CPU work,
//! not I/O, so it runs on a small dedicated thread pool off the reactor thread
//! (AGENTS.md 5.3). Work is submitted with a piece index and its bytes; results
//! come back on an MPSC channel.
//!
//! The current bridge is synchronous at the call site ([`HashPool::hash`]
//! blocks the caller until the worker finishes) — the computation still happens
//! on a pool thread, keeping SHA-1 off the reactor's critical instructions.
//! Overlapping hashing with in-flight disk I/O via a reactor eventfd wake is a
//! performance follow-up (M3), not a correctness item.

use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;

use sha1::{Digest, Sha1};

/// `(tag, digest, buffer)` returned from a worker.
type HashReply = (u64, [u8; 20], Vec<u8>);

/// Compute the SHA-1 of `data` (used directly for one-off hashing).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

struct Job {
    tag: u64,
    data: Vec<u8>,
    reply: Sender<HashReply>,
}

/// A pool of worker threads computing SHA-1.
pub struct HashPool {
    tx: Option<Sender<Job>>,
    workers: Vec<JoinHandle<()>>,
}

impl HashPool {
    /// Start a pool with `threads` workers (at least 1).
    pub fn new(threads: usize) -> HashPool {
        let threads = threads.max(1);
        let (tx, rx) = channel::<Job>();
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let mut workers = Vec::with_capacity(threads);
        for i in 0..threads {
            let rx = rx.clone();
            let handle = std::thread::Builder::new()
                .name(format!("hash-{i}"))
                .spawn(move || {
                    loop {
                        // A poisoned mutex or a closed channel both mean shut down.
                        let job = match rx.lock() {
                            Ok(guard) => guard.recv(),
                            Err(_) => break,
                        };
                        match job {
                            Ok(job) => {
                                let digest = sha1(&job.data);
                                // Return the buffer so the caller can reuse it.
                                let _ = job.reply.send((job.tag, digest, job.data));
                            }
                            Err(_) => break, // sender dropped: shut down
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

    /// Hash `data` on the pool, returning `(digest, data)` (the buffer is handed
    /// back for reuse). Blocks the caller until the worker finishes.
    pub fn hash(&self, tag: u64, data: Vec<u8>) -> ([u8; 20], Vec<u8>) {
        let (reply, rx) = channel::<HashReply>();
        if let Some(tx) = &self.tx
            && tx
                .send(Job {
                    tag,
                    data: data.clone(),
                    reply,
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
    /// buffer.
    pub fn verify(&self, tag: u64, data: Vec<u8>, expected: &[u8; 20]) -> (bool, Vec<u8>) {
        let (digest, buf) = self.hash(tag, data);
        (&digest == expected, buf)
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
        let (digest, buf) = pool.hash(7, b"abc".to_vec());
        assert_eq!(
            bencode::hex(&digest),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(buf, b"abc");
        let (ok, _) = pool.verify(1, b"abc".to_vec(), &sha1(b"abc"));
        assert!(ok);
        let (bad, _) = pool.verify(2, b"abd".to_vec(), &sha1(b"abc"));
        assert!(!bad);
    }
}
