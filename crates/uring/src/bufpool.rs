// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Pooled owned buffers. Async operations take and return owned [`Buffer`]s so
//! that a buffer handed to the kernel always outlives its SQE (see the crate
//! docs). Dropping a `Buffer` returns its allocation to the pool it came from
//! (if any) for reuse.

use std::cell::RefCell;
use std::rc::Rc;

/// An owned, heap-allocated byte buffer with a fixed capacity and a tracked
/// length (the meaningful prefix). Backed by a `Vec<u8>` whose capacity is
/// preserved across pool reuse.
pub struct Buffer {
    data: Vec<u8>,
    pool: Option<Rc<PoolInner>>,
}

impl Buffer {
    /// A standalone buffer of at least `cap` bytes, length 0, not pooled.
    pub fn with_capacity(cap: usize) -> Buffer {
        Buffer {
            data: Vec::with_capacity(cap),
            pool: None,
        }
    }

    /// A standalone buffer owning `data`.
    pub fn from_vec(data: Vec<u8>) -> Buffer {
        Buffer { data, pool: None }
    }

    /// The meaningful bytes (`&data[..len]`).
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Mutable access to the meaningful bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Current length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Total capacity.
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Set the length to `n`, growing with zeros or truncating as needed.
    /// Used to size a receive buffer to the pool's read size before a `recv`.
    pub fn resize(&mut self, n: usize) {
        self.data.resize(n, 0);
    }

    /// Replace the contents with `bytes`.
    pub fn set(&mut self, bytes: &[u8]) {
        self.data.clear();
        self.data.extend_from_slice(bytes);
    }

    /// Truncate to `n` bytes (used to record how many bytes a recv filled).
    pub fn truncate(&mut self, n: usize) {
        self.data.truncate(n);
    }

    /// Consume and return the inner `Vec`.
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }

    // --- reactor-internal raw access (buffers in flight) ---

    /// Pointer to the backing storage (for building an SQE). The buffer must
    /// stay alive (owned by the reactor) for the op's lifetime.
    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            let mut data = std::mem::take(&mut self.data);
            data.clear();
            pool.recycle(data);
        }
    }
}

impl std::fmt::Debug for Buffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Buffer")
            .field("len", &self.data.len())
            .field("cap", &self.data.capacity())
            .field("pooled", &self.pool.is_some())
            .finish()
    }
}

struct PoolInner {
    buf_size: usize,
    max_idle: usize,
    free: RefCell<Vec<Vec<u8>>>,
}

impl PoolInner {
    fn recycle(&self, buf: Vec<u8>) {
        let mut free = self.free.borrow_mut();
        if free.len() < self.max_idle && buf.capacity() >= self.buf_size {
            free.push(buf);
        }
        // else: let it drop
    }
}

/// A pool of same-sized buffers, reused to avoid per-operation allocation on
/// the hot path. `!Send` — each ring thread owns its own pool.
#[derive(Clone)]
pub struct BufferPool {
    inner: Rc<PoolInner>,
}

impl BufferPool {
    /// A pool handing out buffers of `buf_size` capacity, keeping at most
    /// `max_idle` free buffers around.
    pub fn new(buf_size: usize, max_idle: usize) -> BufferPool {
        BufferPool {
            inner: Rc::new(PoolInner {
                buf_size,
                max_idle,
                free: RefCell::new(Vec::new()),
            }),
        }
    }

    /// Take a buffer (length 0, capacity >= `buf_size`). Reuses a free one if
    /// available.
    pub fn take(&self) -> Buffer {
        let data = self
            .inner
            .free
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.inner.buf_size));
        Buffer {
            data,
            pool: Some(self.inner.clone()),
        }
    }

    /// Take a buffer already sized to `buf_size` (zero-filled), ready for a
    /// `recv`/`read`.
    pub fn take_sized(&self) -> Buffer {
        let mut b = self.take();
        b.resize(self.inner.buf_size);
        b
    }

    /// The configured buffer size.
    pub fn buf_size(&self) -> usize {
        self.inner.buf_size
    }

    /// Number of free buffers currently cached.
    pub fn idle(&self) -> usize {
        self.inner.free.borrow().len()
    }

    /// Return an allocation that left the pool through [`Buffer::into_vec`]
    /// (e.g. after a round trip to a worker thread) so it can be reused.
    pub fn put(&self, data: Vec<u8>) {
        let mut data = data;
        data.clear();
        self.inner.recycle(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_returns_allocation() {
        let pool = BufferPool::new(4096, 4);
        let b = pool.take_sized();
        assert_eq!(b.len(), 4096);
        assert!(b.capacity() >= 4096);
        assert_eq!(pool.idle(), 0);
        drop(b);
        assert_eq!(pool.idle(), 1);
        let b2 = pool.take();
        assert_eq!(b2.len(), 0);
        assert!(b2.capacity() >= 4096);
        assert_eq!(pool.idle(), 0);
    }

    #[test]
    fn max_idle_caps_cache() {
        let pool = BufferPool::new(64, 2);
        let bufs: Vec<_> = (0..5).map(|_| pool.take()).collect();
        drop(bufs);
        assert_eq!(pool.idle(), 2);
    }

    #[test]
    fn standalone_buffer_not_pooled() {
        let mut b = Buffer::with_capacity(16);
        b.set(b"hello");
        assert_eq!(b.as_slice(), b"hello");
        assert_eq!(b.into_vec(), b"hello");
    }
}
