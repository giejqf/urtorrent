// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Provided buffer rings (`IORING_REGISTER_PBUF_RING`) for multishot receives.
//!
//! A [`BufRing`] owns `entries` equally sized buffers and a ring of
//! `io_uring_buf` descriptors the kernel picks from when a multishot `recv`
//! with `IOSQE_BUFFER_SELECT` completes. Each completion names the buffer it
//! filled (`IORING_CQE_F_BUFFER`); the consumer gets a [`RingBuf`] and the
//! buffer goes back to the ring when that guard drops. Compared with a
//! buffer per connection, thousands of idle peers share one small pool and
//! a socket needs no user-space buffer until data actually arrives.
//!
//! Ownership rules (the crate's buffer discipline): the kernel may write any
//! buffer that is *on the ring*; a buffer handed out in a `RingBuf` is off
//! the ring until the guard returns it, and the ring's memory outlives every
//! guard and every in-flight op (guards hold an `Rc` to it; the ring is
//! unregistered before the memory is freed).

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::Waker;

use io_uring::types::BufRingEntry;

use crate::error::{Error, Result};
use crate::reactor;

/// One buffer ring shared by the connections of a ring thread.
#[derive(Clone)]
pub struct BufRing {
    inner: Rc<BufRingInner>,
}

pub(crate) struct BufRingInner {
    bgid: u16,
    entries: u16,
    buf_size: usize,
    /// `entries` descriptors, page-aligned (the kernel maps them).
    ring: *mut BufRingEntry,
    ring_layout: Layout,
    /// `entries * buf_size` bytes of buffer storage.
    bufs: *mut u8,
    bufs_layout: Layout,
    /// Our copy of the ring tail (the kernel only reads it).
    tail: Cell<u16>,
    /// Buffers currently on the ring (available to the kernel).
    free: Cell<u16>,
    /// Tasks waiting for a buffer to come back (re-arming after `ENOBUFS`).
    waiters: RefCell<Vec<Waker>>,
    registered: Cell<bool>,
}

impl BufRing {
    /// Allocate `entries` buffers of `buf_size` bytes and register them as
    /// buffer group `bgid` on the current thread's ring. `entries` must be a
    /// power of two (`IORING_REGISTER_PBUF_RING` requires it) of at most
    /// 32 768.
    pub fn new(bgid: u16, entries: u16, buf_size: usize) -> Result<BufRing> {
        if entries == 0
            || !entries.is_power_of_two()
            || buf_size == 0
            || buf_size > u32::MAX as usize
        {
            return Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::InvalidInput,
            )));
        }
        let ring_layout = Layout::from_size_align(
            usize::from(entries) * std::mem::size_of::<BufRingEntry>(),
            4096,
        )
        .map_err(|_| Error::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        let bufs_layout = Layout::from_size_align(usize::from(entries) * buf_size, 4096)
            .map_err(|_| Error::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        // SAFETY: both layouts have non-zero size (checked above).
        let ring = unsafe { alloc_zeroed(ring_layout) } as *mut BufRingEntry;
        if ring.is_null() {
            return Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::OutOfMemory,
            )));
        }
        // SAFETY: as above.
        let bufs = unsafe { alloc_zeroed(bufs_layout) };
        if bufs.is_null() {
            // SAFETY: `ring` came from `alloc_zeroed(ring_layout)`.
            unsafe { dealloc(ring as *mut u8, ring_layout) };
            return Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::OutOfMemory,
            )));
        }
        let inner = Rc::new(BufRingInner {
            bgid,
            entries,
            buf_size,
            ring,
            ring_layout,
            bufs,
            bufs_layout,
            tail: Cell::new(0),
            free: Cell::new(0),
            waiters: RefCell::new(Vec::new()),
            registered: Cell::new(false),
        });
        let reactor = reactor::current();
        // SAFETY: `ring` is page-aligned, holds `entries` descriptors and is
        // freed only in `Drop`, after `unregister_buf_ring`.
        unsafe {
            reactor
                .borrow()
                .register_buf_ring(ring as u64, entries, bgid)?;
        }
        inner.registered.set(true);
        // Hand every buffer to the kernel.
        for bid in 0..entries {
            inner.push(bid);
        }
        Ok(BufRing { inner })
    }

    /// The buffer group id.
    pub fn group(&self) -> u16 {
        self.inner.bgid
    }

    /// Size of each buffer.
    pub fn buf_size(&self) -> usize {
        self.inner.buf_size
    }

    /// Buffers currently available to the kernel.
    pub fn free(&self) -> usize {
        usize::from(self.inner.free.get())
    }

    pub(crate) fn inner(&self) -> &Rc<BufRingInner> {
        &self.inner
    }
}

impl BufRingInner {
    fn mask(&self) -> u16 {
        self.entries - 1
    }

    /// Address of buffer `bid`.
    fn buf_ptr(&self, bid: u16) -> *mut u8 {
        debug_assert!(bid < self.entries);
        // SAFETY: `bid < entries`, so the offset stays inside `bufs`.
        unsafe { self.bufs.add(usize::from(bid) * self.buf_size) }
    }

    /// Put buffer `bid` (back) on the ring for the kernel to use.
    pub(crate) fn push(&self, bid: u16) {
        let tail = self.tail.get();
        let idx = usize::from(tail & self.mask());
        // SAFETY: `idx < entries`; the entry is ours to write until the tail
        // publishes it.
        let entry = unsafe { &mut *self.ring.add(idx) };
        entry.set_addr(self.buf_ptr(bid) as u64);
        entry.set_len(self.buf_size as u32);
        entry.set_bid(bid);
        let new_tail = tail.wrapping_add(1);
        self.tail.set(new_tail);
        // SAFETY: `tail()` points at the shared tail word inside the ring
        // memory; the kernel reads it with acquire semantics, so a release
        // store publishes the entry written above.
        unsafe {
            let tail_ptr = BufRingEntry::tail(self.ring) as *const AtomicU16;
            (*tail_ptr).store(new_tail, Ordering::Release);
        }
        self.free.set(self.free.get() + 1);
        for w in self.waiters.borrow_mut().drain(..) {
            w.wake();
        }
    }

    /// Register interest in a buffer coming back.
    pub(crate) fn wait_free(&self, waker: &Waker) {
        self.waiters.borrow_mut().push(waker.clone());
    }

    pub(crate) fn free(&self) -> u16 {
        self.free.get()
    }

    pub(crate) fn bgid(&self) -> u16 {
        self.bgid
    }

    /// The kernel took buffer `bid` for a completion of `len` bytes.
    pub(crate) fn take(self: &Rc<Self>, bid: u16, len: usize) -> RingBuf {
        self.free.set(self.free.get().saturating_sub(1));
        RingBuf {
            ring: self.clone(),
            bid,
            len: len.min(self.buf_size),
        }
    }

    /// Return a buffer the kernel used for a completion nobody consumed.
    pub(crate) fn recycle_bid(&self, bid: u16) {
        self.free.set(self.free.get().saturating_sub(1));
        self.push(bid);
    }
}

impl reactor::Recycle for BufRingInner {
    fn recycle(&self, flags: u32) {
        if let Some(bid) = io_uring::cqueue::buffer_select(flags) {
            self.recycle_bid(bid);
        }
    }
}

/// A ring whose last owner went away: unregistered and freed by the runtime
/// between ticks (see [`release_retired`]). Dropping may happen while the
/// reactor is borrowed (a slot holding the last `Rc` is removed inside
/// `reap`), so `Drop` never touches the reactor itself.
struct Retired {
    bgid: u16,
    registered: bool,
    ring: *mut u8,
    ring_layout: Layout,
    bufs: *mut u8,
    bufs_layout: Layout,
}

thread_local! {
    static RETIRED: RefCell<Vec<Retired>> = const { RefCell::new(Vec::new()) };
}

impl Drop for BufRingInner {
    fn drop(&mut self) {
        RETIRED.with(|r| {
            r.borrow_mut().push(Retired {
                bgid: self.bgid,
                registered: self.registered.get(),
                ring: self.ring as *mut u8,
                ring_layout: self.ring_layout,
                bufs: self.bufs,
                bufs_layout: self.bufs_layout,
            });
        });
    }
}

/// Unregister and free rings retired since the last call. Called by the
/// runtime with the reactor unborrowed. Rings retired on a thread whose
/// runtime is already gone stay registered and allocated until the thread
/// exits, which closes the ring fd and with it the registration.
pub(crate) fn release_retired(reactor: Option<&Rc<RefCell<reactor::Reactor>>>) {
    let retired: Vec<Retired> = RETIRED.with(|r| std::mem::take(&mut *r.borrow_mut()));
    for t in retired {
        if t.registered {
            match reactor {
                Some(r) => {
                    let _ = r.borrow().unregister_buf_ring(t.bgid);
                }
                None => continue, // keep the memory: the kernel may still map it
            }
        }
        // SAFETY: both allocations came from `alloc_zeroed` with these
        // layouts; no `RingBuf` and no op slot reference the ring any more
        // (they held an `Rc` to it) and the group is unregistered, so
        // neither we nor the kernel use them.
        unsafe {
            dealloc(t.ring, t.ring_layout);
            dealloc(t.bufs, t.bufs_layout);
        }
    }
}

/// A received chunk living in a [`BufRing`] buffer. The buffer returns to the
/// ring when this drops.
pub struct RingBuf {
    ring: Rc<BufRingInner>,
    bid: u16,
    len: usize,
}

impl RingBuf {
    /// The received bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the buffer is off the ring while this guard exists (the
        // kernel does not touch it) and `len <= buf_size`.
        unsafe { std::slice::from_raw_parts(self.ring.buf_ptr(self.bid), self.len) }
    }

    /// The received bytes, mutably (ciphers decrypt in place).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, plus `&mut self` makes this the only reference.
        unsafe { std::slice::from_raw_parts_mut(self.ring.buf_ptr(self.bid), self.len) }
    }

    /// Number of received bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing was received.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for RingBuf {
    fn drop(&mut self) {
        self.ring.push(self.bid);
    }
}

impl std::fmt::Debug for RingBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingBuf")
            .field("bid", &self.bid)
            .field("len", &self.len)
            .finish()
    }
}
