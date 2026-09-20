// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
//
// Ported from libtorrent's `packet_buffer` (src/packet_buffer.cpp,
// Copyright (c) 2010-2020 Arvid Norberg; BSD-3-Clause). See NOTICE.

//! A circular buffer of packets indexed by 16-bit sequence number: the
//! send window (`outbuf`) and the reorder buffer (`inbuf`).

use crate::header::compare_less_wrap;

const INDEX_MASK: u32 = 0xffff;

/// Packets keyed by sequence number; the storage is a power-of-two ring
/// that grows as the span between the lowest and highest occupied index
/// grows.
pub struct PacketBuffer<T> {
    storage: Vec<Option<T>>,
    capacity: u32,
    size: u32,
    /// Lowest occupied index (the cursor).
    first: u32,
    /// One past the highest occupied index.
    last: u32,
}

impl<T> Default for PacketBuffer<T> {
    fn default() -> Self {
        PacketBuffer {
            storage: Vec::new(),
            capacity: 0,
            size: 0,
            first: 0,
            last: 0,
        }
    }
}

impl<T> PacketBuffer<T> {
    /// Number of stored packets.
    pub fn len(&self) -> usize {
        self.size as usize
    }

    /// Whether nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// The lowest occupied index.
    pub fn cursor(&self) -> u16 {
        self.first as u16
    }

    /// Distance from the cursor to one past the highest occupied index.
    pub fn span(&self) -> u32 {
        self.last.wrapping_sub(self.first) & INDEX_MASK
    }

    fn in_range(&self, idx: u32) -> bool {
        idx <= INDEX_MASK && (idx.wrapping_sub(self.first) & INDEX_MASK) < self.capacity
    }

    fn slot(&self, idx: u32) -> usize {
        (idx & (self.capacity - 1)) as usize
    }

    /// Store `value` at `idx`, returning what was there.
    pub fn insert(&mut self, idx: u16, value: T) -> Option<T> {
        let idx = u32::from(idx);
        if self.size != 0 {
            if compare_less_wrap(idx, self.first, INDEX_MASK) {
                // Inserting before the cursor: how many free slots precede it?
                let mut free_space = 0u32;
                let mut i = self.first.wrapping_sub(1) & (self.capacity - 1);
                while i != (self.first & (self.capacity - 1)) {
                    if self.storage[i as usize].is_some() {
                        break;
                    }
                    free_space += 1;
                    i = i.wrapping_sub(1) & (self.capacity - 1);
                }
                let dist = self.first.wrapping_sub(idx) & INDEX_MASK;
                if dist > free_space {
                    self.reserve(dist + self.capacity - free_space);
                }
                self.first = idx;
            } else if idx >= self.first + self.capacity {
                self.reserve(idx - self.first + 1);
            } else if idx < self.first
                && idx >= ((self.first + self.capacity) & INDEX_MASK)
                && self.capacity < INDEX_MASK
            {
                self.reserve(
                    self.capacity + (idx + 1 - ((self.first + self.capacity) & INDEX_MASK)),
                );
            }
            if compare_less_wrap(self.last, (idx + 1) & INDEX_MASK, INDEX_MASK) {
                self.last = (idx + 1) & INDEX_MASK;
            }
        } else {
            self.first = idx;
            self.last = (idx + 1) & INDEX_MASK;
        }
        if self.capacity == 0 {
            self.reserve(16);
        }
        let slot = self.slot(idx);
        let old = self.storage[slot].replace(value);
        if self.size == 0 {
            self.first = idx;
        }
        if old.is_none() {
            self.size += 1;
        }
        old
    }

    /// The packet at `idx`, if stored.
    pub fn at(&self, idx: u16) -> Option<&T> {
        let idx = u32::from(idx);
        if !self.in_range(idx) {
            return None;
        }
        self.storage[self.slot(idx)].as_ref()
    }

    /// The packet at `idx`, mutably.
    pub fn at_mut(&mut self, idx: u16) -> Option<&mut T> {
        let idx = u32::from(idx);
        if !self.in_range(idx) {
            return None;
        }
        let slot = self.slot(idx);
        self.storage[slot].as_mut()
    }

    fn reserve(&mut self, size: u32) {
        let mut new_size = if self.capacity == 0 {
            16
        } else {
            self.capacity
        };
        while new_size < size {
            new_size <<= 1;
        }
        let mut new_storage: Vec<Option<T>> = (0..new_size).map(|_| None).collect();
        for i in self.first..self.first + self.capacity {
            let old = self.storage[(i & (self.capacity - 1)) as usize].take();
            new_storage[(i & (new_size - 1)) as usize] = old;
        }
        self.storage = new_storage;
        self.capacity = new_size;
    }

    /// Remove and return the packet at `idx`.
    pub fn remove(&mut self, idx: u16) -> Option<T> {
        let idx = u32::from(idx);
        if !self.in_range(idx) {
            return None;
        }
        let slot = self.slot(idx);
        let old = self.storage[slot].take();
        if old.is_some() {
            self.size -= 1;
            if self.size == 0 {
                self.last = self.first;
            }
        }
        if idx == self.first && self.size != 0 {
            self.first += 1;
            for _ in 0..self.capacity {
                if self.storage[self.slot(self.first)].is_some() {
                    break;
                }
                self.first += 1;
            }
            self.first &= INDEX_MASK;
        }
        if ((idx + 1) & INDEX_MASK) == self.last && self.size != 0 {
            self.last = self.last.wrapping_sub(1);
            for _ in 0..self.capacity {
                if self.storage[self.slot(self.last.wrapping_sub(1) & INDEX_MASK)].is_some() {
                    break;
                }
                self.last = self.last.wrapping_sub(1);
            }
            self.last &= INDEX_MASK;
        }
        old
    }

    /// Remove everything, yielding the packets in index order from the cursor.
    pub fn drain(&mut self) -> Vec<T> {
        let mut out = Vec::with_capacity(self.len());
        let start = self.first;
        for i in 0..self.capacity {
            let idx = (start + i) & INDEX_MASK;
            if let Some(p) = self.remove(idx as u16) {
                out.push(p);
            }
            if self.size == 0 {
                break;
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn insert_remove_span() {
        let mut b: PacketBuffer<u32> = PacketBuffer::default();
        assert!(b.is_empty());
        b.insert(123, 1);
        b.insert(125, 3);
        assert_eq!(b.cursor(), 123);
        assert_eq!(b.span(), 3);
        assert_eq!(b.len(), 2);
        assert_eq!(b.at(124), None);
        assert_eq!(b.remove(123), Some(1));
        assert_eq!(b.cursor(), 125);
        assert_eq!(b.span(), 1);
        assert_eq!(b.remove(125), Some(3));
        assert!(b.is_empty());
        assert_eq!(b.span(), 0);
    }

    #[test]
    fn wraps_around_and_grows() {
        let mut b: PacketBuffer<u16> = PacketBuffer::default();
        for i in 0..40u16 {
            let idx = 0xfff0u16.wrapping_add(i);
            b.insert(idx, idx);
        }
        assert_eq!(b.len(), 40);
        assert_eq!(b.cursor(), 0xfff0);
        assert_eq!(b.span(), 40);
        for i in 0..40u16 {
            let idx = 0xfff0u16.wrapping_add(i);
            assert_eq!(b.at(idx), Some(&idx));
        }
        assert_eq!(b.remove(0xfff0), Some(0xfff0));
        assert_eq!(b.cursor(), 0xfff1);
        // Insert before the cursor.
        b.insert(0xffe0, 7);
        assert_eq!(b.cursor(), 0xffe0);
        assert_eq!(b.at(0xffe0), Some(&7));
        let all = b.drain();
        assert_eq!(all.len(), 40);
        assert_eq!(all[0], 7);
        assert!(b.is_empty());
    }

    #[test]
    fn far_insert_grows() {
        let mut b: PacketBuffer<u8> = PacketBuffer::default();
        b.insert(10, 1);
        b.insert(10 + 1000, 2);
        assert_eq!(b.at(10), Some(&1));
        assert_eq!(b.at(1010), Some(&2));
        assert_eq!(b.span(), 1001);
    }
}
