// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! A piece bitfield: which pieces we have. The wire format (BEP 3) is
//! big-endian, bit 0 = piece 0 in the most significant bit of byte 0.

/// A fixed-size bitfield over `len` pieces.
#[derive(Clone, PartialEq, Eq)]
pub struct Bitfield {
    bytes: Vec<u8>,
    len: usize,
}

impl Bitfield {
    /// A bitfield of `len` pieces, all unset.
    pub fn new(len: usize) -> Bitfield {
        Bitfield {
            bytes: vec![0; len.div_ceil(8)],
            len,
        }
    }

    /// A bitfield of `len` pieces, all set.
    pub fn all_set(len: usize) -> Bitfield {
        let mut bf = Bitfield::new(len);
        for i in 0..len {
            bf.set(i);
        }
        bf
    }

    /// Build from wire bytes, validating length and that spare bits are zero
    /// (BEP 6 requires the padding bits past `len` to be zero).
    pub fn from_bytes(bytes: &[u8], len: usize) -> Option<Bitfield> {
        if bytes.len() != len.div_ceil(8) {
            return None;
        }
        let bf = Bitfield {
            bytes: bytes.to_vec(),
            len,
        };
        // spare bits must be zero
        for i in len..bytes.len() * 8 {
            if bf.raw_get(i) {
                return None;
            }
        }
        Some(bf)
    }

    /// The wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of pieces.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether there are zero pieces.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn raw_get(&self, i: usize) -> bool {
        self.bytes
            .get(i / 8)
            .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
    }

    /// Whether piece `i` is set.
    pub fn get(&self, i: usize) -> bool {
        i < self.len && self.raw_get(i)
    }

    /// Set piece `i`.
    pub fn set(&mut self, i: usize) {
        if i < self.len
            && let Some(b) = self.bytes.get_mut(i / 8)
        {
            *b |= 0x80 >> (i % 8);
        }
    }

    /// Clear piece `i`.
    pub fn clear(&mut self, i: usize) {
        if i < self.len
            && let Some(b) = self.bytes.get_mut(i / 8)
        {
            *b &= !(0x80 >> (i % 8));
        }
    }

    /// Number of set pieces.
    pub fn count(&self) -> usize {
        self.bytes.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Whether all pieces are set.
    pub fn is_complete(&self) -> bool {
        self.count() == self.len
    }

    /// Iterate the indices of set pieces.
    pub fn iter_set(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.len).filter(move |&i| self.raw_get(i))
    }
}

impl std::fmt::Debug for Bitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bitfield({}/{} pieces)", self.count(), self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_count() {
        let mut bf = Bitfield::new(20);
        assert_eq!(bf.as_bytes().len(), 3);
        bf.set(0);
        bf.set(7);
        bf.set(19);
        assert!(bf.get(0) && bf.get(7) && bf.get(19));
        assert!(!bf.get(1));
        assert_eq!(bf.count(), 3);
        assert_eq!(bf.iter_set().collect::<Vec<_>>(), vec![0, 7, 19]);
        bf.clear(7);
        assert!(!bf.get(7));
        assert_eq!(bf.as_bytes()[0], 0x80);
    }

    #[test]
    fn wire_roundtrip_and_spare_bits() {
        let mut bf = Bitfield::new(12);
        bf.set(0);
        bf.set(11);
        let bytes = bf.as_bytes().to_vec();
        assert_eq!(Bitfield::from_bytes(&bytes, 12), Some(bf));
        // spare bit set past len -> rejected
        let bad = [0x00u8, 0x01];
        assert!(Bitfield::from_bytes(&bad, 12).is_none());
        // wrong length -> rejected
        assert!(Bitfield::from_bytes(&[0u8], 12).is_none());
    }

    #[test]
    fn complete() {
        let bf = Bitfield::all_set(9);
        assert!(bf.is_complete());
        assert_eq!(bf.count(), 9);
        // spare bits in the last byte are zero
        assert_eq!(bf.as_bytes()[1], 0x80);
    }
}
