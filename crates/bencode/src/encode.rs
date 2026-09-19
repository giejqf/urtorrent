// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Canonical encoding. Integers have no leading zeros or `-0`; dictionary keys
//! are written in sorted order. Encoding a decoded [`Value`] and decoding the
//! result is the identity, and the output is byte-identical to any other
//! canonical encoder's.

use crate::Value;

/// Appends canonical bencode to a `Vec<u8>`.
pub struct Encoder<'o> {
    out: &'o mut Vec<u8>,
}

impl<'o> Encoder<'o> {
    /// Create an encoder writing into `out`.
    pub fn new(out: &'o mut Vec<u8>) -> Self {
        Encoder { out }
    }

    /// Encode `value`, appending to the output buffer.
    pub fn encode(&mut self, value: &Value<'_>) {
        match value {
            Value::Int(i) => self.int(*i),
            Value::Bytes(b) => self.bytes(b),
            Value::List { items, .. } => {
                self.out.push(b'l');
                for it in items {
                    self.encode(it);
                }
                self.out.push(b'e');
            }
            Value::Dict { entries, .. } => {
                self.out.push(b'd');
                // Entries are kept sorted by the decoder, but a caller may have
                // built a Value by hand; sort defensively without allocating
                // when already ordered.
                if is_sorted(entries) {
                    for (k, v) in entries {
                        self.bytes(k);
                        self.encode(v);
                    }
                } else {
                    let mut idx: Vec<usize> = (0..entries.len()).collect();
                    idx.sort_by(|&a, &b| entries[a].0.cmp(entries[b].0));
                    for &i in &idx {
                        self.bytes(entries[i].0);
                        self.encode(&entries[i].1);
                    }
                }
                self.out.push(b'e');
            }
        }
    }

    fn int(&mut self, i: i64) {
        self.out.push(b'i');
        self.write_i64(i);
        self.out.push(b'e');
    }

    fn bytes(&mut self, b: &[u8]) {
        self.write_usize(b.len());
        self.out.push(b':');
        self.out.extend_from_slice(b);
    }

    fn write_i64(&mut self, mut n: i64) {
        if n == 0 {
            self.out.push(b'0');
            return;
        }
        if n < 0 {
            self.out.push(b'-');
        }
        // Work in i128 to handle i64::MIN without overflow on negation.
        let mut m = (n as i128).unsigned_abs();
        let _ = &mut n;
        let mut buf = [0u8; 40];
        let mut i = buf.len();
        while m > 0 {
            i -= 1;
            buf[i] = b'0' + (m % 10) as u8;
            m /= 10;
        }
        self.out.extend_from_slice(&buf[i..]);
    }

    fn write_usize(&mut self, mut m: usize) {
        if m == 0 {
            self.out.push(b'0');
            return;
        }
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        while m > 0 {
            i -= 1;
            buf[i] = b'0' + (m % 10) as u8;
            m /= 10;
        }
        self.out.extend_from_slice(&buf[i..]);
    }
}

fn is_sorted(entries: &[(&[u8], Value<'_>)]) -> bool {
    entries.windows(2).all(|w| w[0].0 < w[1].0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decoder, to_bytes};

    fn roundtrip(input: &[u8]) {
        let v = Decoder::new(input).decode_all().unwrap();
        assert_eq!(to_bytes(&v), input, "canonical roundtrip");
    }

    #[test]
    fn canonical_roundtrips() {
        roundtrip(b"i0e");
        roundtrip(b"i-9223372036854775808e");
        roundtrip(b"i9223372036854775807e");
        roundtrip(b"0:");
        roundtrip(b"11:hello world");
        roundtrip(b"le");
        roundtrip(b"de");
        roundtrip(b"d1:a1:b3:cati-1e4:listli1ei2eee");
        roundtrip(b"d4:infod6:lengthi123e4:name4:test12:piece lengthi16384e6:pieces0:ee");
    }

    #[test]
    fn min_int() {
        let v = Value::Int(i64::MIN);
        assert_eq!(to_bytes(&v), b"i-9223372036854775808e");
    }

    #[test]
    fn hand_built_dict_is_sorted_on_encode() {
        let v = Value::Dict {
            entries: vec![(&b"b"[..], Value::Int(2)), (&b"a"[..], Value::Int(1))],
            raw: b"",
        };
        assert_eq!(to_bytes(&v), b"d1:ai1e1:bi2ee");
    }
}
