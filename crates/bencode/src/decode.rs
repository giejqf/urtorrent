// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The decoder. Strict about canonical form so re-encoding is a fixed point
//! and info-hashes are stable.

use crate::{Error, Value};

/// Resource limits applied while decoding untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum nesting depth of lists/dicts. BEP torrents are shallow; peers
    /// have no reason to send deeply nested structures.
    pub max_depth: usize,
    /// Maximum number of items in a single list or entries in a single dict.
    pub max_container_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // Generous for real torrents (thousands of files -> thousands of
        // `files` entries and `pieces` is one string, not a container), tight
        // enough to stop a hostile peer from forcing huge allocations. Depth 32
        // is far beyond anything a real bencode structure needs.
        Limits {
            max_depth: 32,
            max_container_len: 10_000_000,
        }
    }
}

/// A streaming decoder over a byte slice.
///
/// Use [`Decoder::decode_all`] for a complete top-level value, or
/// [`Decoder::decode_value`] to decode one value and leave the cursor after it
/// (for framed protocols that put several values back-to-back).
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    limits: Limits,
}

impl<'a> Decoder<'a> {
    /// A decoder with default [`Limits`].
    pub fn new(input: &'a [u8]) -> Self {
        Decoder {
            input,
            pos: 0,
            limits: Limits::default(),
        }
    }

    /// A decoder with custom limits.
    pub fn with_limits(input: &'a [u8], limits: Limits) -> Self {
        Decoder {
            input,
            pos: 0,
            limits,
        }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The not-yet-consumed input.
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.pos..]
    }

    /// Decode one value and require that it consumes the whole input.
    pub fn decode_all(mut self) -> Result<Value<'a>, Error> {
        let v = self.decode_value()?;
        if self.pos != self.input.len() {
            return Err(Error::Trailing(self.input.len() - self.pos));
        }
        Ok(v)
    }

    /// Decode one value, advancing the cursor past it.
    pub fn decode_value(&mut self) -> Result<Value<'a>, Error> {
        self.value(0)
    }

    fn peek(&self) -> Result<u8, Error> {
        self.input
            .get(self.pos)
            .copied()
            .ok_or(Error::Eof(self.pos))
    }

    fn value(&mut self, depth: usize) -> Result<Value<'a>, Error> {
        if depth > self.limits.max_depth {
            return Err(Error::TooDeep(self.pos));
        }
        match self.peek()? {
            b'i' => self.integer(),
            b'0'..=b'9' => self.bytes().map(Value::Bytes),
            b'l' => self.list(depth),
            b'd' => self.dict(depth),
            byte => Err(Error::Unexpected {
                byte,
                offset: self.pos,
            }),
        }
    }

    fn integer(&mut self) -> Result<Value<'a>, Error> {
        let start = self.pos;
        self.pos += 1; // 'i'
        let end = self.find(b'e').ok_or(Error::Eof(start))?;
        let digits = &self.input[start + 1..end];
        let n = parse_int(digits).ok_or(Error::Integer(start))?;
        self.pos = end + 1;
        Ok(Value::Int(n))
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let start = self.pos;
        let colon = self.find(b':').ok_or(Error::Eof(start))?;
        let len_digits = &self.input[start..colon];
        let len = parse_len(len_digits).ok_or(Error::StringLen(start))?;
        let data_start = colon + 1;
        let data_end = data_start.checked_add(len).ok_or(Error::StringLen(start))?;
        if data_end > self.input.len() {
            return Err(Error::StringLen(start));
        }
        self.pos = data_end;
        Ok(&self.input[data_start..data_end])
    }

    fn list(&mut self, depth: usize) -> Result<Value<'a>, Error> {
        let start = self.pos;
        self.pos += 1; // 'l'
        let mut items = Vec::new();
        loop {
            if self.peek()? == b'e' {
                self.pos += 1;
                let raw = &self.input[start..self.pos];
                return Ok(Value::List { items, raw });
            }
            if items.len() >= self.limits.max_container_len {
                return Err(Error::TooDeep(self.pos));
            }
            items.push(self.value(depth + 1)?);
        }
    }

    fn dict(&mut self, depth: usize) -> Result<Value<'a>, Error> {
        let start = self.pos;
        self.pos += 1; // 'd'
        let mut entries: Vec<(&'a [u8], Value<'a>)> = Vec::new();
        loop {
            if self.peek()? == b'e' {
                self.pos += 1;
                let raw = &self.input[start..self.pos];
                return Ok(Value::Dict { entries, raw });
            }
            if entries.len() >= self.limits.max_container_len {
                return Err(Error::TooDeep(self.pos));
            }
            let key_start = self.pos;
            if !self.peek()?.is_ascii_digit() {
                return Err(Error::KeyNotString(key_start));
            }
            let key = self.bytes()?;
            if let Some((prev, _)) = entries.last()
                && *prev >= key
            {
                return Err(Error::UnsortedKeys(key_start));
            }
            let val = self.value(depth + 1)?;
            entries.push((key, val));
        }
    }

    fn find(&self, needle: u8) -> Option<usize> {
        self.input[self.pos..]
            .iter()
            .position(|&b| b == needle)
            .map(|i| i + self.pos)
    }
}

/// Parse a canonical bencode integer body (between `i` and `e`).
/// Rejects empty, `-0`, and leading zeros; enforces `i64` range.
fn parse_int(digits: &[u8]) -> Option<i64> {
    match digits {
        [] => None,
        b"0" => Some(0),
        [b'-', b'0', ..] => None, // -0 and -0...
        [b'0', _, ..] => None,    // leading zero
        [b'-'] => None,           // lone minus
        [b'-', rest @ ..] => {
            if !rest.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let s = core::str::from_utf8(digits).ok()?;
            s.parse::<i64>().ok()
        }
        _ => {
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let s = core::str::from_utf8(digits).ok()?;
            s.parse::<i64>().ok()
        }
    }
}

/// Parse a canonical byte-string length: digits only, no leading zero (except
/// "0" itself). Bounded to `usize`.
fn parse_len(digits: &[u8]) -> Option<usize> {
    match digits {
        [] => None,
        b"0" => Some(0),
        [b'0', _, ..] => None, // leading zero
        _ => {
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            core::str::from_utf8(digits).ok()?.parse::<usize>().ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(input: &[u8]) -> Result<Value<'_>, Error> {
        Decoder::new(input).decode_all()
    }

    #[test]
    fn integers() {
        assert_eq!(dec(b"i0e").unwrap().as_int(), Some(0));
        assert_eq!(dec(b"i-42e").unwrap().as_int(), Some(-42));
        assert_eq!(
            dec(b"i9223372036854775807e").unwrap().as_int(),
            Some(i64::MAX)
        );
        // non-canonical / invalid
        for bad in [
            &b"i-0e"[..],
            b"i01e",
            b"ie",
            b"i-e",
            b"i 1e",
            b"i9223372036854775808e",
            b"i1",
        ] {
            assert!(dec(bad).is_err(), "{bad:?} should fail");
        }
    }

    #[test]
    fn strings() {
        assert_eq!(dec(b"0:").unwrap().as_bytes(), Some(&b""[..]));
        assert_eq!(dec(b"5:hello").unwrap().as_bytes(), Some(&b"hello"[..]));
        for bad in [&b"01:a"[..], b"5:hi", b"2:", b"-1:x", b"3 :abc"] {
            assert!(dec(bad).is_err(), "{bad:?} should fail");
        }
    }

    #[test]
    fn containers_and_raw() {
        let raw = b"d1:ali1ei2ee3:foo3:bare";
        let v = dec(raw).unwrap();
        assert_eq!(v.raw(), Some(&raw[..]));
        assert_eq!(v.get(b"foo").unwrap().as_bytes(), Some(&b"bar"[..]));
        let list = v.get(b"a").unwrap();
        assert_eq!(list.as_list().unwrap().len(), 2);
        assert_eq!(list.raw(), Some(&b"li1ei2ee"[..]));
    }

    #[test]
    fn dict_key_rules() {
        assert!(dec(b"d1:b0:1:a0:e").is_err()); // unsorted
        assert!(dec(b"d1:a0:1:a0:e").is_err()); // duplicate
        assert!(dec(b"di1e0:e").is_err()); // non-string key
        assert!(dec(b"d1:a0:e").is_ok());
    }

    #[test]
    fn depth_limit() {
        let mut deep = vec![b'l'; 40];
        deep.extend(std::iter::repeat_n(b'e', 40));
        assert!(matches!(dec(&deep), Err(Error::TooDeep(_))));
    }

    #[test]
    fn trailing_and_eof() {
        assert!(matches!(dec(b"i1ee"), Err(Error::Trailing(1))));
        assert!(matches!(dec(b"l"), Err(Error::Eof(_))));
        assert!(matches!(dec(b""), Err(Error::Eof(0))));
    }

    #[test]
    fn framed_decode_value() {
        let mut d = Decoder::new(b"i1e3:abcle");
        assert_eq!(d.decode_value().unwrap().as_int(), Some(1));
        assert_eq!(d.decode_value().unwrap().as_bytes(), Some(&b"abc"[..]));
        assert_eq!(d.decode_value().unwrap().as_list().unwrap().len(), 0);
        assert!(d.remaining().is_empty());
    }

    #[test]
    fn no_panic_on_arbitrary_prefixes() {
        // A crash-resistance smoke test; the fuzz target is the real check.
        let seed = b"d4:infod6:lengthi123e4:name4:test12:piece lengthi16384e6:pieces0:ee";
        for i in 0..=seed.len() {
            let _ = dec(&seed[..i]);
            let _ = Decoder::new(&seed[..i]).decode_value();
        }
    }
}
