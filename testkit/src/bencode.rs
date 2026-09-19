// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! A small, independent bencode implementation for the test harness.
//!
//! This is deliberately *not* the library's `bencode` crate: the harness must
//! be able to generate fixtures and parse tracker/peer traffic without trusting
//! the code under test, and having two independent implementations lets us
//! cross-check them in differential tests.

use std::collections::BTreeMap;
use std::fmt;

/// A decoded bencode value. Dictionaries keep their keys sorted (BTreeMap), so
/// re-encoding a decoded value is canonical.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{i}"),
            Value::Bytes(b) => match std::str::from_utf8(b) {
                Ok(s) if b.len() <= 64 && !s.chars().any(char::is_control) => write!(f, "{s:?}"),
                _ => write!(f, "<{} bytes: {}>", b.len(), hex(&b[..b.len().min(20)])),
            },
            Value::List(l) => f.debug_list().entries(l).finish(),
            Value::Dict(d) => {
                let mut m = f.debug_map();
                for (k, v) in d {
                    m.entry(&String::from_utf8_lossy(k), v);
                }
                m.finish()
            }
        }
    }
}

impl Value {
    pub fn str(s: &str) -> Value {
        Value::Bytes(s.as_bytes().to_vec())
    }
    pub fn dict() -> Value {
        Value::Dict(BTreeMap::new())
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_dict().and_then(|d| d.get(key.as_bytes()))
    }
    /// Insert into a dict value; a no-op on non-dicts (harness code).
    pub fn insert(&mut self, key: &str, v: Value) -> &mut Value {
        if let Value::Dict(d) = self {
            d.insert(key.as_bytes().to_vec(), v);
        } else {
            debug_assert!(false, "insert on non-dict");
        }
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Value::Int(i) => {
                out.push(b'i');
                out.extend_from_slice(i.to_string().as_bytes());
                out.push(b'e');
            }
            Value::Bytes(b) => {
                out.extend_from_slice(b.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(b);
            }
            Value::List(l) => {
                out.push(b'l');
                for v in l {
                    v.encode_into(out);
                }
                out.push(b'e');
            }
            Value::Dict(d) => {
                out.push(b'd');
                for (k, v) in d {
                    out.extend_from_slice(k.len().to_string().as_bytes());
                    out.push(b':');
                    out.extend_from_slice(k);
                    v.encode_into(out);
                }
                out.push(b'e');
            }
        }
    }
}

#[derive(Debug)]
pub enum DecodeError {
    Truncated,
    BadToken(usize),
    BadInt(usize),
    TrailingData(usize),
    TooDeep,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DecodeError {}

/// Decode one value, requiring the whole input to be consumed.
pub fn decode(input: &[u8]) -> Result<Value, DecodeError> {
    let (v, n) = decode_prefix(input)?;
    if n != input.len() {
        return Err(DecodeError::TrailingData(n));
    }
    Ok(v)
}

/// Decode one value from the start of `input` and return it with the number of
/// bytes consumed. Use [`value_span`] to locate the raw bytes of a top-level
/// key (e.g. `info`) for hashing.
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), DecodeError> {
    let mut pos = 0;
    let v = parse(input, &mut pos, 0)?;
    Ok((v, pos))
}

/// Return the byte range of the value under top-level key `key` of a dict
/// (used to grab the raw `info` dictionary for hashing).
pub fn value_span(input: &[u8], key: &[u8]) -> Result<Option<std::ops::Range<usize>>, DecodeError> {
    let mut pos = 0;
    if input.first() != Some(&b'd') {
        return Err(DecodeError::BadToken(0));
    }
    pos += 1;
    loop {
        if pos >= input.len() {
            return Err(DecodeError::Truncated);
        }
        if input[pos] == b'e' {
            return Ok(None);
        }
        let (k, n) = parse_bytes(input, pos)?;
        pos = n;
        let start = pos;
        parse(input, &mut pos, 1)?;
        if k == key {
            return Ok(Some(start..pos));
        }
    }
}

fn parse(input: &[u8], pos: &mut usize, depth: usize) -> Result<Value, DecodeError> {
    if depth > 64 {
        return Err(DecodeError::TooDeep);
    }
    let Some(&c) = input.get(*pos) else {
        return Err(DecodeError::Truncated);
    };
    match c {
        b'i' => {
            let start = *pos + 1;
            let end = find(input, start, b'e').ok_or(DecodeError::Truncated)?;
            let s =
                std::str::from_utf8(&input[start..end]).map_err(|_| DecodeError::BadInt(start))?;
            let i: i64 = s.parse().map_err(|_| DecodeError::BadInt(start))?;
            *pos = end + 1;
            Ok(Value::Int(i))
        }
        b'0'..=b'9' => {
            let (b, n) = parse_bytes(input, *pos)?;
            *pos = n;
            Ok(Value::Bytes(b.to_vec()))
        }
        b'l' => {
            *pos += 1;
            let mut items = Vec::new();
            loop {
                match input.get(*pos) {
                    None => return Err(DecodeError::Truncated),
                    Some(b'e') => {
                        *pos += 1;
                        return Ok(Value::List(items));
                    }
                    Some(_) => items.push(parse(input, pos, depth + 1)?),
                }
            }
        }
        b'd' => {
            *pos += 1;
            let mut map = BTreeMap::new();
            loop {
                match input.get(*pos) {
                    None => return Err(DecodeError::Truncated),
                    Some(b'e') => {
                        *pos += 1;
                        return Ok(Value::Dict(map));
                    }
                    Some(_) => {
                        let (k, n) = parse_bytes(input, *pos)?;
                        *pos = n;
                        let v = parse(input, pos, depth + 1)?;
                        map.insert(k.to_vec(), v);
                    }
                }
            }
        }
        _ => Err(DecodeError::BadToken(*pos)),
    }
}

fn parse_bytes(input: &[u8], pos: usize) -> Result<(&[u8], usize), DecodeError> {
    let colon = find(input, pos, b':').ok_or(DecodeError::Truncated)?;
    let s = std::str::from_utf8(&input[pos..colon]).map_err(|_| DecodeError::BadToken(pos))?;
    let len: usize = s.parse().map_err(|_| DecodeError::BadToken(pos))?;
    let start = colon + 1;
    let end = start.checked_add(len).ok_or(DecodeError::Truncated)?;
    if end > input.len() {
        return Err(DecodeError::Truncated);
    }
    Ok((&input[start..end], end))
}

fn find(input: &[u8], from: usize, needle: u8) -> Option<usize> {
    input
        .get(from..)?
        .iter()
        .position(|&b| b == needle)
        .map(|i| i + from)
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse lowercase/uppercase hex.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut d = Value::dict();
        d.insert("b", Value::Int(-3))
            .insert("a", Value::str("x"))
            .insert("l", Value::List(vec![Value::Int(1), Value::str("")]));
        let enc = d.encode();
        assert_eq!(enc, b"d1:a1:x1:bi-3e1:lli1e0:ee");
        assert_eq!(decode(&enc).unwrap(), d);
    }

    #[test]
    fn info_span() {
        let raw = b"d4:infod1:xi1ee3:foo3:bare";
        let span = value_span(raw, b"info").unwrap().unwrap();
        assert_eq!(&raw[span], b"d1:xi1ee");
        assert!(value_span(raw, b"nope").unwrap().is_none());
    }

    #[test]
    fn errors() {
        assert!(decode(b"i12").is_err());
        assert!(decode(b"3:ab").is_err());
        assert!(decode(b"i1ee").is_err());
        assert!(decode(b"x").is_err());
    }
}
