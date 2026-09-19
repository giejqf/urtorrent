// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Zero-copy bencode decoding and canonical encoding.
//!
//! Bencode (BEP 3) has four types: integers, byte strings, lists and
//! dictionaries. This crate decodes untrusted bytes into borrowed [`Value`]s
//! (no allocation for the values themselves — byte strings and the raw spans
//! of composite values borrow from the input) and encodes back canonically
//! (integers without leading zeros, dictionary keys sorted as raw byte
//! strings). It is sans-IO and `#![forbid(unsafe_code)]`.
//!
//! # Safety against hostile input
//!
//! Remote peers and trackers send bencode. Decoding therefore:
//!
//! - never panics, never allocates unboundedly, and never recurses without a
//!   depth limit ([`Limits`]);
//! - rejects the non-canonical encodings BEP 3 forbids (leading zeros,
//!   negative zero, unsorted or duplicate dictionary keys, leading-zero string
//!   lengths) so that the info-hash of a re-encoded dict is stable;
//! - bounds every length against the remaining input before allocating.
//!
//! # Info-dict preservation
//!
//! The info-hash is `SHA-1` of the *raw* bytes of the `info` dictionary as it
//! appeared in the `.torrent`, not of a re-encoding. [`Value::raw`] on a
//! decoded composite returns exactly those bytes, so callers hash what was on
//! disk even when the file was not canonically encoded.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod decode;
mod encode;
mod value;

pub use decode::{Decoder, Limits};
pub use encode::Encoder;
pub use value::{Value, ValueKind};

use core::fmt;

/// An error decoding bencode. The byte offset is where the problem was found.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Input ended in the middle of a value.
    #[error("unexpected end of input at offset {0}")]
    Eof(usize),
    /// A byte that cannot start (or continue) a value.
    #[error("unexpected byte {byte:#04x} at offset {offset}")]
    Unexpected {
        /// The offending byte.
        byte: u8,
        /// Its offset.
        offset: usize,
    },
    /// An integer was malformed, out of range, or non-canonical (leading zero,
    /// `-0`, empty).
    #[error("invalid integer at offset {0}")]
    Integer(usize),
    /// A byte-string length was malformed, non-canonical, or larger than the
    /// remaining input.
    #[error("invalid string length at offset {0}")]
    StringLen(usize),
    /// Dictionary keys were not strictly increasing (unsorted or duplicated).
    #[error("dictionary keys not sorted at offset {0}")]
    UnsortedKeys(usize),
    /// A dictionary key was not a byte string.
    #[error("dictionary key is not a string at offset {0}")]
    KeyNotString(usize),
    /// Nesting exceeded [`Limits::max_depth`].
    #[error("nesting too deep at offset {0}")]
    TooDeep(usize),
    /// Trailing bytes after a complete top-level value (only for the whole-input
    /// decoders).
    #[error("{0} trailing bytes after value")]
    Trailing(usize),
}

impl Error {
    /// The byte offset the error refers to (0 for [`Error::Trailing`], whose
    /// offset is the tail length instead).
    pub fn offset(&self) -> usize {
        match self {
            Error::Eof(o)
            | Error::Unexpected { offset: o, .. }
            | Error::Integer(o)
            | Error::StringLen(o)
            | Error::UnsortedKeys(o)
            | Error::KeyNotString(o)
            | Error::TooDeep(o) => *o,
            Error::Trailing(_) => 0,
        }
    }
}

/// Decode one value, requiring it to consume the entire input, with default
/// [`Limits`].
pub fn from_bytes(input: &[u8]) -> Result<Value<'_>, Error> {
    Decoder::new(input).decode_all()
}

/// Encode a value canonically into a new `Vec`.
pub fn to_bytes(value: &Value<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    Encoder::new(&mut out).encode(value);
    out
}

/// Lowercase hex of `bytes`, useful for info-hashes and debug output.
pub fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
