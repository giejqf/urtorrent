// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The borrowed [`Value`] type.

use core::fmt;

/// A decoded bencode value borrowing from the input buffer.
///
/// Composite values ([`Value::List`], [`Value::Dict`]) also carry the exact
/// raw bytes they were decoded from (see [`Value::raw`]); this is what makes
/// the info-hash reproducible.
#[derive(Clone, PartialEq, Eq)]
pub enum Value<'a> {
    /// A bencode integer (`i<n>e`).
    Int(i64),
    /// A byte string (`<len>:<bytes>`).
    Bytes(&'a [u8]),
    /// A list (`l...e`), with the raw bytes of the whole list.
    List {
        /// Elements in order.
        items: Vec<Value<'a>>,
        /// The exact bytes `l...e` this list decoded from.
        raw: &'a [u8],
    },
    /// A dictionary (`d...e`), keys in sorted order, with the raw bytes of the
    /// whole dict.
    Dict {
        /// `(key, value)` pairs, sorted by key (as decoded).
        entries: Vec<(&'a [u8], Value<'a>)>,
        /// The exact bytes `d...e` this dict decoded from.
        raw: &'a [u8],
    },
}

/// The kind of a [`Value`], without its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// [`Value::Int`].
    Int,
    /// [`Value::Bytes`].
    Bytes,
    /// [`Value::List`].
    List,
    /// [`Value::Dict`].
    Dict,
}

impl<'a> Value<'a> {
    /// This value's kind.
    pub fn kind(&self) -> ValueKind {
        match self {
            Value::Int(_) => ValueKind::Int,
            Value::Bytes(_) => ValueKind::Bytes,
            Value::List { .. } => ValueKind::List,
            Value::Dict { .. } => ValueKind::Dict,
        }
    }

    /// The integer, if this is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The byte string, if this is one.
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The byte string as UTF-8, if this is a valid-UTF-8 string.
    pub fn as_str(&self) -> Option<&'a str> {
        self.as_bytes().and_then(|b| core::str::from_utf8(b).ok())
    }

    /// The list items, if this is a list.
    pub fn as_list(&self) -> Option<&[Value<'a>]> {
        match self {
            Value::List { items, .. } => Some(items),
            _ => None,
        }
    }

    /// The dict entries, if this is a dict.
    pub fn as_dict(&self) -> Option<&[(&'a [u8], Value<'a>)]> {
        match self {
            Value::Dict { entries, .. } => Some(entries),
            _ => None,
        }
    }

    /// The value for `key` in this dict (binary search; keys are sorted).
    pub fn get(&self, key: &[u8]) -> Option<&Value<'a>> {
        let entries = self.as_dict()?;
        entries
            .binary_search_by(|(k, _)| (*k).cmp(key))
            .ok()
            .map(|i| &entries[i].1)
    }

    /// Convenience: `get` by a `&str` key.
    pub fn get_str(&self, key: &str) -> Option<&Value<'a>> {
        self.get(key.as_bytes())
    }

    /// The raw bytes this value decoded from. For [`Value::Int`] and
    /// [`Value::Bytes`] this is `None` (they are cheap to re-encode
    /// canonically and callers rarely need their raw span); for lists and
    /// dicts it is the exact `l...e` / `d...e` slice, which is what the
    /// info-hash is computed over.
    pub fn raw(&self) -> Option<&'a [u8]> {
        match self {
            Value::List { raw, .. } | Value::Dict { raw, .. } => Some(raw),
            _ => None,
        }
    }
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{i}"),
            Value::Bytes(b) => match core::str::from_utf8(b) {
                Ok(s) if b.len() <= 48 && !s.chars().any(char::is_control) => write!(f, "{s:?}"),
                _ => write!(f, "<{} bytes>", b.len()),
            },
            Value::List { items, .. } => f.debug_list().entries(items).finish(),
            Value::Dict { entries, .. } => {
                let mut m = f.debug_map();
                for (k, v) in entries {
                    m.entry(&String::from_utf8_lossy(k), v);
                }
                m.finish()
            }
        }
    }
}
