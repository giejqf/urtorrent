// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Torrent metainfo (`.torrent`) and magnet-link parsing, the file tree, and
//! the piece↔file span mapping the storage layer needs.
//!
//! This crate is sans-IO: it parses bytes into owned structures and answers
//! layout questions, but never opens a file or a socket. Parsing is hardened
//! against hostile input (bounded, panic-free, path sanitisation in [`path`]).
//!
//! Only BEP 3 v1 torrents are parsed today; v2/hybrid (BEP 52) is deferred
//! (AGENTS.md 4). The v2-related keys are detected and reported via
//! [`Info::has_v2`] so a v1-only path never silently mishandles them.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod bitfield;
mod magnet;
pub mod path;
mod span;

use bencode::{Decoder, Value};
use sha1::{Digest, Sha1};

pub use bitfield::Bitfield;
pub use magnet::MagnetLink;
pub use path::SafePath;
pub use span::{FileSlice, PieceLocation};

/// A 20-byte SHA-1 info-hash.
pub type InfoHash = [u8; 20];

/// An error parsing metainfo or a magnet link.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The outer bencode was invalid.
    #[error("bencode: {0}")]
    Bencode(#[from] bencode::Error),
    /// A required key was missing.
    #[error("missing key {0:?}")]
    Missing(&'static str),
    /// A key had the wrong type or an invalid value.
    #[error("invalid {key}: {reason}")]
    Invalid {
        /// The key.
        key: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A file path was unsafe (path-traversal, absolute, reserved, ...).
    #[error("file {index}: {reason}")]
    Path {
        /// The file's index in the `files` list.
        index: usize,
        /// Why the path was rejected.
        reason: &'static str,
    },
    /// A magnet link was malformed.
    #[error("magnet: {0}")]
    Magnet(&'static str),
}

/// BEP 47 file attributes (`attr` string: a set of flag characters).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileAttr {
    /// `p`: padding file (its content is ignored, used only for piece alignment).
    pub padding: bool,
    /// `x`: executable.
    pub executable: bool,
    /// `h`: hidden.
    pub hidden: bool,
    /// `l`: symlink (we never create these; recorded for fidelity).
    pub symlink: bool,
}

impl FileAttr {
    fn parse(attr: &[u8]) -> FileAttr {
        let mut a = FileAttr::default();
        for &c in attr {
            match c {
                b'p' => a.padding = true,
                b'x' => a.executable = true,
                b'h' => a.hidden = true,
                b'l' => a.symlink = true,
                _ => {}
            }
        }
        a
    }
}

/// One file in the torrent's logical byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// Sanitised relative path, including the torrent's top directory for
    /// multi-file torrents.
    pub path: SafePath,
    /// Length in bytes.
    pub length: u64,
    /// Byte offset of this file within the concatenated torrent stream.
    pub offset: u64,
    /// BEP 47 attributes.
    pub attr: FileAttr,
}

impl File {
    /// Whether this is a padding file (BEP 47) whose content is not stored.
    pub fn is_padding(&self) -> bool {
        self.attr.padding
    }
}

/// The `info` dictionary: names, piece layout and files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// The info-hash (SHA-1 of the raw info-dict bytes).
    pub info_hash: InfoHash,
    /// The suggested display name (`name`).
    pub name: String,
    /// Piece length in bytes.
    pub piece_length: u32,
    /// SHA-1 hash of each piece (20 bytes each).
    pub piece_hashes: Vec<[u8; 20]>,
    /// Total length of the content (sum of file lengths, padding included).
    pub total_length: u64,
    /// Files, in stream order (single-file torrents have exactly one).
    pub files: Vec<File>,
    /// Whether this is a single-file torrent (`length`) vs multi-file (`files`).
    pub single_file: bool,
    /// BEP 27 private flag.
    pub private: bool,
    /// Whether v2/hybrid (BEP 52) keys were present (deferred; see crate docs).
    pub has_v2: bool,
}

impl Info {
    /// Parse a bare bencoded `info` dictionary (what `ut_metadata` delivers,
    /// BEP 9). The caller checks its SHA-1 against the expected info-hash.
    pub fn from_info_dict(bytes: &[u8]) -> Result<Info, Error> {
        let v = Decoder::new(bytes).decode_all()?;
        parse_info(&v)
    }

    /// Number of pieces.
    pub fn piece_count(&self) -> usize {
        self.piece_hashes.len()
    }

    /// The length of piece `index` (the last piece may be short).
    pub fn piece_size(&self, index: usize) -> Option<u32> {
        if index >= self.piece_hashes.len() {
            return None;
        }
        let full = u64::from(self.piece_length);
        let start = index as u64 * full;
        Some((self.total_length - start).min(full) as u32)
    }

    /// The expected SHA-1 of piece `index`.
    pub fn piece_hash(&self, index: usize) -> Option<&[u8; 20]> {
        self.piece_hashes.get(index)
    }

    /// The file slices that make up piece `index` (see [`PieceLocation`]).
    pub fn piece_location(&self, index: usize) -> Option<PieceLocation> {
        span::piece_location(self, index)
    }

    /// Non-padding files only (what the user actually receives).
    pub fn content_files(&self) -> impl Iterator<Item = &File> {
        self.files.iter().filter(|f| !f.is_padding())
    }
}

/// A parsed `.torrent` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Torrent {
    /// The info dictionary.
    pub info: Info,
    /// `announce` (primary tracker), if present.
    pub announce: Option<String>,
    /// `announce-list` tiers (BEP 12), if present.
    pub announce_list: Vec<Vec<String>>,
    /// `url-list` web seeds (BEP 19), if present.
    pub url_list: Vec<String>,
    /// `comment`.
    pub comment: Option<String>,
    /// `created by`.
    pub created_by: Option<String>,
    /// `creation date` (unix seconds).
    pub creation_date: Option<i64>,
}

impl Torrent {
    /// Parse a `.torrent` from its bytes.
    pub fn parse(bytes: &[u8]) -> Result<Torrent, Error> {
        let root = Decoder::new(bytes).decode_all()?;
        let info_val = root.get_str("info").ok_or(Error::Missing("info"))?;
        let info = parse_info(info_val)?;
        let announce = root
            .get_str("announce")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let announce_list = parse_announce_list(&root);
        let url_list = parse_url_list(&root);
        Ok(Torrent {
            info,
            announce,
            announce_list,
            url_list,
            comment: root
                .get_str("comment")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            created_by: root
                .get_str("created by")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            creation_date: root
                .get_str("creation date")
                .and_then(bencode::Value::as_int),
        })
    }

    /// The tracker tiers to announce to. If `announce-list` is present it wins
    /// (BEP 12); otherwise the single `announce` forms one tier. Empty for a
    /// trackerless torrent.
    pub fn tiers(&self) -> Vec<Vec<String>> {
        if !self.announce_list.is_empty() {
            return self.announce_list.clone();
        }
        match &self.announce {
            Some(a) => vec![vec![a.clone()]],
            None => Vec::new(),
        }
    }
}

fn parse_info(info: &Value<'_>) -> Result<Info, Error> {
    if info.kind() != bencode::ValueKind::Dict {
        return Err(Error::Invalid {
            key: "info",
            reason: "not a dictionary",
        });
    }
    let raw = info.raw().ok_or(Error::Invalid {
        key: "info",
        reason: "no raw bytes",
    })?;
    let mut hasher = Sha1::new();
    hasher.update(raw);
    let info_hash: InfoHash = hasher.finalize().into();

    let name_bytes = info
        .get_str("name")
        .and_then(Value::as_bytes)
        .ok_or(Error::Missing("name"))?;
    let name = String::from_utf8_lossy(name_bytes).into_owned();
    let name_component = SafePath::single(name_bytes)?;

    let piece_length = info
        .get_str("piece length")
        .and_then(Value::as_int)
        .ok_or(Error::Missing("piece length"))?;
    if piece_length <= 0 || piece_length > (1 << 30) {
        return Err(Error::Invalid {
            key: "piece length",
            reason: "out of range",
        });
    }
    let piece_length = piece_length as u32;

    let pieces = info
        .get_str("pieces")
        .and_then(Value::as_bytes)
        .ok_or(Error::Missing("pieces"))?;
    if pieces.len() % 20 != 0 {
        return Err(Error::Invalid {
            key: "pieces",
            reason: "length not a multiple of 20",
        });
    }
    let piece_hashes: Vec<[u8; 20]> = pieces.as_chunks::<20>().0.to_vec();

    let has_v2 = info.get_str("meta version").is_some() || info.get_str("file tree").is_some();
    let private = info.get_str("private").and_then(Value::as_int) == Some(1);

    let (files, total_length, single_file) = if let Some(files_val) = info.get_str("files") {
        let (files, total) = parse_files(files_val, &name_component)?;
        (files, total, false)
    } else {
        let length = info
            .get_str("length")
            .and_then(Value::as_int)
            .ok_or(Error::Missing("length"))?;
        if length < 0 {
            return Err(Error::Invalid {
                key: "length",
                reason: "negative",
            });
        }
        let attr = info
            .get_str("attr")
            .and_then(Value::as_bytes)
            .map(FileAttr::parse)
            .unwrap_or_default();
        (
            vec![File {
                path: name_component,
                length: length as u64,
                offset: 0,
                attr,
            }],
            length as u64,
            true,
        )
    };

    // Piece count must match total length.
    let expected_pieces = total_length.div_ceil(u64::from(piece_length)) as usize;
    // A zero-length torrent has zero pieces; otherwise counts must match.
    if piece_hashes.len() != expected_pieces {
        return Err(Error::Invalid {
            key: "pieces",
            reason: "count does not match total length",
        });
    }

    Ok(Info {
        info_hash,
        name,
        piece_length,
        piece_hashes,
        total_length,
        files,
        single_file,
        private,
        has_v2,
    })
}

fn parse_files(files_val: &Value<'_>, top: &SafePath) -> Result<(Vec<File>, u64), Error> {
    let list = files_val.as_list().ok_or(Error::Invalid {
        key: "files",
        reason: "not a list",
    })?;
    if list.is_empty() {
        return Err(Error::Invalid {
            key: "files",
            reason: "empty",
        });
    }
    let top_name = top.components().first().cloned().unwrap_or_default();
    let mut files = Vec::with_capacity(list.len());
    let mut offset = 0u64;
    for (index, entry) in list.iter().enumerate() {
        if entry.kind() != bencode::ValueKind::Dict {
            return Err(Error::Invalid {
                key: "files",
                reason: "entry is not a dict",
            });
        }
        let length = entry
            .get_str("length")
            .and_then(Value::as_int)
            .ok_or(Error::Missing("files[].length"))?;
        if length < 0 {
            return Err(Error::Invalid {
                key: "files",
                reason: "negative length",
            });
        }
        let path_list = entry
            .get_str("path")
            .and_then(Value::as_list)
            .ok_or(Error::Missing("files[].path"))?;
        let raw_components: Vec<&[u8]> = path_list
            .iter()
            .map(|c| {
                c.as_bytes().ok_or(Error::Path {
                    index,
                    reason: "path element not a string",
                })
            })
            .collect::<Result<_, _>>()?;
        let path = SafePath::from_components(&raw_components, index)?.prefixed(&top_name);
        let attr = entry
            .get_str("attr")
            .and_then(Value::as_bytes)
            .map(FileAttr::parse)
            .unwrap_or_default();
        files.push(File {
            path,
            length: length as u64,
            offset,
            attr,
        });
        offset = offset.checked_add(length as u64).ok_or(Error::Invalid {
            key: "files",
            reason: "total length overflow",
        })?;
    }
    Ok((files, offset))
}

fn parse_announce_list(root: &Value<'_>) -> Vec<Vec<String>> {
    let Some(tiers) = root.get_str("announce-list").and_then(Value::as_list) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for tier in tiers {
        let Some(urls) = tier.as_list() else { continue };
        let tier: Vec<String> = urls
            .iter()
            .filter_map(|u| u.as_str())
            .map(str::to_string)
            .collect();
        if !tier.is_empty() {
            out.push(tier);
        }
    }
    out
}

fn parse_url_list(root: &Value<'_>) -> Vec<String> {
    match root.get_str("url-list") {
        Some(Value::Bytes(b)) => core::str::from_utf8(b)
            .ok()
            .map(|s| vec![s.to_string()])
            .unwrap_or_default(),
        Some(v) => v
            .as_list()
            .map(|l| {
                l.iter()
                    .filter_map(|u| u.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal single-file torrent by hand (via the bencode encoder in
    // the harness would be circular; construct bytes directly).
    fn single_file(len: u64, piece_len: u32) -> Vec<u8> {
        let pieces = len.div_ceil(u64::from(piece_len)) as usize;
        let mut hashes = Vec::new();
        for _ in 0..pieces {
            hashes.extend_from_slice(&[0u8; 20]);
        }
        let mut info = Vec::new();
        info.extend_from_slice(b"d6:lengthi");
        info.extend_from_slice(len.to_string().as_bytes());
        info.extend_from_slice(b"e4:name4:test12:piece lengthi");
        info.extend_from_slice(piece_len.to_string().as_bytes());
        info.extend_from_slice(b"e6:pieces");
        info.extend_from_slice(hashes.len().to_string().as_bytes());
        info.push(b':');
        info.extend_from_slice(&hashes);
        info.push(b'e');
        let mut t = Vec::new();
        t.extend_from_slice(b"d8:announce19:http://tracker/anno4:info");
        t.extend_from_slice(&info);
        t.push(b'e');
        t
    }

    #[test]
    fn parses_single_file() {
        let t = Torrent::parse(&single_file(100_000, 16384)).unwrap();
        assert_eq!(t.info.name, "test");
        assert_eq!(t.info.total_length, 100_000);
        assert_eq!(t.info.piece_count(), 7);
        assert_eq!(t.info.piece_size(6), Some((100_000 - 6 * 16384) as u32));
        assert!(t.info.single_file);
        assert_eq!(t.announce.as_deref(), Some("http://tracker/anno"));
        assert_eq!(t.tiers(), vec![vec!["http://tracker/anno".to_string()]]);
        // stable info-hash
        let again = Torrent::parse(&single_file(100_000, 16384)).unwrap();
        assert_eq!(t.info.info_hash, again.info.info_hash);
    }

    #[test]
    fn rejects_bad_piece_count() {
        // pieces says 1 hash but length needs 7.
        let mut info = Vec::new();
        info.extend_from_slice(b"d6:lengthi100000e4:name4:test12:piece lengthi16384e6:pieces20:");
        info.extend_from_slice(&[0u8; 20]);
        info.push(b'e');
        let mut t = Vec::new();
        t.extend_from_slice(b"d4:info");
        t.extend_from_slice(&info);
        t.push(b'e');
        assert!(matches!(
            Torrent::parse(&t),
            Err(Error::Invalid { key: "pieces", .. })
        ));
    }

    #[test]
    fn no_panic_on_truncation() {
        let full = single_file(100_000, 16384);
        for i in 0..full.len() {
            let _ = Torrent::parse(&full[..i]);
        }
    }
}
