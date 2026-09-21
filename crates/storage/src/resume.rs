// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Crash-safe resume data (AGENTS.md 5.4). Our own versioned format, written
//! atomically: write a temp file, `fsync` it, `rename` it over the target, then
//! `fsync` the directory. `kill -9` at any moment therefore never leaves a
//! resume file that claims pieces we do not have — the reader sees either the
//! old complete file or the new complete file, never a torn one. When in doubt
//! (missing/corrupt/mismatched resume data) the caller rechecks.
//!
//! The format carries its own version, independent of the crate version, and
//! every released version must read every format version it ever wrote.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use bencode::{Decoder, Value};
use metainfo::InfoHash;

use crate::Error;
use metainfo::Bitfield;

/// Current resume-data format version. Version 2 added `file_priorities`
/// (optional; version-1 files read as "all default"), version 3 the time
/// counters, version 4 the queue fields (`auto_managed`, `queue_position`;
/// absent in older files: managed, appended).
pub const FORMAT_VERSION: i64 = 4;

/// Decoded resume data for one torrent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeData {
    /// Format version this was written with.
    pub format_version: i64,
    /// The torrent's info-hash (must match on load).
    pub info_hash: InfoHash,
    /// Piece length (sanity check against the metainfo).
    pub piece_length: u32,
    /// Total length (sanity check).
    pub total_length: u64,
    /// Which pieces are verified-present.
    pub have: Bitfield,
    /// Bytes uploaded so far (truthful accounting, AGENTS.md rule 1).
    pub uploaded: u64,
    /// Bytes downloaded so far.
    pub downloaded: u64,
    /// File priorities per `info.files` entry (empty = all default).
    pub file_priorities: Vec<u8>,
    /// Seconds the torrent has been active (not paused) in total (v3).
    pub active_time: u64,
    /// Seconds the torrent has been active as a seed in total (v3).
    pub seeding_time: u64,
    /// Whether the active-torrent queue manages the torrent (v4; `true`
    /// when absent).
    pub auto_managed: bool,
    /// Queue order key (v4; `None` when absent: appended on load).
    pub queue_position: Option<u64>,
}

impl ResumeData {
    /// Build fresh resume data for a torrent with no pieces yet.
    pub fn empty(
        info_hash: InfoHash,
        piece_length: u32,
        total_length: u64,
        pieces: usize,
    ) -> ResumeData {
        ResumeData {
            format_version: FORMAT_VERSION,
            info_hash,
            piece_length,
            total_length,
            have: Bitfield::new(pieces),
            uploaded: 0,
            downloaded: 0,
            file_priorities: Vec::new(),
            active_time: 0,
            seeding_time: 0,
            auto_managed: true,
            queue_position: None,
        }
    }

    /// Encode to bytes (canonical bencode).
    pub fn encode(&self) -> Vec<u8> {
        let piece_len = i64::from(self.piece_length);
        let total = self.total_length as i64;
        let up = self.uploaded as i64;
        let down = self.downloaded as i64;
        let pieces = self.have.len() as i64;
        let active = self.active_time.min(i64::MAX as u64) as i64;
        let seeding = self.seeding_time.min(i64::MAX as u64) as i64;
        // Keys in sorted order (canonical bencode).
        let mut entries: Vec<(&[u8], Value)> = vec![
            (b"active_time", Value::Int(active)),
            (b"auto_managed", Value::Int(i64::from(self.auto_managed))),
            (b"downloaded", Value::Int(down)),
            (b"format", Value::Int(self.format_version)),
            (b"have", Value::Bytes(self.have.as_bytes())),
            (b"info_hash", Value::Bytes(&self.info_hash)),
            (b"pieces", Value::Int(pieces)),
            (b"piece_length", Value::Int(piece_len)),
            (b"seeding_time", Value::Int(seeding)),
            (b"total_length", Value::Int(total)),
            (b"uploaded", Value::Int(up)),
        ];
        if !self.file_priorities.is_empty() {
            // `file_priorities` sorts between `downloaded` and `format`.
            entries.insert(3, (b"file_priorities", Value::Bytes(&self.file_priorities)));
        }
        if let Some(q) = self.queue_position {
            // `queue_position` sorts between `pieces` and `seeding_time`.
            let at = entries
                .iter()
                .position(|(k, _)| *k == b"seeding_time")
                .unwrap_or(entries.len());
            entries.insert(
                at,
                (b"queue_position", Value::Int(q.min(i64::MAX as u64) as i64)),
            );
        }
        bencode::to_bytes(&Value::Dict { entries, raw: b"" })
    }

    /// Decode from bytes, validating the version and internal consistency.
    pub fn decode(bytes: &[u8]) -> Result<ResumeData, Error> {
        let v = Decoder::new(bytes)
            .decode_all()
            .map_err(|_| Error::Resume("invalid bencode"))?;
        let format_version = v
            .get_str("format")
            .and_then(Value::as_int)
            .ok_or(Error::Resume("missing format"))?;
        if format_version > FORMAT_VERSION {
            return Err(Error::Resume(
                "resume format newer than this build understands",
            ));
        }
        let ih = v
            .get_str("info_hash")
            .and_then(Value::as_bytes)
            .ok_or(Error::Resume("missing info_hash"))?;
        let info_hash: InfoHash = ih
            .try_into()
            .map_err(|_| Error::Resume("bad info_hash length"))?;
        let piece_length = v
            .get_str("piece_length")
            .and_then(Value::as_int)
            .ok_or(Error::Resume("missing piece_length"))?;
        let total_length = v
            .get_str("total_length")
            .and_then(Value::as_int)
            .ok_or(Error::Resume("missing total_length"))?;
        let pieces = v
            .get_str("pieces")
            .and_then(Value::as_int)
            .ok_or(Error::Resume("missing pieces"))?;
        let have_bytes = v
            .get_str("have")
            .and_then(Value::as_bytes)
            .ok_or(Error::Resume("missing have"))?;
        if piece_length <= 0 || total_length < 0 || pieces < 0 {
            return Err(Error::Resume("out-of-range field"));
        }
        let have = Bitfield::from_bytes(have_bytes, pieces as usize)
            .ok_or(Error::Resume("bad bitfield"))?;
        let uploaded = v
            .get_str("uploaded")
            .and_then(Value::as_int)
            .unwrap_or(0)
            .max(0) as u64;
        let downloaded = v
            .get_str("downloaded")
            .and_then(Value::as_int)
            .unwrap_or(0)
            .max(0) as u64;
        let file_priorities = v
            .get_str("file_priorities")
            .and_then(Value::as_bytes)
            .map(|b| b.iter().map(|p| (*p).min(7)).collect())
            .unwrap_or_default();
        // v3 fields; absent in v1/v2 files.
        let secs = |key: &str| v.get_str(key).and_then(Value::as_int).unwrap_or(0).max(0) as u64;
        Ok(ResumeData {
            format_version,
            info_hash,
            piece_length: piece_length as u32,
            total_length: total_length as u64,
            have,
            uploaded,
            downloaded,
            file_priorities,
            active_time: secs("active_time"),
            seeding_time: secs("seeding_time"),
            // v4 fields.
            auto_managed: v
                .get_str("auto_managed")
                .and_then(Value::as_int)
                .is_none_or(|a| a != 0),
            queue_position: v
                .get_str("queue_position")
                .and_then(Value::as_int)
                .filter(|q| *q >= 0)
                .map(|q| q as u64),
        })
    }

    /// Atomically write to `path` (tmp + fsync + rename + dir fsync).
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let dir = path
            .parent()
            .ok_or(Error::Resume("resume path has no parent"))?;
        fs::create_dir_all(dir)?;
        let tmp = path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&self.encode())?;
            f.flush()?;
            f.sync_all()?; // fsync the data
        }
        fs::rename(&tmp, path)?; // atomic replace
        // fsync the directory so the rename itself is durable. `File::sync_all`
        // issues fsync on the fd; on a directory that is well-defined on Linux.
        // Some filesystems return EINVAL for a directory fsync — tolerate that.
        if let Ok(dirf) = fs::File::open(dir) {
            match dirf.sync_all() {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(22) => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
        Ok(())
    }

    /// Load from `path`, or `Ok(None)` if it does not exist.
    pub fn load(path: &Path) -> Result<Option<ResumeData>, Error> {
        match fs::read(path) {
            Ok(bytes) => Ok(Some(ResumeData::decode(&bytes)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Check that this resume data matches a torrent's metainfo. On any mismatch
    /// the caller should recheck rather than trust the bitfield.
    pub fn matches(&self, info: &metainfo::Info) -> bool {
        self.info_hash == info.info_hash
            && self.piece_length == info.piece_length
            && self.total_length == info.total_length
            && self.have.len() == info.piece_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ResumeData {
        let mut have = Bitfield::new(10);
        have.set(0);
        have.set(3);
        have.set(9);
        ResumeData {
            format_version: FORMAT_VERSION,
            info_hash: [7u8; 20],
            piece_length: 16384,
            total_length: 150_000,
            have,
            uploaded: 1000,
            downloaded: 2000,
            file_priorities: vec![4, 0, 7],
            active_time: 3600,
            seeding_time: 1200,
            auto_managed: false,
            queue_position: Some(7),
        }
    }

    /// A version-3 file (no queue fields) still loads: managed, no position.
    #[test]
    fn reads_format_version_3() {
        let mut v3 = sample();
        v3.format_version = 3;
        v3.auto_managed = true;
        v3.queue_position = None;
        let bytes = v3.encode();
        let strip = |b: &[u8], needle: &[u8]| -> Vec<u8> {
            let at = b
                .windows(needle.len())
                .position(|w| w == needle)
                .expect("key present");
            [&b[..at], &b[at + needle.len()..]].concat()
        };
        let stripped = strip(&bytes, b"12:auto_managedi1e");
        assert!(!stripped.windows(14).any(|w| w == b"queue_position"));
        let back = ResumeData::decode(&stripped).unwrap();
        assert_eq!(back.format_version, 3);
        assert!(back.auto_managed);
        assert_eq!(back.queue_position, None);
        assert_eq!(back.active_time, 3600);
    }

    /// A version-2 file (no time counters) still loads, with zero times; the
    /// bytes a v2 writer produced are exactly what v2 wrote.
    #[test]
    fn reads_format_version_2() {
        let mut v2 = sample();
        v2.format_version = 2;
        v2.active_time = 0;
        v2.seeding_time = 0;
        v2.auto_managed = true;
        v2.queue_position = None;
        // What 0.1.0 wrote: the same dictionary minus the two time keys.
        let bytes = v2.encode();
        let strip = |b: &[u8], needle: &[u8]| -> Vec<u8> {
            let at = b
                .windows(needle.len())
                .position(|w| w == needle)
                .expect("key present");
            [&b[..at], &b[at + needle.len()..]].concat()
        };
        let stripped = strip(&bytes, b"11:active_timei0e");
        let stripped = strip(&stripped, b"12:seeding_timei0e");
        let stripped = strip(&stripped, b"12:auto_managedi1e");
        assert_ne!(bytes, stripped);
        let back = ResumeData::decode(&stripped).unwrap();
        assert_eq!(back.format_version, 2);
        assert_eq!(back.active_time, 0);
        assert_eq!(back.seeding_time, 0);
        assert_eq!(back.have, v2.have);
        assert_eq!(back.file_priorities, v2.file_priorities);
    }

    /// A version-1 file (no `file_priorities`) still loads.
    #[test]
    fn reads_format_version_1() {
        let mut v1 = sample();
        v1.format_version = 1;
        v1.file_priorities = Vec::new();
        v1.auto_managed = true;
        v1.queue_position = None;
        let bytes = v1.encode();
        assert!(!bytes.windows(15).any(|w| w == b"file_priorities"));
        let back = ResumeData::decode(&bytes).unwrap();
        assert_eq!(back.format_version, 1);
        assert!(back.file_priorities.is_empty());
        assert_eq!(back.have, v1.have);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let r = sample();
        let bytes = r.encode();
        assert_eq!(ResumeData::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn atomic_save_load() {
        let dir = std::env::temp_dir().join(format!("urt-resume-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("torrent.resume");
        let r = sample();
        r.save(&path).unwrap();
        // no leftover temp file
        assert!(!path.with_extension("tmp").exists());
        let loaded = ResumeData::load(&path).unwrap().unwrap();
        assert_eq!(loaded, r);
        assert!(
            ResumeData::load(&dir.join("missing.resume"))
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_newer_format() {
        let mut r = sample();
        r.format_version = 999;
        assert!(ResumeData::decode(&r.encode()).is_err());
    }

    #[test]
    fn rejects_torn_bitfield_len() {
        // pieces says 10 but have bytes for 8 -> rejected on decode.
        let r = sample();
        let mut bytes = r.encode();
        // Corrupt: flip a spare bit region is hard here; instead decode a
        // hand-built dict with mismatched lengths.
        let _ = &mut bytes;
        let bad = b"d6:formati1e4:have1:\xff9:info_hash20:\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x0712:piece_lengthi16384e6:piecesi10e12:total_lengthi150000ee";
        assert!(ResumeData::decode(bad).is_err());
    }
}
