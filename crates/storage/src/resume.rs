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

use std::net::SocketAddr;

use crate::Error;
use metainfo::Bitfield;

/// Compact peer lists (BEP 23 / BEP 7 layout: 6 and 18 bytes per peer).
fn compact_peers(peers: &[SocketAddr]) -> (Vec<u8>, Vec<u8>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for p in peers.iter().take(MAX_RESUME_PEERS) {
        match p.ip() {
            std::net::IpAddr::V4(ip) => {
                v4.extend_from_slice(&ip.octets());
                v4.extend_from_slice(&p.port().to_be_bytes());
            }
            std::net::IpAddr::V6(ip) => {
                v6.extend_from_slice(&ip.octets());
                v6.extend_from_slice(&p.port().to_be_bytes());
            }
        }
    }
    (v4, v6)
}

/// Current resume-data format version. Version 2 added `file_priorities`
/// (optional; version-1 files read as "all default"), version 3 the time
/// counters, version 4 the queue fields (`auto_managed`, `queue_position`;
/// absent in older files: managed, appended), version 5 the per-torrent
/// settings (`sequential`, rate limits, `max_peers`, `max_uploads`) and the
/// renamed file paths (`mapped_files`); version 6 the trackers, web seeds,
/// timestamps, last peers and the unfinished pieces' written ranges (the
/// self-contained blob of `Session::resume_data`); version 7 the activity
/// times (`last_seen_complete`, `last_download`, `last_upload`); all
/// optional on read.
pub const FORMAT_VERSION: i64 = 7;

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
    /// Sequential download (v5).
    pub sequential: bool,
    /// Upload limit in bytes/s, 0 = unlimited (v5).
    pub upload_limit: u64,
    /// Download limit in bytes/s, 0 = unlimited (v5).
    pub download_limit: u64,
    /// Per-torrent connection cap (v5).
    pub max_peers: Option<u32>,
    /// Per-torrent upload slot cap (v5).
    pub max_uploads: Option<u32>,
    /// Renamed file paths per `info.files` entry, `/`-separated; an empty
    /// string means the metainfo's path (v5; empty list = none renamed).
    pub mapped_files: Vec<String>,
    /// Tracker tiers as they stood (v6; empty = the metainfo's). They
    /// replace the metainfo's on load, like libtorrent's resume trackers.
    pub trackers: Vec<Vec<String>>,
    /// Web seed URLs as they stood (v6; empty = the metainfo's).
    pub web_seeds: Vec<String>,
    /// When the torrent was added, unix seconds (v6; 0 = unknown).
    pub added_time: u64,
    /// When the download completed, unix seconds (v6).
    pub completed_time: Option<u64>,
    /// Peers worth dialling first after a restart (v6; at most
    /// `MAX_RESUME_PEERS`).
    pub peers: Vec<SocketAddr>,
    /// Pieces in progress: `(piece, [(start, end)])` byte ranges written
    /// and synced but not yet hashed (v6). Restored as downloaded blocks;
    /// the hash check happens when the piece completes.
    pub unfinished: Vec<(u32, Vec<(u32, u32)>)>,
    /// When a complete copy was last seen, among the peers or ours, unix
    /// seconds (v7; libtorrent `last_seen_complete`).
    pub last_seen_complete: Option<u64>,
    /// When payload last arrived, unix seconds (v7; libtorrent
    /// `last_download`).
    pub last_download: Option<u64>,
    /// When payload last left, unix seconds (v7; libtorrent `last_upload`).
    pub last_upload: Option<u64>,
}

/// Most peers kept in resume data.
pub const MAX_RESUME_PEERS: usize = 100;
/// Most unfinished pieces kept in resume data.
pub const MAX_RESUME_UNFINISHED: usize = 4096;

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
            sequential: false,
            upload_limit: 0,
            download_limit: 0,
            max_peers: None,
            max_uploads: None,
            mapped_files: Vec::new(),
            trackers: Vec::new(),
            web_seeds: Vec::new(),
            added_time: 0,
            completed_time: None,
            peers: Vec::new(),
            unfinished: Vec::new(),
            last_seen_complete: None,
            last_download: None,
            last_upload: None,
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
        let mapped: Vec<Value<'_>> = self
            .mapped_files
            .iter()
            .map(|p| Value::Bytes(p.as_bytes()))
            .collect();
        // The encoder sorts the keys (canonical bencode); optional keys are
        // simply left out.
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
            entries.push((b"file_priorities", Value::Bytes(&self.file_priorities)));
        }
        if let Some(q) = self.queue_position {
            entries.push((b"queue_position", Value::Int(q.min(i64::MAX as u64) as i64)));
        }
        if self.format_version >= 5 {
            entries.push((b"sequential", Value::Int(i64::from(self.sequential))));
            entries.push((
                b"upload_limit",
                Value::Int(self.upload_limit.min(i64::MAX as u64) as i64),
            ));
            entries.push((
                b"download_limit",
                Value::Int(self.download_limit.min(i64::MAX as u64) as i64),
            ));
            if let Some(m) = self.max_peers {
                entries.push((b"max_peers", Value::Int(i64::from(m))));
            }
            if let Some(m) = self.max_uploads {
                entries.push((b"max_uploads", Value::Int(i64::from(m))));
            }
            if !mapped.is_empty() {
                entries.push((
                    b"mapped_files",
                    Value::List {
                        items: mapped,
                        raw: b"",
                    },
                ));
            }
        }
        // v6: kept as owned values while the entries borrow them.
        let tiers: Vec<Value<'_>> = self
            .trackers
            .iter()
            .map(|t| Value::List {
                items: t.iter().map(|u| Value::Bytes(u.as_bytes())).collect(),
                raw: b"",
            })
            .collect();
        let seeds: Vec<Value<'_>> = self
            .web_seeds
            .iter()
            .map(|u| Value::Bytes(u.as_bytes()))
            .collect();
        let (peers4, peers6) = compact_peers(&self.peers);
        let unfinished: Vec<Value<'_>> = self
            .unfinished
            .iter()
            .take(MAX_RESUME_UNFINISHED)
            .map(|(piece, ranges)| {
                let mut items = vec![Value::Int(i64::from(*piece))];
                for (s, e) in ranges {
                    items.push(Value::Int(i64::from(*s)));
                    items.push(Value::Int(i64::from(*e)));
                }
                Value::List { items, raw: b"" }
            })
            .collect();
        if self.format_version >= 6 {
            if !tiers.is_empty() {
                entries.push((
                    b"trackers",
                    Value::List {
                        items: tiers,
                        raw: b"",
                    },
                ));
            }
            if !seeds.is_empty() {
                entries.push((
                    b"web_seeds",
                    Value::List {
                        items: seeds,
                        raw: b"",
                    },
                ));
            }
            entries.push((
                b"added_time",
                Value::Int(self.added_time.min(i64::MAX as u64) as i64),
            ));
            if let Some(c) = self.completed_time {
                entries.push((b"completed_time", Value::Int(c.min(i64::MAX as u64) as i64)));
            }
            if self.format_version >= 7 {
                for (key, t) in [
                    (&b"last_seen_complete"[..], self.last_seen_complete),
                    (&b"last_download"[..], self.last_download),
                    (&b"last_upload"[..], self.last_upload),
                ] {
                    if let Some(t) = t {
                        entries.push((key, Value::Int(t.min(i64::MAX as u64) as i64)));
                    }
                }
            }
            if !peers4.is_empty() {
                entries.push((b"peers", Value::Bytes(&peers4)));
            }
            if !peers6.is_empty() {
                entries.push((b"peers6", Value::Bytes(&peers6)));
            }
            if !unfinished.is_empty() {
                entries.push((
                    b"unfinished",
                    Value::List {
                        items: unfinished,
                        raw: b"",
                    },
                ));
            }
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
            // v5 fields.
            sequential: v
                .get_str("sequential")
                .and_then(Value::as_int)
                .is_some_and(|x| x != 0),
            upload_limit: secs("upload_limit"),
            download_limit: secs("download_limit"),
            max_peers: v
                .get_str("max_peers")
                .and_then(Value::as_int)
                .filter(|m| *m >= 0)
                .map(|m| m.min(i64::from(u32::MAX)) as u32),
            max_uploads: v
                .get_str("max_uploads")
                .and_then(Value::as_int)
                .filter(|m| *m >= 0)
                .map(|m| m.min(i64::from(u32::MAX)) as u32),
            mapped_files: v
                .get_str("mapped_files")
                .and_then(|l| match l {
                    Value::List { items, .. } => Some(
                        items
                            .iter()
                            .take(1 << 20)
                            .map(|it| {
                                it.as_bytes()
                                    .map(|b| String::from_utf8_lossy(b).into_owned())
                                    .unwrap_or_default()
                            })
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default(),
            // v6 fields.
            trackers: v
                .get_str("trackers")
                .and_then(|l| match l {
                    Value::List { items, .. } => Some(
                        items
                            .iter()
                            .take(256)
                            .filter_map(|tier| match tier {
                                Value::List { items, .. } => Some(
                                    items
                                        .iter()
                                        .take(256)
                                        .filter_map(|u| {
                                            u.as_bytes()
                                                .map(|b| String::from_utf8_lossy(b).into_owned())
                                        })
                                        .collect::<Vec<String>>(),
                                ),
                                _ => None,
                            })
                            .filter(|t: &Vec<String>| !t.is_empty())
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default(),
            web_seeds: v
                .get_str("web_seeds")
                .and_then(|l| match l {
                    Value::List { items, .. } => Some(
                        items
                            .iter()
                            .take(256)
                            .filter_map(|u| {
                                u.as_bytes()
                                    .map(|b| String::from_utf8_lossy(b).into_owned())
                            })
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default(),
            added_time: secs("added_time"),
            completed_time: v
                .get_str("completed_time")
                .and_then(Value::as_int)
                .filter(|c| *c > 0)
                .map(|c| c as u64),
            last_seen_complete: v
                .get_str("last_seen_complete")
                .and_then(Value::as_int)
                .filter(|c| *c > 0)
                .map(|c| c as u64),
            last_download: v
                .get_str("last_download")
                .and_then(Value::as_int)
                .filter(|c| *c > 0)
                .map(|c| c as u64),
            last_upload: v
                .get_str("last_upload")
                .and_then(Value::as_int)
                .filter(|c| *c > 0)
                .map(|c| c as u64),
            peers: {
                let mut peers = Vec::new();
                if let Some(b) = v.get_str("peers").and_then(Value::as_bytes) {
                    for c in b.as_chunks::<6>().0.iter().take(MAX_RESUME_PEERS) {
                        let ip = std::net::Ipv4Addr::new(c[0], c[1], c[2], c[3]);
                        peers.push(SocketAddr::new(ip.into(), u16::from_be_bytes([c[4], c[5]])));
                    }
                }
                if let Some(b) = v.get_str("peers6").and_then(Value::as_bytes) {
                    for c in b.as_chunks::<18>().0.iter().take(MAX_RESUME_PEERS) {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(&c[..16]);
                        let ip = std::net::Ipv6Addr::from(o);
                        peers.push(SocketAddr::new(
                            ip.into(),
                            u16::from_be_bytes([c[16], c[17]]),
                        ));
                    }
                }
                peers.truncate(MAX_RESUME_PEERS);
                peers
            },
            unfinished: v
                .get_str("unfinished")
                .and_then(|l| match l {
                    Value::List { items, .. } => Some(
                        items
                            .iter()
                            .take(MAX_RESUME_UNFINISHED)
                            .filter_map(|entry| match entry {
                                Value::List { items, .. } => {
                                    let ints: Vec<i64> = items
                                        .iter()
                                        .take(1 + 2 * 4096)
                                        .filter_map(Value::as_int)
                                        .collect();
                                    let (&piece, rest) = ints.split_first()?;
                                    if piece < 0 || piece > i64::from(u32::MAX) {
                                        return None;
                                    }
                                    let ranges: Vec<(u32, u32)> = rest
                                        .as_chunks::<2>()
                                        .0
                                        .iter()
                                        .filter(|r| {
                                            r[0] >= 0 && r[1] > r[0] && r[1] <= i64::from(u32::MAX)
                                        })
                                        .map(|r| (r[0] as u32, r[1] as u32))
                                        .collect();
                                    (!ranges.is_empty()).then_some((piece as u32, ranges))
                                }
                                _ => None,
                            })
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default(),
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
            sequential: true,
            upload_limit: 1234,
            download_limit: 0,
            max_peers: Some(30),
            max_uploads: None,
            mapped_files: vec![String::new(), "renamed/b.bin".into(), String::new()],
            trackers: vec![
                vec!["http://a/announce".into(), "http://b/announce".into()],
                vec!["udp://c:1/announce".into()],
            ],
            web_seeds: vec!["http://w/files/".into()],
            added_time: 1_700_000_000,
            completed_time: Some(1_700_000_100),
            peers: vec![
                "10.1.2.3:6881".parse().unwrap(),
                "[fd77::1]:51413".parse().unwrap(),
            ],
            unfinished: vec![
                (3, vec![(0, 32768), (65536, 81920)]),
                (7, vec![(16384, 32768)]),
            ],
            last_seen_complete: Some(1_700_000_200),
            last_download: Some(1_700_000_150),
            last_upload: None,
        }
    }

    /// A version-6 file (no activity times) still loads.
    #[test]
    fn reads_format_version_6() {
        let mut v6 = sample();
        v6.format_version = 6;
        let bytes = v6.encode();
        assert!(!bytes.windows(13).any(|w| w == b"last_download"));
        let back = ResumeData::decode(&bytes).unwrap();
        assert_eq!(back.format_version, 6);
        assert_eq!(
            (
                back.last_seen_complete,
                back.last_download,
                back.last_upload
            ),
            (None, None, None)
        );
        assert_eq!(back.unfinished, v6.unfinished);
    }

    /// A version-5 file (no trackers, timestamps, peers or unfinished
    /// pieces) still loads with the defaults.
    #[test]
    fn reads_format_version_5() {
        let mut v5 = sample();
        v5.format_version = 5;
        let bytes = v5.encode();
        assert!(!bytes.windows(10).any(|w| w == b"unfinished"));
        let back = ResumeData::decode(&bytes).unwrap();
        assert_eq!(back.format_version, 5);
        assert!(back.trackers.is_empty() && back.web_seeds.is_empty());
        assert_eq!(back.added_time, 0);
        assert_eq!(back.completed_time, None);
        assert!(back.peers.is_empty() && back.unfinished.is_empty());
        assert_eq!(back.mapped_files, v5.mapped_files);
    }

    /// Hostile unfinished entries are dropped, not trusted.
    #[test]
    fn unfinished_ranges_are_validated() {
        let mut r = sample();
        r.unfinished = vec![(1, vec![(10, 5)]), (2, vec![(0, 100)])];
        let back = ResumeData::decode(&r.encode()).unwrap();
        assert_eq!(back.unfinished, vec![(2, vec![(0, 100)])]);
    }

    /// A version-4 file (no per-torrent settings) still loads with the
    /// defaults.
    #[test]
    fn reads_format_version_4() {
        let mut v4 = sample();
        v4.format_version = 4;
        let bytes = v4.encode();
        assert!(!bytes.windows(10).any(|w| w == b"sequential"));
        let back = ResumeData::decode(&bytes).unwrap();
        assert_eq!(back.format_version, 4);
        assert!(!back.sequential);
        assert_eq!((back.upload_limit, back.download_limit), (0, 0));
        assert_eq!(back.max_peers, None);
        assert!(back.mapped_files.is_empty());
        assert_eq!(back.queue_position, Some(7));
        assert!(!back.auto_managed);
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
