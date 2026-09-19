// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Torrent fixture generation. Torrent *creation* is not a library feature, so
//! the harness has its own generator. Content is deterministic from a seed and
//! computed lazily, so multi-gigabyte fixtures never need to be held in memory.

use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};

use crate::bencode::{self, Value};

/// One file in a fixture.
#[derive(Clone, Debug)]
pub struct FileSpec {
    /// Path components below the torrent root (multi-file) or the single file name.
    pub path: Vec<String>,
    pub len: u64,
}

impl FileSpec {
    pub fn new(path: &str, len: u64) -> FileSpec {
        FileSpec {
            path: path.split('/').map(str::to_string).collect(),
            len,
        }
    }
}

/// What to generate.
#[derive(Clone, Debug)]
pub struct FixtureSpec {
    pub name: String,
    pub files: Vec<FileSpec>,
    /// `true` forces multi-file layout even with one file.
    pub multi_file: bool,
    pub piece_length: u32,
    pub private: bool,
    /// Tracker tiers (BEP 12). Empty means no `announce` at all.
    pub trackers: Vec<Vec<String>>,
    /// Insert BEP 47 padding files so every file starts on a piece boundary.
    pub padding: bool,
    /// Web seeds (BEP 19 `url-list`).
    pub url_list: Vec<String>,
    pub seed: u64,
    pub comment: Option<String>,
}

impl FixtureSpec {
    /// A small single-file torrent: 1 MiB, 64 KiB pieces.
    pub fn small(name: &str) -> FixtureSpec {
        FixtureSpec {
            name: name.to_string(),
            files: vec![FileSpec::new(name, 1 << 20)],
            multi_file: false,
            piece_length: 64 << 10,
            private: false,
            trackers: Vec::new(),
            padding: false,
            url_list: Vec::new(),
            seed: 0x5eed,
            comment: None,
        }
    }

    pub fn with_size(mut self, len: u64) -> Self {
        self.files = vec![FileSpec::new(&self.name.clone(), len)];
        self
    }
    pub fn with_piece_length(mut self, len: u32) -> Self {
        self.piece_length = len;
        self
    }
    pub fn with_trackers(mut self, tiers: Vec<Vec<String>>) -> Self {
        self.trackers = tiers;
        self
    }
    pub fn with_tracker(self, url: &str) -> Self {
        self.with_trackers(vec![vec![url.to_string()]])
    }
    pub fn private(mut self, private: bool) -> Self {
        self.private = private;
        self
    }
    pub fn with_files(mut self, files: Vec<FileSpec>) -> Self {
        self.files = files;
        self.multi_file = true;
        self
    }
    pub fn with_padding(mut self, padding: bool) -> Self {
        self.padding = padding;
        self
    }
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }
    pub fn with_url_list(mut self, urls: Vec<String>) -> Self {
        self.url_list = urls;
        self
    }
}

/// A file as laid out in the torrent (after padding insertion).
#[derive(Clone, Debug)]
pub struct LaidOutFile {
    pub path: Vec<String>,
    pub len: u64,
    pub offset: u64,
    pub padding: bool,
}

/// A generated fixture.
#[derive(Clone, Debug)]
pub struct Fixture {
    pub spec: FixtureSpec,
    pub layout: Vec<LaidOutFile>,
    pub total_len: u64,
    pub piece_hashes: Vec<[u8; 20]>,
    pub torrent: Vec<u8>,
    pub info_hash: [u8; 20],
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Fixture {
    pub fn generate(spec: FixtureSpec) -> Fixture {
        let multi = spec.multi_file || spec.files.len() != 1;
        let mut layout = Vec::new();
        let mut offset = 0u64;
        let piece_len = u64::from(spec.piece_length);
        let n = spec.files.len();
        for (i, f) in spec.files.iter().enumerate() {
            layout.push(LaidOutFile {
                path: f.path.clone(),
                len: f.len,
                offset,
                padding: false,
            });
            offset += f.len;
            if spec.padding && multi && i + 1 < n && !offset.is_multiple_of(piece_len) {
                let pad = piece_len - offset % piece_len;
                layout.push(LaidOutFile {
                    path: vec![".pad".to_string(), pad.to_string()],
                    len: pad,
                    offset,
                    padding: true,
                });
                offset += pad;
            }
        }
        let total_len = offset;
        let mut fx = Fixture {
            spec,
            layout,
            total_len,
            piece_hashes: Vec::new(),
            torrent: Vec::new(),
            info_hash: [0; 20],
        };
        let pieces = fx.piece_count();
        for p in 0..pieces {
            let data = fx.piece(p);
            let mut h = Sha1::new();
            h.update(&data);
            fx.piece_hashes.push(h.finalize().into());
        }
        let mut info = Value::dict();
        info.insert("name", Value::str(&fx.spec.name));
        info.insert("piece length", Value::Int(i64::from(fx.spec.piece_length)));
        let mut pieces_bytes = Vec::with_capacity(pieces * 20);
        for h in &fx.piece_hashes {
            pieces_bytes.extend_from_slice(h);
        }
        info.insert("pieces", Value::Bytes(pieces_bytes));
        if fx.spec.private {
            info.insert("private", Value::Int(1));
        }
        if multi {
            let files: Vec<Value> = fx
                .layout
                .iter()
                .map(|f| {
                    let mut d = Value::dict();
                    d.insert("length", Value::Int(f.len as i64));
                    d.insert(
                        "path",
                        Value::List(f.path.iter().map(|c| Value::str(c)).collect()),
                    );
                    if f.padding {
                        d.insert("attr", Value::str("p"));
                    }
                    d
                })
                .collect();
            info.insert("files", Value::List(files));
        } else {
            info.insert("length", Value::Int(fx.total_len as i64));
        }
        let mut top = Value::dict();
        if let Some(first) = fx.spec.trackers.first().and_then(|t| t.first()) {
            top.insert("announce", Value::str(first));
        }
        if fx.spec.trackers.iter().map(Vec::len).sum::<usize>() > 1 || fx.spec.trackers.len() > 1 {
            let tiers = fx
                .spec
                .trackers
                .iter()
                .map(|t| Value::List(t.iter().map(|u| Value::str(u)).collect()))
                .collect();
            top.insert("announce-list", Value::List(tiers));
        }
        if let Some(c) = &fx.spec.comment {
            top.insert("comment", Value::str(c));
        }
        top.insert("created by", Value::str("urtorrent testkit"));
        top.insert("creation date", Value::Int(1_700_000_000));
        if !fx.spec.url_list.is_empty() {
            top.insert(
                "url-list",
                Value::List(fx.spec.url_list.iter().map(|u| Value::str(u)).collect()),
            );
        }
        top.insert("info", info.clone());
        fx.torrent = top.encode();
        let mut h = Sha1::new();
        h.update(info.encode());
        fx.info_hash = h.finalize().into();
        fx
    }

    pub fn piece_count(&self) -> usize {
        self.total_len.div_ceil(u64::from(self.spec.piece_length)) as usize
    }

    pub fn piece_size(&self, index: usize) -> usize {
        let pl = u64::from(self.spec.piece_length);
        let start = index as u64 * pl;
        (self.total_len - start).min(pl) as usize
    }

    /// Bytes of the torrent's logical stream at `offset..offset+len`.
    pub fn data_range(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut pos = 0usize;
        for f in &self.layout {
            let f_end = f.offset + f.len;
            let want_start = offset + pos as u64;
            if want_start >= f_end {
                continue;
            }
            if want_start < f.offset {
                break;
            }
            let take = ((f_end - want_start) as usize).min(len - pos);
            if !f.padding {
                let file_off = want_start - f.offset;
                self.fill(&mut out[pos..pos + take], f, file_off);
            }
            pos += take;
            if pos == len {
                break;
            }
        }
        out
    }

    fn fill(&self, out: &mut [u8], f: &LaidOutFile, file_off: u64) {
        // Content depends on the file path (so identical-length files differ) and
        // on the 8-byte block index within the file.
        let mut ph = Sha1::new();
        for c in &f.path {
            ph.update(c.as_bytes());
            ph.update(b"/");
        }
        let fh: [u8; 20] = ph.finalize().into();
        let file_seed = self.spec.seed ^ u64::from_le_bytes(fh[..8].try_into().unwrap_or([0; 8]));
        for (off, b) in (file_off..).zip(out.iter_mut()) {
            let word = splitmix64(file_seed ^ (off / 8));
            *b = word.to_le_bytes()[(off % 8) as usize];
        }
    }

    pub fn piece(&self, index: usize) -> Vec<u8> {
        let pl = u64::from(self.spec.piece_length);
        self.data_range(index as u64 * pl, self.piece_size(index))
    }

    /// Root path of the content inside `save_dir` (the file itself or the directory).
    pub fn content_path(&self, save_dir: &Path) -> PathBuf {
        save_dir.join(&self.spec.name)
    }

    fn file_path(&self, save_dir: &Path, f: &LaidOutFile) -> PathBuf {
        let multi = self.spec.multi_file || self.spec.files.len() != 1;
        let mut p = save_dir.to_path_buf();
        if multi {
            p.push(&self.spec.name);
            for c in &f.path {
                p.push(c);
            }
        } else {
            p.push(&self.spec.name);
        }
        p
    }

    /// Write the full content under `save_dir` (the way a seeder would have it).
    pub fn write_data(&self, save_dir: &Path) -> io::Result<()> {
        for f in &self.layout {
            if f.padding {
                continue;
            }
            let p = self.file_path(save_dir, f);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut fh = std::fs::File::create(&p)?;
            let mut off = 0u64;
            while off < f.len {
                let chunk = (f.len - off).min(1 << 20) as usize;
                let mut buf = vec![0u8; chunk];
                self.fill(&mut buf, f, off);
                fh.write_all(&buf)?;
                off += chunk as u64;
            }
        }
        Ok(())
    }

    /// Verify that the content under `save_dir` matches the fixture byte for byte.
    pub fn verify_data(&self, save_dir: &Path) -> io::Result<Result<(), String>> {
        for f in &self.layout {
            if f.padding {
                continue;
            }
            let p = self.file_path(save_dir, f);
            let data = match std::fs::read(&p) {
                Ok(d) => d,
                Err(e) if f.len == 0 && e.kind() == io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Ok(Err(format!("{}: {e}", p.display()))),
            };
            if data.len() as u64 != f.len {
                return Ok(Err(format!(
                    "{}: length {} != {}",
                    p.display(),
                    data.len(),
                    f.len
                )));
            }
            let mut want = vec![0u8; data.len()];
            self.fill(&mut want, f, 0);
            if want != data {
                let first = want
                    .iter()
                    .zip(&data)
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                return Ok(Err(format!(
                    "{}: content differs at byte {first}",
                    p.display()
                )));
            }
        }
        Ok(Ok(()))
    }

    /// Corrupt `len` bytes of the on-disk content at logical `offset`.
    pub fn corrupt(&self, save_dir: &Path, offset: u64, len: usize) -> io::Result<()> {
        for f in &self.layout {
            if f.padding || offset < f.offset || offset >= f.offset + f.len {
                continue;
            }
            let p = self.file_path(save_dir, f);
            let mut fh = std::fs::OpenOptions::new().write(true).open(p)?;
            fh.seek(SeekFrom::Start(offset - f.offset))?;
            let n = len.min((f.offset + f.len - offset) as usize);
            fh.write_all(&vec![0xFFu8; n])?;
            return Ok(());
        }
        Ok(())
    }

    pub fn info_hash_hex(&self) -> String {
        bencode::hex(&self.info_hash)
    }

    pub fn magnet(&self) -> String {
        let mut m = format!(
            "magnet:?xt=urn:btih:{}&dn={}",
            self.info_hash_hex(),
            self.spec.name
        );
        for tier in &self.spec.trackers {
            for t in tier {
                m.push_str("&tr=");
                m.push_str(&crate::http::percent_encode(t.as_bytes()));
            }
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_file_shape() {
        let fx = Fixture::generate(
            FixtureSpec::small("a.bin")
                .with_size(100_000)
                .with_piece_length(16384),
        );
        assert_eq!(fx.piece_count(), 7);
        assert_eq!(fx.piece_size(6), 100_000 - 6 * 16384);
        let t = bencode::decode(&fx.torrent).unwrap();
        assert_eq!(
            t.get("info").unwrap().get("length").unwrap().as_int(),
            Some(100_000)
        );
        assert!(t.get("info").unwrap().get("files").is_none());
        let span = bencode::value_span(&fx.torrent, b"info").unwrap().unwrap();
        let mut h = Sha1::new();
        h.update(&fx.torrent[span]);
        assert_eq!(<[u8; 20]>::from(h.finalize()), fx.info_hash);
    }

    #[test]
    fn padding_layout_and_roundtrip() {
        let spec = FixtureSpec::small("multi")
            .with_files(vec![
                FileSpec::new("a/one", 1000),
                FileSpec::new("empty", 0),
                FileSpec::new("b/two", 70_000),
                FileSpec::new("three", 5),
            ])
            .with_piece_length(16384)
            .with_padding(true);
        let fx = Fixture::generate(spec);
        assert!(fx.layout.iter().any(|f| f.padding));
        for f in fx.layout.iter().skip(1) {
            if !f.padding {
                assert_eq!(f.offset % 16384, 0, "{:?} not aligned", f.path);
            }
        }
        let dir = std::env::temp_dir().join(format!("urt-fixture-{}", std::process::id()));
        fx.write_data(&dir).unwrap();
        assert_eq!(fx.verify_data(&dir).unwrap(), Ok(()));
        // piece hashes match the data written to disk, via a separate read path
        for p in 0..fx.piece_count() {
            let mut h = Sha1::new();
            h.update(fx.piece(p));
            assert_eq!(<[u8; 20]>::from(h.finalize()), fx.piece_hashes[p]);
        }
        fx.corrupt(&dir, 16384 + 10, 4).unwrap();
        assert!(fx.verify_data(&dir).unwrap().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
