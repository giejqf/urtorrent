// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The piece store: maps a torrent's pieces onto on-disk files and reads,
//! writes, preallocates, and verifies them over io_uring. Multi-file piece
//! spans and BEP 47 padding files are handled here; padding bytes are synthetic
//! zeros for hashing and are never written to disk.
//!
//! File priorities (selective download): a file with priority 0 is not
//! downloaded for its own sake, but a piece that straddles it and a wanted
//! file is. The bytes of such a piece that fall into a skipped file go to the
//! **parts file** (`.<name>.parts` next to the content, sparse, indexed by
//! torrent offset) instead of creating the skipped file (libtorrent's
//! `part_file` semantics: a skipped file that already exists on disk keeps
//! receiving its bytes directly). When a skipped file is later wanted, the
//! parts already held for it are exported into the real file.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use metainfo::{FileSlice, Info};
use uring::{Buffer, File};

use crate::Error;
use crate::hash::HashPool;
use metainfo::Bitfield;

/// Default file priority (libtorrent's `default_priority`).
pub const DEFAULT_PRIORITY: u8 = 4;
/// Highest file priority.
pub const MAX_PRIORITY: u8 = 7;

/// A per-torrent piece store rooted at a save directory.
pub struct Storage {
    info: Rc<Info>,
    root: RefCell<PathBuf>,
    pool: Rc<HashPool>,
    files: RefCell<HashMap<usize, Rc<File>>>,
    have: RefCell<Bitfield>,
    /// Priority per `info.files` entry (padding files are always 0).
    priorities: RefCell<Vec<u8>>,
    /// Whether a file's bytes live in the parts file (skipped and never
    /// created on disk).
    use_parts: RefCell<Vec<bool>>,
    parts: RefCell<Option<Rc<File>>>,
}

impl Storage {
    /// Create a store for `info` under `root`, using `pool` for hashing.
    /// Every content file starts at [`DEFAULT_PRIORITY`].
    pub fn new(info: Rc<Info>, root: PathBuf, pool: Rc<HashPool>) -> Storage {
        let pieces = info.piece_count();
        let priorities = info
            .files
            .iter()
            .map(|f| if f.is_padding() { 0 } else { DEFAULT_PRIORITY })
            .collect::<Vec<u8>>();
        let n = info.files.len();
        Storage {
            info,
            root: RefCell::new(root),
            pool,
            files: RefCell::new(HashMap::new()),
            have: RefCell::new(Bitfield::new(pieces)),
            priorities: RefCell::new(priorities),
            use_parts: RefCell::new(vec![false; n]),
            parts: RefCell::new(None),
        }
    }

    /// Path of the parts file.
    pub fn parts_path(&self) -> PathBuf {
        self.root
            .borrow()
            .join(format!(".{}.parts", self.info.name))
    }

    /// Current file priorities (per `info.files` entry).
    pub fn file_priorities(&self) -> Vec<u8> {
        self.priorities.borrow().clone()
    }

    /// Set the initial priorities before any file is created: skipped files
    /// that do not exist on disk are routed to the parts file.
    pub fn init_priorities(&self, prios: &[u8]) {
        let mut cur = self.priorities.borrow_mut();
        let mut use_parts = self.use_parts.borrow_mut();
        let root = self.root.borrow();
        for (i, f) in self.info.files.iter().enumerate() {
            let p = if f.is_padding() {
                0
            } else {
                prios
                    .get(i)
                    .copied()
                    .unwrap_or(DEFAULT_PRIORITY)
                    .min(MAX_PRIORITY)
            };
            cur[i] = p;
            use_parts[i] = !f.is_padding() && p == 0 && !f.path.to_path(&root).exists();
        }
    }

    /// Change file priorities. A file leaving priority 0 gets the parts held
    /// for it exported into its real file; a file dropping to 0 keeps
    /// receiving bytes directly if it already exists on disk.
    pub async fn set_file_priorities(&self, prios: &[u8]) -> Result<(), Error> {
        let old = self.priorities.borrow().clone();
        let mut to_export = Vec::new();
        {
            let mut cur = self.priorities.borrow_mut();
            let mut use_parts = self.use_parts.borrow_mut();
            let root = self.root.borrow();
            for (i, f) in self.info.files.iter().enumerate() {
                if f.is_padding() {
                    continue;
                }
                let p = prios.get(i).copied().unwrap_or(old[i]).min(MAX_PRIORITY);
                cur[i] = p;
                if p > 0 && use_parts[i] {
                    to_export.push(i);
                } else if p == 0 && old[i] > 0 {
                    let path = f.path.to_path(&root);
                    let has_data = std::fs::metadata(&path).is_ok_and(|m| m.len() > 0);
                    if !has_data {
                        use_parts[i] = true;
                    }
                }
            }
        }
        for i in to_export {
            self.export_parts(i).await?;
            self.use_parts.borrow_mut()[i] = false;
        }
        Ok(())
    }

    /// Piece priorities derived from the file priorities: the highest
    /// priority of any non-padding file the piece touches (libtorrent).
    pub fn piece_priorities(&self) -> Vec<u8> {
        let prios = self.priorities.borrow();
        (0..self.info.piece_count())
            .map(|i| {
                self.info
                    .piece_location(i)
                    .map(|loc| {
                        loc.slices
                            .iter()
                            .filter(|s| !s.padding)
                            .map(|s| prios.get(s.file_index).copied().unwrap_or(0))
                            .max()
                            .unwrap_or(0)
                    })
                    .unwrap_or(0)
            })
            .collect()
    }

    /// Copy the bytes of verified pieces that fall into file `i` from the
    /// parts file into the real file (the file became wanted).
    async fn export_parts(&self, i: usize) -> Result<(), Error> {
        let f = &self.info.files[i];
        if f.length == 0 {
            return Ok(());
        }
        let have = self.have.borrow().clone();
        let piece_len = u64::from(self.info.piece_length);
        let first = (f.offset / piece_len) as usize;
        let last = ((f.offset + f.length - 1) / piece_len) as usize;
        let parts = self.parts_file().await?;
        let target = self.file(i).await?;
        for piece in first..=last {
            if !have.get(piece) {
                continue;
            }
            let ps = piece as u64 * piece_len;
            let pe = (ps + piece_len).min(self.info.total_length);
            let s = ps.max(f.offset);
            let e = pe.min(f.offset + f.length);
            if e <= s {
                continue;
            }
            let buf = Buffer::from_vec(vec![0u8; (e - s) as usize]);
            let got = parts.read_exact_at(s, buf).await?;
            target.write_all_at(s - f.offset, got).await?;
        }
        Ok(())
    }

    async fn parts_file(&self) -> Result<Rc<File>, Error> {
        if let Some(p) = self.parts.borrow().as_ref() {
            return Ok(p.clone());
        }
        let path = self.parts_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = Rc::new(File::open_rw(&path).await?);
        *self.parts.borrow_mut() = Some(f.clone());
        Ok(f)
    }

    /// Where a slice's bytes live: `(file, offset within it)`.
    async fn target(&self, s: &FileSlice) -> Result<(Rc<File>, u64), Error> {
        if self
            .use_parts
            .borrow()
            .get(s.file_index)
            .copied()
            .unwrap_or(false)
        {
            let base = self
                .info
                .files
                .get(s.file_index)
                .ok_or(Error::OutOfRange)?
                .offset;
            Ok((self.parts_file().await?, base + s.file_offset))
        } else {
            Ok((self.file(s.file_index).await?, s.file_offset))
        }
    }

    /// Move the content (and parts file) to `new_root`: `rename` on the same
    /// filesystem, copy-then-delete across filesystems (over the ring). The
    /// caller must have quiesced I/O. Open handles are dropped and reopened
    /// lazily under the new root.
    pub async fn move_to(&self, new_root: PathBuf) -> Result<(), Error> {
        self.sync_all().await?;
        self.files.borrow_mut().clear();
        *self.parts.borrow_mut() = None;
        let old_root = self.root.borrow().clone();
        std::fs::create_dir_all(&new_root)?;
        let mut moves: Vec<(PathBuf, PathBuf)> = Vec::new();
        for f in self.info.files.iter().filter(|f| !f.is_padding()) {
            let from = f.path.to_path(&old_root);
            if from.exists() {
                moves.push((from, f.path.to_path(&new_root)));
            }
        }
        let parts_from = self.parts_path();
        if parts_from.exists() {
            let name = parts_from
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_default();
            moves.push((parts_from, new_root.join(name)));
        }
        for (from, to) in moves {
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)?;
            }
            match std::fs::rename(&from, &to) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc_exdev()) => {
                    copy_file(&from, &to).await?;
                    std::fs::remove_file(&from)?;
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
        // Remove now-empty directories of a multi-file torrent.
        if !self.info.single_file {
            let _ = std::fs::remove_dir(old_root.join(&self.info.name));
        }
        *self.root.borrow_mut() = new_root;
        Ok(())
    }

    /// The torrent metainfo.
    pub fn info(&self) -> &Info {
        &self.info
    }

    /// The hash pool this store verifies with.
    pub fn pool(&self) -> &Rc<HashPool> {
        &self.pool
    }

    /// The save directory.
    pub fn root(&self) -> PathBuf {
        self.root.borrow().clone()
    }

    /// A snapshot of the pieces we currently have verified.
    pub fn have(&self) -> Bitfield {
        self.have.borrow().clone()
    }

    /// Replace the have-bitfield (e.g. from validated resume data).
    pub fn set_have(&self, have: Bitfield) {
        *self.have.borrow_mut() = have;
    }

    /// Whether piece `index` is verified-present.
    pub fn has_piece(&self, index: usize) -> bool {
        self.have.borrow().get(index)
    }

    /// Create every wanted content file's parent directory and the files
    /// themselves (skipped files routed to the parts file are not created).
    pub async fn create_files(&self) -> Result<(), Error> {
        for (i, f) in self.info.files.iter().enumerate() {
            if f.is_padding() || self.use_parts.borrow()[i] {
                continue;
            }
            let path = f.path.to_path(&self.root.borrow());
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Open (creating) so the file exists even at zero length.
            self.file(i).await?;
        }
        Ok(())
    }

    /// Preallocate all non-padding files to their full length (`fallocate`).
    pub async fn preallocate(&self) -> Result<(), Error> {
        self.create_files().await?;
        for (i, f) in self.info.files.iter().enumerate() {
            if f.is_padding() || f.length == 0 {
                continue;
            }
            let file = self.file(i).await?;
            file.allocate(0, f.length).await?;
        }
        Ok(())
    }

    /// The open handle for file `index`, opening it through the ring on first
    /// use (directory creation is a one-time blocking call, AGENTS.md 5.3).
    async fn file(&self, index: usize) -> Result<Rc<File>, Error> {
        if let Some(f) = self.files.borrow().get(&index) {
            return Ok(f.clone());
        }
        let spec = self.info.files.get(index).ok_or(Error::OutOfRange)?;
        let path = spec.path.to_path(&self.root.borrow());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = Rc::new(File::open_rw(&path).await?);
        self.files.borrow_mut().insert(index, f.clone());
        Ok(f)
    }

    /// Write a block (`data`) at `offset` within `piece`. Returns the buffer.
    /// Padding regions in the span are skipped (never written).
    pub async fn write_block(
        &self,
        piece: usize,
        offset: u32,
        data: Buffer,
    ) -> Result<Buffer, Error> {
        let torrent_off = self.torrent_offset(piece, offset)?;
        let len = data.len() as u64;
        let slices = self.info.slices_for(torrent_off, len);
        let bytes = data.into_vec();
        let mut pos = 0usize;
        for s in slices {
            let take = s.length as usize;
            let chunk = &bytes[pos..pos + take];
            pos += take;
            if s.padding {
                continue; // synthetic zeros, not stored
            }
            let (file, off) = self.target(&s).await?;
            let buf = Buffer::from_vec(chunk.to_vec());
            file.write_all_at(off, buf).await?;
        }
        Ok(Buffer::from_vec(bytes))
    }

    /// Read the full contents of `piece` into a buffer. Returns `(data,
    /// complete)`; `complete` is false if any non-padding region was short of
    /// data on disk (a hole / not-yet-downloaded), in which case the missing
    /// bytes are zero-filled so hashing is deterministic.
    pub async fn read_piece(&self, piece: usize) -> Result<(Vec<u8>, bool), Error> {
        let loc = self.info.piece_location(piece).ok_or(Error::OutOfRange)?;
        let mut out = vec![0u8; loc.length as usize];
        let mut pos = 0usize;
        let mut complete = true;
        for s in &loc.slices {
            let take = s.length as usize;
            if s.padding {
                // already zero-filled
                pos += take;
                continue;
            }
            let (file, off) = self.target(s).await?;
            let buf = Buffer::from_vec(vec![0u8; take]);
            let (r, filled) = file.read_at(off, buf).await;
            let n = r.unwrap_or(0) as usize;
            out[pos..pos + n].copy_from_slice(&filled.as_slice()[..n]);
            if n < take {
                complete = false;
            }
            pos += take;
        }
        Ok((out, complete))
    }

    /// Read an arbitrary block for upload: `length` bytes at `offset` within
    /// `piece`. Errors if the data is not fully present.
    pub async fn read_block(
        &self,
        piece: usize,
        offset: u32,
        length: u32,
    ) -> Result<Buffer, Error> {
        let torrent_off = self.torrent_offset(piece, offset)?;
        let slices = self.info.slices_for(torrent_off, u64::from(length));
        let mut out = vec![0u8; length as usize];
        let mut pos = 0usize;
        for s in slices {
            let take = s.length as usize;
            if s.padding {
                pos += take;
                continue;
            }
            let (file, off) = self.target(&s).await?;
            let buf = Buffer::from_vec(vec![0u8; take]);
            let got = file.read_exact_at(off, buf).await?;
            out[pos..pos + take].copy_from_slice(got.as_slice());
            pos += take;
        }
        Ok(Buffer::from_vec(out))
    }

    /// Verify `piece` against its expected hash. On success the have-bit is set.
    /// Returns whether it verified.
    pub async fn verify_piece(&self, piece: usize) -> Result<bool, Error> {
        let expected = *self.info.piece_hash(piece).ok_or(Error::OutOfRange)?;
        let (data, complete) = self.read_piece(piece).await?;
        if !complete {
            self.have.borrow_mut().clear(piece);
            return Ok(false);
        }
        let (ok, _buf) = self.pool.verify_async(data, expected).await;
        if ok {
            self.have.borrow_mut().set(piece);
        } else {
            self.have.borrow_mut().clear(piece);
        }
        Ok(ok)
    }

    /// Write a block and, if the piece is now complete, verify it. Returns
    /// `Some(true)` if the piece verified, `Some(false)` if it was complete but
    /// failed the hash (caller attributes blame), `None` if still incomplete.
    /// This is the download write path (AGENTS.md 5.4).
    pub async fn write_and_maybe_verify(
        &self,
        piece: usize,
        offset: u32,
        data: Buffer,
    ) -> Result<Option<bool>, Error> {
        self.write_block(piece, offset, data).await?;
        let (bytes, complete) = self.read_piece(piece).await?;
        if !complete {
            return Ok(None);
        }
        let expected = *self.info.piece_hash(piece).ok_or(Error::OutOfRange)?;
        let (ok, _) = self.pool.verify_async(bytes, expected).await;
        if ok {
            self.have.borrow_mut().set(piece);
        }
        Ok(Some(ok))
    }

    /// Recheck every piece against the data on disk, rebuilding the have set
    /// (force recheck / crash recovery).
    pub async fn check_all(&self) -> Result<Bitfield, Error> {
        let pieces = self.info.piece_count();
        let mut have = Bitfield::new(pieces);
        for p in 0..pieces {
            let expected = match self.info.piece_hash(p) {
                Some(h) => *h,
                None => continue,
            };
            let (data, complete) = self.read_piece(p).await?;
            if complete {
                let (ok, _) = self.pool.verify_async(data, expected).await;
                if ok {
                    have.set(p);
                }
            }
        }
        *self.have.borrow_mut() = have.clone();
        Ok(have)
    }

    /// Flush all open files (and the parts file) to disk (`fsync`).
    pub async fn sync_all(&self) -> Result<(), Error> {
        let mut files: Vec<Rc<File>> = self.files.borrow().values().cloned().collect();
        if let Some(p) = self.parts.borrow().as_ref() {
            files.push(p.clone());
        }
        for f in files {
            f.sync_all().await?;
        }
        Ok(())
    }

    fn torrent_offset(&self, piece: usize, offset: u32) -> Result<u64, Error> {
        let piece_len = u64::from(self.info.piece_length);
        let base = (piece as u64)
            .checked_mul(piece_len)
            .ok_or(Error::OutOfRange)?;
        let off = base
            .checked_add(u64::from(offset))
            .ok_or(Error::OutOfRange)?;
        if off > self.info.total_length {
            return Err(Error::OutOfRange);
        }
        Ok(off)
    }

    /// Bytes of file `index` covered by verified pieces (progress per file).
    pub fn file_done(&self, index: usize) -> u64 {
        let Some(f) = self.info.files.get(index) else {
            return 0;
        };
        if f.length == 0 {
            return 0;
        }
        let have = self.have.borrow();
        let piece_len = u64::from(self.info.piece_length);
        let first = (f.offset / piece_len) as usize;
        let last = ((f.offset + f.length - 1) / piece_len) as usize;
        let mut done = 0u64;
        for piece in first..=last {
            if !have.get(piece) {
                continue;
            }
            let ps = piece as u64 * piece_len;
            let pe = (ps + piece_len).min(self.info.total_length);
            let s = ps.max(f.offset);
            let e = pe.min(f.offset + f.length);
            if e > s {
                done += e - s;
            }
        }
        done
    }

    /// The file slices covering a block (for diagnostics/tests).
    pub fn block_slices(
        &self,
        piece: usize,
        offset: u32,
        length: u32,
    ) -> Result<Vec<FileSlice>, Error> {
        let torrent_off = self.torrent_offset(piece, offset)?;
        Ok(self.info.slices_for(torrent_off, u64::from(length)))
    }
}

fn libc_exdev() -> i32 {
    18 // EXDEV on Linux
}

/// Copy `from` to `to` through the ring in 1 MiB chunks.
async fn copy_file(from: &std::path::Path, to: &std::path::Path) -> Result<(), Error> {
    let src = File::open_ro(from).await?;
    let dst = File::open_rw(to).await?;
    let len = std::fs::metadata(from)?.len();
    let mut off = 0u64;
    while off < len {
        let chunk = (len - off).min(1024 * 1024) as usize;
        let (r, buf) = src.read_at(off, Buffer::from_vec(vec![0u8; chunk])).await;
        let n = r? as usize;
        if n == 0 {
            break;
        }
        let mut data = buf.into_vec();
        data.truncate(n);
        dst.write_all_at(off, Buffer::from_vec(data)).await?;
        off += n as u64;
    }
    dst.sync_all().await?;
    Ok(())
}
