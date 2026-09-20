// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The piece store: maps a torrent's pieces onto on-disk files and reads,
//! writes, preallocates, and verifies them over io_uring. Multi-file piece
//! spans and BEP 47 padding files are handled here; padding bytes are synthetic
//! zeros for hashing and are never written to disk.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use metainfo::{FileSlice, Info};
use uring::{Buffer, File};

use crate::Error;
use crate::hash::HashPool;
use metainfo::Bitfield;

/// A per-torrent piece store rooted at a save directory.
pub struct Storage {
    info: Rc<Info>,
    root: PathBuf,
    pool: Rc<HashPool>,
    files: RefCell<HashMap<usize, Rc<File>>>,
    have: RefCell<Bitfield>,
}

impl Storage {
    /// Create a store for `info` under `root`, using `pool` for hashing.
    pub fn new(info: Rc<Info>, root: PathBuf, pool: Rc<HashPool>) -> Storage {
        let pieces = info.piece_count();
        Storage {
            info,
            root,
            pool,
            files: RefCell::new(HashMap::new()),
            have: RefCell::new(Bitfield::new(pieces)),
        }
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
    pub fn root(&self) -> &std::path::Path {
        &self.root
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

    /// Create every content file's parent directory and the files themselves.
    pub fn create_files(&self) -> Result<(), Error> {
        for (i, f) in self.info.files.iter().enumerate() {
            if f.is_padding() {
                continue;
            }
            let path = f.path.to_path(&self.root);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Open (creating) so the file exists even at zero length.
            self.file(i)?;
        }
        Ok(())
    }

    /// Preallocate all non-padding files to their full length (`fallocate`).
    pub async fn preallocate(&self) -> Result<(), Error> {
        self.create_files()?;
        for (i, f) in self.info.files.iter().enumerate() {
            if f.is_padding() || f.length == 0 {
                continue;
            }
            let file = self.file(i)?;
            file.allocate(0, f.length).await?;
        }
        Ok(())
    }

    fn file(&self, index: usize) -> Result<Rc<File>, Error> {
        if let Some(f) = self.files.borrow().get(&index) {
            return Ok(f.clone());
        }
        let spec = self.info.files.get(index).ok_or(Error::OutOfRange)?;
        let path = spec.path.to_path(&self.root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = Rc::new(File::open_rw(&path)?);
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
            let file = self.file(s.file_index)?;
            let buf = Buffer::from_vec(chunk.to_vec());
            file.write_all_at(s.file_offset, buf).await?;
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
            let file = self.file(s.file_index)?;
            let buf = Buffer::from_vec(vec![0u8; take]);
            let (r, filled) = file.read_at(s.file_offset, buf).await;
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
            let file = self.file(s.file_index)?;
            let buf = Buffer::from_vec(vec![0u8; take]);
            let got = file.read_exact_at(s.file_offset, buf).await?;
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

    /// Flush all open files to disk (`fsync`).
    pub async fn sync_all(&self) -> Result<(), Error> {
        let files: Vec<Rc<File>> = self.files.borrow().values().cloned().collect();
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
