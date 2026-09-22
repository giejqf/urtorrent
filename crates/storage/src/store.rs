// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The piece store: maps a torrent's pieces onto on-disk files and reads,
//! writes, preallocates, and verifies them over io_uring. Multi-file piece
//! spans and BEP 47 padding files are handled here; padding bytes are synthetic
//! zeros for hashing and are never written to disk.
//!
//! Hashing happens as blocks are written ("hash cursor"): each piece being
//! downloaded carries a running SHA-1 that advances over the contiguous
//! prefix written so far; blocks that land ahead of the cursor are kept in a
//! small in-memory stash (bounded per piece) or, past that bound, read back
//! from the page cache when the cursor reaches them. When the cursor reaches
//! the end the digest is compared and the have-bit set — after every write
//! of the piece completed, so resume data never claims unwritten bytes.
//! `verify_piece` returns that verdict; pieces without a cursor (rechecks,
//! data found on disk) are read back and hashed whole, through a pool of
//! piece-sized buffers rather than a fresh allocation per piece.
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
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::task::Waker;

use metainfo::{FileSlice, Info, SafePath};
use uring::{Buffer, BufferPool, File};

use crate::Error;
use crate::hash::{HashPool, HashState};
use metainfo::Bitfield;

/// Bytes of not-yet-hashed blocks kept in memory per in-progress piece;
/// beyond this, blocks ahead of the cursor are read back when reached.
const STASH_CAP: usize = 1024 * 1024;
/// Largest read-back run per hash job.
const MAX_RUN: u32 = 1024 * 1024;

/// Hash-as-you-write state of one piece being downloaded.
struct PieceHash {
    /// The running digest (`None` while a pool job holds it).
    state: Option<HashState>,
    /// Bytes hashed so far (contiguous from the piece start).
    cursor: u32,
    /// Written ranges `[start, end)`, sorted and merged.
    written: Vec<(u32, u32)>,
    /// Written-but-unhashed block data, by offset.
    /// Written blocks kept for the hash cursor: `(buffer, payload start)`.
    stash: BTreeMap<u32, (Vec<u8>, usize)>,
    stash_bytes: usize,
    /// An advancer is running for this piece.
    hashing: bool,
    /// The verdict once the cursor reached the end (taken by `verify_piece`).
    verdict: Option<bool>,
    /// Tasks waiting for the verdict.
    waiters: Vec<Waker>,
}

impl PieceHash {
    fn new() -> PieceHash {
        PieceHash {
            state: Some(HashState::new()),
            cursor: 0,
            written: Vec::new(),
            stash: BTreeMap::new(),
            stash_bytes: 0,
            hashing: false,
            verdict: None,
            waiters: Vec::new(),
        }
    }

    /// Record `[start, end)` as written.
    fn mark(&mut self, start: u32, end: u32) {
        self.written.push((start, end));
        self.written.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.written.len());
        for (s, e) in self.written.drain(..) {
            match merged.last_mut() {
                Some((_, le)) if s <= *le => *le = (*le).max(e),
                _ => merged.push((s, e)),
            }
        }
        self.written = merged;
    }

    /// End of the written run that contains `pos`, if any.
    fn run_end(&self, pos: u32) -> Option<u32> {
        self.written
            .iter()
            .find(|(s, e)| *s <= pos && pos < *e)
            .map(|(_, e)| *e)
    }

    /// Start over (a failed hash): the bytes on disk are wrong and will be
    /// overwritten by the re-download.
    fn reset(&mut self) {
        let waiters = std::mem::take(&mut self.waiters);
        *self = PieceHash::new();
        self.waiters = waiters;
    }
}

/// Resources every store of one disk ring shares: an LRU of open file
/// handles capped at `max_open` (libtorrent's file pool), and piece-sized
/// buffer pools per piece length. Without the cap a session with thousands
/// of torrents holds every content file open forever; without sharing, each
/// store would keep its own idle piece buffers (megabytes each).
pub struct DiskResources {
    files: RefCell<FilePool>,
    bufs: RefCell<HashMap<usize, BufferPool>>,
    next_store: std::cell::Cell<u64>,
    stats: Arc<DiskStats>,
}

/// Counters of the disk side readable from any thread (the session's
/// stats). Relaxed atomics: they are indicators, not synchronisation.
#[derive(Debug, Default)]
pub struct DiskStats {
    /// Jobs submitted to the disk ring and not finished.
    pub jobs_pending: std::sync::atomic::AtomicUsize,
    /// Hash jobs handed to the SHA-1 workers and not finished (shared with
    /// the [`HashPool`](crate::HashPool) through `HashPool::with_counter`).
    pub hash_pending: Arc<std::sync::atomic::AtomicUsize>,
    /// Bytes re-read from disk (page cache) to hash blocks that arrived out
    /// of order, across every store since start (see
    /// [`Storage::hash_readback_bytes`]).
    pub readback_bytes: std::sync::atomic::AtomicU64,
}

/// Which file of which store a pooled handle is.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct FileKey {
    store: u64,
    /// `None` is the store's parts file.
    index: Option<usize>,
}

struct FilePool {
    max_open: usize,
    open: HashMap<FileKey, (Rc<File>, u64)>,
    /// Last-use stamp -> key, for eviction.
    lru: std::collections::BTreeMap<u64, FileKey>,
    stamp: u64,
}

impl FilePool {
    fn touch(&mut self, key: FileKey) -> Option<Rc<File>> {
        let stamp = self.stamp;
        self.stamp += 1;
        let (f, old) = self.open.get_mut(&key)?;
        self.lru.remove(old);
        *old = stamp;
        self.lru.insert(stamp, key);
        Some(f.clone())
    }

    fn insert(&mut self, key: FileKey, f: Rc<File>) {
        while self.open.len() >= self.max_open.max(1) {
            let Some((&stamp, &victim)) = self.lru.iter().next() else {
                break;
            };
            self.lru.remove(&stamp);
            // The handle closes (through the ring) when the last user drops it.
            self.open.remove(&victim);
        }
        let stamp = self.stamp;
        self.stamp += 1;
        self.open.insert(key, (f, stamp));
        self.lru.insert(stamp, key);
    }

    fn remove(&mut self, key: FileKey) {
        if let Some((_, stamp)) = self.open.remove(&key) {
            self.lru.remove(&stamp);
        }
    }

    fn remove_store(&mut self, store: u64) {
        let keys: Vec<FileKey> = self
            .open
            .keys()
            .filter(|k| k.store == store)
            .copied()
            .collect();
        for k in keys {
            if let Some((_, stamp)) = self.open.remove(&k) {
                self.lru.remove(&stamp);
            }
        }
    }
}

impl DiskResources {
    /// Resources allowing `max_open` open file handles across stores.
    pub fn new(max_open: usize) -> Rc<DiskResources> {
        Self::with_stats(max_open, Arc::new(DiskStats::default()))
    }

    /// [`DiskResources::new`] reporting into `stats`.
    pub fn with_stats(max_open: usize, stats: Arc<DiskStats>) -> Rc<DiskResources> {
        Rc::new(DiskResources {
            files: RefCell::new(FilePool {
                max_open: max_open.max(1),
                open: HashMap::new(),
                lru: std::collections::BTreeMap::new(),
                stamp: 0,
            }),
            bufs: RefCell::new(HashMap::new()),
            next_store: std::cell::Cell::new(1),
            stats,
        })
    }

    /// The shared counters.
    pub fn stats(&self) -> &Arc<DiskStats> {
        &self.stats
    }

    /// Open file handles right now.
    pub fn open_files(&self) -> usize {
        self.files.borrow().open.len()
    }

    fn take_buf(&self, size: usize) -> Buffer {
        self.bufs
            .borrow_mut()
            .entry(size)
            .or_insert_with(|| BufferPool::new(size, 2))
            .take()
    }

    fn put_buf(&self, size: usize, data: Vec<u8>) {
        if let Some(p) = self.bufs.borrow().get(&size) {
            p.put(data);
        }
    }
}

/// Default file priority (libtorrent's `default_priority`).
pub const DEFAULT_PRIORITY: u8 = 4;
/// Highest file priority.
pub const MAX_PRIORITY: u8 = 7;

/// A per-torrent piece store rooted at a save directory.
pub struct Storage {
    info: Arc<Info>,
    root: RefCell<PathBuf>,
    pool: Rc<HashPool>,
    res: Rc<DiskResources>,
    store_id: u64,
    /// Files written since the last `sync_all` (fsync must reach them even
    /// if their handle was evicted from the pool meanwhile).
    dirty: RefCell<std::collections::HashSet<Option<usize>>>,
    have: RefCell<Bitfield>,
    /// Priority per `info.files` entry (padding files are always 0).
    priorities: RefCell<Vec<u8>>,
    /// Whether a file's bytes live in the parts file (skipped and never
    /// created on disk).
    use_parts: RefCell<Vec<bool>>,
    /// Per `info.files` entry: the path the file lives at when it was
    /// renamed (`rename_file`), else the metainfo's.
    mapped: RefCell<Vec<Option<SafePath>>>,
    /// Preallocation mode (`preallocate` was called): files that become
    /// wanted later are reserved too.
    prealloc: std::cell::Cell<bool>,
    /// Pieces being downloaded, hashed as they are written.
    progress: RefCell<HashMap<usize, PieceHash>>,
    /// Bytes the hash cursor had to read back (diagnostics: zero when blocks
    /// arrive in order).
    readback_bytes: std::cell::Cell<u64>,
}

impl Storage {
    /// Create a store for `info` under `root`, using `pool` for hashing, with
    /// its own file/buffer resources (tests; the disk ring shares one
    /// [`DiskResources`] across stores). Every content file starts at
    /// [`DEFAULT_PRIORITY`].
    pub fn new(info: Arc<Info>, root: PathBuf, pool: Rc<HashPool>) -> Storage {
        Storage::with_resources(info, root, pool, DiskResources::new(64))
    }

    /// Create a store sharing `res` with other stores.
    pub fn with_resources(
        info: Arc<Info>,
        root: PathBuf,
        pool: Rc<HashPool>,
        res: Rc<DiskResources>,
    ) -> Storage {
        let pieces = info.piece_count();
        let priorities = info
            .files
            .iter()
            .map(|f| if f.is_padding() { 0 } else { DEFAULT_PRIORITY })
            .collect::<Vec<u8>>();
        let n = info.files.len();
        let store_id = res.next_store.get();
        res.next_store.set(store_id + 1);
        Storage {
            info,
            root: RefCell::new(root),
            pool,
            res,
            store_id,
            dirty: RefCell::new(std::collections::HashSet::new()),
            have: RefCell::new(Bitfield::new(pieces)),
            priorities: RefCell::new(priorities),
            use_parts: RefCell::new(vec![false; n]),
            mapped: RefCell::new(vec![None; n]),
            prealloc: std::cell::Cell::new(false),
            progress: RefCell::new(HashMap::new()),
            readback_bytes: std::cell::Cell::new(0),
        }
    }

    /// Bytes of one piece (for buffer sizing).
    fn piece_buf_size(&self) -> usize {
        self.info.piece_length as usize
    }

    /// The disk side's shared counters.
    pub fn stats(&self) -> &Arc<DiskStats> {
        self.res.stats()
    }

    /// Bytes the hash cursor read back from disk because blocks arrived ahead
    /// of it beyond the in-memory stash (0 for in-order downloads).
    pub fn hash_readback_bytes(&self) -> u64 {
        self.readback_bytes.get()
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
            use_parts[i] =
                !f.is_padding() && p == 0 && !self.abs_path(i, &root).is_some_and(|p| p.exists());
        }
    }

    /// Install renamed paths (from resume data) before any file is touched.
    pub fn set_mapped_files(&self, mapped: Vec<Option<SafePath>>) {
        let mut m = self.mapped.borrow_mut();
        for (i, p) in mapped.into_iter().enumerate() {
            if i < m.len() {
                m[i] = p;
            }
        }
    }

    /// The renamed paths, per `info.files` entry (`None` = the metainfo's).
    pub fn mapped_files(&self) -> Vec<Option<SafePath>> {
        self.mapped.borrow().clone()
    }

    /// Where file `index` lives, relative to the root.
    pub fn rel_path(&self, index: usize) -> Option<SafePath> {
        let f = self.info.files.get(index)?;
        Some(
            self.mapped
                .borrow()
                .get(index)
                .cloned()
                .flatten()
                .unwrap_or_else(|| f.path.clone()),
        )
    }

    fn abs_path(&self, index: usize, root: &Path) -> Option<PathBuf> {
        self.rel_path(index).map(|p| p.to_path(root))
    }

    /// Where file `index` lives on disk now.
    pub fn file_path(&self, index: usize) -> Option<PathBuf> {
        self.abs_path(index, &self.root.borrow())
    }

    /// Rename (move within the save path) file `index` to `new`: the file on
    /// disk is renamed if it exists, the mapping is kept for every later
    /// open. Padding files, out-of-range indices and a path another file
    /// already uses are refused. The caller must have quiesced I/O on the
    /// file (the disk ring runs this as a barrier).
    pub async fn rename_file(&self, index: usize, new: SafePath) -> Result<(), Error> {
        let f = self.info.files.get(index).ok_or(Error::OutOfRange)?;
        if f.is_padding() {
            return Err(Error::OutOfRange);
        }
        let current = self.rel_path(index).ok_or(Error::OutOfRange)?;
        if current == new {
            return Ok(());
        }
        for i in 0..self.info.files.len() {
            if i != index && self.rel_path(i).is_some_and(|p| p == new) {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "another file of the torrent has that path",
                )));
            }
        }
        self.sync_all().await?;
        self.res.files.borrow_mut().remove(FileKey {
            store: self.store_id,
            index: Some(index),
        });
        let root = self.root.borrow().clone();
        let from = current.to_path(&root);
        let to = new.to_path(&root);
        if from.exists() {
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(&from, &to)?;
        }
        self.mapped.borrow_mut()[index] = Some(new);
        Ok(())
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
                    let has_data = self
                        .abs_path(i, &root)
                        .is_some_and(|path| std::fs::metadata(&path).is_ok_and(|m| m.len() > 0));
                    if !has_data {
                        use_parts[i] = true;
                    }
                }
            }
        }
        for i in to_export {
            if self.prealloc.get() {
                self.reserve(i).await?;
            }
            self.export_parts(i).await?;
            self.use_parts.borrow_mut()[i] = false;
        }
        Ok(())
    }

    /// Piece priorities derived from the file priorities: the highest
    /// priority of any non-padding file the piece touches (libtorrent).
    pub fn piece_priorities(&self) -> Vec<u8> {
        crate::layout::piece_priorities(&self.info, &self.priorities.borrow())
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
            self.dirty.borrow_mut().insert(Some(i));
        }
        Ok(())
    }

    async fn parts_file(&self) -> Result<Rc<File>, Error> {
        let key = FileKey {
            store: self.store_id,
            index: None,
        };
        if let Some(f) = self.res.files.borrow_mut().touch(key) {
            return Ok(f);
        }
        let path = self.parts_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = Rc::new(File::open_rw(&path).await?);
        self.res.files.borrow_mut().insert(key, f.clone());
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
        self.res.files.borrow_mut().remove_store(self.store_id);
        let old_root = self.root.borrow().clone();
        std::fs::create_dir_all(&new_root)?;
        let mut moves: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (i, _) in self
            .info
            .files
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.is_padding())
        {
            let Some(rel) = self.rel_path(i) else {
                continue;
            };
            let from = rel.to_path(&old_root);
            if from.exists() {
                moves.push((from, rel.to_path(&new_root)));
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
            let path = self.file_path(i).ok_or(Error::OutOfRange)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Open (creating) so the file exists even at zero length.
            self.file(i).await?;
        }
        Ok(())
    }

    /// Delete every content file of the torrent, the parts file, and the
    /// directories that became empty (from the deepest up to, but not
    /// including, the save path). Files that are already gone are fine.
    /// Handles are closed first. Directory walking is one-time blocking
    /// work off the data path (AGENTS.md 5.3).
    pub async fn delete_files(&self) -> Result<(), Error> {
        self.res.files.borrow_mut().remove_store(self.store_id);
        self.dirty.borrow_mut().clear();
        let root = self.root.borrow().clone();
        let mut dirs: Vec<PathBuf> = Vec::new();
        for (i, f) in self.info.files.iter().enumerate() {
            if f.is_padding() {
                continue;
            }
            let Some(path) = self.abs_path(i, &root) else {
                continue;
            };
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let mut p = path.parent();
            while let Some(d) = p
                && d.starts_with(&root)
                && d != root
            {
                if !dirs.contains(&d.to_path_buf()) {
                    dirs.push(d.to_path_buf());
                }
                p = d.parent();
            }
        }
        let parts = self.parts_path();
        if parts.exists() {
            std::fs::remove_file(&parts)?;
        }
        // Deepest first so parents empty out.
        dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
        for d in dirs {
            let _ = std::fs::remove_dir(d); // only if empty
        }
        Ok(())
    }

    /// Preallocate every wanted content file to its full length
    /// (`fallocate`; a plain size set where the file system cannot
    /// allocate) and remember the mode: files that become wanted later
    /// (`set_file_priorities`) are reserved the same way. Skipped files
    /// routed to the parts file are not created.
    pub async fn preallocate(&self) -> Result<(), Error> {
        self.prealloc.set(true);
        self.create_files().await?;
        for (i, f) in self.info.files.iter().enumerate() {
            if f.is_padding() || f.length == 0 || self.use_parts.borrow()[i] {
                continue;
            }
            self.reserve(i).await?;
        }
        Ok(())
    }

    /// Reserve file `i`'s full length on disk (see [`Storage::preallocate`]).
    async fn reserve(&self, i: usize) -> Result<(), Error> {
        let len = self.info.files.get(i).map_or(0, |f| f.length);
        if len == 0 {
            return Ok(());
        }
        let file = self.file(i).await?;
        if !file.reserve(len).await? {
            tracing::warn!(
                file = i,
                "file system cannot preallocate; size set, blocks not reserved"
            );
        }
        Ok(())
    }

    /// The open handle for file `index`, opening it through the ring on first
    /// use (directory creation is a one-time blocking call, AGENTS.md 5.3).
    async fn file(&self, index: usize) -> Result<Rc<File>, Error> {
        let key = FileKey {
            store: self.store_id,
            index: Some(index),
        };
        if let Some(f) = self.res.files.borrow_mut().touch(key) {
            return Ok(f);
        }
        let path = self.file_path(index).ok_or(Error::OutOfRange)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = Rc::new(File::open_rw(&path).await?);
        self.res.files.borrow_mut().insert(key, f.clone());
        Ok(f)
    }

    /// Write a block (`data`) at `offset` within `piece`, then advance the
    /// piece's hash cursor (see the module docs). Padding regions in the span
    /// are skipped on disk and hashed as zeros, as BEP 47 defines them.
    pub async fn write_block(&self, piece: usize, offset: u32, data: Buffer) -> Result<(), Error> {
        self.write_block_from(piece, offset, data, 0).await
    }

    /// [`Storage::write_block`] for a payload that starts at `start` within
    /// `data` (a peer-wire frame kept whole: the block follows its header).
    /// Nothing is copied on the common single-file path: the range is
    /// written from the buffer and hashed from it afterwards.
    pub async fn write_block_from(
        &self,
        piece: usize,
        offset: u32,
        data: Buffer,
        start: usize,
    ) -> Result<(), Error> {
        let start = start.min(data.len());
        let torrent_off = self.torrent_offset(piece, offset)?;
        let len = (data.len() - start) as u64;
        let slices = self.info.slices_for(torrent_off, len);
        // The common case, a block inside one content file: write the
        // buffer itself and hash from it afterwards. No copy.
        if let [s] = slices.as_slice()
            && !s.padding
            && s.length == len
        {
            let (file, off) = self.target(s).await?;
            self.mark_dirty(s);
            let data = file
                .write_range_all_at(off, data, start, len as usize)
                .await?;
            return self
                .on_written(piece, offset, (data.into_vec(), start))
                .await;
        }
        // A block spanning files (or padding): each slice is written from
        // its range of the same buffer, one file after the other.
        let mut data = data;
        let mut pos = start;
        for s in slices {
            let take = s.length as usize;
            if s.padding {
                // Synthetic zeros: not stored, and hashed as zeros whatever
                // the peer sent.
                data.as_mut_slice()[pos..pos + take].fill(0);
                pos += take;
                continue;
            }
            let (file, off) = self.target(&s).await?;
            self.mark_dirty(&s);
            data = file.write_range_all_at(off, data, pos, take).await?;
            pos += take;
        }
        self.on_written(piece, offset, (data.into_vec(), start))
            .await
    }

    /// Remember that the file behind `s` has unsynced writes.
    fn mark_dirty(&self, s: &FileSlice) {
        let key = if self
            .use_parts
            .borrow()
            .get(s.file_index)
            .copied()
            .unwrap_or(false)
        {
            None
        } else {
            Some(s.file_index)
        };
        self.dirty.borrow_mut().insert(key);
    }

    /// A block of `piece` is on disk: record it and advance the hash cursor as
    /// far as the contiguous written prefix goes.
    async fn on_written(
        &self,
        piece: usize,
        offset: u32,
        data: (Vec<u8>, usize),
    ) -> Result<(), Error> {
        let data_len = data.0.len() - data.1;
        if data_len == 0 {
            return Ok(());
        }
        let piece_len = self.piece_len(piece)?;
        let end = offset.saturating_add(data_len as u32).min(piece_len);
        {
            let mut prog = self.progress.borrow_mut();
            let p = prog.entry(piece).or_insert_with(PieceHash::new);
            if p.verdict.is_some() {
                // A verdict is pending collection; this write belongs to a
                // re-download after a failure that was not collected yet.
                p.reset();
            }
            p.mark(offset, end);
            if offset >= p.cursor && (offset == p.cursor || p.stash_bytes + data_len <= STASH_CAP) {
                p.stash_bytes += data_len;
                p.stash.insert(offset, data);
            }
            if p.hashing {
                return Ok(());
            }
            p.hashing = true;
        }
        self.advance(piece, piece_len).await;
        Ok(())
    }

    /// Run the hash cursor of `piece` forward until it hits an unwritten byte
    /// (or the end), one pool job per contiguous run.
    async fn advance(&self, piece: usize, piece_len: u32) {
        loop {
            // Plan the next run: stash entries first, read-back for the rest.
            let (chunks, readback, next, state) = {
                let mut prog = self.progress.borrow_mut();
                let Some(p) = prog.get_mut(&piece) else {
                    return;
                };
                let mut pos = p.cursor;
                let mut chunks: Vec<(Vec<u8>, usize)> = Vec::new();
                let mut readback: Vec<(u32, u32)> = Vec::new();
                let mut budget = MAX_RUN;
                while pos < piece_len && budget > 0 {
                    if let Some(d) = p.stash.remove(&pos) {
                        let l = (d.0.len() - d.1) as u32;
                        p.stash_bytes -= l as usize;
                        chunks.push(d);
                        pos += l;
                        budget = budget.saturating_sub(l);
                    } else if let Some(run_end) = p.run_end(pos) {
                        // Written earlier, not stashed: read it back, but only
                        // up to the next stashed block so that one is used.
                        let mut e = run_end.min(pos.saturating_add(budget));
                        if let Some((&next_stash, _)) = p.stash.range(pos + 1..).next() {
                            e = e.min(next_stash);
                        }
                        readback.push((pos, e));
                        chunks.push((Vec::new(), 0)); // placeholder, filled below
                        budget = budget.saturating_sub(e - pos);
                        pos = e;
                    } else {
                        break;
                    }
                }
                if chunks.is_empty() {
                    p.hashing = false;
                    return;
                }
                (chunks, readback, pos, p.state.take())
            };
            let mut chunks = chunks;
            // Fill the read-back placeholders through the ring.
            let mut rb = readback.iter();
            let mut pooled_idx = Vec::new();
            for (i, c) in chunks.iter_mut().enumerate() {
                if !c.0.is_empty() {
                    continue;
                }
                let Some(&(s, e)) = rb.next() else { break };
                let mut buf = self.res.take_buf(self.piece_buf_size());
                buf.resize((e - s) as usize);
                match self.read_exact_piece_range(piece, s, buf).await {
                    Ok(b) => {
                        self.readback_bytes
                            .set(self.readback_bytes.get() + u64::from(e - s));
                        self.res
                            .stats
                            .readback_bytes
                            .fetch_add(u64::from(e - s), std::sync::atomic::Ordering::Relaxed);
                        *c = (b.into_vec(), 0);
                        pooled_idx.push(i);
                    }
                    Err(err) => {
                        // Cannot hash what cannot be read: leave the cursor
                        // where it is; `verify_piece` falls back to a full
                        // read-back and reports the truth.
                        tracing::warn!(piece, "hash read-back failed: {err}");
                        let mut prog = self.progress.borrow_mut();
                        if let Some(p) = prog.get_mut(&piece) {
                            p.state = state;
                            p.hashing = false;
                        }
                        return;
                    }
                }
            }
            let finish = next == piece_len;
            let state = state.unwrap_or_default();
            let (state, chunks, digest) = self.pool.update_async(state, chunks, finish).await;
            for (i, c) in chunks.into_iter().enumerate() {
                if pooled_idx.contains(&i) {
                    self.res.put_buf(self.piece_buf_size(), c.0);
                }
            }
            let mut prog = self.progress.borrow_mut();
            let Some(p) = prog.get_mut(&piece) else {
                return;
            };
            p.state = Some(state);
            p.cursor = next;
            if finish {
                let ok = digest.is_some_and(|d| Some(&d) == self.info.piece_hash(piece));
                if ok {
                    self.have.borrow_mut().set(piece);
                } else {
                    self.have.borrow_mut().clear(piece);
                }
                p.verdict = Some(ok);
                p.hashing = false;
                for w in p.waiters.drain(..) {
                    w.wake();
                }
                return;
            }
        }
    }

    /// Read exactly `[start, start + buf.len())` of `piece` (padding regions
    /// zero-filled) into `buf`.
    async fn read_exact_piece_range(
        &self,
        piece: usize,
        start: u32,
        buf: Buffer,
    ) -> Result<Buffer, Error> {
        let len = buf.len() as u32;
        let torrent_off = self.torrent_offset(piece, start)?;
        let slices = self.info.slices_for(torrent_off, u64::from(len));
        let mut out = buf;
        let mut pos = 0usize;
        for s in slices {
            let take = s.length as usize;
            if s.padding {
                out.as_mut_slice()[pos..pos + take].fill(0);
                pos += take;
                continue;
            }
            let (file, off) = self.target(&s).await?;
            out = file.read_exact_into(off, out, pos, take).await?;
            pos += take;
        }
        Ok(out)
    }

    fn piece_len(&self, piece: usize) -> Result<u32, Error> {
        self.info.piece_size(piece).ok_or(Error::OutOfRange)
    }

    /// Read the full contents of `piece` into a buffer. Returns `(data,
    /// complete)`; `complete` is false if any non-padding region was short of
    /// data on disk (a hole / not-yet-downloaded), in which case the missing
    /// bytes are zero-filled so hashing is deterministic.
    pub async fn read_piece(&self, piece: usize) -> Result<(Vec<u8>, bool), Error> {
        let loc = self.info.piece_location(piece).ok_or(Error::OutOfRange)?;
        let mut buf = self.res.take_buf(self.piece_buf_size());
        buf.resize(loc.length as usize);
        let mut out = buf.into_vec();
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
        // The block must lie within its piece (the last piece is short).
        let piece_size = self.info.piece_size(piece).ok_or(Error::OutOfRange)?;
        if offset
            .checked_add(length)
            .is_none_or(|end| end > piece_size)
        {
            return Err(Error::OutOfRange);
        }
        let slices = self.info.slices_for(torrent_off, u64::from(length));
        // One content file (the common case): read straight into the block
        // buffer. Otherwise assemble the block slice by slice, zero-filling
        // padding.
        if let [s] = slices.as_slice()
            && !s.padding
            && s.length == u64::from(length)
        {
            let (file, off) = self.target(s).await?;
            let mut buf = Buffer::with_capacity(length as usize);
            buf.resize(length as usize);
            return file.read_exact_at(off, buf).await.map_err(Into::into);
        }
        let mut out = Buffer::from_vec(vec![0u8; length as usize]);
        let mut pos = 0usize;
        for s in slices {
            let take = s.length as usize;
            if s.padding {
                pos += take;
                continue;
            }
            let (file, off) = self.target(&s).await?;
            out = file.read_exact_into(off, out, pos, take).await?;
            pos += take;
        }
        Ok(out)
    }

    /// Verify `piece` against its expected hash. On success the have-bit is set.
    /// Returns whether it verified.
    pub async fn verify_piece(&self, piece: usize) -> Result<bool, Error> {
        let expected = *self.info.piece_hash(piece).ok_or(Error::OutOfRange)?;
        // Hash-as-you-write verdict, waiting for a cursor still running.
        loop {
            let waiting = {
                let mut prog = self.progress.borrow_mut();
                match prog.get_mut(&piece) {
                    Some(p) => {
                        if let Some(v) = p.verdict.take() {
                            if v {
                                prog.remove(&piece);
                            } else {
                                p.reset();
                            }
                            return Ok(v);
                        }
                        p.hashing
                    }
                    None => false,
                }
            };
            if !waiting {
                break;
            }
            VerdictWait {
                storage: self,
                piece,
            }
            .await;
        }
        // No cursor (data found on disk, recheck, or an incomplete cursor):
        // read the piece back and hash it whole.
        self.progress.borrow_mut().remove(&piece);
        let (data, complete) = self.read_piece(piece).await?;
        if !complete {
            self.res.put_buf(self.piece_buf_size(), data);
            self.have.borrow_mut().clear(piece);
            return Ok(false);
        }
        let (ok, buf) = self.pool.verify_async(data, expected).await;
        self.res.put_buf(self.piece_buf_size(), buf);
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
        let complete = {
            let prog = self.progress.borrow();
            match prog.get(&piece) {
                Some(p) => p.verdict.is_some() || p.hashing,
                None => false,
            }
        };
        if !complete {
            return Ok(None);
        }
        Ok(Some(self.verify_piece(piece).await?))
    }

    /// Recheck every piece against the data on disk, rebuilding the have set
    /// (force recheck / crash recovery).
    pub async fn check_all(&self) -> Result<Bitfield, Error> {
        let pieces = self.info.piece_count();
        let mut have = Bitfield::new(pieces);
        self.progress.borrow_mut().clear();
        for p in 0..pieces {
            let expected = match self.info.piece_hash(p) {
                Some(h) => *h,
                None => continue,
            };
            let (data, complete) = self.read_piece(p).await?;
            if complete {
                let (ok, buf) = self.pool.verify_async(data, expected).await;
                self.res.put_buf(self.piece_buf_size(), buf);
                if ok {
                    have.set(p);
                }
            } else {
                self.res.put_buf(self.piece_buf_size(), data);
            }
        }
        *self.have.borrow_mut() = have.clone();
        Ok(have)
    }

    /// `fsync` every file written since the last sync (reopening one whose
    /// handle left the pool; the dirty pages are the kernel's, not the
    /// handle's).
    pub async fn sync_all(&self) -> Result<(), Error> {
        let dirty: Vec<Option<usize>> = self.dirty.borrow().iter().copied().collect();
        for key in dirty {
            let f = match key {
                Some(i) => self.file(i).await?,
                None => self.parts_file().await?,
            };
            f.sync_all().await?;
            self.dirty.borrow_mut().remove(&key);
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
        crate::layout::file_done(&self.info, &self.have.borrow(), index)
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

impl Drop for Storage {
    fn drop(&mut self) {
        // Give the pool's slots back right away rather than at eviction.
        self.res.files.borrow_mut().remove_store(self.store_id);
    }
}

/// Resolves when the piece's hash cursor finishes (or is no longer running).
struct VerdictWait<'a> {
    storage: &'a Storage,
    piece: usize,
}

impl std::future::Future for VerdictWait<'_> {
    type Output = ();
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let mut prog = self.storage.progress.borrow_mut();
        match prog.get_mut(&self.piece) {
            Some(p) if p.verdict.is_none() && p.hashing => {
                p.waiters.push(cx.waker().clone());
                std::task::Poll::Pending
            }
            _ => std::task::Poll::Ready(()),
        }
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
