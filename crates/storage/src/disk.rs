// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The disk ring: a dedicated `urt-disk` thread with its own io_uring
//! [`uring::Runtime`] that owns every [`Storage`] (and the SHA-1
//! [`HashPool`], whose completions it drains), so torrent file I/O never
//! competes with peer sockets on the network ring (AGENTS.md 5.3, ADR 0004).
//!
//! The engine holds a [`DiskStore`] per torrent: an engine-thread handle whose
//! async methods queue a job for the disk thread and resolve through a
//! [`uring::Bridge`] on the engine's own ring. Jobs of one store execute in
//! order of submission on the disk thread (each is spawned as a task, but
//! the store serialises them), so a `write_block` followed by `verify_piece`
//! sees the write. The handle mirrors the state the engine reads
//! synchronously (have-set, priorities, root); the authoritative copy on the
//! disk thread is updated by the same jobs.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use metainfo::{Bitfield, Info};
use uring::{Bridge, Completer, Notifier, NotifyHandle, Runtime, Ticket};

use crate::hash::HashPool;
use crate::store::Storage;
use crate::{Error, layout};

/// A job for the disk thread.
enum Job {
    Open {
        id: u64,
        info: Arc<Info>,
        root: PathBuf,
        prios: Option<Vec<u8>>,
    },
    CreateFiles {
        id: u64,
        done: Done,
    },
    Write {
        id: u64,
        piece: usize,
        offset: u32,
        data: Vec<u8>,
        done: Done,
    },
    ReadBlock {
        id: u64,
        piece: usize,
        offset: u32,
        length: u32,
        done: Done,
    },
    VerifyPiece {
        id: u64,
        piece: usize,
        done: Done,
    },
    CheckAll {
        id: u64,
        done: Done,
    },
    SetHave {
        id: u64,
        have: Bitfield,
    },
    SetPriorities {
        id: u64,
        prios: Vec<u8>,
        done: Done,
    },
    MoveTo {
        id: u64,
        root: PathBuf,
        done: Done,
    },
    SyncAll {
        id: u64,
        done: Done,
    },
    Close {
        id: u64,
    },
    Shutdown,
}

/// How a job reports back: through the cross-thread bridge (disk thread) or
/// a same-thread slot (inline mode, no syscalls involved).
enum Done {
    Remote(Completer<Reply>),
    /// Same-thread slot (an uncontended mutex keeps `Job: Send` without
    /// `unsafe`; it is never actually shared across threads).
    Local(Arc<Mutex<LocalSlot>>),
}

impl Done {
    fn complete(self, r: Reply) {
        match self {
            Done::Remote(c) => c.complete(r),
            Done::Local(slot) => {
                let waker = match slot.lock() {
                    Ok(mut s) => {
                        s.value = Some(r);
                        s.waker.take()
                    }
                    Err(_) => None,
                };
                if let Some(w) = waker {
                    w.wake();
                }
            }
        }
    }
}

struct LocalSlot {
    value: Option<Reply>,
    waker: Option<std::task::Waker>,
}

/// The future half of a job: a bridge ticket or a local slot.
enum ReplyFuture {
    Remote(Ticket<Reply>),
    Local(Arc<Mutex<LocalSlot>>),
}

impl std::future::Future for ReplyFuture {
    type Output = Reply;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Reply> {
        match self.get_mut() {
            ReplyFuture::Remote(t) => std::pin::Pin::new(t).poll(cx),
            ReplyFuture::Local(slot) => {
                let Ok(mut s) = slot.lock() else {
                    return std::task::Poll::Ready(Reply::Unit(Err(Error::Io(
                        std::io::Error::other("disk reply slot poisoned"),
                    ))));
                };
                match s.value.take() {
                    Some(v) => std::task::Poll::Ready(v),
                    None => {
                        s.waker = Some(cx.waker().clone());
                        std::task::Poll::Pending
                    }
                }
            }
        }
    }
}

/// A job's result.
pub enum Reply {
    /// Nothing but success or an error.
    Unit(Result<(), Error>),
    /// A verification verdict.
    Bool(Result<bool, Error>),
    /// Block bytes.
    Bytes(Result<Vec<u8>, Error>),
    /// A have-set (from a full check).
    Bits(Result<Bitfield, Error>),
}

struct Shared {
    jobs: Mutex<VecDeque<Job>>,
    /// The disk thread's eventfd.
    wake: NotifyHandle,
}

/// Where jobs run.
enum Mode {
    /// A dedicated `urt-disk` thread with its own ring.
    Thread {
        shared: Arc<Shared>,
        thread: Option<JoinHandle<()>>,
    },
    /// On the caller's own ring (no thread hop; for hosts without a spare
    /// core, see `docs/perf.md`).
    Inline { stores: Stores, pool: Rc<HashPool> },
}

/// The disk ring handle (owned by the engine; dropping it joins the thread).
pub struct DiskRing {
    mode: Mode,
    /// Completions back to the engine's ring.
    bridge: Bridge<Reply>,
    next_id: RefCell<u64>,
}

impl DiskRing {
    /// Run storage on the caller's ring (the ring that polls the futures
    /// must be the one the caller's `notify` belongs to). `hash_threads`
    /// SHA-1 workers complete through `notify` as well.
    pub fn inline(hash_threads: usize, notify: NotifyHandle) -> DiskRing {
        let pool = Rc::new(HashPool::new(hash_threads));
        pool.attach_notifier(notify.clone());
        DiskRing {
            mode: Mode::Inline {
                stores: Rc::new(RefCell::new(HashMap::new())),
                pool,
            },
            bridge: Bridge::new(notify),
            next_id: RefCell::new(1),
        }
    }

    /// Start the disk thread with `hash_threads` SHA-1 workers. `notify` is
    /// the engine ring's eventfd, rung on every completion; the engine calls
    /// [`DiskRing::drain`] when it fires.
    pub fn start(hash_threads: usize, notify: NotifyHandle) -> Result<DiskRing, Error> {
        // The disk thread's own eventfd must be created on that thread's ring?
        // No: an eventfd is a plain fd; only the read op must run there. It is
        // created here so the handle is available before the thread runs.
        let notifier = Notifier::new()?;
        let wake = notifier.handle();
        let shared = Arc::new(Shared {
            jobs: Mutex::new(VecDeque::new()),
            wake,
        });
        let shared2 = shared.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let thread = std::thread::Builder::new()
            .name("urt-disk".into())
            .spawn(move || run(shared2, notifier, hash_threads, ready_tx))
            .map_err(Error::Io)?;
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(Error::Uring(uring::Error::Unavailable(e))),
            Err(_) => {
                return Err(Error::Uring(uring::Error::Unavailable(
                    "disk thread died during start-up".into(),
                )));
            }
        }
        Ok(DiskRing {
            mode: Mode::Thread {
                shared,
                thread: Some(thread),
            },
            bridge: Bridge::new(notify),
            next_id: RefCell::new(1),
        })
    }

    /// Whether storage runs on its own thread.
    pub fn is_threaded(&self) -> bool {
        matches!(self.mode, Mode::Thread { .. })
    }

    fn submit(&self, job: Job) {
        match &self.mode {
            Mode::Thread { shared, .. } => {
                let was_empty = match shared.jobs.lock() {
                    Ok(mut q) => {
                        let e = q.is_empty();
                        q.push_back(job);
                        e
                    }
                    Err(_) => true,
                };
                if was_empty {
                    shared.wake.notify();
                }
            }
            Mode::Inline { stores, pool } => dispatch(stores, pool, job),
        }
    }

    /// Deliver queued completions to their futures (engine ring, on wakeup).
    pub fn drain(&self) -> usize {
        if let Mode::Inline { pool, .. } = &self.mode {
            pool.drain();
        }
        self.bridge.drain()
    }

    /// Open a store for `info` under `root` with initial file priorities
    /// (`None` = all default). The disk thread creates it before any later
    /// job of the same store runs.
    pub fn open(
        self: &Rc<Self>,
        info: Arc<Info>,
        root: PathBuf,
        prios: Option<Vec<u8>>,
    ) -> DiskStore {
        let id = {
            let mut n = self.next_id.borrow_mut();
            let v = *n;
            *n += 1;
            v
        };
        let n = info.files.len();
        let priorities: Vec<u8> = match &prios {
            Some(p) => info
                .files
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    if f.is_padding() {
                        0
                    } else {
                        p.get(i)
                            .copied()
                            .unwrap_or(crate::store::DEFAULT_PRIORITY)
                            .min(crate::store::MAX_PRIORITY)
                    }
                })
                .collect(),
            None => info
                .files
                .iter()
                .map(|f| {
                    if f.is_padding() {
                        0
                    } else {
                        crate::store::DEFAULT_PRIORITY
                    }
                })
                .collect(),
        };
        debug_assert_eq!(priorities.len(), n);
        self.submit(Job::Open {
            id,
            info: info.clone(),
            root: root.clone(),
            prios,
        });
        DiskStore {
            ring: self.clone(),
            id,
            info: info.clone(),
            root: RefCell::new(root),
            have: RefCell::new(Bitfield::new(info.piece_count())),
            priorities: RefCell::new(priorities),
        }
    }
}

impl Drop for DiskRing {
    fn drop(&mut self) {
        if let Mode::Thread { shared, thread } = &mut self.mode {
            if let Ok(mut q) = shared.jobs.lock() {
                q.push_back(Job::Shutdown);
            }
            shared.wake.notify();
            if let Some(t) = thread.take() {
                let _ = t.join();
            }
        }
    }
}

/// The engine-side handle to one torrent's storage on the disk thread.
pub struct DiskStore {
    ring: Rc<DiskRing>,
    id: u64,
    info: Arc<Info>,
    root: RefCell<PathBuf>,
    /// Mirror of the disk side's have-set.
    have: RefCell<Bitfield>,
    /// Mirror of the file priorities (per `info.files` entry).
    priorities: RefCell<Vec<u8>>,
}

impl DiskStore {
    fn ticket(&self) -> (ReplyFuture, Done) {
        match &self.ring.mode {
            Mode::Thread { .. } => {
                let (t, c) = self.ring.bridge.ticket();
                (ReplyFuture::Remote(t), Done::Remote(c))
            }
            Mode::Inline { .. } => {
                let slot = Arc::new(Mutex::new(LocalSlot {
                    value: None,
                    waker: None,
                }));
                (ReplyFuture::Local(slot.clone()), Done::Local(slot))
            }
        }
    }

    /// The torrent's info.
    pub fn info(&self) -> &Arc<Info> {
        &self.info
    }

    /// The save directory.
    pub fn root(&self) -> PathBuf {
        self.root.borrow().clone()
    }

    /// Path of the parts file (see [`Storage::parts_path`]).
    pub fn parts_path(&self) -> PathBuf {
        self.root
            .borrow()
            .join(format!(".{}.parts", self.info.name))
    }

    /// A snapshot of the verified have-set.
    pub fn have(&self) -> Bitfield {
        self.have.borrow().clone()
    }

    /// Whether piece `index` is verified-present.
    pub fn has_piece(&self, index: usize) -> bool {
        self.have.borrow().get(index)
    }

    /// Replace the have-set (validated resume data), disk side included.
    pub fn set_have(&self, have: Bitfield) {
        *self.have.borrow_mut() = have.clone();
        self.ring.submit(Job::SetHave { id: self.id, have });
    }

    /// Current file priorities (per `info.files` entry).
    pub fn file_priorities(&self) -> Vec<u8> {
        self.priorities.borrow().clone()
    }

    /// Piece priorities derived from the file priorities.
    pub fn piece_priorities(&self) -> Vec<u8> {
        layout::piece_priorities(&self.info, &self.priorities.borrow())
    }

    /// Bytes of file `index` covered by verified pieces.
    pub fn file_done(&self, index: usize) -> u64 {
        layout::file_done(&self.info, &self.have.borrow(), index)
    }

    /// Create the wanted files (see [`Storage::create_files`]).
    pub async fn create_files(&self) -> Result<(), Error> {
        let (t, done) = self.ticket();
        self.ring.submit(Job::CreateFiles { id: self.id, done });
        unit(t.await)
    }

    /// Write a block (see [`Storage::write_block`]). The job is queued
    /// **now** (not when the future is first polled), so a verify submitted
    /// right after is ordered behind it even if this future is awaited later
    /// or from another task.
    pub fn write_block(
        &self,
        piece: usize,
        offset: u32,
        data: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), Error>> + 'static {
        let (t, done) = self.ticket();
        self.ring.submit(Job::Write {
            id: self.id,
            piece,
            offset,
            data,
            done,
        });
        async move { unit(t.await) }
    }

    /// Read a block for upload (see [`Storage::read_block`]). Queued now, so
    /// several reads can be in flight while the caller awaits them in turn.
    pub fn read_block(
        &self,
        piece: usize,
        offset: u32,
        length: u32,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Error>> + 'static {
        let (t, done) = self.ticket();
        self.ring.submit(Job::ReadBlock {
            id: self.id,
            piece,
            offset,
            length,
            done,
        });
        async move {
            match t.await {
                Reply::Bytes(r) => r,
                other => Err(unexpected(other)),
            }
        }
    }

    /// Verify a piece against its hash; the have mirror follows the verdict.
    pub async fn verify_piece(&self, piece: usize) -> Result<bool, Error> {
        let (t, done) = self.ticket();
        self.ring.submit(Job::VerifyPiece {
            id: self.id,
            piece,
            done,
        });
        let r = match t.await {
            Reply::Bool(r) => r,
            other => Err(unexpected(other)),
        };
        if let Ok(ok) = &r {
            let mut have = self.have.borrow_mut();
            if *ok {
                have.set(piece);
            } else {
                have.clear(piece);
            }
        }
        r
    }

    /// Re-hash everything on disk; the have mirror is replaced by the result.
    pub async fn check_all(&self) -> Result<Bitfield, Error> {
        let (t, done) = self.ticket();
        self.ring.submit(Job::CheckAll { id: self.id, done });
        let r = match t.await {
            Reply::Bits(r) => r,
            other => Err(unexpected(other)),
        };
        if let Ok(h) = &r {
            *self.have.borrow_mut() = h.clone();
        }
        r
    }

    /// Change file priorities (see [`Storage::set_file_priorities`]).
    pub async fn set_file_priorities(&self, prios: &[u8]) -> Result<(), Error> {
        let (t, done) = self.ticket();
        self.ring.submit(Job::SetPriorities {
            id: self.id,
            prios: prios.to_vec(),
            done,
        });
        let r = unit(t.await);
        if r.is_ok() {
            let mut cur = self.priorities.borrow_mut();
            for (i, f) in self.info.files.iter().enumerate() {
                if f.is_padding() {
                    continue;
                }
                if let Some(p) = prios.get(i) {
                    cur[i] = (*p).min(crate::store::MAX_PRIORITY);
                }
            }
        }
        r
    }

    /// Move the content (see [`Storage::move_to`]).
    pub async fn move_to(&self, root: PathBuf) -> Result<(), Error> {
        let (t, done) = self.ticket();
        self.ring.submit(Job::MoveTo {
            id: self.id,
            root: root.clone(),
            done,
        });
        let r = unit(t.await);
        if r.is_ok() {
            *self.root.borrow_mut() = root;
        }
        r
    }

    /// `fsync` every open file.
    pub async fn sync_all(&self) -> Result<(), Error> {
        let (t, done) = self.ticket();
        self.ring.submit(Job::SyncAll { id: self.id, done });
        unit(t.await)
    }
}

impl Drop for DiskStore {
    fn drop(&mut self) {
        self.ring.submit(Job::Close { id: self.id });
    }
}

fn unit(r: Reply) -> Result<(), Error> {
    match r {
        Reply::Unit(r) => r,
        other => Err(unexpected(other)),
    }
}

fn unexpected(r: Reply) -> Error {
    let what = match r {
        Reply::Unit(_) => "unit",
        Reply::Bool(_) => "bool",
        Reply::Bytes(_) => "bytes",
        Reply::Bits(_) => "bitfield",
    };
    Error::Io(std::io::Error::other(format!(
        "disk thread answered with an unexpected reply ({what})"
    )))
}

/// Per-store state on the disk thread. Block reads and writes run
/// concurrently (the kernel overlaps them). Ordering rules keep the picture
/// consistent without stalling the pipeline:
///
/// - a `verify_piece` waits for every earlier write to *its* piece and holds
///   later reads/writes of that piece while it runs; other pieces flow;
/// - check-all, priorities, move, sync, set-have and create-files are full
///   barriers: they wait for everything before them and hold everything
///   after them.
struct Entry {
    storage: Rc<Storage>,
    /// Jobs not yet started, in submission order.
    queue: VecDeque<Job>,
    /// Jobs running right now.
    inflight: usize,
    /// Running reads/writes per piece.
    inflight_pieces: HashMap<usize, usize>,
    /// Pieces with a running verify.
    verifying: std::collections::HashSet<usize>,
    /// A full barrier is running.
    barrier: bool,
}

fn is_barrier(j: &Job) -> bool {
    matches!(
        j,
        Job::CheckAll { .. }
            | Job::SetHave { .. }
            | Job::SetPriorities { .. }
            | Job::MoveTo { .. }
            | Job::SyncAll { .. }
            | Job::CreateFiles { .. }
    )
}

/// The piece a read/write/verify touches.
fn job_piece(j: &Job) -> Option<usize> {
    match j {
        Job::Write { piece, .. }
        | Job::ReadBlock { piece, .. }
        | Job::VerifyPiece { piece, .. } => Some(*piece),
        _ => None,
    }
}

type Stores = Rc<RefCell<HashMap<u64, Rc<RefCell<Entry>>>>>;

/// The disk thread's body.
fn run(
    shared: Arc<Shared>,
    notifier: Notifier,
    hash_threads: usize,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let rt = match Runtime::with_defaults() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(e.to_string()));
            return;
        }
    };
    rt.block_on(async move {
        let pool = Rc::new(HashPool::new(hash_threads));
        pool.attach_notifier(notifier.handle());
        let _ = ready.send(Ok(()));
        let stores: Stores = Rc::new(RefCell::new(HashMap::new()));
        loop {
            if notifier.wait().await.is_err() {
                break;
            }
            pool.drain();
            let jobs: Vec<Job> = match shared.jobs.lock() {
                Ok(mut q) => q.drain(..).collect(),
                Err(_) => Vec::new(),
            };
            let mut shutdown = false;
            for job in jobs {
                if matches!(job, Job::Shutdown) {
                    shutdown = true;
                } else {
                    dispatch(&stores, &pool, job);
                }
            }
            if shutdown {
                break;
            }
        }
        // Let spawned jobs observe the end; nothing critical is in flight (the
        // engine awaits every job it cares about before shutting down).
        uring::sleep(std::time::Duration::from_millis(5)).await;
    });
}

/// Route one job on the ring that owns `stores`: open / close a store, or
/// queue the job on its store.
fn dispatch(stores: &Stores, pool: &Rc<HashPool>, job: Job) {
    match job {
        Job::Shutdown => {}
        Job::Open {
            id,
            info,
            root,
            prios,
        } => {
            let storage = Storage::new(info, root, pool.clone());
            if let Some(p) = prios {
                storage.init_priorities(&p);
            }
            stores.borrow_mut().insert(
                id,
                Rc::new(RefCell::new(Entry {
                    storage: Rc::new(storage),
                    queue: VecDeque::new(),
                    inflight: 0,
                    inflight_pieces: HashMap::new(),
                    verifying: std::collections::HashSet::new(),
                    barrier: false,
                })),
            );
        }
        Job::Close { id } => {
            stores.borrow_mut().remove(&id);
        }
        other => {
            let id = job_id(&other);
            let entry = stores.borrow().get(&id).cloned();
            match entry {
                Some(e) => enqueue(e, other),
                None => fail(other, "store is closed"),
            }
        }
    }
}

fn job_id(j: &Job) -> u64 {
    match j {
        Job::Open { id, .. }
        | Job::CreateFiles { id, .. }
        | Job::Write { id, .. }
        | Job::ReadBlock { id, .. }
        | Job::VerifyPiece { id, .. }
        | Job::CheckAll { id, .. }
        | Job::SetHave { id, .. }
        | Job::SetPriorities { id, .. }
        | Job::MoveTo { id, .. }
        | Job::SyncAll { id, .. }
        | Job::Close { id } => *id,
        Job::Shutdown => 0,
    }
}

/// Answer a job that cannot run.
fn fail(job: Job, why: &str) {
    let err = || Error::Io(std::io::Error::other(why.to_string()));
    match job {
        Job::CreateFiles { done, .. }
        | Job::Write { done, .. }
        | Job::SetPriorities { done, .. }
        | Job::MoveTo { done, .. }
        | Job::SyncAll { done, .. } => done.complete(Reply::Unit(Err(err()))),
        Job::ReadBlock { done, .. } => done.complete(Reply::Bytes(Err(err()))),
        Job::VerifyPiece { done, .. } => done.complete(Reply::Bool(Err(err()))),
        Job::CheckAll { done, .. } => done.complete(Reply::Bits(Err(err()))),
        Job::Open { .. } | Job::SetHave { .. } | Job::Close { .. } | Job::Shutdown => {}
    }
}

/// Queue a job on its store and start whatever may run.
fn enqueue(entry: Rc<RefCell<Entry>>, job: Job) {
    entry.borrow_mut().queue.push_back(job);
    pump(&entry);
}

/// Start every queued job the ordering rules allow, in submission order.
fn pump(entry: &Rc<RefCell<Entry>>) {
    let mut to_run = Vec::new();
    {
        let mut e = entry.borrow_mut();
        if e.barrier {
            return;
        }
        let mut i = 0;
        while i < e.queue.len() {
            let job = &e.queue[i];
            if is_barrier(job) {
                // Runs alone; nothing behind it may pass.
                if e.inflight == 0 && to_run.is_empty() {
                    e.barrier = true;
                    e.inflight += 1;
                    if let Some(j) = e.queue.remove(i) {
                        to_run.push(j);
                    }
                }
                break;
            }
            let runnable = match job {
                Job::VerifyPiece { piece, .. } => {
                    let p = *piece;
                    e.inflight_pieces.get(&p).copied().unwrap_or(0) == 0
                        && !e.verifying.contains(&p)
                        // An earlier write to this piece still queued? It sits
                        // before us and was not started, so it is a piece we
                        // must not overtake.
                        && !e.queue.iter().take(i).any(|q| job_piece(q) == Some(p))
                }
                Job::Write { piece, .. } | Job::ReadBlock { piece, .. } => {
                    !e.verifying.contains(piece)
                        && !e.queue.iter().take(i).any(|q| {
                            matches!(q, Job::VerifyPiece { .. }) && job_piece(q) == Some(*piece)
                        })
                }
                _ => true,
            };
            if runnable {
                let Some(job) = e.queue.remove(i) else { break };
                match &job {
                    Job::VerifyPiece { piece, .. } => {
                        e.verifying.insert(*piece);
                    }
                    Job::Write { piece, .. } | Job::ReadBlock { piece, .. } => {
                        *e.inflight_pieces.entry(*piece).or_insert(0) += 1;
                    }
                    _ => {}
                }
                e.inflight += 1;
                to_run.push(job);
            } else {
                i += 1;
            }
        }
    }
    for job in to_run {
        uring::spawn(run_job(entry.clone(), job));
    }
}

/// Run one job, then let the next ones through.
async fn run_job(entry: Rc<RefCell<Entry>>, job: Job) {
    let storage = entry.borrow().storage.clone();
    let barrier = is_barrier(&job);
    let piece = job_piece(&job);
    let verify = matches!(job, Job::VerifyPiece { .. });
    match job {
        Job::CreateFiles { done, .. } => {
            done.complete(Reply::Unit(storage.create_files().await));
        }
        Job::Write {
            piece,
            offset,
            data,
            done,
            ..
        } => {
            let r = storage
                .write_block(piece, offset, uring::Buffer::from_vec(data))
                .await
                .map(|_| ());
            done.complete(Reply::Unit(r));
        }
        Job::ReadBlock {
            piece,
            offset,
            length,
            done,
            ..
        } => {
            let r = storage
                .read_block(piece, offset, length)
                .await
                .map(|b| b.into_vec());
            done.complete(Reply::Bytes(r));
        }
        Job::VerifyPiece { piece, done, .. } => {
            done.complete(Reply::Bool(storage.verify_piece(piece).await));
        }
        Job::CheckAll { done, .. } => {
            done.complete(Reply::Bits(storage.check_all().await));
        }
        Job::SetHave { have, .. } => storage.set_have(have),
        Job::SetPriorities { prios, done, .. } => {
            done.complete(Reply::Unit(storage.set_file_priorities(&prios).await));
        }
        Job::MoveTo { root, done, .. } => {
            done.complete(Reply::Unit(storage.move_to(root).await));
        }
        Job::SyncAll { done, .. } => {
            done.complete(Reply::Unit(storage.sync_all().await));
        }
        Job::Open { .. } | Job::Close { .. } | Job::Shutdown => {}
    }
    {
        let mut e = entry.borrow_mut();
        e.inflight -= 1;
        if barrier {
            e.barrier = false;
        }
        if let Some(p) = piece {
            if verify {
                e.verifying.remove(&p);
            } else if let Some(n) = e.inflight_pieces.get_mut(&p) {
                *n -= 1;
                if *n == 0 {
                    e.inflight_pieces.remove(&p);
                }
            }
        }
    }
    pump(&entry);
}
