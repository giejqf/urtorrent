// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Torrent file I/O over io_uring. `open` (one-time setup) uses blocking libc;
//! `read`/`write`/`fsync`/`fallocate`/`close` go through the ring. All async
//! ops take and return owned [`Buffer`]s.

use std::ffi::CString;
use std::io;
use std::marker::PhantomData;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::rc::Rc;

use crate::bufpool::Buffer;
use crate::error::Result;
use crate::reactor::{
    self, close_fd_detached, fallocate, fsync, ftruncate, read_at, read_range_at, write_at,
    write_range_at,
};

/// A torrent file opened for positional (offset-based) I/O.
pub struct File {
    fd: RawFd,
    _not_send: PhantomData<Rc<()>>,
}

impl File {
    /// Open `path` for read+write through the ring (`IORING_OP_OPENAT`),
    /// creating it (parent dirs are the caller's responsibility). Sparse by
    /// default.
    pub async fn open_rw(path: &Path) -> Result<File> {
        Self::open_with(path, libc::O_RDWR | libc::O_CREAT).await
    }

    /// Open `path` read-only through the ring.
    pub async fn open_ro(path: &Path) -> Result<File> {
        Self::open_with(path, libc::O_RDONLY).await
    }

    async fn open_with(path: &Path, flags: libc::c_int) -> Result<File> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        let fd = reactor::openat(c, flags | libc::O_CLOEXEC, 0o644).await?;
        Ok(File {
            fd,
            _not_send: PhantomData,
        })
    }

    /// The raw fd (tests / diagnostics).
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Read into `buf` (sized to its length) starting at `offset`. Returns the
    /// bytes read and the buffer truncated to that length.
    pub async fn read_at(&self, offset: u64, buf: Buffer) -> (Result<u32>, Buffer) {
        let (r, b) = read_at(self.fd, offset, buf).await;
        (r.map_err(Into::into), b)
    }

    /// Read exactly `buf.len()` bytes at `offset`, resubmitting short reads.
    /// Errors with `UnexpectedEof` if the file ends first.
    pub async fn read_exact_at(&self, offset: u64, buf: Buffer) -> Result<Buffer> {
        let want = buf.len();
        self.read_exact_into(offset, buf, 0, want).await
    }

    /// Read exactly `len` bytes at `offset` into `buf[start..start + len]`
    /// (the rest of `buf` is untouched), resubmitting short reads. Lets a
    /// caller assemble a multi-file range in one buffer without temporaries.
    pub async fn read_exact_into(
        &self,
        offset: u64,
        buf: Buffer,
        start: usize,
        len: usize,
    ) -> Result<Buffer> {
        if start + len > buf.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let mut buf = buf;
        let mut got = 0usize;
        while got < len {
            let (r, b) =
                read_range_at(self.fd, offset + got as u64, buf, start + got, len - got).await;
            buf = b;
            match r {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Ok(n) => got += n as usize,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(buf)
    }

    /// Write `buf` at `offset`. Returns bytes written and the buffer back.
    pub async fn write_at(&self, offset: u64, buf: Buffer) -> (Result<u32>, Buffer) {
        let (r, b) = write_at(self.fd, offset, buf).await;
        (r.map_err(Into::into), b)
    }

    /// Write all of `buf` at `offset`, resubmitting short writes.
    pub async fn write_all_at(&self, offset: u64, buf: Buffer) -> Result<Buffer> {
        let total = buf.len();
        self.write_range_all_at(offset, buf, 0, total).await
    }

    /// Write `buf[start..start + len]` at `offset`, resubmitting short
    /// writes; the buffer comes back untouched (no copy of a payload that
    /// sits behind a header).
    pub async fn write_range_all_at(
        &self,
        offset: u64,
        buf: Buffer,
        start: usize,
        len: usize,
    ) -> Result<Buffer> {
        let mut buf = buf;
        let mut done = 0usize;
        while done < len {
            let (r, b) =
                write_range_at(self.fd, offset + done as u64, buf, start + done, len - done).await;
            buf = b;
            match r {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => done += n as usize,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(buf)
    }

    /// Preallocate `len` bytes from `offset` (`fallocate`).
    pub async fn allocate(&self, offset: u64, len: u64) -> Result<()> {
        fallocate(self.fd, offset, len).await.map_err(Into::into)
    }

    /// Set the file's length (`ftruncate`): through the ring on kernels
    /// with `IORING_OP_FTRUNCATE` (6.9+), else the plain syscall (one-time
    /// file setup, off the data path; AGENTS.md 5.3).
    pub async fn set_len(&self, len: u64) -> Result<()> {
        static VIA_RING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let via_ring = *VIA_RING.get_or_init(|| crate::probe().is_ok_and(|f| f.ftruncate));
        if via_ring {
            return ftruncate(self.fd, len).await.map_err(Into::into);
        }
        // SAFETY: plain syscall on a valid fd; the result is checked.
        let r = unsafe { libc::ftruncate(self.fd, len as libc::off_t) };
        if r < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// Reserve the file's full `len` bytes up front: `fallocate`, with a
    /// plain `ftruncate` (sparse; the size is right, the blocks are not
    /// reserved) where the filesystem does not support allocation. Running
    /// out of space is an error either way: that is what preallocation is
    /// for.
    pub async fn reserve(&self, len: u64) -> Result<bool> {
        match self.allocate(0, len).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_unsupported() => {
                self.set_len(len).await?;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// `fsync` — flush data and metadata.
    pub async fn sync_all(&self) -> Result<()> {
        fsync(self.fd, false).await.map_err(Into::into)
    }

    /// `fdatasync` — flush data only.
    pub async fn sync_data(&self) -> Result<()> {
        fsync(self.fd, true).await.map_err(Into::into)
    }

    /// Graceful close through the ring (awaits the CQE).
    pub async fn close(self) -> Result<()> {
        let fd = self.fd;
        std::mem::forget(self);
        reactor::close(fd).await.map_err(Into::into)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        close_fd_detached(self.fd);
    }
}
