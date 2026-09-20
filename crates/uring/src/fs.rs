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
use crate::reactor::{self, close_fd_detached, fallocate, fsync, read_at, write_at};

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
        let mut data = buf.into_vec();
        let mut got = 0usize;
        while got < want {
            let chunk = Buffer::from_vec(vec![0u8; want - got]);
            let (r, filled) = read_at(self.fd, offset + got as u64, chunk).await;
            match r {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Ok(n) => {
                    data[got..got + n as usize].copy_from_slice(filled.as_slice());
                    got += n as usize;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Buffer::from_vec(data))
    }

    /// Write `buf` at `offset`. Returns bytes written and the buffer back.
    pub async fn write_at(&self, offset: u64, buf: Buffer) -> (Result<u32>, Buffer) {
        let (r, b) = write_at(self.fd, offset, buf).await;
        (r.map_err(Into::into), b)
    }

    /// Write all of `buf` at `offset`, resubmitting short writes.
    pub async fn write_all_at(&self, offset: u64, buf: Buffer) -> Result<Buffer> {
        let total = buf.len();
        let mut data = buf.into_vec();
        let mut done = 0usize;
        while done < total {
            let chunk = Buffer::from_vec(data[done..].to_vec());
            let (r, _b) = write_at(self.fd, offset + done as u64, chunk).await;
            match r {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => done += n as usize,
                Err(e) => return Err(e.into()),
            }
        }
        data.truncate(total);
        Ok(Buffer::from_vec(data))
    }

    /// Preallocate `len` bytes from `offset` (`fallocate`).
    pub async fn allocate(&self, offset: u64, len: u64) -> Result<()> {
        fallocate(self.fd, offset, len).await.map_err(Into::into)
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
