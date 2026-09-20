// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Cross-thread wakeups into the ring. The executor's wakers are thread-local
//! (`Rc`-based) and must never be called from another thread; instead, other
//! threads (the public-API side, the hash pool, the DNS helper) write to an
//! `eventfd` whose read completion arrives on the ring like any other CQE.
//! The ring thread keeps one [`Notifier::wait`] outstanding and, when it
//! completes, drains whatever queues the other threads filled.
//!
//! The eventfd itself is not a socket or a torrent file, and the write from
//! the notifying thread is a single `write(2)` off the critical path.

use std::io;
use std::os::fd::RawFd;
use std::sync::Arc;

use io_uring::{opcode, types};

use crate::bufpool::Buffer;
use crate::error::Result;
use crate::reactor::{Op, cqe_result};

struct EventFd(RawFd);

impl Drop for EventFd {
    fn drop(&mut self) {
        // SAFETY: we own the fd and close it exactly once. Plain close is fine:
        // the last owner may be any thread, and this fd is not on the data path.
        unsafe { libc::close(self.0) };
    }
}

/// The ring-thread end of a wakeup channel.
pub struct Notifier {
    fd: Arc<EventFd>,
}

/// A `Send + Sync` handle that wakes the ring thread.
#[derive(Clone)]
pub struct NotifyHandle {
    fd: Arc<EventFd>,
}

impl Notifier {
    /// Create an eventfd-backed notifier.
    pub fn new() -> Result<Notifier> {
        // SAFETY: eventfd creation with valid flags; the result is checked.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Notifier {
            fd: Arc::new(EventFd(fd)),
        })
    }

    /// A handle other threads use to wake this notifier.
    pub fn handle(&self) -> NotifyHandle {
        NotifyHandle {
            fd: self.fd.clone(),
        }
    }

    /// Wait (through the ring) until at least one `notify()` happened since
    /// the last wait. Returns the number of notifications coalesced.
    pub async fn wait(&self) -> Result<u64> {
        let fd = self.fd.0;
        let (res, buf) = Op::submit(Buffer::from_vec(vec![0u8; 8]), |b, ud| {
            opcode::Read::new(types::Fd(fd), b.as_mut_ptr(), 8)
                .build()
                .user_data(ud)
        })
        .await;
        let n = cqe_result(res)?;
        if n as usize != 8 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short eventfd read").into());
        }
        let bytes: [u8; 8] = buf.as_slice()[..8]
            .try_into()
            .map_err(|_| io::Error::other("eventfd read size"))?;
        Ok(u64::from_ne_bytes(bytes))
    }
}

impl NotifyHandle {
    /// Wake the ring thread. Never blocks; a saturated counter is impossible in
    /// practice (2^64 - 1 pending notifications).
    pub fn notify(&self) {
        let one = 1u64.to_ne_bytes();
        // SAFETY: valid fd and an 8-byte buffer, as eventfd requires. EAGAIN
        // (counter about to overflow) is ignored: the reader is already woken.
        unsafe {
            libc::write(self.fd.0, one.as_ptr() as *const libc::c_void, 8);
        }
    }
}

impl std::fmt::Debug for NotifyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NotifyHandle(fd {})", self.fd.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Runtime;

    #[test]
    fn wake_from_another_thread() {
        let rt = Runtime::with_defaults().unwrap();
        let n = Notifier::new().unwrap();
        let h = n.handle();
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            h.notify();
            h.notify();
        });
        let count = rt.block_on(async move { n.wait().await.unwrap() });
        t.join().unwrap();
        assert!(count >= 1);
    }

    #[test]
    fn notify_before_wait_is_not_lost() {
        let rt = Runtime::with_defaults().unwrap();
        let n = Notifier::new().unwrap();
        n.handle().notify();
        let count = rt.block_on(async move { n.wait().await.unwrap() });
        assert_eq!(count, 1);
    }
}
