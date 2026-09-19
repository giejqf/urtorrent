// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The io_uring reactor: a thread-per-core, completion-based executor for the
//! performance-critical I/O paths (peer sockets, torrent files, timers, UDP).
//! This is the only crate in the workspace that contains `unsafe` code
//! (AGENTS.md 9); every block carries a `// SAFETY:` note.
//!
//! # Design (ADR 0001)
//!
//! A [`Runtime`] owns one `io_uring` instance and a single-threaded task
//! executor. Async operations submit an SQE tagged with a slab key and await
//! the matching CQE. The executor *is* the reactor: when every task is parked
//! it calls `submit_and_wait`, reaps completions, wakes the parked tasks, and
//! runs them again. There is no epoll, no background thread pool, and no
//! fallback (rule 4) — construction fails hard if io_uring or a required
//! opcode is missing.
//!
//! # Buffer ownership (the core safety rule)
//!
//! A buffer handed to the kernel is owned by the reactor until its CQE
//! arrives. An operation future owns its buffer; if the future is dropped
//! before completion, the buffer is *moved into the reactor* and an
//! `ASYNC_CANCEL` is submitted, so the kernel never writes into freed memory.
//! The buffer is reclaimed when the (possibly cancelled) CQE finally arrives.
//! No async operation takes `&mut [u8]`; all take owned [`Buffer`]s.

#![cfg_attr(not(target_os = "linux"), allow(unused))]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(clippy::missing_safety_doc)] // SAFETY comments are used instead.

// Enforcement #1 (AGENTS.md 5.3): this crate is Linux-only, by construction.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "the `uring` crate requires Linux io_uring; there is no fallback (AGENTS.md rule 4)"
);

mod bufpool;
mod error;
mod fs;
mod net;
mod probe;
mod reactor;
mod runtime;
mod timer;

pub use bufpool::{Buffer, BufferPool};
pub use error::{Error, Result};
pub use fs::File;
pub use net::{TcpListener, TcpStream, UdpSocket};
pub use probe::{Features, probe};
pub use runtime::{JoinHandle, Runtime, spawn};
pub use timer::{sleep, timeout};
