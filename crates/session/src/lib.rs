// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The engine and its public API (AGENTS.md 5.6).
//!
//! [`Session::builder`]`.build().await` spawns the engine's own threads: the
//! network ring (an io_uring [`uring::Runtime`] on which peers, trackers, disk
//! I/O and timers run), the SHA-1 hash pool, and a DNS helper. It returns a
//! [`Session`] handle that is `Clone + Send + Sync`. Every operation is an
//! `async fn` that sends a command over a `tokio::sync::mpsc` channel and
//! awaits a `tokio::sync::oneshot` reply; those primitives never touch a
//! reactor, so the `await` completes on whatever runtime the caller uses.
//! Events arrive on [`Session::events`]; slow consumers see
//! [`Event::Lagged`] rather than blocking the engine.
//!
//! Boundary rule: nothing tokio owns is ever handed to `uring`, and nothing
//! `uring` owns is ever polled by tokio. The caller's runtime never polls an
//! engine future; the engine thread is woken through an eventfd.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod api;
mod engine;

pub use api::{
    AddTorrent, EncryptionMode, Event, EventStream, PeerInfo, PeerSource, Session, SessionBuilder,
    SessionStats, TorrentId, TorrentSource, TorrentState, TorrentStatus, TrackerStatus,
};
pub use profile::Profile;

/// A session-level error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// io_uring (or a required opcode) is unavailable; there is no fallback.
    #[error("io_uring unavailable: {0}")]
    Unavailable(String),
    /// The engine is shut down (or shutting down).
    #[error("session is shut down")]
    Shutdown,
    /// The torrent id is unknown.
    #[error("no such torrent")]
    NoSuchTorrent,
    /// The torrent is already in the session.
    #[error("torrent already added")]
    Duplicate,
    /// Invalid metainfo or magnet link.
    #[error("metainfo: {0}")]
    Metainfo(String),
    /// A feature that is not in this release.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// An I/O error (listen socket, storage, resume file).
    #[error("io: {0}")]
    Io(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e.to_string())
    }
}

impl From<uring::Error> for Error {
    fn from(e: uring::Error) -> Error {
        match e {
            uring::Error::Unavailable(s) => Error::Unavailable(s),
            other => Error::Io(other.to_string()),
        }
    }
}

impl From<storage::Error> for Error {
    fn from(e: storage::Error) -> Error {
        Error::Io(e.to_string())
    }
}
