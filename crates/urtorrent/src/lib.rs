// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! urtorrent: a BitTorrent library for Linux with every data-path operation on
//! io_uring, first-class IPv4 + IPv6, and wire behaviour that matches a pinned
//! qBittorrent build (see `AGENTS.md`).
//!
//! This crate is the stable facade: it re-exports the public API of the
//! engine (`session`) and the types callers need from `metainfo` and
//! `profile`.
//!
//! ```no_run
//! use urtorrent::{AddTorrent, Event, Session};
//!
//! # async fn demo() -> Result<(), urtorrent::Error> {
//! let session = Session::builder().listen_port(6881).build().await?;
//! let bytes = std::fs::read("example.torrent")?;
//! let id = session
//!     .add_torrent(AddTorrent::metainfo(bytes, "/srv/downloads"))
//!     .await?;
//! let mut events = session.events();
//! while let Some(ev) = events.recv().await {
//!     if let Event::TorrentFinished { id: done } = ev
//!         && done == id
//!     {
//!         break;
//!     }
//! }
//! session.shutdown().await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub use metainfo::{InfoHash, MagnetLink, Torrent};
pub use profile::Profile;
pub use session::{
    ActiveLimits, AddTorrent, EncryptionMode, Error, Event, EventStream, FileStatus, PeerInfo,
    PeerSource, PeerTransport, QueueMove, Session, SessionBuilder, SessionStats, TorrentId,
    TorrentSource, TorrentState, TorrentStatus, TrackerStatus, TransportPolicy,
};

/// Stream conveniences for [`EventStream`] (`tokio` feature).
#[cfg(feature = "tokio")]
pub use tokio_stream::StreamExt;
