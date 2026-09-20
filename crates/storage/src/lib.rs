// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Disk storage for urtorrent: on-disk layout, preallocation, the hashing
//! pipeline, the piece read/write/verify path, and crash-safe resume data.
//!
//! Storage is one of the three crates permitted to perform I/O; its piece I/O
//! runs on the `uring` reactor of a dedicated disk thread ([`DiskRing`],
//! reached from the engine through [`DiskStore`] handles), while SHA-1
//! hashing runs on a dedicated [`HashPool`] off both reactors (AGENTS.md 5.3). Resume data
//! is written atomically (temp + fsync + rename + dir fsync) so a `kill -9`
//! never yields a torrent that claims pieces it does not have (5.4).
//!
//! Accounting is truthful (AGENTS.md rule 1): the have-bitfield only ever
//! reflects pieces whose bytes on disk hash to the expected value, and resume
//! data records real `uploaded`/`downloaded` byte counts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod disk;
mod hash;
pub mod layout;
mod resume;
mod store;

pub use disk::{DiskRing, DiskStore, Reply};
pub use hash::{HashPool, sha1};
pub use metainfo::Bitfield;
pub use resume::{FORMAT_VERSION, ResumeData};
pub use store::{DEFAULT_PRIORITY, MAX_PRIORITY, Storage};

/// A storage error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An underlying I/O error (uring or std).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A uring operation failed.
    #[error("uring: {0}")]
    Uring(#[from] uring::Error),
    /// A piece/offset/length was out of range for the torrent.
    #[error("out of range")]
    OutOfRange,
    /// Resume data was missing, malformed, or inconsistent.
    #[error("resume data: {0}")]
    Resume(&'static str),
}
