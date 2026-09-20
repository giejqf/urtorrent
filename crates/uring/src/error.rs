// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Errors for the uring layer.

use std::io;

/// Result alias for uring operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A uring-layer error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// io_uring could not be set up, or a required opcode is unavailable. There
    /// is no degraded mode (AGENTS.md rule 4).
    #[error("io_uring unavailable: {0}")]
    Unavailable(String),
    /// An I/O operation failed. The kernel returns negative errnos on CQEs;
    /// they are mapped to `io::Error` here.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The operation was cancelled (e.g. a timeout fired, or the future was
    /// dropped and later observed).
    #[error("operation cancelled")]
    Cancelled,
    /// A deadline elapsed before the operation completed.
    #[error("timed out")]
    TimedOut,
}

impl Error {
    /// The `io::ErrorKind`, if this wraps an I/O error.
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Error::Io(e) => Some(e.kind()),
            _ => None,
        }
    }

    /// Whether this is `EMSGSIZE` (a datagram larger than the path MTU with
    /// don't-fragment set).
    pub fn is_message_too_long(&self) -> bool {
        matches!(self, Error::Io(e) if e.raw_os_error() == Some(libc::EMSGSIZE))
    }
}
