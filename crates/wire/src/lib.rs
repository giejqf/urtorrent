// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The BitTorrent peer-wire protocol as a pure state machine: handshake
//! (BEP 3), message framing and codec (BEP 3 + BEP 6 fast extension), the LTEP
//! extended handshake (BEP 10), and a per-connection [`Connection`] that
//! validates the peer's behaviour, tracks choke/interest and request state, and
//! tells the caller what happened.
//!
//! Sans-IO (AGENTS.md 5.2): bytes in via [`Connection::receive`], bytes out via
//! [`Connection::take_outbound`]; no sockets, no clocks. Everything the wire
//! delivers is untrusted: every length is bounded, every index range-checked,
//! and a violation is a [`Error::Protocol`] the caller turns into a disconnect.
//! Identity (reserved bits, LTEP `m`, first-messages order) comes from
//! [`profile::Profile`], never from constants here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod conn;
pub mod ext;
mod fast;
mod framer;
mod handshake;
pub mod identify;
mod ltep;
mod message;
mod priority;

pub use conn::{Connection, ConnectionParams, Event, PeerHave, Role};
pub use fast::allowed_fast_set;
pub use framer::{Frame, Framer, MAX_FRAME};
pub use handshake::{HANDSHAKE_LEN, Handshake};
pub use ltep::{EXT_HANDSHAKE_ID, ExtHandshake, MAX_EXT_PAYLOAD};
pub use message::{Block, MAX_BITFIELD, MAX_BLOCK, Message, Request};
pub use priority::{crc32c, peer_priority};

/// A peer-wire error. `Protocol` means the peer misbehaved and the connection
/// must be closed; nothing here is recoverable in place.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The peer violated the protocol (bad handshake, malformed message,
    /// out-of-range index, message not allowed in this state, ...).
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// The peer's handshake carried a different info-hash than expected.
    #[error("info-hash mismatch")]
    InfoHashMismatch,
    /// A frame or buffer exceeded its bound (remote input must never OOM us).
    #[error("frame too large")]
    TooLarge,
}
