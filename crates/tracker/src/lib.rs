// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Tracker protocol as pure functions and state machines: HTTP announce
//! request building (BEP 3, with the parameter set, order and encoding owned by
//! the [`profile::Profile`]), announce response parsing (BEP 3 / BEP 23 compact
//! peers / BEP 7 `peers6`), an HTTP/1.1 response framer with gzip, and the
//! per-torrent [`Announcer`] that implements multi-tracker tiers (BEP 12 with
//! libtorrent semantics), event sequencing (`started` / `completed` exactly
//! once / `stopped`) and failure backoff over an injected clock.
//!
//! Also: the BEP 15 UDP tracker packets and connection-id cache ([`udp`]) and
//! BEP 48 scrape ([`scrape`]). Sans-IO (AGENTS.md 5.2): no sockets, no DNS,
//! no clocks.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod announce;
mod announcer;
pub mod http;
pub mod scrape;
pub mod udp;
mod url;

pub use announce::{AnnounceEvent, AnnounceRequest, AnnounceResponse, MAX_PEERS};
pub use announcer::{AnnounceJob, Announcer, TrackerSnapshot};
pub use url::Url;

/// A tracker-layer error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The announce URL could not be parsed or has an unsupported scheme.
    #[error("bad tracker url: {0}")]
    Url(&'static str),
    /// The HTTP response was malformed or too large.
    #[error("http: {0}")]
    Http(&'static str),
    /// The response body was not a valid announce response.
    #[error("bad announce response: {0}")]
    Response(&'static str),
    /// The tracker returned `failure reason`.
    #[error("tracker failure: {0}")]
    Failure(String),
    /// The HTTP status was not 2xx (after redirects).
    #[error("http status {0}")]
    Status(u16),
}
