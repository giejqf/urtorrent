// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! urtorrent test harness: oracle, tracker and peer orchestration inside an
//! isolated network lab, plus capture / normalise / diff tooling.
//!
//! Nothing in here is part of the library. It deliberately re-implements the
//! small protocol pieces it needs (bencode, peer-wire framing) so that the
//! harness never trusts the code under test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    missing_docs
)]

pub mod bencode;
pub mod capture;
pub mod client;
pub mod fixtures;
pub mod http;
pub mod lab;
pub mod oracle;
pub mod peerwire;
pub mod scenario;
pub mod tap;
pub mod trackers;
pub mod transmission;
pub mod webapi;

/// Initialise tracing from `RUST_LOG` (default `info`).
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
