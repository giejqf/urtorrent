// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Mainline DHT (BEP 5) node as a sans-IO state machine.
//!
//! Datagrams and `Instant`s in, datagrams and events out; randomness through
//! [`profile::Rng`]. The session owns the UDP sockets and timers (`uring`),
//! one [`Node`] per address family, and feeds discovered peers to torrents.
//!
//! Wire shape and behaviour follow the pinned oracle (libtorrent 2.0.14 in
//! qBittorrent 5.2.3) as captured in `testkit/golden/capture_dht`: KRPC
//! messages in [`krpc`], BEP 42 ids in [`id`], the routing table in
//! [`table`], lookups and the request loop in [`node`], the peer store in
//! [`storage`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod blocker;
pub mod id;
pub mod krpc;
pub mod node;
pub mod storage;
pub mod table;
pub mod token;

pub use id::NodeId;
pub use node::{Action, Config, LookupId, Node, Stats};
