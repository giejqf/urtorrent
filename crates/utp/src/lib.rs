// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! uTP (BEP 29) as a sans-IO state machine: the header codec, one
//! connection ([`Socket`]) with LEDBAT congestion control, retransmission,
//! selective acks, path-MTU discovery and nagle, and the per-port
//! connection table ([`Manager`]). No sockets, no clocks, no randomness
//! except through the arguments (`Instant`, [`profile::Rng`]).
//!
//! The behaviour is a port of libtorrent 2.0's `utp_stream` (BSD-3-Clause,
//! see NOTICE), which is what the oracle speaks; wire shapes (SYN fields,
//! first-packet sequence, extension use, window and MTU probing) were
//! checked against captures of it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod header;
pub mod history;
pub mod manager;
pub mod packet_buffer;
pub mod socket;

pub use header::{Header, PacketType, is_utp};
pub use manager::{Incoming, Key, Manager};
pub use socket::{Clock, Config, Error, Notify, Outgoing, Socket, State, Stats};
