// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Method selection and padding follow libtorrent-rasterbar (BSD-3-Clause),
// Copyright (c) Arvid Norberg and contributors; see NOTICE.

//! Message Stream Encryption ("protocol encryption"): the DH key exchange,
//! the obfuscated handshake and the RC4 stream cipher, as pure state
//! machines. Bytes in via `receive`, bytes out via `take_outbound`; no
//! sockets, no clocks, randomness via [`profile::Rng`] plus caller-supplied
//! key material (`Initiator::new` / `Responder::new` take 20 random bytes for
//! the DH private key, which the session draws from `getrandom`).
//!
//! Wire shape follows libtorrent 2.0.14 (the oracle): pads A/B/C/D are
//! `random(512)` (0..=512 bytes, uniform), the initiator's IA is the 68-byte
//! BitTorrent handshake, `crypto_provide` is the allowed level (1 plaintext,
//! 2 RC4, 3 both) and the responder's `crypto_select` keeps the least
//! significant allowed bit unless `prefer_rc4`. Both RC4 keystreams discard
//! their first 1024 bytes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod dh;
mod handshake;
mod rc4s;

pub use dh::{DH_KEY_LEN, dh_public, dh_secret};
pub use handshake::{
    CryptoMethod, Initiator, MAX_PAD, Observed, Outcome, Responder, SKEY_UNKNOWN, SkeyIndex,
    SkeyLookup, allowed_mask, req2_hash, select,
};
pub use rc4s::Rc4Stream;

/// An MSE error: the peer's handshake is malformed or incompatible; the
/// connection must be closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The verification constant never appeared where it should.
    #[error("mse: sync failed")]
    Sync,
    /// The peer's `req2` hash matched none of our torrents.
    #[error("mse: unknown stream key")]
    UnknownSkey,
    /// The peer offered / selected no method we allow.
    #[error("mse: no acceptable crypto method")]
    NoMethod,
    /// A length field was out of range.
    #[error("mse: invalid length")]
    Length,
}
