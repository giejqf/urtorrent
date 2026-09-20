// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Non-cryptographic randomness for the engine (peer-id tails, announce keys,
//! picker tie-breaks). Seeded from `/dev/urandom` at startup with a blocking
//! std read (one-time setup, off the critical path); SplitMix64 afterwards.

use std::cell::Cell;

/// SplitMix64.
pub struct Rng {
    state: Cell<u64>,
}

impl Rng {
    /// Seed from the OS (falls back to the clock if `/dev/urandom` is
    /// unavailable, which does not happen on Linux).
    pub fn from_os() -> Rng {
        let mut seed = [0u8; 8];
        let ok = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
            .is_ok();
        let mut s = u64::from_ne_bytes(seed);
        if !ok || s == 0 {
            s = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9E37_79B9_7F4A_7C15)
                ^ (std::process::id() as u64).rotate_left(32);
        }
        Rng {
            state: Cell::new(s),
        }
    }

    /// Next 64 random bits.
    pub fn next_u64(&self) -> u64 {
        let mut z = self.state.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
        self.state.set(z);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl profile::Rng for Rng {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
}

/// `profile::Rng` over a shared `&Rng` (the engine keeps one in an `Rc`).
pub struct RngRef<'a>(pub &'a Rng);

impl profile::Rng for RngRef<'_> {
    fn next_u32(&mut self) -> u32 {
        (self.0.next_u64() >> 32) as u32
    }
}
