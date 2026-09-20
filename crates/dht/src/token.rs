// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Token derivation follows libtorrent-rasterbar's node.cpp (BSD-3-Clause),
// Copyright (c) Arvid Norberg and contributors; see NOTICE.

//! Write tokens for `announce_peer`: `sha1(address text || secret ||
//! info_hash)[..4]`, with two secrets so a token stays valid across one
//! rotation (every 5 minutes).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use profile::Rng;

use crate::id::NodeId;

/// Token length on the wire (libtorrent `write_token_size`).
pub const TOKEN_LEN: usize = 4;
/// How often the write key rotates (libtorrent `key_refresh`).
pub const ROTATE_EVERY: Duration = Duration::from_secs(5 * 60);

/// The token secrets.
#[derive(Debug, Clone)]
pub struct Tokens {
    secret: [[u8; 20]; 2],
    rotated: Instant,
}

impl Tokens {
    /// Fresh secrets.
    pub fn new(now: Instant, rng: &mut dyn Rng) -> Tokens {
        let mut t = Tokens {
            secret: [[0; 20]; 2],
            rotated: now,
        };
        fill(&mut t.secret[0], rng);
        fill(&mut t.secret[1], rng);
        t
    }

    /// Rotate if due; returns whether it did.
    pub fn tick(&mut self, now: Instant, rng: &mut dyn Rng) -> bool {
        if now.duration_since(self.rotated) < ROTATE_EVERY {
            return false;
        }
        self.secret[1] = self.secret[0];
        fill(&mut self.secret[0], rng);
        self.rotated = now;
        true
    }

    fn derive(secret: &[u8; 20], ip: IpAddr, info_hash: &NodeId) -> [u8; TOKEN_LEN] {
        let mut h = <sha1::Sha1 as sha1::Digest>::new();
        // libtorrent hashes the address's text form.
        sha1::Digest::update(&mut h, ip.to_string().as_bytes());
        sha1::Digest::update(&mut h, secret);
        sha1::Digest::update(&mut h, info_hash.0);
        let d = sha1::Digest::finalize(h);
        let mut t = [0u8; TOKEN_LEN];
        t.copy_from_slice(&d[..TOKEN_LEN]);
        t
    }

    /// The token to hand `ip` for `info_hash`.
    pub fn generate(&self, ip: IpAddr, info_hash: &NodeId) -> [u8; TOKEN_LEN] {
        Self::derive(&self.secret[0], ip, info_hash)
    }

    /// Whether `token` is one we issued to `ip` for `info_hash` recently.
    pub fn verify(&self, token: &[u8], ip: IpAddr, info_hash: &NodeId) -> bool {
        token.len() == TOKEN_LEN
            && (token == Self::derive(&self.secret[0], ip, info_hash)
                || token == Self::derive(&self.secret[1], ip, info_hash))
    }
}

fn fill(out: &mut [u8; 20], rng: &mut dyn Rng) {
    for chunk in out.chunks_mut(4) {
        let r = rng.next_u32().to_be_bytes();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u64);
    impl Rng for Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (self.0 >> 33) as u32
        }
    }

    #[test]
    fn tokens_survive_one_rotation() {
        let t0 = Instant::now();
        let mut rng = Lcg(1);
        let mut t = Tokens::new(t0, &mut rng);
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let ih = NodeId([7; 20]);
        let tok = t.generate(ip, &ih);
        assert!(t.verify(&tok, ip, &ih));
        assert!(!t.verify(&tok, "10.1.2.4".parse().unwrap(), &ih));
        assert!(!t.verify(&tok, ip, &NodeId([8; 20])));
        assert!(!t.verify(&tok[..3], ip, &ih));
        assert!(!t.tick(t0 + Duration::from_secs(10), &mut rng));
        assert!(t.tick(t0 + ROTATE_EVERY, &mut rng));
        assert!(t.verify(&tok, ip, &ih), "still valid after one rotation");
        assert!(t.tick(t0 + ROTATE_EVERY * 2, &mut rng));
        assert!(!t.verify(&tok, ip, &ih), "gone after two");
    }
}
