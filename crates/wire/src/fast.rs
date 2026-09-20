// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 6 allowed-fast set generation: a deterministic set of `k` pieces a
//! peer may request while choked, derived from its address and the info-hash.
//! The address bytes that seed it are profile data ([`AllowedFastAddr`]): the
//! BEP masks IPv4 to the /24, libtorrent uses the full address (Q7).

use std::net::IpAddr;

use metainfo::InfoHash;
pub use profile::AllowedFastAddr;
use sha1::{Digest, Sha1};

/// Compute the allowed-fast set for `peer` over `piece_count` pieces.
pub fn allowed_fast_set(
    peer: IpAddr,
    info_hash: &InfoHash,
    piece_count: u32,
    k: u32,
    style: AllowedFastAddr,
) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    if piece_count == 0 || k == 0 {
        return out;
    }
    let k = k.min(piece_count) as usize;
    let mut x: Vec<u8> = match (peer, style) {
        (IpAddr::V4(a), AllowedFastAddr::Bep6Masked) => {
            (u32::from(a) & 0xffff_ff00).to_be_bytes().to_vec()
        }
        (IpAddr::V6(a), AllowedFastAddr::Bep6Masked) => a.octets()[..8].to_vec(),
        (IpAddr::V4(a), AllowedFastAddr::LibtorrentFull) => a.octets().to_vec(),
        (IpAddr::V6(a), AllowedFastAddr::LibtorrentFull) => a.octets().to_vec(),
    };
    x.extend_from_slice(info_hash);
    // Bounded: each round yields 5 indices; with duplicates the loop ends when
    // `k` distinct pieces are found, which always happens for k <= piece_count.
    let mut rounds = 0;
    while out.len() < k && rounds < 1024 {
        rounds += 1;
        let digest: [u8; 20] = Sha1::digest(&x).into();
        x = digest.to_vec();
        for chunk in digest.as_chunks::<4>().0 {
            if out.len() >= k {
                break;
            }
            let y = u32::from_be_bytes(*chunk);
            let index = y % piece_count;
            if !out.contains(&index) {
                out.push(index);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BEP 6 reference vector: ip 80.4.4.200, info hash all 0xAA, 1313
    /// pieces, k = 7 -> {1059, 431, 808, 1217, 287, 376, 1188}.
    #[test]
    fn bep6_reference_vector() {
        let m = AllowedFastAddr::Bep6Masked;
        let set = allowed_fast_set("80.4.4.200".parse().unwrap(), &[0xAA; 20], 1313, 7, m);
        assert_eq!(set, vec![1059, 431, 808, 1217, 287, 376, 1188]);
        // Same /24 -> same set; k = 9 extends the same sequence.
        let same = allowed_fast_set("80.4.4.1".parse().unwrap(), &[0xAA; 20], 1313, 7, m);
        assert_eq!(same, set);
        let nine = allowed_fast_set("80.4.4.200".parse().unwrap(), &[0xAA; 20], 1313, 9, m);
        assert_eq!(&nine[..7], &set[..]);
        assert_eq!(nine.len(), 9);
    }

    #[test]
    fn bounds() {
        let m = AllowedFastAddr::Bep6Masked;
        assert!(allowed_fast_set("10.0.0.1".parse().unwrap(), &[1; 20], 0, 5, m).is_empty());
        assert_eq!(
            allowed_fast_set("10.0.0.1".parse().unwrap(), &[1; 20], 3, 10, m).len(),
            3
        );
        let v6 = allowed_fast_set("fd77:8e::a".parse().unwrap(), &[1; 20], 64, 5, m);
        assert_eq!(v6.len(), 5);
        assert!(v6.iter().all(|&i| i < 64));
        let same64 = allowed_fast_set("fd77:8e::ffff".parse().unwrap(), &[1; 20], 64, 5, m);
        assert_eq!(same64, v6);
        // libtorrent style: the low byte matters.
        let f = AllowedFastAddr::LibtorrentFull;
        let a = allowed_fast_set("10.0.0.1".parse().unwrap(), &[1; 20], 64, 5, f);
        let b = allowed_fast_set("10.0.0.2".parse().unwrap(), &[1; 20], 64, 5, f);
        assert_ne!(a, b);
    }
}
