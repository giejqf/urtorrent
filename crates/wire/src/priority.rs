// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 40 canonical peer priority: a rank both ends of a potential connection
//! compute identically, used to order connection attempts so a swarm's
//! connection graph converges. Ported from libtorrent's `peer_priority`
//! (`src/torrent_peer.cpp`, BSD-3; see `NOTICE`).

use std::net::{IpAddr, SocketAddr};

/// CRC32-C (Castagnoli), reflected, as BEP 40 specifies.
pub fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLY & mask);
        }
    }
    !crc
}

/// The canonical priority of the pair `(a, b)`; `None` when the families
/// differ (no meaningful rank). Symmetric in its arguments.
pub fn peer_priority(a: SocketAddr, b: SocketAddr) -> Option<u32> {
    if a.is_ipv4() != b.is_ipv4() {
        return None;
    }
    if a.ip() == b.ip() {
        let (p1, p2) = if a.port() > b.port() {
            (b.port(), a.port())
        } else {
            (a.port(), b.port())
        };
        let mut buf = [0u8; 4];
        buf[..2].copy_from_slice(&p1.to_be_bytes());
        buf[2..].copy_from_slice(&p2.to_be_bytes());
        return Some(crc32c(&buf));
    }
    let (lo, hi) = if a > b { (b, a) } else { (a, b) };
    match (lo.ip(), hi.ip()) {
        (IpAddr::V4(x), IpAddr::V4(y)) => {
            let mut b1 = x.octets();
            let mut b2 = y.octets();
            // Different /16: keep 2 bytes; same /16, different /24: keep 3;
            // same /24: keep all. Masked bytes drop to `& 0x55`.
            let mask: [u8; 4] = if b1[..2] != b2[..2] {
                [0xff, 0xff, 0x55, 0x55]
            } else if b1[..3] != b2[..3] {
                [0xff, 0xff, 0xff, 0x55]
            } else {
                [0xff; 4]
            };
            for i in 0..4 {
                b1[i] &= mask[i];
                b2[i] &= mask[i];
            }
            let mut buf = [0u8; 8];
            buf[..4].copy_from_slice(&b1);
            buf[4..].copy_from_slice(&b2);
            Some(crc32c(&buf))
        }
        (IpAddr::V6(x), IpAddr::V6(y)) => {
            let mut b1 = x.octets();
            let mut b2 = y.octets();
            // The first 6 bytes are never masked; masking starts after the
            // first differing byte (at the earliest, byte 6).
            let mut offset = usize::MAX;
            for i in 0..16 {
                if offset == usize::MAX && b1[i] != b2[i] {
                    offset = (i + 1).max(5);
                } else if i > offset {
                    b1[i] &= 0x55;
                    b2[i] &= 0x55;
                }
            }
            let mut buf = [0u8; 32];
            buf[..16].copy_from_slice(&b1);
            buf[16..].copy_from_slice(&b2);
            Some(crc32c(&buf))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_check_value() {
        // The CRC catalogue check value for CRC-32C.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    /// The two worked examples in BEP 40.
    #[test]
    fn bep40_vectors() {
        let a: SocketAddr = "123.213.32.10:0".parse().unwrap();
        let b: SocketAddr = "98.76.54.32:0".parse().unwrap();
        assert_eq!(crc32c(&hex("624C14007BD50000")), 0xEC2D_7224);
        assert_eq!(peer_priority(a, b), Some(0xEC2D_7224));
        assert_eq!(peer_priority(b, a), Some(0xEC2D_7224));
        let c: SocketAddr = "123.213.32.234:0".parse().unwrap();
        assert_eq!(crc32c(&hex("7BD5200A7BD520EA")), 0x9956_8189);
        assert_eq!(peer_priority(a, c), Some(0x9956_8189));
    }

    #[test]
    fn same_ip_uses_ports_and_families_must_match() {
        let a: SocketAddr = "10.0.0.1:6881".parse().unwrap();
        let b: SocketAddr = "10.0.0.1:51413".parse().unwrap();
        let mut buf = [0u8; 4];
        buf[..2].copy_from_slice(&6881u16.to_be_bytes());
        buf[2..].copy_from_slice(&51413u16.to_be_bytes());
        assert_eq!(peer_priority(a, b), Some(crc32c(&buf)));
        assert_eq!(peer_priority(a, b), peer_priority(b, a));
        let v6: SocketAddr = "[2001:db8::1]:6881".parse().unwrap();
        assert_eq!(peer_priority(a, v6), None);
        let v6b: SocketAddr = "[2001:db8:1::2]:6881".parse().unwrap();
        assert_eq!(peer_priority(v6, v6b), peer_priority(v6b, v6));
        assert!(peer_priority(v6, v6b).is_some());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
