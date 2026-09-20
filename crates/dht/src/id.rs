// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Node-id generation and verification (BEP 42) and the secret-id scheme
// follow libtorrent-rasterbar (BSD-3-Clause), Copyright (c) Arvid Norberg and
// contributors; see NOTICE.

//! 160-bit node ids: XOR distance, the BEP 42 derivation from an external
//! address, and libtorrent's "secret" ids (lookup targets whose low bytes
//! prove we generated them).

use std::net::IpAddr;

use profile::Rng;

/// A 160-bit DHT node id (also the type of lookup targets and info-hashes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct NodeId(pub [u8; 20]);

impl NodeId {
    /// All zero (libtorrent's "no id yet").
    pub const ZERO: NodeId = NodeId([0; 20]);

    /// A uniformly random id.
    pub fn random(rng: &mut dyn Rng) -> NodeId {
        let mut id = [0u8; 20];
        fill_random(&mut id, rng);
        NodeId(id)
    }

    /// XOR distance to `other`.
    pub fn distance(&self, other: &NodeId) -> NodeId {
        let mut d = [0u8; 20];
        for (o, (a, b)) in d.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *o = a ^ b;
        }
        NodeId(d)
    }

    /// `max(159 - leading zero bits of the distance, 0)`: the bucket index a
    /// node at that distance falls into (libtorrent `distance_exp`).
    pub fn distance_exp(&self, other: &NodeId) -> u32 {
        let d = self.distance(other);
        let lz = d.leading_zeros();
        159u32.saturating_sub(lz)
    }

    /// Leading zero bits.
    pub fn leading_zeros(&self) -> u32 {
        let mut n = 0;
        for b in self.0 {
            if b == 0 {
                n += 8;
            } else {
                n += b.leading_zeros();
                break;
            }
        }
        n
    }

    /// Whether every byte is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 20]
    }

    /// Lowercase hex.
    pub fn hex(&self) -> String {
        bencode::hex(&self.0)
    }

    /// Bit `i` (0 = most significant).
    pub fn bit(&self, i: usize) -> bool {
        self.0[i / 8] & (0x80 >> (i % 8)) != 0
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({})", self.hex())
    }
}

impl From<[u8; 20]> for NodeId {
    fn from(b: [u8; 20]) -> NodeId {
        NodeId(b)
    }
}

/// `n1 ^ ref < n2 ^ ref`: `n1` is closer to `ref` than `n2` (libtorrent
/// `compare_ref`).
pub fn closer(n1: &NodeId, n2: &NodeId, reference: &NodeId) -> std::cmp::Ordering {
    n1.distance(reference).cmp(&n2.distance(reference))
}

fn fill_random(out: &mut [u8], rng: &mut dyn Rng) {
    for chunk in out.chunks_mut(4) {
        let r = rng.next_u32().to_be_bytes();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
}

/// CRC-32C (Castagnoli), as BEP 42 requires.
pub fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// BEP 42: the id prefix an address must carry, with random rand `r`
/// (libtorrent `generate_id_impl`). The returned id has the 21 checked bits
/// set from the CRC, random middle bytes, and `r & 0xff` in the last byte.
fn generate_id_impl(ip: IpAddr, r: u32, rng: &mut dyn Rng) -> NodeId {
    const V4MASK: [u8; 4] = [0x03, 0x0f, 0x3f, 0xff];
    const V6MASK: [u8; 8] = [0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];
    let mut buf = [0u8; 8];
    let n = match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            for i in 0..4 {
                buf[i] = o[i] & V4MASK[i];
            }
            4
        }
        IpAddr::V6(a) => {
            let o = a.octets();
            for i in 0..8 {
                buf[i] = o[i] & V6MASK[i];
            }
            8
        }
    };
    buf[0] |= ((r & 0x7) << 5) as u8;
    let c = crc32c(&buf[..n]);
    let mut id = [0u8; 20];
    id[0] = (c >> 24) as u8;
    id[1] = (c >> 16) as u8;
    id[2] = (((c >> 8) & 0xf8) as u8) | (rng.below(8) as u8);
    for b in &mut id[3..19] {
        *b = rng.below(256) as u8;
    }
    id[19] = r as u8;
    NodeId(id)
}

/// A fresh BEP 42 id for our external address `ip`.
pub fn generate_id(ip: IpAddr, rng: &mut dyn Rng) -> NodeId {
    let r = rng.next_u32();
    generate_id_impl(ip, r, rng)
}

/// Whether `id` is a valid BEP 42 id for `source_ip`. Local (private,
/// loopback, link-local) sources are always accepted, as libtorrent does.
pub fn verify_id(id: &NodeId, source_ip: IpAddr) -> bool {
    if is_local(source_ip) {
        return true;
    }
    struct NoRng;
    impl Rng for NoRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
    }
    let h = generate_id_impl(source_ip, u32::from(id.0[19]), &mut NoRng);
    id.0[0] == h.0[0] && id.0[1] == h.0[1] && (id.0[2] & 0xf8) == (h.0[2] & 0xf8)
}

/// libtorrent `aux::is_local`: private, loopback and link-local ranges.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified()
        }
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || (a.segments()[0] & 0xfe00) == 0xfc00
                || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The "secret id" scheme: a per-process secret so we can recognise lookup
/// targets we generated (libtorrent `make_id_secret` / `verify_secret_id`).
#[derive(Debug, Clone)]
pub struct SecretIds {
    secret: u32,
}

impl SecretIds {
    /// A fresh secret.
    pub fn new(rng: &mut dyn Rng) -> SecretIds {
        SecretIds {
            secret: rng.below(0xffff_fffe) + 1,
        }
    }

    /// Replace the last 8 bytes of `id` with `rand || sha1(secret || rand)[..4]`.
    pub fn make_secret(&self, id: &mut NodeId, rng: &mut dyn Rng) {
        let rand = rng.next_u32().to_ne_bytes();
        let mut h = <sha1::Sha1 as sha1::Digest>::new();
        sha1::Digest::update(&mut h, self.secret.to_ne_bytes());
        sha1::Digest::update(&mut h, rand);
        let digest = sha1::Digest::finalize(h);
        id.0[16..20].copy_from_slice(&digest[..4]);
        id.0[12..16].copy_from_slice(&rand);
    }

    /// Whether `id`'s tail was produced by [`SecretIds::make_secret`].
    pub fn verify(&self, id: &NodeId) -> bool {
        let mut h = <sha1::Sha1 as sha1::Digest>::new();
        sha1::Digest::update(&mut h, self.secret.to_ne_bytes());
        sha1::Digest::update(&mut h, &id.0[12..16]);
        let digest = sha1::Digest::finalize(h);
        id.0[16..20] == digest[..4]
    }

    /// A random id with the secret tail (refresh targets).
    pub fn random(&self, rng: &mut dyn Rng) -> NodeId {
        let mut id = NodeId::random(rng);
        self.make_secret(&mut id, rng);
        id
    }
}

/// A mask with the first `bits` bits set (libtorrent `generate_prefix_mask`).
pub fn prefix_mask(bits: u32) -> NodeId {
    let mut m = [0u8; 20];
    let bits = bits.min(160) as usize;
    let full = bits / 8;
    for b in &mut m[..full] {
        *b = 0xff;
    }
    if full < 20 && !bits.is_multiple_of(8) {
        m[full] = (0xffu16 << (8 - (bits % 8))) as u8;
    }
    NodeId(m)
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
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }
    }

    #[test]
    fn crc32c_vectors() {
        // Known CRC-32C values.
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }

    #[test]
    fn bep42_examples() {
        // BEP 42 test vectors: ip, rand, expected id prefix (first 21 bits).
        let cases: [(&str, u32, [u8; 3]); 5] = [
            ("124.31.75.21", 1, [0x5f, 0xbf, 0xbf]),
            ("21.75.31.124", 86, [0x5a, 0x3c, 0xe9]),
            ("65.23.51.170", 22, [0xa5, 0xd4, 0x32]),
            ("84.124.73.14", 65, [0x1b, 0x03, 0x21]),
            ("43.213.53.83", 90, [0xe5, 0x6f, 0x6c]),
        ];
        for (ip, r, want) in cases {
            let ip: IpAddr = ip.parse().unwrap();
            let id = generate_id_impl(ip, r, &mut Lcg(3));
            assert_eq!(id.0[0], want[0], "{ip}");
            assert_eq!(id.0[1], want[1], "{ip}");
            assert_eq!(id.0[2] & 0xf8, want[2] & 0xf8, "{ip}");
            assert_eq!(id.0[19], r as u8);
            assert!(verify_id(&id, ip));
            let mut bad = id;
            bad.0[0] ^= 0x80;
            assert!(!verify_id(&bad, ip));
        }
        // Local sources are always fine.
        assert!(verify_id(&NodeId([9; 20]), "10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn distance_and_masks() {
        let a = NodeId([0; 20]);
        let mut b = [0u8; 20];
        b[0] = 0x40;
        let b = NodeId(b);
        assert_eq!(a.distance_exp(&b), 158);
        assert_eq!(a.distance_exp(&a), 0);
        assert_eq!(prefix_mask(0), NodeId::ZERO);
        assert_eq!(prefix_mask(3).0[0], 0xe0);
        assert_eq!(prefix_mask(8).0[0], 0xff);
        assert_eq!(prefix_mask(9).0[1], 0x80);
        assert_eq!(prefix_mask(160).0, [0xff; 20]);
        let mut rng = Lcg(1);
        let s = SecretIds::new(&mut rng);
        let id = s.random(&mut rng);
        assert!(s.verify(&id));
        assert!(!s.verify(&NodeId::random(&mut rng)));
    }
}
