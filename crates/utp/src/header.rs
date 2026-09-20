// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The 20-byte uTP header (BEP 29) and its extension chain.

/// Size of the fixed header.
pub const HEADER_LEN: usize = 20;

/// No extension follows.
pub const EXT_NONE: u8 = 0;
/// Selective-ack bitmask extension.
pub const EXT_SACK: u8 = 1;
/// libtorrent's close-reason extension (4 bytes: 2 reserved + u16 code).
pub const EXT_CLOSE_REASON: u8 = 3;

/// Packet types (the high nibble of the first byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PacketType {
    /// Payload.
    #[default]
    Data = 0,
    /// Close of the sender's direction.
    Fin = 1,
    /// Acknowledgement only.
    State = 2,
    /// Hard close.
    Reset = 3,
    /// Connection request.
    Syn = 4,
}

impl PacketType {
    fn from_nibble(n: u8) -> Option<PacketType> {
        Some(match n {
            0 => PacketType::Data,
            1 => PacketType::Fin,
            2 => PacketType::State,
            3 => PacketType::Reset,
            4 => PacketType::Syn,
            _ => return None,
        })
    }
}

/// A decoded fixed header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Header {
    /// Packet type.
    pub ty: PacketType,
    /// First extension type (0 = none).
    pub extension: u8,
    /// Connection id (the receiver's id, except on SYN).
    pub connection_id: u16,
    /// Sender's clock in microseconds.
    pub timestamp_us: u32,
    /// Sender's last measured one-way delay difference.
    pub timestamp_diff_us: u32,
    /// Sender's advertised receive window in bytes.
    pub wnd_size: u32,
    /// Sequence number of this packet.
    pub seq_nr: u16,
    /// Last in-order sequence number received.
    pub ack_nr: u16,
}

impl Header {
    /// Parse a header; `None` if the buffer is short or the version is not 1.
    pub fn parse(b: &[u8]) -> Option<Header> {
        if b.len() < HEADER_LEN {
            return None;
        }
        let version = b[0] & 0x0f;
        if version != 1 {
            return None;
        }
        let ty = PacketType::from_nibble(b[0] >> 4)?;
        let u16at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        let u32at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Some(Header {
            ty,
            extension: b[1],
            connection_id: u16at(2),
            timestamp_us: u32at(4),
            timestamp_diff_us: u32at(8),
            wnd_size: u32at(12),
            seq_nr: u16at(16),
            ack_nr: u16at(18),
        })
    }

    /// Write the header into the first 20 bytes of `out`.
    pub fn write(&self, out: &mut [u8]) {
        if out.len() < HEADER_LEN {
            return;
        }
        out[0] = ((self.ty as u8) << 4) | 1;
        out[1] = self.extension;
        out[2..4].copy_from_slice(&self.connection_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.timestamp_us.to_be_bytes());
        out[8..12].copy_from_slice(&self.timestamp_diff_us.to_be_bytes());
        out[12..16].copy_from_slice(&self.wnd_size.to_be_bytes());
        out[16..18].copy_from_slice(&self.seq_nr.to_be_bytes());
        out[18..20].copy_from_slice(&self.ack_nr.to_be_bytes());
    }
}

/// Whether a datagram looks like uTP: at least a header, version 1, a known
/// type. This is the demultiplexer's test (after the KRPC `'d'` check; a
/// bencoded dictionary never has a low nibble of 1 in `'d'` = 0x64).
pub fn is_utp(pkt: &[u8]) -> bool {
    pkt.len() >= HEADER_LEN && (pkt[0] & 0x0f) == 1 && (pkt[0] >> 4) <= 4
}

/// `lhs < rhs` under wrap-around with `mask` (0xffff for sequence numbers).
/// Ported from libtorrent's `compare_less_wrap`.
pub fn compare_less_wrap(lhs: u32, rhs: u32, mask: u32) -> bool {
    // distance walking from lhs to rhs, downwards
    let dist_down = lhs.wrapping_sub(rhs) & mask;
    // distance walking from lhs to rhs, upwards
    let dist_up = rhs.wrapping_sub(lhs) & mask;
    dist_up < dist_down
}

/// Walk the extension chain of `pkt` (whose header is `h`); returns the
/// payload offset and calls `f(extension_type, body)` for each extension.
/// `None` if the chain runs past the end of the packet.
pub fn walk_extensions(h: &Header, pkt: &[u8], mut f: impl FnMut(u8, &[u8])) -> Option<usize> {
    let mut ext = h.extension;
    let mut pos = HEADER_LEN;
    while ext != 0 {
        let next = *pkt.get(pos)?;
        let len = usize::from(*pkt.get(pos + 1)?);
        let body = pkt.get(pos + 2..pos + 2 + len)?;
        f(ext, body);
        pos += 2 + len;
        ext = next;
    }
    Some(pos)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let h = Header {
            ty: PacketType::Syn,
            extension: 0,
            connection_id: 0xe0d8,
            timestamp_us: 123_456_789,
            timestamp_diff_us: 0,
            wnd_size: 0,
            seq_nr: 27043,
            ack_nr: 0,
        };
        let mut out = [0u8; 20];
        h.write(&mut out);
        assert_eq!(out[0], 0x41);
        assert_eq!(Header::parse(&out), Some(h));
        assert!(is_utp(&out));
        assert!(!is_utp(b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae"));
        assert!(!is_utp(&[0x51; 20]));
    }

    #[test]
    fn wrap_compare() {
        assert!(compare_less_wrap(0xfff0, 0x0010, 0xffff));
        assert!(!compare_less_wrap(0x0010, 0xfff0, 0xffff));
        assert!(compare_less_wrap(1, 2, 0xffff));
        assert!(!compare_less_wrap(2, 2, 0xffff));
    }

    #[test]
    fn extension_chain() {
        let mut pkt = vec![0x21, 1];
        pkt.extend_from_slice(&[0; 18]);
        pkt.extend_from_slice(&[3, 2, 0xff, 0x01]); // sack, next=3
        pkt.extend_from_slice(&[0, 4, 0, 0, 0, 6]); // close reason, next=0
        pkt.extend_from_slice(b"xy");
        let h = Header::parse(&pkt).unwrap();
        let mut seen = Vec::new();
        let off = walk_extensions(&h, &pkt, |t, b| seen.push((t, b.to_vec()))).unwrap();
        assert_eq!(seen, vec![(1, vec![0xff, 1]), (3, vec![0, 0, 0, 6])]);
        assert_eq!(&pkt[off..], b"xy");
        // Truncated chain.
        pkt.truncate(23);
        assert!(walk_extensions(&h, &pkt, |_, _| {}).is_none());
    }
}
