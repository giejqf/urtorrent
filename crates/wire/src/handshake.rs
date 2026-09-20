// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The 68-byte BEP 3 handshake.

use metainfo::InfoHash;

use crate::Error;

/// Length of a v1 handshake on the wire.
pub const HANDSHAKE_LEN: usize = 68;

const PSTR: &[u8] = b"BitTorrent protocol";

/// A parsed or to-be-sent handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// Reserved bytes (extension bits).
    pub reserved: [u8; 8],
    /// The torrent's info-hash.
    pub info_hash: InfoHash,
    /// The sender's peer id.
    pub peer_id: [u8; 20],
}

impl Handshake {
    /// Encode into the 68 wire bytes.
    pub fn encode(&self) -> [u8; HANDSHAKE_LEN] {
        let mut out = [0u8; HANDSHAKE_LEN];
        out[0] = PSTR.len() as u8;
        out[1..20].copy_from_slice(PSTR);
        out[20..28].copy_from_slice(&self.reserved);
        out[28..48].copy_from_slice(&self.info_hash);
        out[48..68].copy_from_slice(&self.peer_id);
        out
    }

    /// Parse the first 68 bytes of `buf`. Returns `Ok(None)` if more bytes are
    /// needed, `Err` if what is there is not a BitTorrent handshake.
    pub fn parse(buf: &[u8]) -> Result<Option<Handshake>, Error> {
        // Reject early on the protocol string so garbage is detected before
        // 68 bytes arrive.
        let check = buf.len().min(20);
        if check > 0 && buf[0] != PSTR.len() as u8 {
            return Err(Error::Protocol("not a BitTorrent handshake"));
        }
        if check > 1 && buf[1..check] != PSTR[..check - 1] {
            return Err(Error::Protocol("not a BitTorrent handshake"));
        }
        if buf.len() < HANDSHAKE_LEN {
            return Ok(None);
        }
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&buf[20..28]);
        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&buf[28..48]);
        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&buf[48..68]);
        Ok(Some(Handshake {
            reserved,
            info_hash,
            peer_id,
        }))
    }

    /// Whether the LTEP bit (BEP 10) is set.
    pub fn supports_ltep(&self) -> bool {
        profile::reserved::has(&self.reserved, profile::reserved::LTEP)
    }

    /// Whether the fast-extension bit (BEP 6) is set.
    pub fn supports_fast(&self) -> bool {
        profile::reserved::has(&self.reserved, profile::reserved::FAST)
    }

    /// Whether the DHT bit (BEP 5) is set.
    pub fn supports_dht(&self) -> bool {
        profile::reserved::has(&self.reserved, profile::reserved::DHT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_partial() {
        let hs = Handshake {
            reserved: [0, 0, 0, 0, 0, 0x10, 0, 0x05],
            info_hash: [7; 20],
            peer_id: *b"-qB5230-CZ7IoSM6gPi~",
        };
        let bytes = hs.encode();
        assert_eq!(Handshake::parse(&bytes), Ok(Some(hs.clone())));
        for i in 0..HANDSHAKE_LEN {
            assert_eq!(Handshake::parse(&bytes[..i]), Ok(None), "prefix {i}");
        }
        assert!(hs.supports_ltep() && hs.supports_fast() && hs.supports_dht());
    }

    #[test]
    fn garbage_is_rejected_early() {
        assert!(Handshake::parse(b"GET / HTTP/1.1").is_err());
        assert!(Handshake::parse(&[19, b'B', b'x']).is_err());
        assert!(Handshake::parse(&[0x16, 0x03]).is_err());
    }
}
