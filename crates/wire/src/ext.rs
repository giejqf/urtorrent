// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! LTEP extension message codecs: `ut_pex` (BEP 11), `ut_metadata` (BEP 9)
//! and `upload_only` (BEP 21). Pure encode/parse over bencode; bounded.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bencode::{Decoder, Value};

use crate::Error;

/// Maximum peers we accept per PEX message per family (the BEP suggests 50
/// per message; libtorrent caps at 50 too and disconnects above 500 total).
pub const MAX_PEX_PEERS: usize = 200;

/// BEP 11 peer flags (`added.f` / `added6.f`).
pub mod pex_flags {
    /// Prefers encryption.
    pub const ENCRYPTION: u8 = 0x01;
    /// Seed / upload only.
    pub const SEED: u8 = 0x02;
    /// Supports uTP.
    pub const UTP: u8 = 0x04;
    /// Supports `ut_holepunch`.
    pub const HOLEPUNCH: u8 = 0x08;
    /// Reachable (the sender connected to it).
    pub const REACHABLE: u8 = 0x10;
}

/// One PEX message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pex {
    /// Peers added since the last message, with their flags.
    pub added: Vec<(SocketAddr, u8)>,
    /// Peers dropped since the last message.
    pub dropped: Vec<SocketAddr>,
}

impl Pex {
    /// Encode as a bencoded dictionary (`added`, `added.f`, `added6`,
    /// `added6.f`, `dropped`, `dropped6`), keys present even when empty, as
    /// libtorrent does.
    pub fn encode(&self) -> Vec<u8> {
        let mut added = Vec::new();
        let mut added_f = Vec::new();
        let mut added6 = Vec::new();
        let mut added6_f = Vec::new();
        for (a, f) in &self.added {
            match a.ip() {
                IpAddr::V4(v4) => {
                    added.extend_from_slice(&v4.octets());
                    added.extend_from_slice(&a.port().to_be_bytes());
                    added_f.push(*f);
                }
                IpAddr::V6(v6) => {
                    added6.extend_from_slice(&v6.octets());
                    added6.extend_from_slice(&a.port().to_be_bytes());
                    added6_f.push(*f);
                }
            }
        }
        let mut dropped = Vec::new();
        let mut dropped6 = Vec::new();
        for a in &self.dropped {
            match a.ip() {
                IpAddr::V4(v4) => {
                    dropped.extend_from_slice(&v4.octets());
                    dropped.extend_from_slice(&a.port().to_be_bytes());
                }
                IpAddr::V6(v6) => {
                    dropped6.extend_from_slice(&v6.octets());
                    dropped6.extend_from_slice(&a.port().to_be_bytes());
                }
            }
        }
        let entries: Vec<(&[u8], Value<'_>)> = vec![
            (b"added", Value::Bytes(&added)),
            (b"added.f", Value::Bytes(&added_f)),
            (b"added6", Value::Bytes(&added6)),
            (b"added6.f", Value::Bytes(&added6_f)),
            (b"dropped", Value::Bytes(&dropped)),
            (b"dropped6", Value::Bytes(&dropped6)),
        ];
        bencode::to_bytes(&Value::Dict { entries, raw: &[] })
    }

    /// Parse a PEX payload. Missing keys are empty; flags default to 0.
    pub fn parse(payload: &[u8]) -> Result<Pex, Error> {
        let root = Decoder::new(payload)
            .decode_all()
            .map_err(|_| Error::Protocol("malformed ut_pex"))?;
        if root.kind() != bencode::ValueKind::Dict {
            return Err(Error::Protocol("ut_pex is not a dict"));
        }
        let bytes = |k: &str| root.get_str(k).and_then(Value::as_bytes).unwrap_or(&[]);
        let mut pex = Pex::default();
        let f4 = bytes("added.f");
        for (i, c) in bytes("added")
            .as_chunks::<6>()
            .0
            .iter()
            .enumerate()
            .take(MAX_PEX_PEERS)
        {
            let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
            let port = u16::from_be_bytes([c[4], c[5]]);
            pex.added.push((
                SocketAddr::new(IpAddr::V4(ip), port),
                f4.get(i).copied().unwrap_or(0),
            ));
        }
        let f6 = bytes("added6.f");
        for (i, c) in bytes("added6")
            .as_chunks::<18>()
            .0
            .iter()
            .enumerate()
            .take(MAX_PEX_PEERS)
        {
            let mut o = [0u8; 16];
            o.copy_from_slice(&c[..16]);
            let port = u16::from_be_bytes([c[16], c[17]]);
            pex.added.push((
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port),
                f6.get(i).copied().unwrap_or(0),
            ));
        }
        for c in bytes("dropped")
            .as_chunks::<6>()
            .0
            .iter()
            .take(MAX_PEX_PEERS)
        {
            let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
            pex.dropped.push(SocketAddr::new(
                IpAddr::V4(ip),
                u16::from_be_bytes([c[4], c[5]]),
            ));
        }
        for c in bytes("dropped6")
            .as_chunks::<18>()
            .0
            .iter()
            .take(MAX_PEX_PEERS)
        {
            let mut o = [0u8; 16];
            o.copy_from_slice(&c[..16]);
            pex.dropped.push(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(o)),
                u16::from_be_bytes([c[16], c[17]]),
            ));
        }
        Ok(pex)
    }
}

/// BEP 9 metadata piece size.
pub const METADATA_PIECE: usize = 16 * 1024;
/// Largest info dictionary we accept from a peer (libtorrent: 4 MiB is
/// generous; BEP 9 uses 16 KiB pieces).
pub const MAX_METADATA_SIZE: usize = 8 * 1024 * 1024;

/// A `ut_metadata` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Metadata {
    /// `msg_type 0`: request `piece`.
    Request {
        /// Piece index.
        piece: u32,
    },
    /// `msg_type 1`: `piece` of a `total_size`-byte info dictionary; `data`
    /// follows the dictionary.
    Data {
        /// Piece index.
        piece: u32,
        /// Total size of the info dictionary.
        total_size: u32,
        /// The piece bytes.
        data: Vec<u8>,
    },
    /// `msg_type 2`: `piece` rejected (no metadata / rate limit).
    Reject {
        /// Piece index.
        piece: u32,
    },
}

impl Metadata {
    /// Encode as bencoded dictionary (+ raw data for `Data`). `known_total`
    /// is the size of the metadata when we have it: libtorrent puts
    /// `total_size` in every message type once it knows the metadata, not
    /// only in `Data`.
    pub fn encode(&self, known_total: Option<u32>) -> Vec<u8> {
        let (msg_type, piece, total, data): (i64, u32, Option<u32>, &[u8]) = match self {
            Metadata::Request { piece } => (0, *piece, known_total, &[]),
            Metadata::Data {
                piece,
                total_size,
                data,
            } => (1, *piece, Some(*total_size), data),
            Metadata::Reject { piece } => (2, *piece, known_total, &[]),
        };
        let mut entries: Vec<(&[u8], Value<'_>)> = vec![
            (b"msg_type", Value::Int(msg_type)),
            (b"piece", Value::Int(i64::from(piece))),
        ];
        if let Some(t) = total {
            entries.push((b"total_size", Value::Int(i64::from(t))));
        }
        let mut out = bencode::to_bytes(&Value::Dict { entries, raw: &[] });
        out.extend_from_slice(data);
        out
    }

    /// Parse a `ut_metadata` payload (dictionary plus trailing data).
    pub fn parse(payload: &[u8]) -> Result<Metadata, Error> {
        let mut dec = Decoder::new(payload);
        let root = dec
            .decode_value()
            .map_err(|_| Error::Protocol("malformed ut_metadata"))?;
        let rest = dec.remaining();
        if root.kind() != bencode::ValueKind::Dict {
            return Err(Error::Protocol("ut_metadata is not a dict"));
        }
        let piece = root
            .get_str("piece")
            .and_then(Value::as_int)
            .filter(|p| (0..=i64::from(u32::MAX)).contains(p))
            .ok_or(Error::Protocol("ut_metadata: bad piece"))? as u32;
        match root.get_str("msg_type").and_then(Value::as_int) {
            Some(0) => Ok(Metadata::Request { piece }),
            Some(1) => {
                let total_size = root
                    .get_str("total_size")
                    .and_then(Value::as_int)
                    .filter(|t| *t > 0 && *t <= MAX_METADATA_SIZE as i64)
                    .ok_or(Error::Protocol("ut_metadata: bad total_size"))?
                    as u32;
                if rest.len() > METADATA_PIECE {
                    return Err(Error::TooLarge);
                }
                Ok(Metadata::Data {
                    piece,
                    total_size,
                    data: rest.to_vec(),
                })
            }
            Some(2) => Ok(Metadata::Reject { piece }),
            _ => Err(Error::Protocol("ut_metadata: bad msg_type")),
        }
    }
}

/// BEP 21 `upload_only` payload: a single byte, `1` on, `0` off.
pub fn upload_only_payload(on: bool) -> Vec<u8> {
    vec![u8::from(on)]
}

/// Parse a BEP 21 payload.
pub fn parse_upload_only(payload: &[u8]) -> Result<bool, Error> {
    match payload {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(Error::Protocol("bad upload_only payload")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pex_roundtrip_and_shape() {
        let pex = Pex {
            added: vec![
                (
                    "10.0.0.1:6881".parse().unwrap(),
                    pex_flags::SEED | pex_flags::REACHABLE,
                ),
                ("[fd77::a]:51413".parse().unwrap(), 0),
            ],
            dropped: vec![
                "10.0.0.2:1".parse().unwrap(),
                "[fd77::b]:2".parse().unwrap(),
            ],
        };
        let bytes = pex.encode();
        // Every key present, sorted (bencode canonical).
        assert!(
            bytes.starts_with(b"d5:added6:"),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(String::from_utf8_lossy(&bytes).contains("7:added.f1:"));
        assert!(String::from_utf8_lossy(&bytes).contains("6:added618:"));
        assert!(String::from_utf8_lossy(&bytes).contains("8:added6.f1:"));
        assert!(String::from_utf8_lossy(&bytes).contains("7:dropped6:"));
        assert!(String::from_utf8_lossy(&bytes).contains("8:dropped618:"));
        let back = Pex::parse(&bytes).unwrap();
        assert_eq!(back, pex);
        // Empty message: all keys, all empty.
        let empty = Pex::default().encode();
        assert_eq!(
            empty,
            b"d5:added0:7:added.f0:6:added60:8:added6.f0:7:dropped0:8:dropped60:e"
        );
        assert_eq!(Pex::parse(&empty).unwrap(), Pex::default());
        assert!(Pex::parse(b"le").is_err());
        // Flags default to zero when `added.f` is short.
        let short = Pex::parse(b"d5:added6:\x0a\x00\x00\x01\x1a\xe1e").unwrap();
        assert_eq!(short.added, vec![("10.0.0.1:6881".parse().unwrap(), 0)]);
    }

    #[test]
    fn metadata_roundtrip() {
        for m in [
            Metadata::Request { piece: 3 },
            Metadata::Data {
                piece: 1,
                total_size: 40_000,
                data: vec![7u8; 16384],
            },
            Metadata::Reject { piece: 0 },
        ] {
            let bytes = m.encode(None);
            assert_eq!(Metadata::parse(&bytes).unwrap(), m);
        }
        assert_eq!(
            Metadata::Request { piece: 3 }.encode(None),
            b"d8:msg_typei0e5:piecei3ee"
        );
        assert_eq!(
            Metadata::Data {
                piece: 0,
                total_size: 5,
                data: b"hello".to_vec()
            }
            .encode(None),
            b"d8:msg_typei1e5:piecei0e10:total_sizei5eehello"
        );
        assert!(Metadata::parse(b"d8:msg_typei9e5:piecei0ee").is_err());
        assert!(
            Metadata::parse(b"d8:msg_typei1e5:piecei0ee").is_err(),
            "no total_size"
        );
        let mut big = b"d8:msg_typei1e5:piecei0e10:total_sizei100000ee".to_vec();
        big.extend_from_slice(&vec![0u8; METADATA_PIECE + 1]);
        assert_eq!(Metadata::parse(&big), Err(Error::TooLarge));
    }

    #[test]
    fn upload_only() {
        assert_eq!(upload_only_payload(true), vec![1]);
        assert_eq!(parse_upload_only(&[0]), Ok(false));
        assert!(parse_upload_only(&[2]).is_err());
        assert!(parse_upload_only(&[]).is_err());
    }
}
