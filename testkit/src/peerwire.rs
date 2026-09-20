// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! An independent peer-wire codec for the harness (tap-peer, captures). Not
//! shared with the library's `wire` crate on purpose.

use std::fmt;
use std::io::{self, Read, Write};

use crate::bencode::{self, Value};

pub const PSTR: &[u8] = b"BitTorrent protocol";

/// Reserved-byte bits (BEP 4 registry, as libtorrent names them).
pub mod reserved {
    /// byte 5, 0x10: extension protocol (BEP 10)
    pub const LTEP: (usize, u8) = (5, 0x10);
    /// byte 7, 0x04: fast extension (BEP 6)
    pub const FAST: (usize, u8) = (7, 0x04);
    /// byte 7, 0x01: DHT (BEP 5)
    pub const DHT: (usize, u8) = (7, 0x01);
    /// byte 7, 0x10: hybrid / v2 support (BEP 52)
    pub const V2: (usize, u8) = (7, 0x10);
    /// byte 7, 0x08: XBT peer exchange (legacy)
    pub const XBT_PEX: (usize, u8) = (7, 0x08);
    /// byte 5, 0x02: NAT traversal (legacy)
    pub const NAT_TRAVERSAL: (usize, u8) = (5, 0x02);
    /// byte 5, 0x08: extension negotiation protocol (legacy)
    pub const EXT_NEG_1: (usize, u8) = (5, 0x08);

    pub fn has(r: &[u8; 8], bit: (usize, u8)) -> bool {
        r[bit.0] & bit.1 != 0
    }
    pub fn set(r: &mut [u8; 8], bit: (usize, u8)) {
        r[bit.0] |= bit.1;
    }

    /// Human-readable names of the set bits, for captures.
    pub fn describe(r: &[u8; 8]) -> Vec<String> {
        let mut out = Vec::new();
        let known = [
            ("ltep", LTEP),
            ("fast", FAST),
            ("dht", DHT),
            ("v2", V2),
            ("xbt_pex", XBT_PEX),
            ("nat_traversal", NAT_TRAVERSAL),
            ("ext_neg_1", EXT_NEG_1),
        ];
        let mut seen = [0u8; 8];
        for (name, bit) in known {
            if has(r, bit) {
                out.push(name.to_string());
                seen[bit.0] |= bit.1;
            }
        }
        for i in 0..8 {
            let rest = r[i] & !seen[i];
            if rest != 0 {
                out.push(format!("byte{i}:0x{rest:02x}"));
            }
        }
        out
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Handshake {
    pub pstr: Vec<u8>,
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

impl fmt::Debug for Handshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handshake")
            .field("pstr", &String::from_utf8_lossy(&self.pstr))
            .field("reserved", &bencode::hex(&self.reserved))
            .field("info_hash", &bencode::hex(&self.info_hash))
            .field("peer_id", &String::from_utf8_lossy(&self.peer_id))
            .finish()
    }
}

impl Handshake {
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20], reserved: [u8; 8]) -> Handshake {
        Handshake {
            pstr: PSTR.to_vec(),
            reserved,
            info_hash,
            peer_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(68);
        out.push(self.pstr.len() as u8);
        out.extend_from_slice(&self.pstr);
        out.extend_from_slice(&self.reserved);
        out.extend_from_slice(&self.info_hash);
        out.extend_from_slice(&self.peer_id);
        out
    }

    /// Parse from a buffer that holds at least the full handshake.
    pub fn parse(buf: &[u8]) -> Option<(Handshake, usize)> {
        let pstrlen = *buf.first()? as usize;
        let total = 1 + pstrlen + 8 + 20 + 20;
        if buf.len() < total {
            return None;
        }
        let pstr = buf[1..1 + pstrlen].to_vec();
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&buf[1 + pstrlen..9 + pstrlen]);
        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&buf[9 + pstrlen..29 + pstrlen]);
        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&buf[29 + pstrlen..49 + pstrlen]);
        Some((
            Handshake {
                pstr,
                reserved,
                info_hash,
                peer_id,
            },
            total,
        ))
    }

    pub fn supports_ltep(&self) -> bool {
        reserved::has(&self.reserved, reserved::LTEP)
    }
    pub fn supports_fast(&self) -> bool {
        reserved::has(&self.reserved, reserved::FAST)
    }
}

/// A peer-wire message.
#[derive(Clone, PartialEq, Eq)]
pub enum Msg {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield(Vec<u8>),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        data: Vec<u8>,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Port(u16),
    Suggest(u32),
    HaveAll,
    HaveNone,
    Reject {
        index: u32,
        begin: u32,
        length: u32,
    },
    AllowedFast(u32),
    Extended {
        id: u8,
        payload: Vec<u8>,
    },
    Unknown {
        id: u8,
        payload: Vec<u8>,
    },
}

impl fmt::Debug for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Msg::Piece { index, begin, data } => write!(
                f,
                "Piece {{ index: {index}, begin: {begin}, len: {} }}",
                data.len()
            ),
            Msg::Bitfield(b) => write!(f, "Bitfield({} bytes)", b.len()),
            Msg::Extended { id, payload } => write!(
                f,
                "Extended {{ id: {id}, payload: {} bytes }}",
                payload.len()
            ),
            Msg::Unknown { id, payload } => write!(
                f,
                "Unknown {{ id: {id}, payload: {} bytes }}",
                payload.len()
            ),
            Msg::KeepAlive => write!(f, "KeepAlive"),
            Msg::Choke => write!(f, "Choke"),
            Msg::Unchoke => write!(f, "Unchoke"),
            Msg::Interested => write!(f, "Interested"),
            Msg::NotInterested => write!(f, "NotInterested"),
            Msg::Have(i) => write!(f, "Have({i})"),
            Msg::Request {
                index,
                begin,
                length,
            } => write!(f, "Request {{ {index}, {begin}, {length} }}"),
            Msg::Cancel {
                index,
                begin,
                length,
            } => write!(f, "Cancel {{ {index}, {begin}, {length} }}"),
            Msg::Port(p) => write!(f, "Port({p})"),
            Msg::Suggest(i) => write!(f, "Suggest({i})"),
            Msg::HaveAll => write!(f, "HaveAll"),
            Msg::HaveNone => write!(f, "HaveNone"),
            Msg::Reject {
                index,
                begin,
                length,
            } => write!(f, "Reject {{ {index}, {begin}, {length} }}"),
            Msg::AllowedFast(i) => write!(f, "AllowedFast({i})"),
        }
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().unwrap_or([0; 4]))
}

impl Msg {
    pub fn name(&self) -> &'static str {
        match self {
            Msg::KeepAlive => "keep_alive",
            Msg::Choke => "choke",
            Msg::Unchoke => "unchoke",
            Msg::Interested => "interested",
            Msg::NotInterested => "not_interested",
            Msg::Have(_) => "have",
            Msg::Bitfield(_) => "bitfield",
            Msg::Request { .. } => "request",
            Msg::Piece { .. } => "piece",
            Msg::Cancel { .. } => "cancel",
            Msg::Port(_) => "port",
            Msg::Suggest(_) => "suggest",
            Msg::HaveAll => "have_all",
            Msg::HaveNone => "have_none",
            Msg::Reject { .. } => "reject",
            Msg::AllowedFast(_) => "allowed_fast",
            Msg::Extended { .. } => "extended",
            Msg::Unknown { .. } => "unknown",
        }
    }

    /// Message id (None for keep-alive).
    pub fn id(&self) -> Option<u8> {
        Some(match self {
            Msg::KeepAlive => return None,
            Msg::Choke => 0,
            Msg::Unchoke => 1,
            Msg::Interested => 2,
            Msg::NotInterested => 3,
            Msg::Have(_) => 4,
            Msg::Bitfield(_) => 5,
            Msg::Request { .. } => 6,
            Msg::Piece { .. } => 7,
            Msg::Cancel { .. } => 8,
            Msg::Port(_) => 9,
            Msg::Suggest(_) => 13,
            Msg::HaveAll => 14,
            Msg::HaveNone => 15,
            Msg::Reject { .. } => 16,
            Msg::AllowedFast(_) => 17,
            Msg::Extended { .. } => 20,
            Msg::Unknown { id, .. } => *id,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Msg::KeepAlive => return vec![0, 0, 0, 0],
            Msg::Have(i) | Msg::Suggest(i) | Msg::AllowedFast(i) => {
                payload.extend_from_slice(&i.to_be_bytes())
            }
            Msg::Bitfield(b) => payload.extend_from_slice(b),
            Msg::Request {
                index,
                begin,
                length,
            }
            | Msg::Cancel {
                index,
                begin,
                length,
            }
            | Msg::Reject {
                index,
                begin,
                length,
            } => {
                payload.extend_from_slice(&index.to_be_bytes());
                payload.extend_from_slice(&begin.to_be_bytes());
                payload.extend_from_slice(&length.to_be_bytes());
            }
            Msg::Piece { index, begin, data } => {
                payload.extend_from_slice(&index.to_be_bytes());
                payload.extend_from_slice(&begin.to_be_bytes());
                payload.extend_from_slice(data);
            }
            Msg::Port(p) => payload.extend_from_slice(&p.to_be_bytes()),
            Msg::Extended { id, payload: p } => {
                payload.push(*id);
                payload.extend_from_slice(p);
            }
            Msg::Unknown { payload: p, .. } => payload.extend_from_slice(p),
            _ => {}
        }
        let mut out = Vec::with_capacity(5 + payload.len());
        out.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
        out.push(self.id().unwrap_or(0));
        out.extend_from_slice(&payload);
        out
    }

    /// Decode a message body (after the 4-byte length prefix). Empty = keep-alive.
    pub fn decode(body: &[u8]) -> Msg {
        let Some((&id, p)) = body.split_first() else {
            return Msg::KeepAlive;
        };
        match id {
            0 => Msg::Choke,
            1 => Msg::Unchoke,
            2 => Msg::Interested,
            3 => Msg::NotInterested,
            4 if p.len() == 4 => Msg::Have(be32(p)),
            5 => Msg::Bitfield(p.to_vec()),
            6 if p.len() == 12 => Msg::Request {
                index: be32(&p[0..4]),
                begin: be32(&p[4..8]),
                length: be32(&p[8..12]),
            },
            7 if p.len() >= 8 => Msg::Piece {
                index: be32(&p[0..4]),
                begin: be32(&p[4..8]),
                data: p[8..].to_vec(),
            },
            8 if p.len() == 12 => Msg::Cancel {
                index: be32(&p[0..4]),
                begin: be32(&p[4..8]),
                length: be32(&p[8..12]),
            },
            9 if p.len() == 2 => Msg::Port(u16::from_be_bytes([p[0], p[1]])),
            13 if p.len() == 4 => Msg::Suggest(be32(p)),
            14 if p.is_empty() => Msg::HaveAll,
            15 if p.is_empty() => Msg::HaveNone,
            16 if p.len() == 12 => Msg::Reject {
                index: be32(&p[0..4]),
                begin: be32(&p[4..8]),
                length: be32(&p[8..12]),
            },
            17 if p.len() == 4 => Msg::AllowedFast(be32(p)),
            20 if !p.is_empty() => Msg::Extended {
                id: p[0],
                payload: p[1..].to_vec(),
            },
            _ => Msg::Unknown {
                id,
                payload: p.to_vec(),
            },
        }
    }

    /// Structured summary for captures (never includes bulk payload).
    pub fn detail(&self) -> serde_json::Value {
        use serde_json::json;
        match self {
            Msg::Have(i) | Msg::Suggest(i) | Msg::AllowedFast(i) => json!({ "index": i }),
            Msg::Bitfield(b) => {
                json!({ "bytes": b.len(), "set_bits": b.iter().map(|x| x.count_ones()).sum::<u32>(), "hex": bencode::hex(&b[..b.len().min(32)]) })
            }
            Msg::Request {
                index,
                begin,
                length,
            }
            | Msg::Cancel {
                index,
                begin,
                length,
            }
            | Msg::Reject {
                index,
                begin,
                length,
            } => json!({ "index": index, "begin": begin, "length": length }),
            Msg::Piece { index, begin, data } => {
                json!({ "index": index, "begin": begin, "length": data.len() })
            }
            Msg::Port(p) => json!({ "port": p }),
            Msg::Extended { id, payload } => {
                let decoded = bencode::decode_prefix(payload).ok().map(
                    |(v, n)| json!({ "dict": value_to_json(&v), "trailing": payload.len() - n }),
                );
                json!({ "ext_id": id, "len": payload.len(), "decoded": decoded, "raw_hex": bencode::hex(&payload[..payload.len().min(512)]) })
            }
            Msg::Unknown { id, payload } => {
                json!({ "id": id, "len": payload.len(), "raw_hex": bencode::hex(&payload[..payload.len().min(64)]) })
            }
            _ => json!({}),
        }
    }
}

/// Convert a bencode value to JSON for captures. Byte strings that are not
/// UTF-8 (or are longer than 64 bytes) become `{"hex": ...}`.
pub fn value_to_json(v: &Value) -> serde_json::Value {
    use serde_json::json;
    match v {
        Value::Int(i) => json!(i),
        Value::Bytes(b) => match std::str::from_utf8(b) {
            Ok(s) if b.len() <= 64 && !s.chars().any(|c| c.is_control()) => json!(s),
            _ => json!({ "hex": bencode::hex(b) }),
        },
        Value::List(l) => serde_json::Value::Array(l.iter().map(value_to_json).collect()),
        Value::Dict(d) => {
            // Preserve key order (already sorted by BTreeMap = canonical order).
            let mut m = serde_json::Map::new();
            for (k, v) in d {
                m.insert(String::from_utf8_lossy(k).into_owned(), value_to_json(v));
            }
            serde_json::Value::Object(m)
        }
    }
}

/// Blocking framed reader over a stream.
pub struct FramedReader {
    buf: Vec<u8>,
    filled: usize,
}

impl Default for FramedReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FramedReader {
    pub fn new() -> FramedReader {
        FramedReader {
            buf: vec![0; 1 << 16],
            filled: 0,
        }
    }

    fn fill<R: Read>(&mut self, r: &mut R, want: usize) -> io::Result<bool> {
        while self.filled < want {
            if self.buf.len() < want {
                self.buf.resize(want.max(self.buf.len() * 2), 0);
            }
            let n = r.read(&mut self.buf[self.filled..])?;
            if n == 0 {
                return Ok(false);
            }
            self.filled += n;
        }
        Ok(true)
    }

    fn consume(&mut self, n: usize) -> Vec<u8> {
        let out = self.buf[..n].to_vec();
        self.buf.copy_within(n..self.filled, 0);
        self.filled -= n;
        out
    }

    /// Read a handshake. Returns the raw bytes consumed too. `Ok(None)` on EOF.
    pub fn read_handshake<R: Read>(
        &mut self,
        r: &mut R,
    ) -> io::Result<Option<(Handshake, Vec<u8>)>> {
        if !self.fill(r, 1)? {
            return Ok(None);
        }
        let pstrlen = self.buf[0] as usize;
        let total = 1 + pstrlen + 48;
        if !self.fill(r, total)? {
            return Ok(None);
        }
        let raw = self.consume(total);
        Ok(Handshake::parse(&raw).map(|(h, _)| (h, raw)))
    }

    /// Whatever is buffered right now (for MSE detection), without consuming.
    pub fn peek(&self) -> &[u8] {
        &self.buf[..self.filled]
    }

    /// Take every buffered byte (e.g. to hand a non-plaintext head to the
    /// MSE responder).
    pub fn take_pending(&mut self) -> Vec<u8> {
        let n = self.filled;
        self.consume(n)
    }

    pub fn peek_fill<R: Read>(&mut self, r: &mut R, want: usize) -> io::Result<&[u8]> {
        let _ = self.fill(r, want)?;
        Ok(&self.buf[..self.filled])
    }

    /// Read one message. `Ok(None)` on EOF. Returns (msg, raw frame bytes).
    pub fn read_msg<R: Read>(&mut self, r: &mut R) -> io::Result<Option<(Msg, Vec<u8>)>> {
        if !self.fill(r, 4)? {
            return Ok(None);
        }
        let len = be32(&self.buf[0..4]) as usize;
        if len > 1 << 24 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large: {len}"),
            ));
        }
        if !self.fill(r, 4 + len)? {
            return Ok(None);
        }
        let raw = self.consume(4 + len);
        Ok(Some((Msg::decode(&raw[4..]), raw)))
    }
}

pub fn write_all<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    w.write_all(bytes)?;
    w.flush()
}

/// Build an LTEP extended handshake payload.
pub fn ext_handshake(
    m: &[(&str, i64)],
    v: Option<&str>,
    reqq: Option<i64>,
    extra: &[(&str, Value)],
) -> Vec<u8> {
    let mut d = Value::dict();
    let mut mm = Value::dict();
    for (k, id) in m {
        mm.insert(k, Value::Int(*id));
    }
    d.insert("m", mm);
    if let Some(v) = v {
        d.insert("v", Value::str(v));
    }
    if let Some(r) = reqq {
        d.insert("reqq", Value::Int(r));
    }
    for (k, val) in extra {
        d.insert(k, val.clone());
    }
    d.encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip() {
        let mut r = [0u8; 8];
        reserved::set(&mut r, reserved::LTEP);
        reserved::set(&mut r, reserved::FAST);
        let h = Handshake::new([1; 20], [2; 20], r);
        let enc = h.encode();
        assert_eq!(enc.len(), 68);
        let (p, n) = Handshake::parse(&enc).unwrap();
        assert_eq!(n, 68);
        assert_eq!(p, h);
        assert_eq!(reserved::describe(&r), vec!["ltep", "fast"]);
    }

    #[test]
    fn msg_roundtrip() {
        for m in [
            Msg::KeepAlive,
            Msg::Choke,
            Msg::Have(7),
            Msg::Bitfield(vec![0xff, 0x80]),
            Msg::Request {
                index: 1,
                begin: 2,
                length: 3,
            },
            Msg::Piece {
                index: 1,
                begin: 16384,
                data: vec![9; 100],
            },
            Msg::Port(6881),
            Msg::HaveAll,
            Msg::Reject {
                index: 1,
                begin: 2,
                length: 3,
            },
            Msg::Extended {
                id: 0,
                payload: b"d1:md6:ut_pexi1eee".to_vec(),
            },
        ] {
            let enc = m.encode();
            let mut fr = FramedReader::new();
            let (dec, raw) = fr.read_msg(&mut &enc[..]).unwrap().unwrap();
            assert_eq!(dec, m);
            assert_eq!(raw, enc);
        }
    }
}
