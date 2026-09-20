// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Peer-wire messages (BEP 3, BEP 6, BEP 10): codec only. Validation against
//! connection state lives in [`crate::Connection`].

use crate::Error;

/// Largest block payload we accept in a `piece` message. We request 16 KiB
/// blocks; libtorrent and most clients refuse anything above this.
pub const MAX_BLOCK: u32 = 128 * 1024;

/// Largest bitfield payload we accept (covers ~8M pieces).
pub const MAX_BITFIELD: usize = 1 << 20;

/// A block reference as carried by `request`, `cancel` and `reject`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Request {
    /// Piece index.
    pub index: u32,
    /// Byte offset within the piece.
    pub begin: u32,
    /// Length in bytes.
    pub length: u32,
}

/// A peer-wire message.
#[derive(Clone, PartialEq, Eq)]
pub enum Message {
    /// Zero-length frame.
    KeepAlive,
    /// `choke` (0).
    Choke,
    /// `unchoke` (1).
    Unchoke,
    /// `interested` (2).
    Interested,
    /// `not interested` (3).
    NotInterested,
    /// `have` (4).
    Have(u32),
    /// `bitfield` (5): raw wire bytes (validated against the piece count by
    /// the connection).
    Bitfield(Vec<u8>),
    /// `request` (6).
    Request(Request),
    /// `piece` (7).
    Piece {
        /// Piece index.
        index: u32,
        /// Byte offset within the piece.
        begin: u32,
        /// Block payload.
        data: Vec<u8>,
    },
    /// `cancel` (8).
    Cancel(Request),
    /// `port` (9, BEP 5). Ignored by 0.1.0 (no DHT), decoded for fidelity.
    Port(u16),
    /// `suggest piece` (13, BEP 6).
    Suggest(u32),
    /// `have all` (14, BEP 6).
    HaveAll,
    /// `have none` (15, BEP 6).
    HaveNone,
    /// `reject request` (16, BEP 6).
    Reject(Request),
    /// `allowed fast` (17, BEP 6).
    AllowedFast(u32),
    /// `extended` (20, BEP 10): extension message id and payload.
    Extended {
        /// The extension message id (0 = handshake).
        id: u8,
        /// Payload (bencoded for the handshake).
        payload: Vec<u8>,
    },
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::KeepAlive => write!(f, "KeepAlive"),
            Message::Choke => write!(f, "Choke"),
            Message::Unchoke => write!(f, "Unchoke"),
            Message::Interested => write!(f, "Interested"),
            Message::NotInterested => write!(f, "NotInterested"),
            Message::Have(i) => write!(f, "Have({i})"),
            Message::Bitfield(b) => write!(f, "Bitfield({} bytes)", b.len()),
            Message::Request(r) => write!(f, "Request({r:?})"),
            Message::Piece { index, begin, data } => {
                write!(f, "Piece({index}, {begin}, {} bytes)", data.len())
            }
            Message::Cancel(r) => write!(f, "Cancel({r:?})"),
            Message::Port(p) => write!(f, "Port({p})"),
            Message::Suggest(i) => write!(f, "Suggest({i})"),
            Message::HaveAll => write!(f, "HaveAll"),
            Message::HaveNone => write!(f, "HaveNone"),
            Message::Reject(r) => write!(f, "Reject({r:?})"),
            Message::AllowedFast(i) => write!(f, "AllowedFast({i})"),
            Message::Extended { id, payload } => {
                write!(f, "Extended({id}, {} bytes)", payload.len())
            }
        }
    }
}

mod id {
    pub const CHOKE: u8 = 0;
    pub const UNCHOKE: u8 = 1;
    pub const INTERESTED: u8 = 2;
    pub const NOT_INTERESTED: u8 = 3;
    pub const HAVE: u8 = 4;
    pub const BITFIELD: u8 = 5;
    pub const REQUEST: u8 = 6;
    pub const PIECE: u8 = 7;
    pub const CANCEL: u8 = 8;
    pub const PORT: u8 = 9;
    pub const SUGGEST: u8 = 13;
    pub const HAVE_ALL: u8 = 14;
    pub const HAVE_NONE: u8 = 15;
    pub const REJECT: u8 = 16;
    pub const ALLOWED_FAST: u8 = 17;
    pub const EXTENDED: u8 = 20;
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_req(out: &mut Vec<u8>, r: &Request) {
    put_u32(out, r.index);
    put_u32(out, r.begin);
    put_u32(out, r.length);
}

fn get_req(body: &[u8]) -> Result<Request, Error> {
    if body.len() != 13 {
        return Err(Error::Protocol("bad request-shaped message length"));
    }
    Ok(Request {
        index: be32(&body[1..5]),
        begin: be32(&body[5..9]),
        length: be32(&body[9..13]),
    })
}

impl Message {
    /// Whether this message type needs the fast extension (BEP 6).
    pub fn needs_fast(&self) -> bool {
        matches!(
            self,
            Message::Suggest(_)
                | Message::HaveAll
                | Message::HaveNone
                | Message::Reject(_)
                | Message::AllowedFast(_)
        )
    }

    /// Append the framing of a `piece` message carrying `data_len` payload
    /// bytes (length prefix, id, index, begin) to `out`; the payload itself
    /// follows separately (see `Connection::take_outbound_chunks`).
    pub fn encode_piece_header(out: &mut Vec<u8>, index: u32, begin: u32, data_len: u32) {
        put_u32(out, 9 + data_len);
        out.push(id::PIECE);
        put_u32(out, index);
        put_u32(out, begin);
    }

    /// Append the framed wire encoding (length prefix included) to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        put_u32(out, 0); // length placeholder
        match self {
            Message::KeepAlive => {}
            Message::Choke => out.push(id::CHOKE),
            Message::Unchoke => out.push(id::UNCHOKE),
            Message::Interested => out.push(id::INTERESTED),
            Message::NotInterested => out.push(id::NOT_INTERESTED),
            Message::Have(i) => {
                out.push(id::HAVE);
                put_u32(out, *i);
            }
            Message::Bitfield(b) => {
                out.push(id::BITFIELD);
                out.extend_from_slice(b);
            }
            Message::Request(r) => {
                out.push(id::REQUEST);
                put_req(out, r);
            }
            Message::Piece { index, begin, data } => {
                out.push(id::PIECE);
                put_u32(out, *index);
                put_u32(out, *begin);
                out.extend_from_slice(data);
            }
            Message::Cancel(r) => {
                out.push(id::CANCEL);
                put_req(out, r);
            }
            Message::Port(p) => {
                out.push(id::PORT);
                out.extend_from_slice(&p.to_be_bytes());
            }
            Message::Suggest(i) => {
                out.push(id::SUGGEST);
                put_u32(out, *i);
            }
            Message::HaveAll => out.push(id::HAVE_ALL),
            Message::HaveNone => out.push(id::HAVE_NONE),
            Message::Reject(r) => {
                out.push(id::REJECT);
                put_req(out, r);
            }
            Message::AllowedFast(i) => {
                out.push(id::ALLOWED_FAST);
                put_u32(out, *i);
            }
            Message::Extended { id, payload } => {
                out.push(id::EXTENDED);
                out.push(*id);
                out.extend_from_slice(payload);
            }
        }
        let len = (out.len() - start - 4) as u32;
        out[start..start + 4].copy_from_slice(&len.to_be_bytes());
    }

    /// The framed wire encoding as a fresh vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }

    /// Decode one frame body (without its length prefix). Bounds every
    /// variable-length payload.
    pub fn decode(body: &[u8]) -> Result<Message, Error> {
        let Some(&kind) = body.first() else {
            return Ok(Message::KeepAlive);
        };
        let fixed = |n: usize| {
            if body.len() == n {
                Ok(())
            } else {
                Err(Error::Protocol("bad message length"))
            }
        };
        Ok(match kind {
            id::CHOKE => {
                fixed(1)?;
                Message::Choke
            }
            id::UNCHOKE => {
                fixed(1)?;
                Message::Unchoke
            }
            id::INTERESTED => {
                fixed(1)?;
                Message::Interested
            }
            id::NOT_INTERESTED => {
                fixed(1)?;
                Message::NotInterested
            }
            id::HAVE => {
                fixed(5)?;
                Message::Have(be32(&body[1..5]))
            }
            id::BITFIELD => {
                if body.len() - 1 > MAX_BITFIELD {
                    return Err(Error::TooLarge);
                }
                Message::Bitfield(body[1..].to_vec())
            }
            id::REQUEST => Message::Request(get_req(body)?),
            id::PIECE => {
                if body.len() < 9 {
                    return Err(Error::Protocol("short piece message"));
                }
                if body.len() - 9 > MAX_BLOCK as usize {
                    return Err(Error::TooLarge);
                }
                Message::Piece {
                    index: be32(&body[1..5]),
                    begin: be32(&body[5..9]),
                    data: body[9..].to_vec(),
                }
            }
            id::CANCEL => Message::Cancel(get_req(body)?),
            id::PORT => {
                fixed(3)?;
                Message::Port(u16::from_be_bytes([body[1], body[2]]))
            }
            id::SUGGEST => {
                fixed(5)?;
                Message::Suggest(be32(&body[1..5]))
            }
            id::HAVE_ALL => {
                fixed(1)?;
                Message::HaveAll
            }
            id::HAVE_NONE => {
                fixed(1)?;
                Message::HaveNone
            }
            id::REJECT => Message::Reject(get_req(body)?),
            id::ALLOWED_FAST => {
                fixed(5)?;
                Message::AllowedFast(be32(&body[1..5]))
            }
            id::EXTENDED => {
                if body.len() < 2 {
                    return Err(Error::Protocol("short extended message"));
                }
                if body.len() - 2 > crate::ltep::MAX_EXT_PAYLOAD {
                    return Err(Error::TooLarge);
                }
                Message::Extended {
                    id: body[1],
                    payload: body[2..].to_vec(),
                }
            }
            _ => return Err(Error::Protocol("unknown message id")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn roundtrip(m: Message) {
        let bytes = m.to_bytes();
        let len = be32(&bytes[..4]) as usize;
        assert_eq!(len + 4, bytes.len());
        assert_eq!(Message::decode(&bytes[4..]).unwrap(), m);
    }

    #[test]
    fn golden_encodings() {
        // Raw frames from testkit/golden/capture_peer_plain (hex in the jsonl).
        assert_eq!(Message::HaveAll.to_bytes(), [0, 0, 0, 1, 0x0e]);
        assert_eq!(Message::HaveNone.to_bytes(), [0, 0, 0, 1, 0x0f]);
        assert_eq!(Message::Interested.to_bytes(), [0, 0, 0, 1, 0x02]);
        assert_eq!(Message::Unchoke.to_bytes(), [0, 0, 0, 1, 0x01]);
        assert_eq!(Message::Have(5).to_bytes(), [0, 0, 0, 5, 0x04, 0, 0, 0, 5]);
        assert_eq!(
            Message::Request(Request {
                index: 8,
                begin: 16384,
                length: 16384
            })
            .to_bytes(),
            [
                0, 0, 0, 0x0d, 0x06, 0, 0, 0, 8, 0, 0, 0x40, 0, 0, 0, 0x40, 0
            ]
        );
        assert_eq!(Message::KeepAlive.to_bytes(), [0, 0, 0, 0]);
    }

    #[test]
    fn all_variants_roundtrip() {
        let r = Request {
            index: 1,
            begin: 2,
            length: 3,
        };
        for m in [
            Message::KeepAlive,
            Message::Choke,
            Message::Unchoke,
            Message::Interested,
            Message::NotInterested,
            Message::Have(9),
            Message::Bitfield(vec![0xff, 0x80]),
            Message::Request(r),
            Message::Piece {
                index: 4,
                begin: 16384,
                data: vec![1, 2, 3],
            },
            Message::Cancel(r),
            Message::Port(6881),
            Message::Suggest(3),
            Message::HaveAll,
            Message::HaveNone,
            Message::Reject(r),
            Message::AllowedFast(7),
            Message::Extended {
                id: 0,
                payload: b"de".to_vec(),
            },
        ] {
            roundtrip(m);
        }
    }

    #[test]
    fn bad_lengths_rejected() {
        assert!(Message::decode(&[id::HAVE, 0, 0]).is_err());
        assert!(Message::decode(&[id::REQUEST, 0]).is_err());
        assert!(Message::decode(&[id::PIECE, 0, 0, 0]).is_err());
        assert!(Message::decode(&[id::EXTENDED]).is_err());
        assert!(Message::decode(&[99]).is_err());
        assert!(Message::decode(&[id::CHOKE, 1]).is_err());
        let big = vec![0u8; MAX_BLOCK as usize + 10];
        let mut body = vec![id::PIECE, 0, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&big);
        assert_eq!(Message::decode(&body), Err(Error::TooLarge));
    }

    proptest! {
        #[test]
        fn decode_never_panics(body in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = Message::decode(&body);
        }

        #[test]
        fn decode_encode_is_identity(body in proptest::collection::vec(any::<u8>(), 0..64)) {
            if let Ok(m) = Message::decode(&body) {
                let bytes = m.to_bytes();
                prop_assert_eq!(&bytes[4..], &body[..]);
            }
        }
    }
}
