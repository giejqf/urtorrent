// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The BEP 10 extended handshake. Which keys appear, and the `m` map, are
//! profile data (AGENTS.md 6, L2); bencode's sorted keys fix the wire order.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bencode::{Decoder, Value};

use crate::Error;

/// The extended message id of the handshake itself.
pub const EXT_HANDSHAKE_ID: u8 = 0;

/// Largest extended-message payload we accept (`ut_metadata` pieces are
/// 16 KiB; PEX lists are small; a handshake is tiny).
pub const MAX_EXT_PAYLOAD: usize = 256 * 1024;

/// The bencoded dictionary exchanged as extension message 0.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtHandshake {
    /// `m`: extension name -> the id the *sender* wants to receive it under.
    pub m: Vec<(String, u8)>,
    /// `v`: client name and version.
    pub v: Option<String>,
    /// `p`: the sender's listen port.
    pub p: Option<u16>,
    /// `reqq`: how many outstanding requests the sender accepts.
    pub reqq: Option<u32>,
    /// `yourip`: the address the sender sees us as.
    pub yourip: Option<IpAddr>,
    /// `ipv4` / `ipv6`: the sender's own addresses, if it chose to tell.
    pub ipv4: Option<Ipv4Addr>,
    /// See `ipv4`.
    pub ipv6: Option<Ipv6Addr>,
    /// `metadata_size` (BEP 9).
    pub metadata_size: Option<u32>,
    /// `upload_only` (BEP 21).
    pub upload_only: Option<bool>,
    /// `complete_ago` (libtorrent extra: seconds since completion, -1 if never).
    pub complete_ago: Option<i64>,
}

impl ExtHandshake {
    /// Build the handshake we send, from the profile's LTEP shape and the
    /// per-connection facts it depends on.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        shape: &profile::LtepShape,
        version: &str,
        outgoing: bool,
        listen_port: Option<u16>,
        yourip: Option<IpAddr>,
        metadata_size: Option<u32>,
        seeding: bool,
        private: bool,
    ) -> ExtHandshake {
        let m = if private { shape.m_private } else { shape.m };
        ExtHandshake {
            m: m.iter().map(|e| (e.name.to_string(), e.id)).collect(),
            v: Some(version.to_string()),
            // `listen_port` is `None` when the port is not advertisable to
            // this peer (docs/quirks.md Q6).
            p: match listen_port {
                Some(p)
                    if (outgoing && shape.p_on_outgoing) || (!outgoing && shape.p_on_incoming) =>
                {
                    Some(p)
                }
                _ => None,
            },
            reqq: Some(shape.reqq),
            yourip: if shape.yourip { yourip } else { None },
            ipv4: None,
            ipv6: None,
            // Q11: no `metadata_size` on private torrents.
            metadata_size: if shape.metadata_size && !private {
                metadata_size
            } else {
                None
            },
            upload_only: if shape.upload_only_when_seeding && seeding {
                Some(true)
            } else {
                None
            },
            complete_ago: if shape.complete_ago { Some(-1) } else { None },
        }
    }

    /// The id under which the peer wants to receive extension `name`, if it
    /// supports it (0 means "disabled").
    pub fn peer_id_for(&self, name: &str) -> Option<u8> {
        self.m
            .iter()
            .find(|(n, id)| n == name && *id != 0)
            .map(|(_, id)| *id)
    }

    /// Bencode the handshake (canonical: keys sorted).
    pub fn encode(&self) -> Vec<u8> {
        let mut entries: Vec<(&[u8], Value<'_>)> = Vec::new();
        let m_entries: Vec<(&[u8], Value<'_>)> = {
            let mut v: Vec<(&[u8], Value<'_>)> = self
                .m
                .iter()
                .map(|(n, id)| (n.as_bytes(), Value::Int(i64::from(*id))))
                .collect();
            v.sort_by(|a, b| a.0.cmp(b.0));
            v
        };
        let ip4 = self.ipv4.map(|a| a.octets());
        let ip6 = self.ipv6.map(|a| a.octets());
        let yourip4 = match self.yourip {
            Some(IpAddr::V4(a)) => Some(a.octets()),
            _ => None,
        };
        let yourip6 = match self.yourip {
            Some(IpAddr::V6(a)) => Some(a.octets()),
            _ => None,
        };
        if let Some(c) = self.complete_ago {
            entries.push((b"complete_ago", Value::Int(c)));
        }
        if let Some(a) = &ip4 {
            entries.push((b"ipv4", Value::Bytes(a)));
        }
        if let Some(a) = &ip6 {
            entries.push((b"ipv6", Value::Bytes(a)));
        }
        entries.push((
            b"m",
            Value::Dict {
                entries: m_entries,
                raw: &[],
            },
        ));
        if let Some(s) = self.metadata_size {
            entries.push((b"metadata_size", Value::Int(i64::from(s))));
        }
        if let Some(p) = self.p {
            entries.push((b"p", Value::Int(i64::from(p))));
        }
        if let Some(r) = self.reqq {
            entries.push((b"reqq", Value::Int(i64::from(r))));
        }
        if let Some(u) = self.upload_only {
            entries.push((b"upload_only", Value::Int(i64::from(u))));
        }
        if let Some(v) = &self.v {
            entries.push((b"v", Value::Bytes(v.as_bytes())));
        }
        if let Some(a) = &yourip4 {
            entries.push((b"yourip", Value::Bytes(a)));
        }
        if let Some(a) = &yourip6 {
            entries.push((b"yourip", Value::Bytes(a)));
        }
        bencode::to_bytes(&Value::Dict { entries, raw: &[] })
    }

    /// Parse a peer's handshake. Unknown keys are ignored; known keys with the
    /// wrong type are ignored too (lenient, like libtorrent), except that the
    /// top level must be a dictionary.
    pub fn parse(payload: &[u8]) -> Result<ExtHandshake, Error> {
        let root = Decoder::new(payload)
            .decode_all()
            .map_err(|_| Error::Protocol("malformed extended handshake"))?;
        if root.kind() != bencode::ValueKind::Dict {
            return Err(Error::Protocol("extended handshake is not a dict"));
        }
        let mut hs = ExtHandshake::default();
        if let Some(m) = root.get_str("m").and_then(Value::as_dict) {
            for (k, v) in m.iter().take(64) {
                if let (Ok(name), Some(id)) = (std::str::from_utf8(k), v.as_int())
                    && (0..=255).contains(&id)
                {
                    hs.m.push((name.to_string(), id as u8));
                }
            }
        }
        hs.v = root
            .get_str("v")
            .and_then(Value::as_bytes)
            .map(|b| String::from_utf8_lossy(&b[..b.len().min(128)]).into_owned());
        hs.p = root
            .get_str("p")
            .and_then(Value::as_int)
            .filter(|p| (1..=65535).contains(p))
            .map(|p| p as u16);
        hs.reqq = root
            .get_str("reqq")
            .and_then(Value::as_int)
            .filter(|r| *r > 0)
            .map(|r| r.min(i64::from(u32::MAX)) as u32);
        hs.yourip = root
            .get_str("yourip")
            .and_then(Value::as_bytes)
            .and_then(ip_from_bytes);
        hs.ipv4 = root
            .get_str("ipv4")
            .and_then(Value::as_bytes)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(Ipv4Addr::from);
        hs.ipv6 = root
            .get_str("ipv6")
            .and_then(Value::as_bytes)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .map(Ipv6Addr::from);
        hs.metadata_size = root
            .get_str("metadata_size")
            .and_then(Value::as_int)
            .filter(|s| *s > 0 && *s <= i64::from(u32::MAX))
            .map(|s| s as u32);
        hs.upload_only = root
            .get_str("upload_only")
            .and_then(Value::as_int)
            .map(|u| u != 0);
        hs.complete_ago = root.get_str("complete_ago").and_then(Value::as_int);
        Ok(hs)
    }
}

fn ip_from_bytes(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => <[u8; 4]>::try_from(b).ok().map(|a| IpAddr::V4(a.into())),
        16 => <[u8; 16]>::try_from(b).ok().map(|a| IpAddr::V6(a.into())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let hs = ExtHandshake {
            m: vec![("ut_pex".into(), 1), ("ut_metadata".into(), 2)],
            v: Some("x 1.0".into()),
            p: Some(6881),
            reqq: Some(250),
            yourip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ipv4: None,
            ipv6: None,
            metadata_size: Some(714),
            upload_only: Some(true),
            complete_ago: Some(-1),
        };
        let bytes = hs.encode();
        let back = ExtHandshake::parse(&bytes).unwrap();
        assert_eq!(back.v, hs.v);
        assert_eq!(back.p, hs.p);
        assert_eq!(back.reqq, hs.reqq);
        assert_eq!(back.yourip, hs.yourip);
        assert_eq!(back.metadata_size, hs.metadata_size);
        assert_eq!(back.upload_only, hs.upload_only);
        assert_eq!(back.complete_ago, hs.complete_ago);
        assert_eq!(back.peer_id_for("ut_pex"), Some(1));
        assert_eq!(back.peer_id_for("ut_metadata"), Some(2));
        assert_eq!(back.peer_id_for("nope"), None);
    }

    #[test]
    fn lenient_on_bad_types_strict_on_shape() {
        let v = ExtHandshake::parse(b"d1:mli1ee1:pi99999e4:reqqi-5e1:vi3ee").unwrap();
        assert!(v.m.is_empty());
        assert_eq!(v.p, None);
        assert_eq!(v.reqq, None);
        assert_eq!(v.v, None);
        assert!(ExtHandshake::parse(b"le").is_err());
        assert!(ExtHandshake::parse(b"d1:m").is_err());
    }
}
