// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Local Service Discovery (BEP 14) datagrams, rendered and parsed the way
//! libtorrent does (`src/lsd.cpp`, BSD-3; see `NOTICE`), as captured from
//! the oracle in `lsd_discovery`:
//!
//! ```text
//! BT-SEARCH * HTTP/1.1\r\n
//! Host: 239.192.152.143:6771\r\n       (or [ff15::efc0:988f]:6771)
//! Port: <listen port>\r\n
//! Infohash: <40 lowercase hex>\r\n
//! cookie: <lowercase hex, no padding>\r\n
//! \r\n\r\n
//! ```
//!
//! Sans-IO: the engine owns the multicast sockets and the retry timer.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The BEP 14 port.
pub const PORT: u16 = 6771;
/// The IPv4 group.
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 192, 152, 143);
/// The IPv6 group.
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff15, 0, 0, 0, 0, 0, 0xefc0, 0x988f);
/// Most `Infohash` headers we take from one datagram.
pub const MAX_HASHES: usize = 64;

/// Render an announce for one family.
pub fn render(v6: bool, listen_port: u16, info_hash: &[u8; 20], cookie: u32) -> Vec<u8> {
    let host = if v6 {
        "[ff15::efc0:988f]"
    } else {
        "239.192.152.143"
    };
    format!(
        "BT-SEARCH * HTTP/1.1\r\nHost: {host}:{PORT}\r\nPort: {listen_port}\r\nInfohash: {}\r\ncookie: {cookie:x}\r\n\r\n\r\n",
        bencode::hex(info_hash),
    )
    .into_bytes()
}

/// A parsed `BT-SEARCH` datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Search {
    /// The announcer's listen port.
    pub port: u16,
    /// Every well-formed `Infohash` header (zero hashes dropped).
    pub info_hashes: Vec<[u8; 20]>,
    /// The `cookie`, if present and hex.
    pub cookie: Option<u32>,
}

/// Parse a datagram; `None` for anything that is not a well-formed search
/// with a usable port (libtorrent ignores those silently).
pub fn parse(data: &[u8]) -> Option<Search> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n");
    let request = lines.next()?;
    let mut parts = request.split(' ');
    if !parts.next()?.eq_ignore_ascii_case("BT-SEARCH") || parts.next()? != "*" {
        return None;
    }
    let mut port = None;
    let mut info_hashes = Vec::new();
    let mut cookie = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("port") {
            let p: u32 = value.parse().ok()?;
            if p == 0 || p >= u32::from(u16::MAX) {
                return None;
            }
            port = Some(p as u16);
        } else if name.eq_ignore_ascii_case("infohash") {
            if value.len() != 40 || !value.is_ascii() {
                continue;
            }
            let mut h = [0u8; 20];
            let mut ok = true;
            for (i, byte) in h.iter_mut().enumerate() {
                match u8::from_str_radix(&value[2 * i..2 * i + 2], 16) {
                    Ok(b) => *byte = b,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && h != [0u8; 20] && info_hashes.len() < MAX_HASHES {
                info_hashes.push(h);
            }
        } else if name.eq_ignore_ascii_case("cookie") {
            cookie = u32::from_str_radix(value, 16).ok();
        }
    }
    Some(Search {
        port: port?,
        info_hashes,
        cookie,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_matches_libtorrent_layout_and_roundtrips() {
        let ih = [0xabu8; 20];
        let p = render(false, 6881, &ih, 0x1234_abcd);
        assert_eq!(
            String::from_utf8(p.clone()).unwrap(),
            "BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: 6881\r\nInfohash: abababababababababababababababababababab\r\ncookie: 1234abcd\r\n\r\n\r\n"
        );
        let s = parse(&p).unwrap();
        assert_eq!(s.port, 6881);
        assert_eq!(s.info_hashes, vec![ih]);
        assert_eq!(s.cookie, Some(0x1234_abcd));
        let p6 = render(true, 1, &ih, 7);
        assert!(p6.starts_with(b"BT-SEARCH * HTTP/1.1\r\nHost: [ff15::efc0:988f]:6771\r\n"));
        assert!(p6.ends_with(b"cookie: 7\r\n\r\n\r\n"));
    }

    #[test]
    fn parse_rejects_garbage_and_bounds_hashes() {
        assert!(parse(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse(b"BT-SEARCH * HTTP/1.1\r\nPort: 0\r\n\r\n").is_none());
        assert!(parse(b"BT-SEARCH * HTTP/1.1\r\nPort: 65535\r\n\r\n").is_none());
        assert!(parse(b"BT-SEARCH * HTTP/1.1\r\nInfohash: 00\r\n\r\n").is_none());
        assert!(parse(&[0xff, 0xfe]).is_none());
        let s = parse(b"BT-SEARCH * HTTP/1.1\r\nPort: 7\r\nInfohash: zz\r\nInfohash: 0000000000000000000000000000000000000000\r\n\r\n").unwrap();
        assert!(s.info_hashes.is_empty());
        assert_eq!(s.cookie, None);
        let mut many = b"BT-SEARCH * HTTP/1.1\r\nPort: 7\r\n".to_vec();
        for i in 0..100u32 {
            many.extend_from_slice(format!("Infohash: {:040x}\r\n", i + 1).as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(parse(&many).unwrap().info_hashes.len(), MAX_HASHES);
    }
}
