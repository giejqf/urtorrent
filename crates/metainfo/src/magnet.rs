// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Magnet-link (BEP 9 / BEP 53) parsing. Only enough to start a metadata
//! fetch: the info-hash (`xt`), display name (`dn`) and trackers (`tr`). In
//! 0.1.0 peers come from trackers/PEX only, so `x.pe`/DHT hints are ignored.

use crate::{Error, InfoHash};

/// A parsed magnet link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagnetLink {
    /// The v1 info-hash from `xt=urn:btih:...` (hex or base32 decoded).
    pub info_hash: InfoHash,
    /// The display name (`dn`), if present.
    pub name: Option<String>,
    /// Tracker URLs (`tr`), in order, deduplicated.
    pub trackers: Vec<String>,
    /// Whether a v2 `xt=urn:btmh:` was present (deferred; recorded for fidelity).
    pub has_v2: bool,
    /// BEP 9 `x.pe`: peer addresses to connect to right away, as given
    /// (`host:port`, `ipv4:port`, `[ipv6]:port`), deduplicated.
    pub peers: Vec<String>,
    /// `ws`: web seed URLs (BEP 19 in a magnet, as libtorrent and qBittorrent
    /// read them), deduplicated.
    pub web_seeds: Vec<String>,
    /// BEP 53 `so`: the file indices to download (`0,2,4-6`), sorted and
    /// deduplicated; `None` when the link selects everything. Bounded to
    /// `MAX_SELECT_ONLY` entries.
    pub select_only: Option<Vec<u32>>,
}

/// Most file indices a `so=` list may expand to (a hostile range like
/// `0-4000000000` must not allocate).
pub const MAX_SELECT_ONLY: usize = 100_000;

impl MagnetLink {
    /// Parse a `magnet:?...` URI.
    pub fn parse(uri: &str) -> Result<MagnetLink, Error> {
        let query = uri
            .strip_prefix("magnet:?")
            .ok_or(Error::Magnet("not a magnet URI"))?;
        let mut info_hash: Option<InfoHash> = None;
        let mut name = None;
        let mut trackers = Vec::new();
        let mut has_v2 = false;
        let mut peers = Vec::new();
        let mut web_seeds = Vec::new();
        let mut select_only: Option<Vec<u32>> = None;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            // Strip the `.N` multi-value suffix magnet allows on some keys
            // (`tr.1=`); `x.pe` is a key of its own (BEP 9).
            let key = if key.starts_with("x.pe") {
                "x.pe"
            } else {
                key.split('.').next().unwrap_or(key)
            };
            match key {
                "xt" => {
                    let value = percent_decode(value);
                    if let Some(hex_or_b32) = value.strip_prefix("urn:btih:") {
                        if info_hash.is_none() {
                            info_hash = Some(parse_btih(hex_or_b32)?);
                        }
                    } else if value.starts_with("urn:btmh:") {
                        has_v2 = true;
                    }
                }
                "dn" => name = Some(percent_decode(value)),
                "tr" => {
                    let t = percent_decode(value);
                    if !t.is_empty() && !trackers.contains(&t) {
                        trackers.push(t);
                    }
                }
                "x.pe" => {
                    let p = percent_decode(value);
                    if !p.is_empty() && p.len() <= 300 && !peers.contains(&p) && peers.len() < 64 {
                        peers.push(p);
                    }
                }
                "ws" => {
                    let w = percent_decode(value);
                    if !w.is_empty() && !web_seeds.contains(&w) && web_seeds.len() < 64 {
                        web_seeds.push(w);
                    }
                }
                "so" => {
                    let list = select_only.get_or_insert_with(Vec::new);
                    parse_select_only(&percent_decode(value), list);
                }
                _ => {}
            }
        }
        let info_hash = info_hash.ok_or(Error::Magnet("no v1 info-hash (xt=urn:btih:)"))?;
        if let Some(list) = select_only.as_mut() {
            list.sort_unstable();
            list.dedup();
        }
        Ok(MagnetLink {
            info_hash,
            name,
            trackers,
            has_v2,
            peers,
            web_seeds,
            select_only,
        })
    }

    /// The tracker tiers (each tracker is its own tier for a magnet).
    pub fn tiers(&self) -> Vec<Vec<String>> {
        self.trackers.iter().map(|t| vec![t.clone()]).collect()
    }
}

/// BEP 53: `0,2,4-6` → indices, appended to `out` (bounded).
fn parse_select_only(text: &str, out: &mut Vec<u32>) {
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => match (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                (Ok(a), Ok(b)) if a <= b => (a, b),
                _ => continue,
            },
            None => match part.parse::<u32>() {
                Ok(v) => (v, v),
                Err(_) => continue,
            },
        };
        for i in lo..=hi {
            if out.len() >= MAX_SELECT_ONLY {
                return;
            }
            out.push(i);
        }
    }
}

fn parse_btih(s: &str) -> Result<InfoHash, Error> {
    match s.len() {
        40 => {
            let b = s.as_bytes();
            let mut out = [0u8; 20];
            for (i, byte) in out.iter_mut().enumerate() {
                let hi = hexval(b[2 * i]).ok_or(Error::Magnet("bad hex in info-hash"))?;
                let lo = hexval(b[2 * i + 1]).ok_or(Error::Magnet("bad hex in info-hash"))?;
                *byte = hi << 4 | lo;
            }
            Ok(out)
        }
        32 => base32_decode(s).ok_or(Error::Magnet("bad base32 info-hash")),
        _ => Err(Error::Magnet("info-hash wrong length")),
    }
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// RFC 4648 base32 (no padding needed for exactly 20 bytes = 32 chars).
fn base32_decode(s: &str) -> Option<InfoHash> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = [0u8; 20];
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut oi = 0usize;
    for c in s.bytes() {
        let c = c.to_ascii_uppercase();
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            if oi >= 20 {
                return None;
            }
            out[oi] = (bits >> nbits) as u8;
            oi += 1;
        }
    }
    (oi == 20).then_some(out)
}

/// Minimal percent-decoding for magnet query values (`+` is a literal here).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_magnet() {
        let uri = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=My%20Torrent&tr=http%3A%2F%2Ft%2Fann&tr=udp%3A%2F%2Fu%3A80";
        let m = MagnetLink::parse(uri).unwrap();
        assert_eq!(m.info_hash[0], 0x01);
        assert_eq!(m.info_hash[19], 0x67);
        assert_eq!(m.name.as_deref(), Some("My Torrent"));
        assert_eq!(
            m.trackers,
            vec!["http://t/ann".to_string(), "udp://u:80".to_string()]
        );
    }

    #[test]
    fn base32_matches_hex() {
        // Same info-hash expressed both ways: 20 zero bytes.
        let hex = MagnetLink::parse("magnet:?xt=urn:btih:0000000000000000000000000000000000000000")
            .unwrap();
        let b32 =
            MagnetLink::parse("magnet:?xt=urn:btih:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(hex.info_hash, b32.info_hash);
    }

    /// BEP 9 `x.pe`, `ws` and BEP 53 `so` (with ranges, duplicates and
    /// junk), plus the `tr.N` suffix form.
    #[test]
    fn peers_web_seeds_and_select_only() {
        let uri = concat!(
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567",
            "&x.pe=10.0.0.1%3A6881&x.pe=%5B2001%3Adb8%3A%3A1%5D%3A51413",
            "&x.pe=seed.example.org:6881&x.pe=10.0.0.1:6881",
            "&ws=http%3A%2F%2Fmirror%2Ffile&ws=http%3A%2F%2Fmirror%2Ffile",
            "&so=0,2,4-6,junk,9-8,6&tr.1=http%3A%2F%2Ft%2Fann"
        );
        let m = MagnetLink::parse(uri).unwrap();
        assert_eq!(
            m.peers,
            vec![
                "10.0.0.1:6881".to_string(),
                "[2001:db8::1]:51413".to_string(),
                "seed.example.org:6881".to_string()
            ]
        );
        assert_eq!(m.web_seeds, vec!["http://mirror/file".to_string()]);
        assert_eq!(m.select_only, Some(vec![0, 2, 4, 5, 6]));
        assert_eq!(m.trackers, vec!["http://t/ann".to_string()]);
        // No `so`: everything selected. A hostile range stays bounded.
        let plain =
            MagnetLink::parse("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567")
                .unwrap();
        assert_eq!(plain.select_only, None);
        let huge = MagnetLink::parse(
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&so=0-4000000000",
        )
        .unwrap();
        assert_eq!(huge.select_only.map(|v| v.len()), Some(MAX_SELECT_ONLY));
    }

    #[test]
    fn rejects_missing_hash() {
        assert!(MagnetLink::parse("magnet:?dn=x").is_err());
        assert!(MagnetLink::parse("http://not-a-magnet").is_err());
    }

    #[test]
    fn records_v2() {
        let m = MagnetLink::parse(
            "magnet:?xt=urn:btih:0000000000000000000000000000000000000000&xt=urn:btmh:1220abcd",
        );
        assert!(m.unwrap().has_v2);
    }
}
