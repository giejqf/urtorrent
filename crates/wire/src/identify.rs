// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 20 peer-id conventions: naming the client behind a peer id. The
//! Azureus style (`-XXvvvv-`), Shadow's style (`Tvvvvv---`), Mainline
//! (`M4-3-6--`) and the one-off schemes the BEP lists (BitComet `exbc`,
//! XBT, Opera, MLdonkey, Bits on Wheels, Queen Bee, BitTyrant, TorrenTopia,
//! BitSpirit, Rufus, G3 Torrent, FlashGet, AllPeers). The LTEP `v` string
//! (BEP 10) is preferred when a peer sends one; this is the fallback and the
//! only source for peers without LTEP.

/// Azureus-style two-letter codes (BEP 20's list plus clients that adopted
/// the style since).
const AZUREUS_STYLE: &[(&[u8; 2], &str)] = &[
    (b"7T", "aTorrent"),
    (b"AB", "AnyEvent::BitTorrent"),
    (b"AG", "Ares"),
    (b"A~", "Ares"),
    (b"AR", "Arctic"),
    (b"AV", "Avicora"),
    (b"AT", "Artemis"),
    (b"AX", "BitPump"),
    (b"AZ", "Azureus"),
    (b"BB", "BitBuddy"),
    (b"BC", "BitComet"),
    (b"BE", "Baretorrent"),
    (b"BF", "Bitflu"),
    (b"BG", "BTG"),
    (b"BI", "BiglyBT"),
    (b"BL", "BitBlinder"),
    (b"BP", "BitTorrent Pro"),
    (b"BR", "BitRocket"),
    (b"BS", "BTSlave"),
    (b"BT", "BitTorrent"),
    (b"Bt", "Bt"),
    (b"BW", "BitWombat"),
    (b"BX", "Bittorrent X"),
    (b"CD", "Enhanced CTorrent"),
    (b"CT", "CTorrent"),
    (b"DE", "Deluge"),
    (b"DP", "Propagate Data Client"),
    (b"EB", "EBit"),
    (b"ES", "electric sheep"),
    (b"FC", "FileCroc"),
    (b"FD", "Free Download Manager"),
    (b"FL", "Folx"),
    (b"FT", "FoxTorrent"),
    (b"FW", "FrostWire"),
    (b"FX", "Freebox BitTorrent"),
    (b"GS", "GSTorrent"),
    (b"HK", "Hekate"),
    (b"HL", "Halite"),
    (b"HM", "hMule"),
    (b"HN", "Hydranode"),
    (b"IL", "iLivid"),
    (b"JS", "Justseed.it"),
    (b"JT", "JavaTorrent"),
    (b"KG", "KGet"),
    (b"KT", "KTorrent"),
    (b"LC", "LeechCraft"),
    (b"LH", "LH-ABC"),
    (b"LP", "Lphant"),
    (b"LT", "libtorrent"),
    (b"lt", "libTorrent"),
    (b"LW", "LimeWire"),
    (b"MK", "Meerkat"),
    (b"MO", "MonoTorrent"),
    (b"MP", "MooPolice"),
    (b"MR", "Miro"),
    (b"MT", "MoonlightTorrent"),
    (b"NB", "Net::BitTorrent"),
    (b"NX", "Net Transport"),
    (b"OS", "OneSwarm"),
    (b"OT", "OmegaTorrent"),
    (b"PB", "Protocol::BitTorrent"),
    (b"PD", "Pando"),
    (b"PI", "PicoTorrent"),
    (b"PT", "PHPTracker"),
    (b"qB", "qBittorrent"),
    (b"QD", "QQDownload"),
    (b"QT", "Qt 4 Torrent example"),
    (b"RT", "Retriever"),
    (b"RZ", "RezTorrent"),
    (b"S~", "Shareaza alpha/beta"),
    (b"SB", "Swiftbit"),
    (b"SD", "Thunder"),
    (b"SM", "SoMud"),
    (b"SP", "BitSpirit"),
    (b"SS", "SwarmScope"),
    (b"ST", "SymTorrent"),
    (b"st", "sharktorrent"),
    (b"SZ", "Shareaza"),
    (b"TB", "Torch"),
    (b"TE", "terasaur Seed Bank"),
    (b"TL", "Tribler"),
    (b"TN", "TorrentDotNET"),
    (b"TR", "Transmission"),
    (b"TS", "Torrentstorm"),
    (b"TT", "TuoTu"),
    (b"UL", "uLeecher!"),
    (b"UM", "\u{b5}Torrent Mac"),
    (b"UR", "urtorrent"),
    (b"UT", "\u{b5}Torrent"),
    (b"UW", "\u{b5}Torrent Web"),
    (b"VG", "Vagaa"),
    (b"WD", "WebTorrent Desktop"),
    (b"WT", "BitLet"),
    (b"WW", "WebTorrent"),
    (b"WY", "FireTorrent"),
    (b"XF", "Xfplay"),
    (b"XL", "Xunlei"),
    (b"XS", "XSwifter"),
    (b"XT", "XanTorrent"),
    (b"XX", "Xtorrent"),
    (b"ZT", "ZipTorrent"),
];

/// Shadow-style single-letter codes.
const SHADOW_STYLE: &[(u8, &str)] = &[
    (b'A', "ABC"),
    (b'O', "Osprey Permaseed"),
    (b'Q', "BTQueue"),
    (b'R', "Tribler"),
    (b'S', "Shadow's client"),
    (b'T', "BitTornado"),
    (b'U', "UPnP NAT Bit Torrent"),
];

/// The client name and version a peer id encodes, or `None` when the id
/// follows no known convention.
pub fn client_name(id: &[u8; 20]) -> Option<String> {
    if let Some(s) = special(id) {
        return Some(s);
    }
    if let Some(s) = azureus_style(id) {
        return Some(s);
    }
    if let Some(s) = shadow_style(id) {
        return Some(s);
    }
    mainline_style(id)
}

/// The Azureus-style version digit set: `0-9`, `A-Z` (10-35), `a-z`
/// (36-61), `.` (62), `-` (63).
fn digit(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some(u32::from(c - b'0')),
        b'A'..=b'Z' => Some(u32::from(c - b'A') + 10),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 36),
        b'.' => Some(62),
        b'-' => Some(63),
        _ => None,
    }
}

/// `-XXvvvv-`: name and a dotted version; a fourth component only when it
/// is non-zero (`-qB5230-` is "qBittorrent 5.2.3").
fn azureus_style(id: &[u8; 20]) -> Option<String> {
    if id[0] != b'-' || id[7] != b'-' {
        return None;
    }
    let code = [id[1], id[2]];
    let name = AZUREUS_STYLE
        .iter()
        .find(|(c, _)| **c == code)
        .map(|(_, n)| *n);
    let v: Vec<u32> = id[3..7].iter().map(|&c| digit(c)).collect::<Option<_>>()?;
    let mut version = format!("{}.{}.{}", v[0], v[1], v[2]);
    if v[3] != 0 {
        version.push_str(&format!(".{}", v[3]));
    }
    match name {
        Some(n) => Some(format!("{n} {version}")),
        None if code.iter().all(|c| c.is_ascii_alphanumeric()) => {
            Some(format!("{} {version}", String::from_utf8_lossy(&code)))
        }
        None => None,
    }
}

/// `Tvvvvv---`: up to five version characters padded with dashes.
fn shadow_style(id: &[u8; 20]) -> Option<String> {
    let (_, name) = SHADOW_STYLE.iter().find(|(c, _)| *c == id[0])?;
    if &id[6..9] != b"---" {
        return None;
    }
    let mut parts = Vec::new();
    for &c in &id[1..6] {
        if c == b'-' {
            break;
        }
        // Shadow's alphabet: 0-9, A-Z, a-z, then `.`; a plain digit prints
        // as is, letters continue the count (A = 10 ...).
        let v = match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'A'..=b'Z' => u32::from(c - b'A') + 10,
            b'a'..=b'z' => u32::from(c - b'a') + 36,
            b'.' => 62,
            _ => return None,
        };
        parts.push(v.to_string());
    }
    if parts.is_empty() {
        return Some((*name).to_string());
    }
    Some(format!("{name} {}", parts.join(".")))
}

/// Mainline `M4-3-6--` / `M4-20-8-`: digits separated by dashes.
fn mainline_style(id: &[u8; 20]) -> Option<String> {
    if id[0] != b'M' {
        return None;
    }
    let text = std::str::from_utf8(&id[1..8]).ok()?;
    let parts: Vec<&str> = text.split('-').take_while(|p| !p.is_empty()).collect();
    if parts.len() < 2 || !parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some(format!("Mainline {}", parts.join(".")))
}

/// The one-off schemes BEP 20 describes.
fn special(id: &[u8; 20]) -> Option<String> {
    // BitComet / BitLord: `exbc` (or the `FUTB` patch) + version bytes.
    if id.starts_with(b"exbc") || id.starts_with(b"FUTB") {
        let name = if &id[6..10] == b"LORD" {
            "BitLord"
        } else {
            "BitComet"
        };
        return Some(format!("{name} {}.{:02}", id[4], id[5]));
    }
    // XBT Client: `XBT054d-` (debug) / `XBT054--`.
    if id.starts_with(b"XBT") && id[3..6].iter().all(u8::is_ascii_digit) {
        let dbg = if id[6] == b'd' { " (debug)" } else { "" };
        return Some(format!(
            "XBT {}.{}.{}{dbg}",
            id[3] - b'0',
            id[4] - b'0',
            id[5] - b'0'
        ));
    }
    // Opera: `OP` + four-digit build number.
    if id.starts_with(b"OP") && id[2..6].iter().all(u8::is_ascii_digit) {
        return Some(format!("Opera {}", String::from_utf8_lossy(&id[2..6])));
    }
    // MLdonkey: `-ML2.7.2-`.
    if id.starts_with(b"-ML") {
        let rest = &id[3..];
        let end = rest.iter().position(|&c| c == b'-').unwrap_or(rest.len());
        let v = String::from_utf8_lossy(&rest[..end]);
        if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Some(format!("MLdonkey {v}"));
        }
        return None;
    }
    // Bits on Wheels: `-BOWxxx-`.
    if id.starts_with(b"-BOW") && id[7] == b'-' {
        return Some(format!(
            "Bits on Wheels {}",
            String::from_utf8_lossy(&id[4..7])
        ));
    }
    // Queen Bee: `Q1-0-0--` (Bram's new style).
    if id[0] == b'Q' && id[1].is_ascii_digit() && id[2] == b'-' {
        let text = std::str::from_utf8(&id[1..8]).ok()?;
        let parts: Vec<&str> = text.split('-').take_while(|p| !p.is_empty()).collect();
        if parts.len() >= 2 && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit())) {
            return Some(format!("Queen Bee {}", parts.join(".")));
        }
    }
    // BitTyrant: `AZ2500BT` (no dashes).
    if id.starts_with(b"AZ") && &id[6..8] == b"BT" && id[2..6].iter().all(u8::is_ascii_digit) {
        return Some(format!(
            "BitTyrant {}.{}.{}.{}",
            id[2] - b'0',
            id[3] - b'0',
            id[4] - b'0',
            id[5] - b'0'
        ));
    }
    // TorrenTopia pretends to be Mainline 3.4.6.
    if id.starts_with(b"346------") {
        return Some("TorrenTopia 1.90".to_string());
    }
    // BitSpirit: `\0\3BS` / `\0\2BS`.
    if id[0] == 0 && &id[2..4] == b"BS" && (id[1] == 2 || id[1] == 3) {
        return Some(format!("BitSpirit {}", id[1]));
    }
    // Rufus: two version bytes then `RS`.
    if &id[2..4] == b"RS" && id[0].is_ascii_digit() && id[1].is_ascii_digit() {
        return Some(format!("Rufus {}.{}", id[0] - b'0', id[1] - b'0'));
    }
    // G3 Torrent: `-G3` + nickname.
    if id.starts_with(b"-G3") {
        return Some("G3 Torrent".to_string());
    }
    // FlashGet: Azureus style without the trailing dash (`-FG0180` for
    // 1.8x: two digits of major, two of minor).
    if id.starts_with(b"-FG") && id[3..7].iter().all(u8::is_ascii_digit) && id[7] != b'-' {
        let major = u32::from(id[3] - b'0') * 10 + u32::from(id[4] - b'0');
        return Some(format!(
            "FlashGet {major}.{}",
            String::from_utf8_lossy(&id[5..7])
        ));
    }
    // AllPeers: `AP` + version + `-`.
    if id.starts_with(b"AP") {
        let rest = &id[2..];
        let end = rest.iter().position(|&c| c == b'-')?;
        let v = String::from_utf8_lossy(&rest[..end]);
        if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Some(format!("AllPeers {v}"));
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn id(prefix: &[u8]) -> [u8; 20] {
        let mut out = [b'x'; 20];
        out[..prefix.len()].copy_from_slice(prefix);
        out
    }

    #[test]
    fn azureus_style_names() {
        assert_eq!(
            client_name(&id(b"-qB5230-")).as_deref(),
            Some("qBittorrent 5.2.3")
        );
        // libtorrent's letter digits for components of ten or more.
        assert_eq!(
            client_name(&id(b"-UR0E20-")).as_deref(),
            Some("urtorrent 0.14.2")
        );
        assert_eq!(
            client_name(&id(b"-TR4010-")).as_deref(),
            Some("Transmission 4.0.1")
        );
        assert_eq!(
            client_name(&id(b"-AZ2060-")).as_deref(),
            Some("Azureus 2.0.6")
        );
        assert_eq!(
            client_name(&id(b"-lt0D80-")).as_deref(),
            Some("libTorrent 0.13.8")
        );
        assert_eq!(
            client_name(&id(b"-DE2011-")).as_deref(),
            Some("Deluge 2.0.1.1")
        );
        assert_eq!(
            client_name(&id(b"-UR0400-")).as_deref(),
            Some("urtorrent 0.4.0")
        );
        // Unknown two-letter code: still Azureus style.
        assert_eq!(client_name(&id(b"-ZZ1234-")).as_deref(), Some("ZZ 1.2.3.4"));
    }

    #[test]
    fn other_styles() {
        assert_eq!(
            client_name(&id(b"S58B-----")).as_deref(),
            Some("Shadow's client 5.8.11")
        );
        assert_eq!(
            client_name(&id(b"T03A0----")).as_deref(),
            Some("BitTornado 0.3.10.0")
        );
        assert_eq!(
            client_name(&id(b"M4-3-6--")).as_deref(),
            Some("Mainline 4.3.6")
        );
        assert_eq!(
            client_name(&id(b"M4-20-8-")).as_deref(),
            Some("Mainline 4.20.8")
        );
        assert_eq!(
            client_name(&id(b"exbc\x00\x38xxxx")).as_deref(),
            Some("BitComet 0.56")
        );
        assert_eq!(
            client_name(&id(b"exbc\x01\x05LORD")).as_deref(),
            Some("BitLord 1.05")
        );
        assert_eq!(
            client_name(&id(b"XBT054d-")).as_deref(),
            Some("XBT 0.5.4 (debug)")
        );
        assert_eq!(client_name(&id(b"OP8123")).as_deref(), Some("Opera 8123"));
        assert_eq!(
            client_name(&id(b"-ML2.7.2-kgjjfkd")).as_deref(),
            Some("MLdonkey 2.7.2")
        );
        assert_eq!(
            client_name(&id(b"-BOWA0C-")).as_deref(),
            Some("Bits on Wheels A0C")
        );
        assert_eq!(
            client_name(&id(b"Q1-10-0-")).as_deref(),
            Some("Queen Bee 1.10.0")
        );
        assert_eq!(
            client_name(&id(b"AZ2500BT")).as_deref(),
            Some("BitTyrant 2.5.0.0")
        );
        assert_eq!(
            client_name(&id(b"346------")).as_deref(),
            Some("TorrenTopia 1.90")
        );
        assert_eq!(
            client_name(&id(b"\x00\x03BSabc")).as_deref(),
            Some("BitSpirit 3")
        );
        assert_eq!(client_name(&id(b"07RSnick")).as_deref(), Some("Rufus 0.7"));
        assert_eq!(client_name(&id(b"-G3nick")).as_deref(), Some("G3 Torrent"));
        assert_eq!(
            client_name(&id(b"-FG0180x")).as_deref(),
            Some("FlashGet 1.80")
        );
        assert_eq!(
            client_name(&id(b"AP1.2-abc")).as_deref(),
            Some("AllPeers 1.2")
        );
        assert_eq!(client_name(&[0xff; 20]), None);
        assert_eq!(client_name(&[b'-'; 20]), None);
    }
}
