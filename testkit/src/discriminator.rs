// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The discriminator (AGENTS.md 6): a classifier fed what a tracker (HTTP
//! layer and above) and a tap peer can observe, scoped to L1 + L2. It must
//! fail to separate the oracle from us under the qbt profile while still
//! flagging Transmission and our `native` profile. TLS and timing are out of
//! scope by design; declared-random fields (peer-id tail, `key`, ports,
//! addresses, counters) are normalised away (AGENTS.md 7.3).

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::tap::peer::PeerCapture;
use crate::tap::tracker::TapEvent;

/// What a tracker can tell about a client from one announce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackerFingerprint {
    /// First 8 bytes of the peer id (Azureus-style prefix).
    pub peer_id_prefix: String,
    /// The whole announce peer id (hex), for the cross-check against the
    /// handshake id; random by design, never compared directly.
    pub peer_id_hex: String,
    /// `User-Agent`.
    pub user_agent: Option<String>,
    /// Header names in order.
    pub headers: Vec<String>,
    /// Query parameter names in order (`event` and `trackerid` are
    /// conditional and dropped; `event` presence is checked separately).
    pub params: Vec<String>,
    /// HTTP version on the request line.
    pub http_version: String,
    /// Percent-encoding hex case (`true` = lower), if any escape was seen.
    pub lower_hex: Option<bool>,
    /// Whether `!*()` are sent literally (libtorrent) or escaped (RFC 3986),
    /// if any of them was observed either way.
    pub literal_bang_star_parens: Option<bool>,
    /// Length of `key` and whether it is upper-case hex.
    pub key: Option<(usize, bool)>,
    /// `numwant` on a regular/started announce.
    pub numwant: Option<String>,
    /// `numwant` on `stopped`.
    pub numwant_stopped: Option<String>,
    /// Fixed flag values (`compact`, `no_peer_id`, `supportcrypto`).
    pub flags: Vec<(String, String)>,
    /// Whether the announce carried an `event` parameter for `started`.
    pub started_event: bool,
}

/// What a tap peer can tell from one connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerFingerprint {
    /// Handshake reserved bytes.
    pub reserved_hex: String,
    /// Peer id prefix.
    pub peer_id_prefix: String,
    /// The whole handshake peer id (hex); see `TrackerFingerprint::peer_id_hex`.
    pub peer_id_hex: String,
    /// LTEP `m` map (name -> id), sorted.
    pub ltep_m: Vec<(String, i64)>,
    /// LTEP handshake keys present, sorted (values of random/contextual keys
    /// are ignored).
    pub ltep_keys: Vec<String>,
    /// LTEP `reqq`.
    pub reqq: Option<i64>,
    /// LTEP `v`.
    pub ltep_v: Option<String>,
    /// Kinds of the first messages after the handshake, up to (excluding) the
    /// first `request`/`piece`/`have`/`unchoke`/`interested` traffic, with
    /// repeats of `allowed_fast` collapsed to a count.
    pub first_messages: Vec<String>,
}

/// What a UDP tracker can tell from a client's datagrams (BEP 15 field
/// values; transaction and connection ids are random by design).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpFingerprint {
    /// Action sequence of the first datagrams (connect, announce, ...).
    pub first_actions: Vec<u32>,
    /// `num_want` on a started announce.
    pub num_want: Option<i32>,
    /// `num_want` on `stopped`.
    pub num_want_stopped: Option<i32>,
    /// `ip` field is zero.
    pub ip_zero: Option<bool>,
    /// The BEP 41 extension bytes after the fixed fields (URL data etc.).
    pub extensions_hex: Option<String>,
    /// Peer id prefix.
    pub peer_id_prefix: Option<String>,
    /// The announce `port` equals the datagram's source port.
    pub port_is_source: Option<bool>,
}

/// What a tap sees of a client's MSE handshake in one role (pads are
/// random and only range-checked).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MseFingerprint {
    /// `initiator` or `responder` (the tap's role, i.e. the client's inverse).
    pub tap_role: String,
    /// `crypto_provide` (client initiated) or `crypto_select` (client answered).
    pub crypto_field: Option<u32>,
    /// `len(IA)` the client announced (client initiated).
    pub ia_len: Option<usize>,
    /// Negotiated method.
    pub method: String,
    /// Both pads within 0..=512.
    pub pads_in_range: bool,
}

/// Build an MSE fingerprint from a tap-peer capture.
pub fn mse_fingerprint(c: &PeerCapture) -> Option<MseFingerprint> {
    let m = c.mse.as_ref()?;
    Some(MseFingerprint {
        tap_role: m.role.clone(),
        crypto_field: m.crypto_field,
        ia_len: m.ia_len,
        method: m.method.clone(),
        pads_in_range: m.pad_after_key.is_none_or(|p| p <= 512)
            && m.pad_crypto.is_none_or(|p| p <= 512),
    })
}

/// A client's observable identity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fingerprint {
    pub tracker: Option<TrackerFingerprint>,
    pub peer: Option<PeerFingerprint>,
    pub udp: Option<UdpFingerprint>,
    pub mse: Option<MseFingerprint>,
    pub pex: Option<PexFingerprint>,
    /// L1 (Q19): the handshake carried the same peer id as the announce for
    /// the same torrent. libtorrent 2.0 uses a fresh id per connection, so
    /// this is `false` for the oracle. Set by scenarios that observe both.
    pub handshake_id_is_announce_id: Option<bool>,
}

/// Whether the handshake id of a peer capture equals the announce id: the
/// cross-check input for [`Fingerprint::handshake_id_is_announce_id`].
pub fn handshake_id_is_announce_id(tracker: &TrackerFingerprint, peer: &PeerFingerprint) -> bool {
    tracker.peer_id_hex == peer.peer_id_hex
}

/// What a tap peer can tell from the first `ut_pex` message it receives
/// (BEP 11; libtorrent-specific shape).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PexFingerprint {
    /// Dictionary keys present, sorted (libtorrent always writes all six).
    pub keys: Vec<String>,
    /// `added.f` / `added6.f` have one byte per `added` / `added6` entry.
    pub flags_consistent: bool,
    /// The recipient's own IP appears in the list (libtorrent does not
    /// exclude the recipient from the full list).
    pub includes_recipient_ip: bool,
    /// Flag bits used across every entry (`0x10` never by libtorrent 2.0).
    pub flag_bits: u8,
}

/// Build a PEX fingerprint from the first `ut_pex` message in `c` (the tap
/// advertised `ut_pex` under `tap_pex_id`).
pub fn pex_fingerprint(c: &PeerCapture, tap_pex_id: u64) -> Option<PexFingerprint> {
    let ev = c.recv().find(|e| {
        e.kind == "extended" && e.detail.get("ext_id").and_then(|v| v.as_u64()) == Some(tap_pex_id)
    })?;
    let raw = crate::bencode::unhex(ev.detail.get("raw_hex")?.as_str()?)?;
    let (v, _) = crate::bencode::decode_prefix(&raw).ok()?;
    let crate::bencode::Value::Dict(entries) = &v else {
        return None;
    };
    let keys: Vec<String> = entries
        .keys()
        .map(|k| String::from_utf8_lossy(k).into_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let bytes = |k: &str| v.get(k).and_then(|x| x.as_bytes()).unwrap_or(&[]).to_vec();
    let added = bytes("added");
    let added_f = bytes("added.f");
    let added6 = bytes("added6");
    let added6_f = bytes("added6.f");
    let flags_consistent = added.len() / 6 == added_f.len() && added6.len() / 18 == added6_f.len();
    let local_ip = c.local.ip();
    let mut includes = false;
    for e in added.as_chunks::<6>().0 {
        if IpAddr::from([e[0], e[1], e[2], e[3]]) == local_ip {
            includes = true;
        }
    }
    for e in added6.as_chunks::<18>().0 {
        let mut o = [0u8; 16];
        o.copy_from_slice(&e[..16]);
        if IpAddr::from(o) == local_ip {
            includes = true;
        }
    }
    let flag_bits = added_f
        .iter()
        .chain(added6_f.iter())
        .fold(0u8, |a, b| a | b);
    Some(PexFingerprint {
        keys,
        flags_consistent,
        includes_recipient_ip: includes,
        flag_bits,
    })
}

/// Build a UDP fingerprint from the datagrams sent by `ips`.
pub fn udp_fingerprint(events: &[TapEvent], ips: &[IpAddr]) -> Option<UdpFingerprint> {
    let ours: Vec<&TapEvent> = events
        .iter()
        .filter(|e| e.transport == "udp" && ips.contains(&e.from.ip()) && e.udp.is_some())
        .collect();
    if ours.is_empty() {
        return None;
    }
    let first_actions = ours
        .iter()
        .take(2)
        .filter_map(|e| e.udp.as_ref().map(|u| u.action))
        .collect();
    let announces: Vec<(&TapEvent, &crate::tap::tracker::UdpAnnounce)> = ours
        .iter()
        .filter_map(|e| {
            e.udp
                .as_ref()
                .and_then(|u| u.announce.as_ref())
                .map(|a| (*e, a))
        })
        .collect();
    let started = announces
        .iter()
        .find(|(_, a)| a.event == 2)
        .or(announces.first());
    let stopped = announces.iter().find(|(_, a)| a.event == 3);
    Some(UdpFingerprint {
        first_actions,
        num_want: started.map(|(_, a)| a.num_want),
        num_want_stopped: stopped.map(|(_, a)| a.num_want),
        ip_zero: started.map(|(_, a)| a.ip == 0),
        extensions_hex: started.map(|(_, a)| a.extensions_hex.clone()),
        peer_id_prefix: started.map(|(_, a)| a.peer_id.chars().take(8).collect()),
        port_is_source: started.map(|(e, a)| a.port == e.from.port()),
    })
}

fn query<'a>(e: &'a TapEvent, key: &str) -> Option<&'a str> {
    e.http
        .as_ref()?
        .query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn header<'a>(e: &'a TapEvent, key: &str) -> Option<&'a str> {
    e.http
        .as_ref()?
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

/// Build a tracker fingerprint from the announces sent by `ips` (all of them
/// must agree; the first `started` announce and the `stopped` one, if any,
/// supply the event-dependent fields).
pub fn tracker_fingerprint(events: &[TapEvent], ips: &[IpAddr]) -> Option<TrackerFingerprint> {
    let ours: Vec<&TapEvent> = events
        .iter()
        .filter(|e| e.kind == "announce" && ips.contains(&e.from.ip()) && e.http.is_some())
        .collect();
    let first = *ours.first()?;
    let h = first.http.as_ref()?;
    let peer_id_raw = crate::http::percent_decode(query(first, "peer_id")?.as_bytes());
    let peer_id_prefix =
        String::from_utf8_lossy(&peer_id_raw[..peer_id_raw.len().min(8)]).into_owned();
    let peer_id_hex = crate::bencode::hex(&peer_id_raw);
    // Escape style from every escaped byte in binary-valued params.
    let mut lower = None;
    let mut literal = None;
    for e in &ours {
        for key in ["info_hash", "peer_id"] {
            let Some(v) = query(e, key) else { continue };
            let bytes = v.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' && i + 2 < bytes.len() {
                    let hex = &v[i + 1..i + 3];
                    {
                        if hex.chars().any(|c| c.is_ascii_lowercase()) {
                            lower = Some(true);
                        } else if hex.chars().any(|c| c.is_ascii_uppercase()) {
                            lower = Some(false);
                        }
                        if matches!(hex.to_ascii_uppercase().as_str(), "21" | "2A" | "28" | "29") {
                            literal = Some(false);
                        }
                        i += 3;
                        continue;
                    }
                }
                if matches!(bytes[i], b'!' | b'*' | b'(' | b')') {
                    literal = Some(true);
                }
                i += 1;
            }
        }
    }
    let started = ours
        .iter()
        .find(|e| query(e, "event") == Some("started"))
        .copied()
        .unwrap_or(first);
    let stopped = ours.iter().find(|e| query(e, "event") == Some("stopped"));
    let params: Vec<String> = started
        .http
        .as_ref()?
        .query
        .iter()
        .map(|(k, _)| k.clone())
        .filter(|k| k != "event" && k != "trackerid")
        .collect();
    let key = query(started, "key").map(|k| {
        (
            k.len(),
            k.chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase()),
        )
    });
    let flags = ["compact", "no_peer_id", "supportcrypto"]
        .iter()
        .filter_map(|f| query(started, f).map(|v| (f.to_string(), v.to_string())))
        .collect();
    Some(TrackerFingerprint {
        peer_id_prefix,
        peer_id_hex,
        user_agent: header(first, "User-Agent").map(str::to_string),
        headers: h.headers.iter().map(|(k, _)| k.clone()).collect(),
        params,
        http_version: h.version.clone(),
        lower_hex: lower,
        literal_bang_star_parens: literal,
        key,
        numwant: query(started, "numwant").map(str::to_string),
        numwant_stopped: stopped
            .and_then(|e| query(e, "numwant"))
            .map(str::to_string),
        flags,
        started_event: query(started, "event") == Some("started"),
    })
}

/// Build a peer fingerprint from one captured connection (the remote side's
/// behaviour).
pub fn peer_fingerprint(c: &PeerCapture) -> Option<PeerFingerprint> {
    let hs = c.handshake.as_ref()?;
    let mut ltep_m = Vec::new();
    let mut ltep_keys = Vec::new();
    let mut reqq = None;
    let mut ltep_v = None;
    if let Some(ext) = c.ext_handshake()
        && let Some(d) = ext.get("dict").and_then(|d| d.as_object())
    {
        ltep_keys = d
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if let Some(m) = d.get("m").and_then(|m| m.as_object()) {
            ltep_m = m
                .iter()
                .map(|(k, v)| (k.clone(), v.as_i64().unwrap_or(-1)))
                .collect();
            ltep_m.sort();
        }
        reqq = d.get("reqq").and_then(|v| v.as_i64());
        ltep_v = d.get("v").and_then(|v| v.as_str()).map(str::to_string);
    }
    let mut first_messages = Vec::new();
    let mut allowed_fast = 0usize;
    for ev in c.recv() {
        match ev.kind.as_str() {
            "handshake" => continue,
            "request" | "piece" | "have" | "unchoke" | "interested" | "not_interested"
            | "keep_alive" | "cancel" | "choke" => break,
            "allowed_fast" => allowed_fast += 1,
            other => {
                if allowed_fast > 0 {
                    first_messages.push(format!("allowed_fast x{allowed_fast}"));
                    allowed_fast = 0;
                }
                first_messages.push(other.to_string());
            }
        }
    }
    if allowed_fast > 0 {
        first_messages.push(format!("allowed_fast x{allowed_fast}"));
    }
    Some(PeerFingerprint {
        reserved_hex: hs.reserved_hex.clone(),
        peer_id_prefix: hs.peer_id_text.chars().take(8).collect(),
        peer_id_hex: hs.peer_id_hex.clone(),
        ltep_m,
        ltep_keys,
        reqq,
        ltep_v,
        first_messages,
    })
}

/// Differences between two fingerprints, as human-readable L1/L2 findings.
/// Empty means the discriminator cannot tell them apart.
pub fn diff(a: &Fingerprint, b: &Fingerprint) -> Vec<String> {
    let mut out = Vec::new();
    match (&a.tracker, &b.tracker) {
        (Some(x), Some(y)) => {
            macro_rules! cmp {
                ($field:ident, $label:expr) => {
                    if x.$field != y.$field {
                        out.push(format!("{}: {:?} vs {:?}", $label, x.$field, y.$field));
                    }
                };
            }
            cmp!(peer_id_prefix, "L1 peer-id prefix");
            cmp!(user_agent, "L1 User-Agent");
            cmp!(headers, "L2 header order");
            cmp!(params, "L2 announce parameter order");
            cmp!(http_version, "L2 HTTP version");
            cmp!(key, "L1 key format");
            cmp!(numwant, "L2 numwant");
            cmp!(flags, "L2 flags");
            cmp!(started_event, "L2 started event");
            if let (Some(p), Some(q)) = (x.lower_hex, y.lower_hex)
                && p != q
            {
                out.push(format!("L2 escape hex case: lower={p} vs lower={q}"));
            }
            if let (Some(p), Some(q)) = (x.literal_bang_star_parens, y.literal_bang_star_parens)
                && p != q
            {
                out.push(format!("L2 escape of !*(): literal={p} vs literal={q}"));
            }
            if let (Some(p), Some(q)) = (&x.numwant_stopped, &y.numwant_stopped)
                && p != q
            {
                out.push(format!("L2 numwant on stopped: {p} vs {q}"));
            }
        }
        (None, None) => {}
        _ => out.push("tracker observation missing on one side".into()),
    }
    match (&a.udp, &b.udp) {
        (Some(x), Some(y)) => {
            macro_rules! cmp {
                ($field:ident, $label:expr) => {
                    if x.$field != y.$field {
                        out.push(format!("{}: {:?} vs {:?}", $label, x.$field, y.$field));
                    }
                };
            }
            cmp!(first_actions, "L2 udp action sequence");
            cmp!(num_want, "L2 udp num_want");
            cmp!(ip_zero, "L2 udp ip field");
            cmp!(extensions_hex, "L2 udp extensions (BEP 41)");
            cmp!(peer_id_prefix, "L1 peer-id prefix (udp)");
            cmp!(port_is_source, "L2 udp announce port vs source port");
            if let (Some(p), Some(q)) = (x.num_want_stopped, y.num_want_stopped)
                && p != q
            {
                out.push(format!("L2 udp num_want on stopped: {p} vs {q}"));
            }
        }
        (None, None) => {}
        _ => out.push("udp observation missing on one side".into()),
    }
    match (&a.mse, &b.mse) {
        (Some(x), Some(y)) => {
            if x.tap_role != y.tap_role {
                out.push(format!(
                    "mse: different roles observed ({} vs {})",
                    x.tap_role, y.tap_role
                ));
            } else {
                if x.crypto_field != y.crypto_field {
                    out.push(format!(
                        "L2 mse crypto field: {:?} vs {:?}",
                        x.crypto_field, y.crypto_field
                    ));
                }
                if x.ia_len != y.ia_len {
                    out.push(format!("L2 mse len(IA): {:?} vs {:?}", x.ia_len, y.ia_len));
                }
                if x.method != y.method {
                    out.push(format!("L2 mse method: {} vs {}", x.method, y.method));
                }
                if x.pads_in_range != y.pads_in_range {
                    out.push("L2 mse pad range".into());
                }
            }
        }
        (None, None) => {}
        _ => out.push("mse observation missing on one side".into()),
    }
    match (&a.peer, &b.peer) {
        (Some(x), Some(y)) => {
            macro_rules! cmp {
                ($field:ident, $label:expr) => {
                    if x.$field != y.$field {
                        out.push(format!("{}: {:?} vs {:?}", $label, x.$field, y.$field));
                    }
                };
            }
            cmp!(reserved_hex, "L2 reserved bits");
            cmp!(peer_id_prefix, "L1 peer-id prefix (handshake)");
            cmp!(ltep_m, "L2 LTEP m map");
            cmp!(ltep_keys, "L2 LTEP handshake keys");
            cmp!(reqq, "L2 LTEP reqq");
            cmp!(ltep_v, "L1 LTEP v");
            cmp!(first_messages, "L2 first-messages sequence");
        }
        (None, None) => {}
        _ => out.push("peer observation missing on one side".into()),
    }
    // L1 (Q19): a client reusing its announce id in handshakes is told apart.
    if let (Some(x), Some(y)) = (a.handshake_id_is_announce_id, b.handshake_id_is_announce_id)
        && x != y
    {
        out.push(format!("L1 handshake id equals announce id: {x} vs {y}"));
    }
    // PEX is only observable in scenarios built for it; its absence on one
    // side is not a tell.
    if let (Some(x), Some(y)) = (&a.pex, &b.pex) {
        if x.keys != y.keys {
            out.push(format!("L2 ut_pex keys: {:?} vs {:?}", x.keys, y.keys));
        }
        if x.flags_consistent != y.flags_consistent {
            out.push("L2 ut_pex flags length".into());
        }
        if x.includes_recipient_ip != y.includes_recipient_ip {
            out.push(format!(
                "L2 ut_pex includes recipient: {} vs {}",
                x.includes_recipient_ip, y.includes_recipient_ip
            ));
        }
        if (x.flag_bits & 0x10) != (y.flag_bits & 0x10) {
            out.push("L2 ut_pex 0x10 flag use".into());
        }
    }
    out
}

/// The oracle's fingerprint from the committed golden captures (the spec).
pub fn golden_oracle() -> anyhow::Result<Fingerprint> {
    use crate::lab::Shape;
    use crate::scenario::golden_file;
    let mut fp = Fingerprint::default();
    if let Some(p) = golden_file("capture_tracker_http", Shape::V4, "tap-tracker.jsonl") {
        let events: Vec<TapEvent> = std::fs::read_to_string(p)?
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        // The leecher's announces: the source that announced `left != 0` first.
        let ips: Vec<IpAddr> = events
            .iter()
            .filter(|e| e.kind == "announce" && query(e, "left").is_some_and(|l| l != "0"))
            .map(|e| e.from.ip())
            .take(1)
            .collect();
        fp.tracker = tracker_fingerprint(&events, &ips);
    }
    if let Some(p) = golden_file(
        "capture_peer_plain",
        Shape::V4,
        "tap-peer-plain-oracle-initiator.jsonl",
    ) {
        let caps: Vec<PeerCapture> = std::fs::read_to_string(p)?
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        fp.peer = caps.iter().find_map(peer_fingerprint);
        // The same scenario's tracker log carries the oracle's announce id
        // for the torrent it fetched from the tap seeder: the Q19 cross-check.
        if let (Some(peer), Some(tp)) = (
            fp.peer.clone(),
            golden_file("capture_peer_plain", Shape::V4, "tap-tracker-plain.jsonl"),
        ) {
            let events: Vec<TapEvent> = std::fs::read_to_string(tp)?
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
            let ih_hex = caps
                .iter()
                .find_map(|c| c.handshake.as_ref().map(|h| h.info_hash.clone()));
            let ips: Vec<IpAddr> = peer_ip_of(&caps).into_iter().collect();
            let matching: Vec<TapEvent> = events
                .into_iter()
                .filter(|e| {
                    e.kind == "announce"
                        && query(e, "info_hash").is_some_and(|q| {
                            let raw = crate::http::percent_decode(q.as_bytes());
                            Some(crate::bencode::hex(&raw)) == ih_hex
                        })
                })
                .collect();
            if let Some(t) = tracker_fingerprint(&matching, &ips) {
                fp.handshake_id_is_announce_id = Some(handshake_id_is_announce_id(&t, &peer));
            }
        }
    }
    if let Some(p) = golden_file("capture_pex", Shape::V4, "tap-peer-pex-A.jsonl") {
        let caps: Vec<PeerCapture> = std::fs::read_to_string(p)?
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        // The tap advertises `ut_pex` as 1 (`TapPeerConfig::new`).
        fp.pex = caps.iter().find_map(|c| pex_fingerprint(c, 1));
    }
    Ok(fp)
}

/// The remote address of the first handshaken connection in `caps`.
fn peer_ip_of(caps: &[PeerCapture]) -> Option<IpAddr> {
    caps.iter()
        .find(|c| c.handshake.is_some())
        .map(|c| c.remote.ip())
}

/// Name the client a fingerprint most likely belongs to.
pub fn classify(fp: &Fingerprint) -> &'static str {
    let prefix = fp
        .tracker
        .as_ref()
        .map(|t| t.peer_id_prefix.clone())
        .or_else(|| fp.peer.as_ref().map(|p| p.peer_id_prefix.clone()))
        .unwrap_or_default();
    if let Ok(oracle) = golden_oracle()
        && diff(&oracle, fp).is_empty()
    {
        return "qBittorrent 5.2.3 / libtorrent 2.0.14 (indistinguishable from the oracle)";
    }
    if prefix.starts_with("-TR") {
        "Transmission"
    } else if prefix.starts_with("-UR") {
        "urtorrent (native profile)"
    } else if prefix.starts_with("-qB") {
        "claims qBittorrent but differs from the oracle"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tap::tracker::HttpView;
    use std::net::SocketAddr;

    fn event(from: &str, line: &str) -> TapEvent {
        let (method, rest) = line.split_once(' ').unwrap();
        let (target, version) = rest.rsplit_once(' ').unwrap();
        let (path, q) = target.split_once('?').unwrap();
        let query = q
            .split('&')
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            })
            .collect();
        TapEvent {
            ts_ms: 0,
            transport: "http".into(),
            from: from.parse::<SocketAddr>().unwrap(),
            to: "10.0.0.1:7070".parse().unwrap(),
            kind: "announce".into(),
            raw_hex: String::new(),
            http: Some(HttpView {
                request_line: line.to_string(),
                method: method.to_string(),
                path: path.to_string(),
                version: version.to_string(),
                headers: vec![
                    ("Host".into(), "10.0.0.1:7070".into()),
                    ("User-Agent".into(), "Transmission/4.1.1".into()),
                    ("Accept-Encoding".into(), "deflate, gzip".into()),
                ],
                query,
            }),
            udp: None,
            response_hex: String::new(),
        }
    }

    #[test]
    fn oracle_golden_is_self_consistent_and_transmission_differs() {
        let oracle = golden_oracle().unwrap();
        assert!(oracle.tracker.is_some() && oracle.peer.is_some());
        assert!(diff(&oracle, &oracle).is_empty());
        assert!(classify(&oracle).starts_with("qBittorrent"));
        // A Transmission announce as seen in the lab (uppercase hex, own order).
        let tr = event(
            "10.0.0.11:5000",
            "GET /announce?info_hash=%88%3A%1E%EC%C0%C4%8Fj%ED%C0jPi%8ABD%AB%8A%B8%BF&peer_id=-TR4110-4fpjabbr2ey8&port=51413&uploaded=0&downloaded=0&left=4194304&numwant=80&key=59FC7E97&compact=1&supportcrypto=1&event=started HTTP/1.1",
        );
        let fp = Fingerprint {
            tracker: tracker_fingerprint(&[tr], &["10.0.0.11".parse().unwrap()]),
            peer: None,
            udp: None,
            mse: None,
            pex: None,
            handshake_id_is_announce_id: None,
        };
        let d = diff(
            &Fingerprint {
                tracker: oracle.tracker.clone(),
                peer: None,
                udp: None,
                mse: None,
                pex: None,
                handshake_id_is_announce_id: None,
            },
            &fp,
        );
        assert!(
            d.iter().any(|x| x.starts_with("L1 peer-id prefix")),
            "{d:?}"
        );
        assert!(
            d.iter()
                .any(|x| x.starts_with("L2 announce parameter order")),
            "{d:?}"
        );
        assert!(d.iter().any(|x| x.contains("hex case")), "{d:?}");
        assert_eq!(classify(&fp), "Transmission");
    }

    #[test]
    fn our_qbt_profile_matches_the_oracle_on_the_tracker_side() {
        // Build an announce with the library's own tracker crate under the qbt
        // profile and fingerprint it the way a tracker would.
        let oracle = golden_oracle().unwrap();
        let profile = profile::Profile::qbt_5_2_3_lt2_0_14();
        let req = tracker::AnnounceRequest {
            info_hash: [
                0xe9, 0x8b, 0x27, 0x01, 0xd6, 0x9b, 0x49, 0xe7, 0x8b, 0x07, 0xa5, 0x0e, 0x0b, 0xc2,
                0x2c, 0x8a, 0x9d, 0xac, 0xee, 0x20,
            ],
            peer_id: *b"-qB5230-PyFu!8(YVAlz",
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 2_097_152,
            corrupt: 0,
            redundant: 0,
            key: 0xC8445FFC,
            event: tracker::AnnounceEvent::Started,
            tracker_id: None,
            crypto_supported: true,
        };
        let url = tracker::Url::parse("http://10.0.0.1:7070/announce").unwrap();
        let bytes = req.http_request(&url, &profile);
        let raw = crate::http::read_request(&mut std::io::Cursor::new(bytes))
            .unwrap()
            .unwrap();
        let ev = TapEvent {
            ts_ms: 0,
            transport: "http".into(),
            from: "10.0.0.11:5000".parse().unwrap(),
            to: "10.0.0.1:7070".parse().unwrap(),
            kind: "announce".into(),
            raw_hex: String::new(),
            http: Some(HttpView {
                request_line: format!("{} {} {}", raw.method, raw.target, raw.version),
                method: raw.method.clone(),
                path: raw.path().to_string(),
                version: raw.version.clone(),
                headers: raw.headers.clone(),
                query: raw.query().params.clone(),
            }),
            udp: None,
            response_hex: String::new(),
        };
        let fp = Fingerprint {
            tracker: tracker_fingerprint(&[ev], &["10.0.0.11".parse().unwrap()]),
            peer: None,
            udp: None,
            mse: None,
            pex: None,
            handshake_id_is_announce_id: None,
        };
        let d = diff(
            &Fingerprint {
                tracker: oracle.tracker.clone(),
                peer: None,
                udp: None,
                mse: None,
                pex: None,
                handshake_id_is_announce_id: None,
            },
            &fp,
        );
        assert!(d.is_empty(), "tracker-side tells: {d:?}");
    }
}
