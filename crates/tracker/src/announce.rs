// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! HTTP announce: request building and response parsing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bencode::{Decoder, Value};
use metainfo::InfoHash;
use profile::{AnnounceHeader, AnnounceParam, Profile};

use crate::Error;
use crate::url::Url;

/// Upper bound on peers taken from one response (remote input is bounded).
pub const MAX_PEERS: usize = 10_000;

/// The announce `event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceEvent {
    /// Regular periodic announce (no `event` parameter).
    None,
    /// First announce for this torrent to this tracker.
    Started,
    /// The download finished.
    Completed,
    /// We are going away.
    Stopped,
}

impl AnnounceEvent {
    fn as_str(self) -> Option<&'static str> {
        match self {
            AnnounceEvent::None => None,
            AnnounceEvent::Started => Some("started"),
            AnnounceEvent::Completed => Some("completed"),
            AnnounceEvent::Stopped => Some("stopped"),
        }
    }
}

/// Everything an announce carries. All counters are truthful (AGENTS.md rule
/// 1): they come straight from the session's accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceRequest {
    /// The torrent.
    pub info_hash: InfoHash,
    /// Our peer id.
    pub peer_id: [u8; 20],
    /// Our listen port.
    pub port: u16,
    /// Payload bytes uploaded.
    pub uploaded: u64,
    /// Payload bytes downloaded.
    pub downloaded: u64,
    /// Bytes still needed.
    pub left: u64,
    /// Bytes that failed the hash check.
    pub corrupt: u64,
    /// Bytes received redundantly (duplicate blocks).
    pub redundant: u64,
    /// The announce key for this torrent.
    pub key: u32,
    /// The event.
    pub event: AnnounceEvent,
    /// `tracker id` returned by an earlier response, if any.
    pub tracker_id: Option<Vec<u8>>,
    /// Whether encryption (MSE) is not disabled on our side: drives
    /// `supportcrypto=1` (docs/quirks.md Q8).
    pub crypto_supported: bool,
    /// BEP 7 `ipv4=` hints: our IPv4 listen addresses worth telling the
    /// tracker (libtorrent sends them for private torrents when the listen
    /// address is explicit and public; empty otherwise).
    pub ipv4_hints: Vec<std::net::Ipv4Addr>,
    /// BEP 7 `ipv6=` hints, same rule.
    pub ipv6_hints: Vec<std::net::Ipv6Addr>,
}

impl AnnounceRequest {
    /// Render the query string (after the `?`/`&`) in the profile's order.
    pub fn query(&self, profile: &Profile) -> String {
        let shape = &profile.http;
        let esc = shape.escape;
        let mut parts: Vec<String> = Vec::with_capacity(shape.params.len());
        let flag = |b: bool| if b { "1" } else { "0" };
        for p in shape.params {
            let kv = match p {
                AnnounceParam::InfoHash => format!("info_hash={}", esc.escape(&self.info_hash)),
                AnnounceParam::PeerId => format!("peer_id={}", esc.escape(&self.peer_id)),
                AnnounceParam::Port => format!("port={}", self.port),
                AnnounceParam::Uploaded => format!("uploaded={}", self.uploaded),
                AnnounceParam::Downloaded => format!("downloaded={}", self.downloaded),
                AnnounceParam::Left => format!("left={}", self.left),
                AnnounceParam::Corrupt => format!("corrupt={}", self.corrupt),
                AnnounceParam::Key => format!("key={}", shape.key.render(self.key)),
                AnnounceParam::Event => match self.event.as_str() {
                    Some(e) => format!("event={e}"),
                    None => continue,
                },
                AnnounceParam::Numwant => {
                    let n = if self.event == AnnounceEvent::Stopped {
                        shape.numwant_stopped
                    } else {
                        shape.numwant
                    };
                    format!("numwant={n}")
                }
                AnnounceParam::Compact => format!("compact={}", flag(shape.compact)),
                AnnounceParam::NoPeerId => format!("no_peer_id={}", flag(shape.no_peer_id)),
                AnnounceParam::SupportCrypto => {
                    if shape.supportcrypto && self.crypto_supported {
                        "supportcrypto=1".to_string()
                    } else {
                        continue;
                    }
                }
                AnnounceParam::Redundant => format!("redundant={}", self.redundant),
                AnnounceParam::TrackerId => match &self.tracker_id {
                    Some(id) => format!("trackerid={}", esc.escape(id)),
                    None => continue,
                },
                AnnounceParam::Ipv4Hints => {
                    for a in &self.ipv4_hints {
                        parts.push(format!("ipv4={a}"));
                    }
                    continue;
                }
                AnnounceParam::Ipv6Hints => {
                    for a in &self.ipv6_hints {
                        parts.push(format!("ipv6={}", esc.escape(a.to_string().as_bytes())));
                    }
                    continue;
                }
            };
            parts.push(kv);
        }
        parts.join("&")
    }

    /// The full HTTP request bytes for `url` (request line + headers in the
    /// profile's order, no body).
    pub fn http_request(&self, url: &Url, profile: &Profile) -> Vec<u8> {
        let mut target = url.path.clone();
        match &url.query {
            Some(q) if !q.is_empty() => {
                target.push('?');
                target.push_str(q);
                target.push('&');
            }
            _ => target.push('?'),
        }
        target.push_str(&self.query(profile));
        let mut out = format!("GET {target} HTTP/1.1\r\n");
        for h in profile.http.headers {
            match h {
                AnnounceHeader::Host => {
                    out.push_str("Host: ");
                    out.push_str(&url.host_header(profile.http.host_port));
                    out.push_str("\r\n");
                }
                AnnounceHeader::UserAgent => {
                    out.push_str("User-Agent: ");
                    out.push_str(profile.user_agent);
                    out.push_str("\r\n");
                }
                AnnounceHeader::AcceptEncodingGzip => out.push_str("Accept-Encoding: gzip\r\n"),
                AnnounceHeader::ConnectionClose => out.push_str("Connection: close\r\n"),
            }
        }
        out.push_str("\r\n");
        out.into_bytes()
    }
}

/// A parsed announce response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnnounceResponse {
    /// Seconds until the next regular announce.
    pub interval: u32,
    /// Minimum seconds between announces, if given.
    pub min_interval: Option<u32>,
    /// `tracker id` to echo back, if given.
    pub tracker_id: Option<Vec<u8>>,
    /// Seeders (`complete`), if given.
    pub complete: Option<u32>,
    /// Leechers (`incomplete`), if given.
    pub incomplete: Option<u32>,
    /// Completed downloads (`downloaded`), if given.
    pub downloaded: Option<u32>,
    /// `warning message`, if given.
    pub warning: Option<String>,
    /// Peers from `peers` (compact or dict form) and `peers6`, in order.
    pub peers: Vec<SocketAddr>,
    /// `external ip`, if given.
    pub external_ip: Option<IpAddr>,
}

/// Interval used when the tracker gives none (libtorrent's default).
pub const DEFAULT_INTERVAL: u32 = 1800;

impl AnnounceResponse {
    /// Parse a bencoded announce response body.
    pub fn parse(body: &[u8]) -> Result<AnnounceResponse, Error> {
        let root = Decoder::new(body)
            .decode_all()
            .map_err(|_| Error::Response("not bencode"))?;
        if root.kind() != bencode::ValueKind::Dict {
            return Err(Error::Response("not a dictionary"));
        }
        if let Some(reason) = root.get_str("failure reason").and_then(Value::as_bytes) {
            return Err(Error::Failure(lossy(reason, 512)));
        }
        let int_u32 = |key: &str| -> Option<u32> {
            root.get_str(key)
                .and_then(Value::as_int)
                .filter(|v| *v >= 0)
                .map(|v| v.min(i64::from(u32::MAX)) as u32)
        };
        let mut resp = AnnounceResponse {
            interval: int_u32("interval").unwrap_or(DEFAULT_INTERVAL),
            min_interval: int_u32("min interval"),
            tracker_id: root
                .get_str("tracker id")
                .and_then(Value::as_bytes)
                .map(|b| b[..b.len().min(256)].to_vec()),
            complete: int_u32("complete"),
            incomplete: int_u32("incomplete"),
            downloaded: int_u32("downloaded"),
            warning: root
                .get_str("warning message")
                .and_then(Value::as_bytes)
                .map(|b| lossy(b, 512)),
            peers: Vec::new(),
            external_ip: root
                .get_str("external ip")
                .and_then(Value::as_bytes)
                .and_then(ip_from_bytes),
        };
        match root.get_str("peers") {
            Some(Value::Bytes(compact)) => {
                for chunk in compact.as_chunks::<6>().0.iter().take(MAX_PEERS) {
                    let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                    let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                    resp.peers.push(SocketAddr::new(IpAddr::V4(ip), port));
                }
            }
            Some(Value::List { items, .. }) => {
                for it in items.iter().take(MAX_PEERS) {
                    let Some(ip) = it.get_str("ip").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(port) = it
                        .get_str("port")
                        .and_then(Value::as_int)
                        .filter(|p| (0..=65535).contains(p))
                    else {
                        continue;
                    };
                    if let Ok(ip) = ip.parse::<IpAddr>() {
                        resp.peers.push(SocketAddr::new(ip, port as u16));
                    }
                }
            }
            Some(_) => return Err(Error::Response("bad peers")),
            None => {}
        }
        if let Some(Value::Bytes(compact6)) = root.get_str("peers6") {
            for chunk in compact6
                .as_chunks::<18>()
                .0
                .iter()
                .take(MAX_PEERS.saturating_sub(resp.peers.len()))
            {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&chunk[..16]);
                let port = u16::from_be_bytes([chunk[16], chunk[17]]);
                resp.peers
                    .push(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port));
            }
        }
        Ok(resp)
    }
}

fn lossy(b: &[u8], max: usize) -> String {
    String::from_utf8_lossy(&b[..b.len().min(max)]).into_owned()
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
    use proptest::prelude::*;

    fn req(event: AnnounceEvent) -> AnnounceRequest {
        AnnounceRequest {
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
            event,
            tracker_id: None,
            crypto_supported: true,
            ipv4_hints: Vec::new(),
            ipv6_hints: Vec::new(),
        }
    }

    /// Byte-exact against the golden capture
    /// (`testkit/golden/capture_tracker_http/v4/tap-tracker.jsonl`, leecher's
    /// `started` announce).
    #[test]
    fn qbt_started_announce_matches_golden() {
        let p = Profile::qbt_5_2_3_lt2_0_14();
        let url = Url::parse("http://10.77.142.1:7070/announce").unwrap();
        let bytes = req(AnnounceEvent::Started).http_request(&url, &p);
        let expected = "GET /announce?info_hash=%e9%8b%27%01%d6%9bI%e7%8b%07%a5%0e%0b%c2%2c%8a%9d%ac%ee%20&peer_id=-qB5230-PyFu!8(YVAlz&port=6881&uploaded=0&downloaded=0&left=2097152&corrupt=0&key=C8445FFC&event=started&numwant=200&compact=1&no_peer_id=1&supportcrypto=1&redundant=0 HTTP/1.1\r\nHost: 10.77.142.1:7070\r\nUser-Agent: qBittorrent/5.2.3\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n";
        assert_eq!(String::from_utf8(bytes).unwrap(), expected);
    }

    #[test]
    fn stopped_uses_numwant_zero_and_regular_has_no_event() {
        let p = Profile::qbt_5_2_3_lt2_0_14();
        let q = req(AnnounceEvent::Stopped).query(&p);
        assert!(q.contains("&event=stopped&numwant=0&"));
        let q = req(AnnounceEvent::None).query(&p);
        assert!(!q.contains("event="));
        assert!(q.contains("&key=C8445FFC&numwant=200&"));
    }

    #[test]
    fn passkey_query_is_preserved() {
        let p = Profile::native();
        let url = Url::parse("https://pt.example/abc123/announce.php?x=1").unwrap();
        let bytes = req(AnnounceEvent::None).http_request(&url, &p);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("GET /abc123/announce.php?x=1&info_hash="));
        assert!(s.contains("\r\nHost: pt.example\r\n"));
        assert!(s.contains("\r\nUser-Agent: urtorrent/0.6.0\r\n"));
    }

    #[test]
    fn supportcrypto_follows_the_encryption_setting() {
        let p = Profile::qbt_5_2_3_lt2_0_14();
        let mut r = req(AnnounceEvent::None);
        r.crypto_supported = false;
        let q = r.query(&p);
        assert!(!q.contains("supportcrypto"), "{q}");
        assert!(q.contains("&no_peer_id=1&redundant=0"), "{q}");
    }

    #[test]
    fn trackerid_echoed() {
        let p = Profile::native();
        let mut r = req(AnnounceEvent::None);
        r.tracker_id = Some(b"t k".to_vec());
        assert!(r.query(&p).ends_with("&redundant=0&trackerid=t%20k"));
    }

    /// BEP 7 hints (private torrents, libtorrent's rule): after `redundant`
    /// and any tracker id, one `ipv4=` / `ipv6=` per listen address, the v6
    /// text percent-escaped.
    #[test]
    fn ipv4_ipv6_hints_trail_the_query() {
        let p = Profile::qbt_5_2_3_lt2_0_14();
        let mut r = req(AnnounceEvent::Started);
        r.tracker_id = Some(b"tid".to_vec());
        r.ipv4_hints = vec!["203.0.113.7".parse().unwrap()];
        r.ipv6_hints = vec!["2001:db8::7".parse().unwrap()];
        let q = r.query(&p);
        assert!(
            q.ends_with("&redundant=0&trackerid=tid&ipv4=203.0.113.7&ipv6=2001%3adb8%3a%3a7"),
            "{q}"
        );
        // Nothing for a public torrent (the caller leaves the hints empty).
        let r = req(AnnounceEvent::Started);
        assert!(r.query(&p).ends_with("&redundant=0"));
    }

    #[test]
    fn parses_golden_responses() {
        // From the capture: compact v4 peers.
        let body = b"d8:completei1e10:downloadedi0e10:incompletei1e8:intervali30e12:min intervali10e5:peers6:\n\x4d\x8e\n\x1a\xe1e";
        let r = AnnounceResponse::parse(body).unwrap();
        assert_eq!(r.interval, 30);
        assert_eq!(r.min_interval, Some(10));
        assert_eq!(r.complete, Some(1));
        assert_eq!(r.peers, vec!["10.77.142.10:6881".parse().unwrap()]);
        // peers6 (v6 capture)
        let mut body6 = b"d8:intervali30e5:peers0:6:peers618:".to_vec();
        body6.extend_from_slice(&[
            0xfd, 0x77, 0, 0x8e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x1a, 0xe1,
        ]);
        body6.push(b'e');
        let r = AnnounceResponse::parse(&body6).unwrap();
        assert_eq!(r.peers, vec!["[fd77:8e::a]:6881".parse().unwrap()]);
    }

    #[test]
    fn dict_peers_failure_and_defaults() {
        let r = AnnounceResponse::parse(
            b"d5:peersld2:ip9:127.0.0.14:porti6881eed2:ip3:::14:porti1eeee",
        )
        .unwrap();
        assert_eq!(r.interval, DEFAULT_INTERVAL);
        assert_eq!(r.peers.len(), 2);
        assert_eq!(
            AnnounceResponse::parse(b"d14:failure reason4:nopee"),
            Err(Error::Failure("nope".into()))
        );
        assert!(AnnounceResponse::parse(b"le").is_err());
        assert!(AnnounceResponse::parse(b"d5:peersi1ee").is_err());
    }

    proptest! {
        #[test]
        fn parse_never_panics(body in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = AnnounceResponse::parse(&body);
        }
    }
}
