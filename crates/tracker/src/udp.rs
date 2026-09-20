// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Packet layout and retry policy follow libtorrent-rasterbar (BSD-3-Clause),
// Copyright (c) Arvid Norberg and contributors; see NOTICE.

//! BEP 15 UDP tracker protocol: packet builders and parsers, plus the
//! connection-id cache. Wire shape as captured from the oracle
//! (`testkit/golden/capture_tracker_udp`): the `0x41727101980` connect magic,
//! the announce field order, `ip = 0`, and a BEP 41 option 2 (URL data)
//! carrying the tracker URL's path and query. libtorrent makes **one**
//! attempt per request (a 15 s receive timeout, then the tracker backoff of
//! [`crate::Announcer`]) rather than the BEP's 15·2ⁿ retransmits; the caller
//! applies that policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use metainfo::InfoHash;

use crate::Error;
use crate::announce::{AnnounceEvent, AnnounceRequest, AnnounceResponse, MAX_PEERS};

/// The connect request's fixed connection id.
pub const CONNECT_MAGIC: u64 = 0x0417_2710_1980;
/// How long a connection id stays valid (BEP 15 says one minute; libtorrent
/// `udp_tracker_token_expiry`).
pub const CONNECTION_ID_TTL: Duration = Duration::from_secs(60);
/// libtorrent `tracker_receive_timeout`: one attempt, then the request fails.
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(15);
/// UDP responses carry no `min interval`; libtorrent assumes 60 s.
pub const IMPLIED_MIN_INTERVAL: u32 = 60;

/// Actions.
pub mod action {
    /// `connect`.
    pub const CONNECT: u32 = 0;
    /// `announce`.
    pub const ANNOUNCE: u32 = 1;
    /// `scrape`.
    pub const SCRAPE: u32 = 2;
    /// `error`.
    pub const ERROR: u32 = 3;
}

fn event_code(e: AnnounceEvent) -> u32 {
    match e {
        AnnounceEvent::None => 0,
        AnnounceEvent::Completed => 1,
        AnnounceEvent::Started => 2,
        AnnounceEvent::Stopped => 3,
    }
}

/// Build a connect request.
pub fn connect_request(transaction_id: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&CONNECT_MAGIC.to_be_bytes());
    out.extend_from_slice(&action::CONNECT.to_be_bytes());
    out.extend_from_slice(&transaction_id.to_be_bytes());
    out
}

/// Build an announce request. `url_path` is the tracker URL's path (plus
/// `?query` if any); when non-empty it is sent as BEP 41 option 2, truncated
/// to 255 bytes. `numwant` follows the profile (0 on `stopped`).
pub fn announce_request(
    connection_id: u64,
    transaction_id: u32,
    req: &AnnounceRequest,
    numwant: i32,
    url_path: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(98 + 2 + url_path.len().min(255));
    out.extend_from_slice(&connection_id.to_be_bytes());
    out.extend_from_slice(&action::ANNOUNCE.to_be_bytes());
    out.extend_from_slice(&transaction_id.to_be_bytes());
    out.extend_from_slice(&req.info_hash);
    out.extend_from_slice(&req.peer_id);
    out.extend_from_slice(&(req.downloaded as i64).to_be_bytes());
    out.extend_from_slice(&(req.left as i64).to_be_bytes());
    out.extend_from_slice(&(req.uploaded as i64).to_be_bytes());
    out.extend_from_slice(&event_code(req.event).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // ip: let the tracker use the source
    out.extend_from_slice(&req.key.to_be_bytes());
    out.extend_from_slice(&numwant.to_be_bytes());
    out.extend_from_slice(&req.port.to_be_bytes());
    if !url_path.is_empty() {
        let bytes = url_path.as_bytes();
        let n = bytes.len().min(255);
        out.push(2);
        out.push(n as u8);
        out.extend_from_slice(&bytes[..n]);
    }
    out
}

/// Build a scrape request for `hashes`.
pub fn scrape_request(connection_id: u64, transaction_id: u32, hashes: &[InfoHash]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 20 * hashes.len());
    out.extend_from_slice(&connection_id.to_be_bytes());
    out.extend_from_slice(&action::SCRAPE.to_be_bytes());
    out.extend_from_slice(&transaction_id.to_be_bytes());
    for h in hashes.iter().take(74) {
        out.extend_from_slice(h);
    }
    out
}

/// A parsed tracker reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `connect` reply: the connection id to use.
    Connect {
        /// Transaction id echoed by the tracker.
        transaction_id: u32,
        /// The connection id.
        connection_id: u64,
    },
    /// `announce` reply.
    Announce {
        /// Transaction id echoed by the tracker.
        transaction_id: u32,
        /// The response (interval, counts, peers).
        response: AnnounceResponse,
    },
    /// `scrape` reply: `(seeders, completed, leechers)` per requested hash, in
    /// request order.
    Scrape {
        /// Transaction id echoed by the tracker.
        transaction_id: u32,
        /// Per-hash counts.
        entries: Vec<(u32, u32, u32)>,
    },
    /// `error` reply.
    Error {
        /// Transaction id echoed by the tracker.
        transaction_id: u32,
        /// Message.
        message: String,
    },
}

impl Reply {
    /// The transaction id of any reply.
    pub fn transaction_id(&self) -> u32 {
        match self {
            Reply::Connect { transaction_id, .. }
            | Reply::Announce { transaction_id, .. }
            | Reply::Scrape { transaction_id, .. }
            | Reply::Error { transaction_id, .. } => *transaction_id,
        }
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse a datagram from the tracker. `v6` says whether the socket it arrived
/// on is IPv6 (announce peers are 18-byte entries then, per BEP 15).
pub fn parse_reply(pkt: &[u8], v6: bool) -> Result<Reply, Error> {
    if pkt.len() < 8 {
        return Err(Error::Response("short udp reply"));
    }
    let action = be32(&pkt[0..4]);
    let transaction_id = be32(&pkt[4..8]);
    match action {
        action::CONNECT => {
            if pkt.len() < 16 {
                return Err(Error::Response("short connect reply"));
            }
            let connection_id = u64::from_be_bytes(
                pkt[8..16]
                    .try_into()
                    .map_err(|_| Error::Response("connect reply"))?,
            );
            Ok(Reply::Connect {
                transaction_id,
                connection_id,
            })
        }
        action::ANNOUNCE => {
            if pkt.len() < 20 {
                return Err(Error::Response("short announce reply"));
            }
            let interval = be32(&pkt[8..12]);
            let leechers = be32(&pkt[12..16]);
            let seeders = be32(&pkt[16..20]);
            let mut peers = Vec::new();
            let entry = if v6 { 18 } else { 6 };
            for chunk in pkt[20..].chunks_exact(entry).take(MAX_PEERS) {
                let (ip, port) = if v6 {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&chunk[..16]);
                    (
                        IpAddr::V6(Ipv6Addr::from(o)),
                        u16::from_be_bytes([chunk[16], chunk[17]]),
                    )
                } else {
                    (
                        IpAddr::V4(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3])),
                        u16::from_be_bytes([chunk[4], chunk[5]]),
                    )
                };
                peers.push(SocketAddr::new(ip, port));
            }
            Ok(Reply::Announce {
                transaction_id,
                response: AnnounceResponse {
                    interval,
                    min_interval: Some(IMPLIED_MIN_INTERVAL),
                    tracker_id: None,
                    complete: Some(seeders),
                    incomplete: Some(leechers),
                    downloaded: None,
                    warning: None,
                    peers,
                    external_ip: None,
                },
            })
        }
        action::SCRAPE => {
            let entries = pkt[8..]
                .as_chunks::<12>()
                .0
                .iter()
                .take(74)
                .map(|c| (be32(&c[0..4]), be32(&c[4..8]), be32(&c[8..12])))
                .collect();
            Ok(Reply::Scrape {
                transaction_id,
                entries,
            })
        }
        action::ERROR => Ok(Reply::Error {
            transaction_id,
            message: String::from_utf8_lossy(&pkt[8..pkt.len().min(8 + 512)]).into_owned(),
        }),
        _ => Err(Error::Response("unknown udp action")),
    }
}

/// Connection ids per tracker address, with expiry.
#[derive(Debug, Default)]
pub struct ConnectionCache {
    entries: Vec<(IpAddr, u64, Instant)>,
}

impl ConnectionCache {
    /// A valid connection id for `addr`, if one is cached and fresh.
    pub fn get(&self, addr: IpAddr, now: Instant) -> Option<u64> {
        self.entries
            .iter()
            .find(|(a, _, exp)| *a == addr && *exp > now)
            .map(|(_, id, _)| *id)
    }

    /// Remember `id` for `addr` for [`CONNECTION_ID_TTL`].
    pub fn insert(&mut self, addr: IpAddr, id: u64, now: Instant) {
        self.entries.retain(|(a, _, exp)| *a != addr && *exp > now);
        self.entries.push((addr, id, now + CONNECTION_ID_TTL));
    }

    /// Forget `addr` (after an error reply).
    pub fn forget(&mut self, addr: IpAddr) {
        self.entries.retain(|(a, _, _)| *a != addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn req() -> AnnounceRequest {
        AnnounceRequest {
            info_hash: [0xAA; 20],
            peer_id: *b"-qB5230-000000000000",
            port: 6881,
            uploaded: 1,
            downloaded: 2,
            left: 3,
            corrupt: 0,
            redundant: 0,
            key: 0x1122_3344,
            event: AnnounceEvent::Started,
            tracker_id: None,
            crypto_supported: true,
        }
    }

    /// Layout as captured: 98 bytes of fields then `02 09 "/announce"`.
    #[test]
    fn announce_layout_matches_capture() {
        let pkt = announce_request(0x8447_cf46_f798_686b, 7, &req(), 200, "/announce");
        assert_eq!(pkt.len(), 98 + 11);
        assert_eq!(&pkt[0..8], &0x8447_cf46_f798_686bu64.to_be_bytes());
        assert_eq!(be32(&pkt[8..12]), 1);
        assert_eq!(be32(&pkt[12..16]), 7);
        assert_eq!(&pkt[16..36], &[0xAA; 20]);
        assert_eq!(&pkt[36..56], b"-qB5230-000000000000");
        assert_eq!(&pkt[56..64], &2i64.to_be_bytes()); // downloaded
        assert_eq!(&pkt[64..72], &3i64.to_be_bytes()); // left
        assert_eq!(&pkt[72..80], &1i64.to_be_bytes()); // uploaded
        assert_eq!(be32(&pkt[80..84]), 2); // started
        assert_eq!(be32(&pkt[84..88]), 0); // ip
        assert_eq!(be32(&pkt[88..92]), 0x1122_3344); // key
        assert_eq!(be32(&pkt[92..96]), 200);
        assert_eq!(&pkt[96..98], &6881u16.to_be_bytes());
        assert_eq!(&pkt[98..], b"\x02\x09/announce");
        let connect = connect_request(9);
        assert_eq!(
            bencode::hex(&connect),
            "0000041727101980".to_string() + "00000000" + "00000009"
        );
        let bare = announce_request(1, 1, &req(), 0, "");
        assert_eq!(bare.len(), 98);
    }

    #[test]
    fn replies_parse() {
        let mut c = vec![0, 0, 0, 0, 0, 0, 0, 7];
        c.extend_from_slice(&0xdead_beefu64.to_be_bytes());
        assert_eq!(
            parse_reply(&c, false).unwrap(),
            Reply::Connect {
                transaction_id: 7,
                connection_id: 0xdead_beef
            }
        );
        let mut a = vec![0, 0, 0, 1, 0, 0, 0, 9];
        a.extend_from_slice(&1800u32.to_be_bytes());
        a.extend_from_slice(&2u32.to_be_bytes());
        a.extend_from_slice(&5u32.to_be_bytes());
        a.extend_from_slice(&[10, 77, 1, 2, 0x1a, 0xe1]);
        match parse_reply(&a, false).unwrap() {
            Reply::Announce {
                transaction_id,
                response,
            } => {
                assert_eq!(transaction_id, 9);
                assert_eq!(response.interval, 1800);
                assert_eq!(response.complete, Some(5));
                assert_eq!(response.incomplete, Some(2));
                assert_eq!(response.peers, vec!["10.77.1.2:6881".parse().unwrap()]);
                assert_eq!(response.min_interval, Some(60));
            }
            other => panic!("{other:?}"),
        }
        let mut a6 = a[..20].to_vec();
        a6.extend_from_slice(&[
            0xfd, 0x77, 0, 0x8e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa, 0x1a, 0xe1,
        ]);
        match parse_reply(&a6, true).unwrap() {
            Reply::Announce { response, .. } => {
                assert_eq!(response.peers, vec!["[fd77:8e::a]:6881".parse().unwrap()]);
            }
            other => panic!("{other:?}"),
        }
        let mut s = vec![0, 0, 0, 2, 0, 0, 0, 3];
        s.extend_from_slice(&[0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7]);
        assert_eq!(
            parse_reply(&s, false).unwrap(),
            Reply::Scrape {
                transaction_id: 3,
                entries: vec![(5, 6, 7)]
            }
        );
        let mut e = vec![0, 0, 0, 3, 0, 0, 0, 4];
        e.extend_from_slice(b"nope");
        assert_eq!(
            parse_reply(&e, false).unwrap(),
            Reply::Error {
                transaction_id: 4,
                message: "nope".into()
            }
        );
        assert!(parse_reply(&[0, 0, 0, 9, 0, 0, 0, 0], false).is_err());
        assert!(parse_reply(&[1, 2], false).is_err());
    }

    #[test]
    fn connection_cache_expires() {
        let t0 = Instant::now();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut c = ConnectionCache::default();
        assert_eq!(c.get(ip, t0), None);
        c.insert(ip, 42, t0);
        assert_eq!(c.get(ip, t0 + Duration::from_secs(59)), Some(42));
        assert_eq!(c.get(ip, t0 + Duration::from_secs(61)), None);
        c.insert(ip, 43, t0);
        c.forget(ip);
        assert_eq!(c.get(ip, t0), None);
    }

    proptest! {
        #[test]
        fn parse_never_panics(pkt in proptest::collection::vec(any::<u8>(), 0..300), v6: bool) {
            let _ = parse_reply(&pkt, v6);
        }
    }
}
