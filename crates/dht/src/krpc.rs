// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Message shape (the `ip` / `p` mirrors, `bs`, error dictionaries) follows
// libtorrent-rasterbar (BSD-3-Clause), Copyright (c) Arvid Norberg and
// contributors, as captured from the oracle (testkit/golden/capture_dht);
// see NOTICE.

//! KRPC (BEP 5) messages: typed queries / responses / errors and their
//! bencode encoding, shaped like the oracle's:
//!
//! - queries: `{a: {id, ...}, q, t: <2 random bytes>, v, y: "q"}`, plus
//!   `ro: 1` when read-only (BEP 43) and `a.want` when asking a node of the
//!   other address family; bootstrap `get_peers` to router nodes carry
//!   `a.bs: 1`;
//! - responses: `{ip: <requester endpoint>, r: {id, p: <requester port>,
//!   ...}, t, v, y: "r"}`;
//! - errors: `{e: [code, message], ip, r: {id, p}, t, v, y: "e"}` once the
//!   top level parsed; a malformed top level gets `{e, t, v, y}` only.
//!
//! Every length is bounded on decode (untrusted datagrams).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bencode::{Decoder, Limits, Value};

use crate::id::NodeId;

/// Largest datagram we parse or produce.
pub const MAX_PACKET: usize = 1500;
/// bencode limits for a KRPC message (libtorrent: depth 10, 500 tokens).
const LIMITS: Limits = Limits {
    max_depth: 10,
    max_container_len: 500,
};
/// Longest `n` (torrent name) we accept in `announce_peer`.
const MAX_NAME: usize = 100;
/// Longest token we accept.
const MAX_TOKEN: usize = 32;

/// Address family a `want` entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// `n4`
    V4,
    /// `n6`
    V6,
}

/// A query's arguments beyond `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// `ping`
    Ping,
    /// `find_node`
    FindNode {
        /// Id to find nodes near.
        target: NodeId,
    },
    /// `get_peers`
    GetPeers {
        /// The torrent.
        info_hash: NodeId,
        /// The querier is a seed and wants no seeds back (libtorrent).
        noseed: bool,
        /// BEP 33 scrape: bloom filters instead of peers.
        scrape: bool,
        /// libtorrent bootstrap marker (`bs: 1`) on queries to router nodes.
        bootstrap: bool,
    },
    /// `announce_peer`
    AnnouncePeer {
        /// The torrent.
        info_hash: NodeId,
        /// Listen port (ignored when `implied_port`).
        port: u16,
        /// Token from an earlier `get_peers` reply.
        token: Vec<u8>,
        /// The announcer is a seed (libtorrent extension).
        seed: bool,
        /// Use the datagram's source port instead of `port`.
        implied_port: bool,
        /// Torrent name (libtorrent extension, optional).
        name: Option<Vec<u8>>,
    },
    /// `sample_infohashes` (BEP 51)
    SampleInfohashes {
        /// Id to find nodes near.
        target: NodeId,
    },
    /// `get` (BEP 44) — answered with nodes and a token; items are not stored.
    Get {
        /// Item target.
        target: NodeId,
    },
    /// Anything else. `target` is `a.target` or `a.info_hash` when either is
    /// a 20-byte string (libtorrent still answers those with nodes).
    Unknown {
        /// The method name.
        name: Vec<u8>,
        /// A target to answer with nodes for, if the arguments carried one.
        target: Option<NodeId>,
    },
}

impl Query {
    /// The `q` name.
    pub fn name(&self) -> &[u8] {
        match self {
            Query::Ping => b"ping",
            Query::FindNode { .. } => b"find_node",
            Query::GetPeers { .. } => b"get_peers",
            Query::AnnouncePeer { .. } => b"announce_peer",
            Query::SampleInfohashes { .. } => b"sample_infohashes",
            Query::Get { .. } => b"get",
            Query::Unknown { name, .. } => name,
        }
    }
}

/// A query message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMsg {
    /// Transaction id (2 bytes on our side; anything on theirs).
    pub tid: Vec<u8>,
    /// The querier's node id.
    pub id: NodeId,
    /// The query.
    pub query: Query,
    /// `ro: 1` (BEP 43): do not add the querier to routing tables.
    pub read_only: bool,
    /// `a.want`: which families' nodes to return.
    pub want: Vec<Want>,
    /// `v`, if present.
    pub version: Option<Vec<u8>>,
}

/// The `r` dictionary of a response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reply {
    /// The responder's id.
    pub id: NodeId,
    /// `p`: the requester's port as the responder saw it (libtorrent).
    pub port: Option<u16>,
    /// Compact IPv4 nodes.
    pub nodes: Vec<(NodeId, SocketAddr)>,
    /// Compact IPv6 nodes.
    pub nodes6: Vec<(NodeId, SocketAddr)>,
    /// Write token.
    pub token: Option<Vec<u8>>,
    /// Peers (`values`).
    pub values: Vec<SocketAddr>,
    /// BEP 33 bloom filters (`BFpe`, `BFsd`), 256 bytes each.
    pub bf_peers: Option<Vec<u8>>,
    /// BEP 33 bloom filter of seeds.
    pub bf_seeds: Option<Vec<u8>>,
    /// BEP 51: sample interval, total count, sampled info-hashes.
    pub samples: Option<(i64, i64, Vec<NodeId>)>,
    /// `n`: torrent name (libtorrent extension on `get_peers` replies).
    pub name: Option<Vec<u8>>,
}

/// A response message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseMsg {
    /// Echoed transaction id.
    pub tid: Vec<u8>,
    /// `ip`: our endpoint as the responder saw it (BEP 42 vote).
    pub ip: Option<SocketAddr>,
    /// The reply.
    pub reply: Reply,
    /// `v`, if present.
    pub version: Option<Vec<u8>>,
}

/// An error message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMsg {
    /// Echoed transaction id.
    pub tid: Vec<u8>,
    /// `e[0]`
    pub code: i64,
    /// `e[1]`
    pub message: Vec<u8>,
    /// `ip`, if present.
    pub ip: Option<SocketAddr>,
    /// libtorrent leaves `r: {id, p}` in errors raised after the top level
    /// parsed.
    pub r: Option<(NodeId, u16)>,
    /// `v`, if present.
    pub version: Option<Vec<u8>>,
}

/// Any KRPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `y = q`
    Query(QueryMsg),
    /// `y = r`
    Response(ResponseMsg),
    /// `y = e`
    Error(ErrorMsg),
}

/// Why a datagram was not a usable message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Not a bencoded dictionary (or too big / too deep).
    #[error("krpc: not a bencoded dictionary")]
    NotDict,
    /// `y` missing or not one of q/r/e.
    #[error("krpc: missing or invalid 'y'")]
    Type,
    /// `t` missing.
    #[error("krpc: missing 't'")]
    Transaction,
    /// A query that libtorrent would answer with this error string.
    #[error("krpc: {0}")]
    Query(&'static str),
    /// A query with a bad argument; the string is libtorrent's error text.
    #[error("krpc: {0}")]
    Argument(String),
    /// A response or error without the fields we need.
    #[error("krpc: malformed response")]
    Response,
}

/// Standard error codes (BEP 5).
pub mod code {
    /// Generic error.
    pub const GENERIC: i64 = 201;
    /// Server error.
    pub const SERVER: i64 = 202;
    /// Protocol error (malformed packet, invalid arguments, bad token).
    pub const PROTOCOL: i64 = 203;
    /// Method unknown.
    pub const METHOD_UNKNOWN: i64 = 204;
}

// --- compact encodings ---

/// 6 / 18 byte compact endpoint.
pub fn compact_endpoint(a: SocketAddr, out: &mut Vec<u8>) {
    match a.ip() {
        IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
    out.extend_from_slice(&a.port().to_be_bytes());
}

/// Decode a 6 / 18 byte compact endpoint.
pub fn parse_endpoint(b: &[u8]) -> Option<SocketAddr> {
    match b.len() {
        6 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
            u16::from_be_bytes([b[4], b[5]]),
        )),
        18 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(o)),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        _ => None,
    }
}

fn compact_nodes(nodes: &[(NodeId, SocketAddr)], out: &mut Vec<u8>) {
    for (id, ep) in nodes {
        out.extend_from_slice(&id.0);
        compact_endpoint(*ep, out);
    }
}

fn parse_nodes(b: &[u8], v6: bool) -> Vec<(NodeId, SocketAddr)> {
    let step = if v6 { 38 } else { 26 };
    b.chunks_exact(step)
        .filter_map(|c| {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            parse_endpoint(&c[20..]).map(|ep| (NodeId(id), ep))
        })
        .take(256)
        .collect()
}

fn bytes20(v: &Value<'_>) -> Option<NodeId> {
    let b = v.as_bytes()?;
    if b.len() != 20 {
        return None;
    }
    let mut id = [0u8; 20];
    id.copy_from_slice(b);
    Some(NodeId(id))
}

fn int_flag(d: &Value<'_>, key: &str) -> bool {
    d.get_str(key)
        .and_then(Value::as_int)
        .is_some_and(|i| i != 0)
}

/// libtorrent's `verify_message` texts for a required 20-byte string.
fn required_hash(a: &Value<'_>, key: &'static str) -> Result<NodeId, DecodeError> {
    match a.get_str(key) {
        None => Err(DecodeError::Argument(format!("missing '{key}' key"))),
        Some(v) => match v.as_bytes() {
            None => Err(DecodeError::Argument(format!("missing '{key}' key"))),
            Some(b) if b.len() != 20 => {
                Err(DecodeError::Argument(format!("invalid value for '{key}'")))
            }
            Some(_) => Ok(bytes20(v).unwrap_or(NodeId::ZERO)),
        },
    }
}

// --- decode ---

/// Parse one datagram. `Err(Query(..))` / `Err(Argument(..))` carry the
/// error text libtorrent would answer with; the caller decides whether to
/// answer (a decode error inside a query's arguments is still answerable:
/// see [`decode_query_head`]).
pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
    if bytes.len() > MAX_PACKET || bytes.first() != Some(&b'd') || bytes.last() != Some(&b'e') {
        return Err(DecodeError::NotDict);
    }
    let v = Decoder::with_limits(bytes, LIMITS)
        .decode_all()
        .map_err(|_| DecodeError::NotDict)?;
    if v.as_dict().is_none() {
        return Err(DecodeError::NotDict);
    }
    let y = v.get_str("y").and_then(Value::as_bytes);
    let tid = v
        .get_str("t")
        .and_then(Value::as_bytes)
        .ok_or(DecodeError::Transaction)?
        .to_vec();
    let version = v.get_str("v").and_then(Value::as_bytes).map(<[u8]>::to_vec);
    let ip = v
        .get_str("ip")
        .and_then(Value::as_bytes)
        .and_then(parse_endpoint);
    match y {
        Some(b"q") => {
            let q = v
                .get_str("q")
                .and_then(Value::as_bytes)
                .ok_or(DecodeError::Argument("missing 'q' key".into()))?;
            let a = v
                .get_str("a")
                .filter(|a| a.as_dict().is_some())
                .ok_or(DecodeError::Argument("missing 'a' key".into()))?;
            let id = required_hash(a, "id")
                .map_err(|_| DecodeError::Argument("missing 'id' key".into()))?;
            let read_only = int_flag(&v, "ro");
            let mut want = Vec::new();
            if let Some(l) = a.get_str("want").and_then(Value::as_list) {
                for w in l.iter().take(8) {
                    match w.as_bytes() {
                        Some(b"n4") => want.push(Want::V4),
                        Some(b"n6") => want.push(Want::V6),
                        _ => {}
                    }
                }
            }
            let query = parse_query(q, a)?;
            Ok(Message::Query(QueryMsg {
                tid,
                id,
                query,
                read_only,
                want,
                version,
            }))
        }
        Some(b"r") => {
            let r = v
                .get_str("r")
                .filter(|r| r.as_dict().is_some())
                .ok_or(DecodeError::Response)?;
            let id = r
                .get_str("id")
                .and_then(bytes20)
                .ok_or(DecodeError::Response)?;
            let mut reply = Reply {
                id,
                ..Reply::default()
            };
            reply.port = r
                .get_str("p")
                .and_then(Value::as_int)
                .and_then(|p| u16::try_from(p).ok());
            if let Some(n) = r.get_str("nodes").and_then(Value::as_bytes) {
                reply.nodes = parse_nodes(n, false);
            }
            if let Some(n) = r.get_str("nodes6").and_then(Value::as_bytes) {
                reply.nodes6 = parse_nodes(n, true);
            }
            reply.token = r
                .get_str("token")
                .and_then(Value::as_bytes)
                .filter(|t| t.len() <= MAX_TOKEN)
                .map(<[u8]>::to_vec);
            if let Some(vals) = r.get_str("values").and_then(Value::as_list) {
                // libtorrent also accepts one long string of v4 endpoints.
                if vals.len() == 1
                    && let Some(b) = vals[0].as_bytes()
                    && b.len() > 6
                    && b.len() % 6 == 0
                {
                    reply.values = b
                        .as_chunks::<6>()
                        .0
                        .iter()
                        .filter_map(|c| parse_endpoint(c))
                        .take(512)
                        .collect();
                } else {
                    reply.values = vals
                        .iter()
                        .filter_map(|e| e.as_bytes().and_then(parse_endpoint))
                        .take(512)
                        .collect();
                }
            }
            reply.bf_peers = r
                .get_str("BFpe")
                .and_then(Value::as_bytes)
                .map(<[u8]>::to_vec);
            reply.bf_seeds = r
                .get_str("BFsd")
                .and_then(Value::as_bytes)
                .map(<[u8]>::to_vec);
            if let Some(s) = r.get_str("samples").and_then(Value::as_bytes) {
                let interval = r.get_str("interval").and_then(Value::as_int).unwrap_or(0);
                let num = r.get_str("num").and_then(Value::as_int).unwrap_or(0);
                let hashes = s
                    .as_chunks::<20>()
                    .0
                    .iter()
                    .take(256)
                    .map(|c| NodeId(*c))
                    .collect();
                reply.samples = Some((interval, num, hashes));
            }
            reply.name = r
                .get_str("n")
                .and_then(Value::as_bytes)
                .map(|n| n[..n.len().min(MAX_NAME)].to_vec());
            Ok(Message::Response(ResponseMsg {
                tid,
                ip,
                reply,
                version,
            }))
        }
        Some(b"e") => {
            let e = v
                .get_str("e")
                .and_then(Value::as_list)
                .ok_or(DecodeError::Response)?;
            let code = e.first().and_then(Value::as_int).unwrap_or(0);
            let message = e
                .get(1)
                .and_then(Value::as_bytes)
                .map(|m| m[..m.len().min(200)].to_vec())
                .unwrap_or_default();
            let r = v.get_str("r").and_then(|r| {
                let id = r.get_str("id").and_then(bytes20)?;
                let p = r
                    .get_str("p")
                    .and_then(Value::as_int)
                    .and_then(|p| u16::try_from(p).ok());
                Some((id, p.unwrap_or(0)))
            });
            Ok(Message::Error(ErrorMsg {
                tid,
                code,
                message,
                ip,
                r,
                version,
            }))
        }
        _ => Err(DecodeError::Type),
    }
}

/// The parts of a malformed query that are still needed to answer it with
/// an error: `(tid, id)`. `None` when even those are missing (then libtorrent
/// answers with an error without `ip` / `r`).
pub fn decode_query_head(bytes: &[u8]) -> Option<(Vec<u8>, Option<NodeId>)> {
    if bytes.len() > MAX_PACKET {
        return None;
    }
    let v = Decoder::with_limits(bytes, LIMITS).decode_all().ok()?;
    if v.get_str("y").and_then(Value::as_bytes) != Some(b"q") {
        return None;
    }
    let tid = v.get_str("t").and_then(Value::as_bytes)?.to_vec();
    let id = v
        .get_str("a")
        .and_then(|a| a.get_str("id"))
        .and_then(bytes20);
    Some((tid, id))
}

fn parse_query(q: &[u8], a: &Value<'_>) -> Result<Query, DecodeError> {
    Ok(match q {
        b"ping" => Query::Ping,
        b"find_node" => Query::FindNode {
            target: required_hash(a, "target")?,
        },
        b"get_peers" => Query::GetPeers {
            info_hash: required_hash(a, "info_hash")?,
            noseed: int_flag(a, "noseed"),
            scrape: int_flag(a, "scrape"),
            bootstrap: int_flag(a, "bs"),
        },
        b"announce_peer" => {
            let info_hash = required_hash(a, "info_hash")?;
            let port = a
                .get_str("port")
                .and_then(Value::as_int)
                .ok_or_else(|| DecodeError::Argument("missing 'port' key".into()))?;
            let token = a
                .get_str("token")
                .and_then(Value::as_bytes)
                .ok_or_else(|| DecodeError::Argument("missing 'token' key".into()))?;
            let implied_port = int_flag(a, "implied_port");
            if !implied_port && !(0..65536).contains(&port) {
                return Err(DecodeError::Argument("invalid port".into()));
            }
            Query::AnnouncePeer {
                info_hash,
                port: port.clamp(0, 65535) as u16,
                token: token[..token.len().min(MAX_TOKEN)].to_vec(),
                seed: int_flag(a, "seed"),
                implied_port,
                name: a
                    .get_str("n")
                    .and_then(Value::as_bytes)
                    .map(|n| n[..n.len().min(MAX_NAME)].to_vec()),
            }
        }
        b"sample_infohashes" => Query::SampleInfohashes {
            target: required_hash(a, "target")?,
        },
        b"get" => Query::Get {
            target: required_hash(a, "target")?,
        },
        other => {
            let target = a
                .get_str("target")
                .and_then(bytes20)
                .or_else(|| a.get_str("info_hash").and_then(bytes20));
            Query::Unknown {
                name: other[..other.len().min(32)].to_vec(),
                target,
            }
        }
    })
}

// --- encode ---

fn dict<'a>(entries: Vec<(&'a [u8], Value<'a>)>) -> Value<'a> {
    Value::Dict { entries, raw: b"" }
}

/// Encode a query.
pub fn encode_query(m: &QueryMsg) -> Vec<u8> {
    let mut a: Vec<(&[u8], Value<'_>)> = vec![(b"id", Value::Bytes(&m.id.0))];
    // Owned scratch for values that need a buffer.
    let mut want_items: Vec<Value<'_>> = Vec::new();
    for w in &m.want {
        want_items.push(Value::Bytes(match w {
            Want::V4 => b"n4",
            Want::V6 => b"n6",
        }));
    }
    match &m.query {
        Query::Ping => {}
        Query::FindNode { target } => a.push((b"target", Value::Bytes(&target.0))),
        Query::GetPeers {
            info_hash,
            noseed,
            scrape,
            bootstrap,
        } => {
            if *bootstrap {
                a.push((b"bs", Value::Int(1)));
            }
            a.push((b"info_hash", Value::Bytes(&info_hash.0)));
            if *noseed {
                a.push((b"noseed", Value::Int(1)));
            }
            if *scrape {
                a.push((b"scrape", Value::Int(1)));
            }
        }
        Query::AnnouncePeer {
            info_hash,
            port,
            token,
            seed,
            implied_port,
            name,
        } => {
            if *implied_port {
                a.push((b"implied_port", Value::Int(1)));
            }
            a.push((b"info_hash", Value::Bytes(&info_hash.0)));
            if let Some(n) = name {
                a.push((b"n", Value::Bytes(n)));
            }
            a.push((b"port", Value::Int(i64::from(*port))));
            a.push((b"seed", Value::Int(i64::from(*seed))));
            a.push((b"token", Value::Bytes(token)));
        }
        Query::SampleInfohashes { target } | Query::Get { target } => {
            a.push((b"target", Value::Bytes(&target.0)));
        }
        Query::Unknown { target, .. } => {
            if let Some(t) = target {
                a.push((b"target", Value::Bytes(&t.0)));
            }
        }
    }
    if !want_items.is_empty() {
        a.push((
            b"want",
            Value::List {
                items: want_items,
                raw: b"",
            },
        ));
    }
    let mut top: Vec<(&[u8], Value<'_>)> = vec![
        (b"a", dict(a)),
        (b"q", Value::Bytes(m.query.name())),
        (b"t", Value::Bytes(&m.tid)),
    ];
    if m.read_only {
        top.push((b"ro", Value::Int(1)));
    }
    if let Some(v) = &m.version {
        top.push((b"v", Value::Bytes(v)));
    }
    top.push((b"y", Value::Bytes(b"q")));
    bencode::to_bytes(&dict(top))
}

/// Encode a response to a query from `requester` (fills `ip` and `r.p` the
/// way libtorrent does).
pub fn encode_response(
    tid: &[u8],
    requester: SocketAddr,
    reply: &Reply,
    version: Option<&[u8]>,
) -> Vec<u8> {
    let mut ip = Vec::with_capacity(18);
    compact_endpoint(requester, &mut ip);
    let mut nodes = Vec::new();
    compact_nodes(&reply.nodes, &mut nodes);
    let mut nodes6 = Vec::new();
    compact_nodes(&reply.nodes6, &mut nodes6);
    let values: Vec<Vec<u8>> = reply
        .values
        .iter()
        .map(|ep| {
            let mut b = Vec::with_capacity(18);
            compact_endpoint(*ep, &mut b);
            b
        })
        .collect();
    let mut samples = Vec::new();
    if let Some((_, _, hashes)) = &reply.samples {
        for h in hashes {
            samples.extend_from_slice(&h.0);
        }
    }
    let mut r: Vec<(&[u8], Value<'_>)> = Vec::new();
    if let Some(b) = &reply.bf_peers {
        r.push((b"BFpe", Value::Bytes(b)));
    }
    if let Some(b) = &reply.bf_seeds {
        r.push((b"BFsd", Value::Bytes(b)));
    }
    r.push((b"id", Value::Bytes(&reply.id.0)));
    if let Some((interval, _, _)) = &reply.samples {
        r.push((b"interval", Value::Int(*interval)));
    }
    if let Some(n) = &reply.name {
        r.push((b"n", Value::Bytes(n)));
    }
    if !reply.nodes.is_empty() {
        r.push((b"nodes", Value::Bytes(&nodes)));
    }
    if !reply.nodes6.is_empty() {
        r.push((b"nodes6", Value::Bytes(&nodes6)));
    }
    if let Some((_, num, _)) = &reply.samples {
        r.push((b"num", Value::Int(*num)));
    }
    if let Some(p) = reply.port {
        r.push((b"p", Value::Int(i64::from(p))));
    }
    if reply.samples.is_some() {
        r.push((b"samples", Value::Bytes(&samples)));
    }
    if let Some(t) = &reply.token {
        r.push((b"token", Value::Bytes(t)));
    }
    if !values.is_empty() {
        r.push((
            b"values",
            Value::List {
                items: values.iter().map(|b| Value::Bytes(b)).collect(),
                raw: b"",
            },
        ));
    }
    let mut top: Vec<(&[u8], Value<'_>)> = vec![
        (b"ip", Value::Bytes(&ip)),
        (b"r", dict(r)),
        (b"t", Value::Bytes(tid)),
    ];
    if let Some(v) = version {
        top.push((b"v", Value::Bytes(v)));
    }
    top.push((b"y", Value::Bytes(b"r")));
    bencode::to_bytes(&dict(top))
}

/// Encode an error. `head` is `Some((our id, requester))` for errors raised
/// after the top level parsed (libtorrent then keeps `ip` and `r: {id, p}`
/// in the error), `None` for a malformed top level.
pub fn encode_error(
    tid: &[u8],
    code: i64,
    message: &[u8],
    head: Option<(NodeId, SocketAddr)>,
    version: Option<&[u8]>,
) -> Vec<u8> {
    let mut ip = Vec::with_capacity(18);
    let e = Value::List {
        items: vec![Value::Int(code), Value::Bytes(message)],
        raw: b"",
    };
    let mut top: Vec<(&[u8], Value<'_>)> = vec![(b"e", e)];
    let id_bytes;
    if let Some((id, requester)) = head {
        compact_endpoint(requester, &mut ip);
        id_bytes = id.0;
        top.push((b"ip", Value::Bytes(&ip)));
        top.push((
            b"r",
            dict(vec![
                (b"id", Value::Bytes(&id_bytes)),
                (b"p", Value::Int(i64::from(requester.port()))),
            ]),
        ));
    }
    top.push((b"t", Value::Bytes(tid)));
    if let Some(v) = version {
        top.push((b"v", Value::Bytes(v)));
    }
    top.push((b"y", Value::Bytes(b"e")));
    bencode::to_bytes(&dict(top))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Byte-exact against the oracle's bootstrap query
    /// (testkit/golden/capture_dht/v4/tap-dht-1.jsonl, first event).
    #[test]
    fn bootstrap_query_matches_oracle_bytes() {
        let golden = unhex(
            "64313a6164323a6273693165323a696432303a71dfd912b64617000a5b004de8d0b6f16c02255b393a696e666f5f6861736832303a71dfd912b64617000a5b004da051aa1a789f9e8065313a71393a6765745f7065657273313a74323a8506313a76343a4c54020e313a79313a7165",
        );
        let m = decode(&golden).unwrap();
        let Message::Query(q) = &m else {
            panic!("query")
        };
        assert_eq!(q.tid, unhex("8506"));
        assert_eq!(q.version, Some(unhex("4c54020e")));
        assert!(matches!(
            q.query,
            Query::GetPeers {
                bootstrap: true,
                noseed: false,
                scrape: false,
                ..
            }
        ));
        assert_eq!(encode_query(q), golden);
    }

    /// Byte-exact against the oracle's `announce_peer`.
    #[test]
    fn announce_matches_oracle_bytes() {
        let golden = unhex(
            "64313a6164323a696432303a3090ff734acabcbbc086bd23fa38b8dd0ebcb26a393a696e666f5f6861736832303aed71b1c019d3e90b1cf794efbc9d51173c269cc1343a706f7274693638383165343a73656564693065353a746f6b656e343a7461702165313a7131333a616e6e6f756e63655f70656572313a74323a2c71313a76343a4c54020e313a79313a7165",
        );
        let m = decode(&golden).unwrap();
        let Message::Query(q) = &m else {
            panic!("query")
        };
        assert!(matches!(
            &q.query,
            Query::AnnouncePeer {
                port: 6881,
                seed: false,
                implied_port: false,
                token,
                ..
            } if token == b"tap!"
        ));
        assert_eq!(encode_query(q), golden);
    }

    /// Byte-exact against the oracle's `get_peers` reply with a value, and
    /// its error for a bad token.
    #[test]
    fn responses_match_oracle_bytes() {
        let golden = unhex(
            "64323a6970363a0a7b02011ae1313a7264323a696432303a71dfd912b64617000a5b004de8d0b6f16c02255b353a6e6f64657332363a22222222222222222222222222222222222222220a7b03011ae1313a70693638383165353a746f6b656e343a8089daaf363a76616c7565736c363a0a7b02011aea6565313a74323a1007313a76343a4c54020e313a79313a7265",
        );
        let m = decode(&golden).unwrap();
        let Message::Response(r) = &m else {
            panic!("response")
        };
        assert_eq!(r.ip, Some("10.123.2.1:6881".parse().unwrap()));
        assert_eq!(r.reply.port, Some(6881));
        assert_eq!(r.reply.nodes.len(), 1);
        assert_eq!(r.reply.nodes[0].1, "10.123.3.1:6881".parse().unwrap());
        assert_eq!(r.reply.values, vec!["10.123.2.1:6890".parse().unwrap()]);
        let again = encode_response(&r.tid, r.ip.unwrap(), &r.reply, r.version.as_deref());
        assert_eq!(again, golden);

        let golden_err = unhex(
            "64313a656c693230336531333a696e76616c696420746f6b656e65323a6970363a0a7b02011ae1313a7264323a696432303a71dfd912b64617000a5b004de8d0b6f16c02255b313a7069363838316565313a74323a1008313a76343a4c54020e313a79313a6565",
        );
        let m = decode(&golden_err).unwrap();
        let Message::Error(e) = &m else {
            panic!("error")
        };
        assert_eq!(e.code, 203);
        assert_eq!(e.message, b"invalid token");
        let (id, _) = e.r.unwrap();
        let again = encode_error(
            &e.tid,
            e.code,
            &e.message,
            Some((id, e.ip.unwrap())),
            e.version.as_deref(),
        );
        assert_eq!(again, golden_err);
    }

    #[test]
    fn malformed_is_rejected_not_panicking() {
        assert_eq!(decode(b"li1ee"), Err(DecodeError::NotDict));
        assert_eq!(decode(b"d1:t2:xxe"), Err(DecodeError::Type));
        assert!(decode(b"d1:y1:qe").is_err());
        assert!(decode(&vec![b'd'; 3000]).is_err());
        // A query with a bad target: the libtorrent error text.
        let q = b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaa6:target3:xyze1:q9:find_node1:t2:ab1:y1:qe";
        assert_eq!(
            decode(q),
            Err(DecodeError::Argument("invalid value for 'target'".into()))
        );
        let (tid, id) = decode_query_head(q).unwrap();
        assert_eq!(tid, b"ab");
        assert_eq!(id, Some(NodeId([b'a'; 20])));
    }
}
