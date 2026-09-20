// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! `tap-dht`: a scriptable DHT node (BEP 5 KRPC over UDP) that records every
//! datagram it sees, answers queries from a configured routing table / peer
//! store, and can send probe queries of its own so the oracle's responses can
//! be captured. It deliberately re-implements the little KRPC it needs on
//! std sockets: the harness never trusts the code under test.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::bencode::{self, Value};
use crate::peerwire::value_to_json;

/// How the node answers queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhtBehaviour {
    /// Answer normally.
    Normal,
    /// Record but never answer.
    Silent,
}

/// A node the tap knows about (returned in `nodes` / `nodes6`).
#[derive(Clone, Debug)]
pub struct KnownNode {
    pub id: [u8; 20],
    pub addr: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct TapDhtConfig {
    /// One socket per family.
    pub listen: Vec<SocketAddr>,
    pub node_id: [u8; 20],
    /// Nodes handed out in `find_node` / `get_peers` replies (per family).
    pub nodes: Vec<KnownNode>,
    /// Peers handed out as `values` for an info-hash.
    pub peers: HashMap<[u8; 20], Vec<SocketAddr>>,
    /// Write token handed out (and accepted) in `get_peers` / `announce_peer`.
    pub token: Vec<u8>,
    /// `v` stamped on our messages.
    pub version: Option<Vec<u8>>,
    pub behaviour: DhtBehaviour,
    /// Act as a real router / storage node: remember every querier as a
    /// node and serve stored announces as `values`.
    pub learn: bool,
}

impl TapDhtConfig {
    pub fn new(listen: Vec<SocketAddr>) -> TapDhtConfig {
        let mut node_id = [0x5au8; 20];
        node_id[19] = std::process::id() as u8;
        TapDhtConfig {
            listen,
            node_id,
            nodes: Vec::new(),
            peers: HashMap::new(),
            token: b"tap!".to_vec(),
            version: Some(b"TP01".to_vec()),
            behaviour: DhtBehaviour::Normal,
            learn: false,
        }
    }
    pub fn learn(mut self, on: bool) -> Self {
        self.learn = on;
        self
    }
    pub fn node_id(mut self, id: [u8; 20]) -> Self {
        self.node_id = id;
        self
    }
    pub fn node(mut self, id: [u8; 20], addr: SocketAddr) -> Self {
        self.nodes.push(KnownNode { id, addr });
        self
    }
    pub fn peer(mut self, info_hash: [u8; 20], addr: SocketAddr) -> Self {
        self.peers.entry(info_hash).or_default().push(addr);
        self
    }
    pub fn behaviour(mut self, b: DhtBehaviour) -> Self {
        self.behaviour = b;
        self
    }
}

/// One datagram, either direction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtEvent {
    pub ts_ms: u64,
    /// `recv` or `send`.
    pub dir: String,
    pub remote: SocketAddr,
    pub local: SocketAddr,
    /// `query:<q>`, `response`, `error`, or `invalid`.
    pub kind: String,
    /// Transaction id, hex.
    pub tid_hex: String,
    pub raw_hex: String,
    pub decoded: serde_json::Value,
}

impl DhtEvent {
    /// Whether this is a query of type `q` received from `from`.
    pub fn is_query_from(&self, q: &str, from: IpAddr) -> bool {
        self.dir == "recv" && self.kind == format!("query:{q}") && self.remote.ip() == from
    }
    /// The `a` (query) or `r` (response) dictionary.
    pub fn body(&self) -> Option<&serde_json::Value> {
        self.decoded.get("a").or_else(|| self.decoded.get("r"))
    }
}

struct Pending {
    reply: Mutex<Option<Value>>,
}

/// Outstanding probe queries by `(peer, transaction id)`.
type PendingMap = HashMap<(SocketAddr, Vec<u8>), Arc<Pending>>;

struct Inner {
    config: TapDhtConfig,
    start: Instant,
    events: Mutex<Vec<DhtEvent>>,
    pending: Mutex<PendingMap>,
    stop: AtomicBool,
    next_tid: AtomicU16,
    /// Announces received: `(info_hash, peer)`.
    announced: Mutex<Vec<([u8; 20], SocketAddr)>>,
    /// Nodes learned from queriers (served in `nodes` / `nodes6` after the
    /// configured ones), when `learn` is on.
    learned: Mutex<Vec<KnownNode>>,
}

/// A running tap DHT node.
pub struct TapDht {
    inner: Arc<Inner>,
    socks: Vec<(Arc<UdpSocket>, SocketAddr)>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// Compact node info: 20-byte id + 6 or 18 byte endpoint.
fn compact_node(n: &KnownNode) -> Vec<u8> {
    let mut v = n.id.to_vec();
    v.extend_from_slice(&compact_endpoint(n.addr));
    v
}

pub fn compact_endpoint(a: SocketAddr) -> Vec<u8> {
    let mut v = match a.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    v.extend_from_slice(&a.port().to_be_bytes());
    v
}

/// Decode a compact endpoint (6 or 18 bytes).
pub fn parse_endpoint(b: &[u8]) -> Option<SocketAddr> {
    match b.len() {
        6 => {
            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Some(SocketAddr::new(
                IpAddr::V4(ip),
                u16::from_be_bytes([b[4], b[5]]),
            ))
        }
        18 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            Some(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(o)),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        _ => None,
    }
}

/// Decode a `nodes` / `nodes6` string into `(id, addr)` pairs.
pub fn parse_nodes(b: &[u8], v6: bool) -> Vec<([u8; 20], SocketAddr)> {
    let step = if v6 { 38 } else { 26 };
    b.chunks_exact(step)
        .filter_map(|c| {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            parse_endpoint(&c[20..]).map(|a| (id, a))
        })
        .collect()
}

impl TapDht {
    pub fn start(config: TapDhtConfig) -> Result<TapDht> {
        let inner = Arc::new(Inner {
            config: config.clone(),
            start: Instant::now(),
            events: Mutex::new(Vec::new()),
            pending: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
            next_tid: AtomicU16::new(0x1000),
            announced: Mutex::new(Vec::new()),
            learned: Mutex::new(Vec::new()),
        });
        let mut socks = Vec::new();
        let mut threads = Vec::new();
        for addr in &config.listen {
            let sock = UdpSocket::bind(addr).with_context(|| format!("tap-dht bind {addr}"))?;
            sock.set_read_timeout(Some(Duration::from_millis(100)))?;
            let local = sock.local_addr()?;
            let sock = Arc::new(sock);
            let inner2 = inner.clone();
            let s2 = sock.clone();
            threads.push(
                std::thread::Builder::new()
                    .name(format!("tap-dht-{}", local.port()))
                    .spawn(move || inner2.serve(s2, local))?,
            );
            socks.push((sock, local));
        }
        Ok(TapDht {
            inner,
            socks,
            threads,
        })
    }

    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.socks.iter().map(|(_, a)| *a).collect()
    }

    pub fn node_id(&self) -> [u8; 20] {
        self.inner.config.node_id
    }

    /// Everything recorded so far.
    pub fn events(&self) -> Vec<DhtEvent> {
        self.inner
            .events
            .lock()
            .map(|e| e.clone())
            .unwrap_or_default()
    }

    /// `(info_hash, peer endpoint)` of every accepted `announce_peer`.
    pub fn announced(&self) -> Vec<([u8; 20], SocketAddr)> {
        self.inner
            .announced
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    pub fn save_jsonl(&self, path: &std::path::Path) -> Result<()> {
        let mut out = String::new();
        for e in self.events() {
            out.push_str(&serde_json::to_string(&e)?);
            out.push('\n');
        }
        std::fs::write(path, out)?;
        Ok(())
    }

    pub fn wait_for<F: Fn(&[DhtEvent]) -> bool>(&self, timeout: Duration, pred: F) -> bool {
        let start = Instant::now();
        loop {
            if pred(&self.events()) {
                return true;
            }
            if start.elapsed() > timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Send a query to `to` and wait (bounded) for its response or error.
    /// `args` are the `a` dictionary entries besides `id` (added here).
    pub fn query(&self, to: SocketAddr, q: &str, args: Value, timeout: Duration) -> Option<Value> {
        let (sock, local) = self
            .socks
            .iter()
            .find(|(_, a)| a.is_ipv4() == to.is_ipv4())?;
        let tid = self
            .inner
            .next_tid
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes()
            .to_vec();
        let mut a = args;
        a.insert("id", Value::Bytes(self.inner.config.node_id.to_vec()));
        let mut m = Value::dict();
        m.insert("a", a);
        m.insert("q", Value::str(q));
        m.insert("t", Value::Bytes(tid.clone()));
        if let Some(v) = &self.inner.config.version {
            m.insert("v", Value::Bytes(v.clone()));
        }
        m.insert("y", Value::str("q"));
        let bytes = m.encode();
        let pending = Arc::new(Pending {
            reply: Mutex::new(None),
        });
        self.inner
            .pending
            .lock()
            .unwrap()
            .insert((to, tid.clone()), pending.clone());
        self.inner.record(*local, to, "send", &bytes, &m);
        sock.send_to(&bytes, to).ok()?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(r) = pending.reply.lock().unwrap().take() {
                return Some(r);
            }
            if Instant::now() > deadline {
                self.inner.pending.lock().unwrap().remove(&(to, tid));
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Send raw bytes (malformed probes).
    pub fn send_raw(&self, to: SocketAddr, bytes: &[u8]) -> Result<()> {
        let (sock, local) = self
            .socks
            .iter()
            .find(|(_, a)| a.is_ipv4() == to.is_ipv4())
            .context("no socket for family")?;
        let decoded = bencode::decode(bytes).unwrap_or(Value::Bytes(bytes.to_vec()));
        self.inner.record(*local, to, "send", bytes, &decoded);
        sock.send_to(bytes, to)?;
        Ok(())
    }
}

impl Drop for TapDht {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn kind_of(v: &Value) -> String {
    match v.get("y").and_then(Value::as_str) {
        Some("q") => format!(
            "query:{}",
            v.get("q").and_then(Value::as_str).unwrap_or("?")
        ),
        Some("r") => "response".into(),
        Some("e") => "error".into(),
        _ => "invalid".into(),
    }
}

impl Inner {
    fn record(&self, local: SocketAddr, remote: SocketAddr, dir: &str, raw: &[u8], v: &Value) {
        let ev = DhtEvent {
            ts_ms: now_ms(self.start),
            dir: dir.into(),
            remote,
            local,
            kind: kind_of(v),
            tid_hex: v
                .get("t")
                .and_then(Value::as_bytes)
                .map(bencode::hex)
                .unwrap_or_default(),
            raw_hex: bencode::hex(raw),
            decoded: value_to_json(v),
        };
        if let Ok(mut e) = self.events.lock() {
            e.push(ev);
        }
    }

    fn serve(&self, sock: Arc<UdpSocket>, local: SocketAddr) {
        let mut buf = vec![0u8; 65536];
        while !self.stop.load(Ordering::Relaxed) {
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => {
                    tracing::warn!("tap-dht recv: {e}");
                    continue;
                }
            };
            let pkt = &buf[..n];
            let decoded = match bencode::decode(pkt) {
                Ok(v) => v,
                Err(_) => {
                    self.record(local, from, "recv", pkt, &Value::Bytes(pkt.to_vec()));
                    continue;
                }
            };
            self.record(local, from, "recv", pkt, &decoded);
            match decoded.get("y").and_then(Value::as_str) {
                Some("q") => {
                    if self.config.behaviour == DhtBehaviour::Silent {
                        continue;
                    }
                    if let Some(resp) = self.answer(&decoded, from) {
                        let bytes = resp.encode();
                        self.record(local, from, "send", &bytes, &resp);
                        let _ = sock.send_to(&bytes, from);
                    }
                }
                Some("r") | Some("e") => {
                    if let Some(t) = decoded.get("t").and_then(Value::as_bytes) {
                        let p = self.pending.lock().unwrap().remove(&(from, t.to_vec()));
                        if let Some(p) = p {
                            *p.reply.lock().unwrap() = Some(decoded.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn nodes_for(&self, from: SocketAddr, want: Option<&Value>) -> Vec<(String, Vec<u8>)> {
        // Families asked for: `want` list of "n4"/"n6", else the requester's.
        let mut fams: Vec<bool> = Vec::new();
        if let Some(l) = want.and_then(Value::as_list) {
            for w in l {
                match w.as_str() {
                    Some("n4") => fams.push(false),
                    Some("n6") => fams.push(true),
                    _ => {}
                }
            }
        }
        if fams.is_empty() {
            fams.push(from.is_ipv6());
        }
        let learned = self.learned.lock().map(|l| l.clone()).unwrap_or_default();
        fams.into_iter()
            .map(|v6| {
                let mut blob = Vec::new();
                for n in self
                    .config
                    .nodes
                    .iter()
                    .chain(learned.iter())
                    .filter(|n| n.addr.is_ipv6() == v6 && n.addr != from)
                    .take(8)
                {
                    blob.extend(compact_node(n));
                }
                ((if v6 { "nodes6" } else { "nodes" }).to_string(), blob)
            })
            .collect()
    }

    fn answer(&self, q: &Value, from: SocketAddr) -> Option<Value> {
        let t = q.get("t").and_then(Value::as_bytes)?.to_vec();
        let name = q.get("q").and_then(Value::as_str).unwrap_or("");
        let a = q.get("a")?;
        if self.config.learn
            && let Some(id) = a.get("id").and_then(Value::as_bytes)
            && id.len() == 20
            && let Ok(mut l) = self.learned.lock()
            && !l.iter().any(|n| n.addr == from)
        {
            let mut nid = [0u8; 20];
            nid.copy_from_slice(id);
            l.push(KnownNode {
                id: nid,
                addr: from,
            });
        }
        let mut r = Value::dict();
        r.insert("id", Value::Bytes(self.config.node_id.to_vec()));
        let mut err: Option<(i64, &str)> = None;
        match name {
            "ping" => {}
            "find_node" => {
                for (k, blob) in self.nodes_for(from, a.get("want")) {
                    r.insert(&k, Value::Bytes(blob));
                }
            }
            "get_peers" => {
                for (k, blob) in self.nodes_for(from, a.get("want")) {
                    r.insert(&k, Value::Bytes(blob));
                }
                r.insert("token", Value::Bytes(self.config.token.clone()));
                if let Some(ih) = a.get("info_hash").and_then(Value::as_bytes)
                    && ih.len() == 20
                {
                    let mut h = [0u8; 20];
                    h.copy_from_slice(ih);
                    let mut peers: Vec<SocketAddr> =
                        self.config.peers.get(&h).cloned().unwrap_or_default();
                    if self.config.learn
                        && let Ok(ann) = self.announced.lock()
                    {
                        for (ih, p) in ann.iter() {
                            if *ih == h && !peers.contains(p) && p.ip() != from.ip() {
                                peers.push(*p);
                            }
                        }
                    }
                    let vals: Vec<Value> = peers
                        .iter()
                        .filter(|p| p.is_ipv6() == from.is_ipv6())
                        .map(|p| Value::Bytes(compact_endpoint(*p)))
                        .collect();
                    if !vals.is_empty() {
                        r.insert("values", Value::List(vals));
                    }
                }
            }
            "announce_peer" => {
                let tok = a.get("token").and_then(Value::as_bytes);
                if tok != Some(self.config.token.as_slice()) {
                    err = Some((203, "invalid token"));
                } else if let Some(ih) = a.get("info_hash").and_then(Value::as_bytes)
                    && ih.len() == 20
                {
                    let mut h = [0u8; 20];
                    h.copy_from_slice(ih);
                    let implied = a.get("implied_port").and_then(Value::as_int) == Some(1);
                    let port = if implied {
                        from.port()
                    } else {
                        a.get("port").and_then(Value::as_int).unwrap_or(0) as u16
                    };
                    self.announced
                        .lock()
                        .unwrap()
                        .push((h, SocketAddr::new(from.ip(), port)));
                }
            }
            "sample_infohashes" => {
                for (k, blob) in self.nodes_for(from, a.get("want")) {
                    r.insert(&k, Value::Bytes(blob));
                }
                r.insert("interval", Value::Int(21600));
                r.insert("num", Value::Int(0));
                r.insert("samples", Value::Bytes(Vec::new()));
            }
            _ => err = Some((204, "Method Unknown")),
        }
        let mut m = Value::dict();
        match err {
            Some((code, msg)) => {
                m.insert("e", Value::List(vec![Value::Int(code), Value::str(msg)]));
                m.insert("y", Value::str("e"));
            }
            None => {
                m.insert("r", r);
                m.insert("y", Value::str("r"));
            }
        }
        m.insert("t", Value::Bytes(t));
        if let Some(v) = &self.config.version {
            m.insert("v", Value::Bytes(v.clone()));
        }
        Some(m)
    }
}

/// Build the `a` dictionary for a query from `(key, value)` pairs.
pub fn args(pairs: &[(&str, Value)]) -> Value {
    let mut d = Value::dict();
    for (k, v) in pairs {
        d.insert(k, v.clone());
    }
    d
}

/// Render a KRPC message compactly for notes (`q` + sorted keys of `a`).
pub fn shape(v: &serde_json::Value) -> String {
    let y = v.get("y").and_then(|y| y.as_str()).unwrap_or("?");
    let q = v.get("q").and_then(|q| q.as_str()).unwrap_or("");
    let body = v
        .get("a")
        .or_else(|| v.get("r"))
        .and_then(|b| b.as_object())
        .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","))
        .unwrap_or_default();
    let top: Vec<String> = v
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    format!("y={y} q={q} top=[{}] body=[{body}]", top.join(","))
}
