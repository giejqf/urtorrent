// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! `tap-tracker`: a functional HTTP / HTTPS / UDP tracker that records the raw
//! bytes of every request (post-TLS) before answering. It can also be
//! configured PT-style (passkey path, client whitelist) and to misbehave
//! (failure reasons, HTTP errors, redirects, silence) for tier/backoff tests.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::bencode::{self, Value};
use crate::http::{self, RawRequest};

/// How the tracker answers announces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Behaviour {
    /// Answer normally.
    Normal,
    /// Bencoded `failure reason`.
    Failure(String),
    /// HTTP status code with an empty body (e.g. 500, 404).
    HttpStatus(u16),
    /// 302 redirect to the given URL (HTTP only).
    Redirect(String),
    /// Accept the connection but never answer.
    Silent,
    /// Drop the datagram / close the connection immediately.
    Drop,
}

/// Tracker configuration.
#[derive(Clone, Debug)]
pub struct TapTrackerConfig {
    pub http: Vec<SocketAddr>,
    pub https: Vec<SocketAddr>,
    pub udp: Vec<SocketAddr>,
    pub interval: u32,
    pub min_interval: Option<u32>,
    /// PT-style: announce/scrape paths must be `/<passkey>/announce`.
    pub passkey: Option<String>,
    /// PT-style: allowed `peer_id` prefixes (8 chars); anything else is refused.
    pub peer_id_whitelist: Option<Vec<String>>,
    /// Extra peers to include in every announce response.
    pub extra_peers: Vec<SocketAddr>,
    pub behaviour: Behaviour,
    /// Reply with a `tracker id` and require it back.
    pub tracker_id: Option<String>,
    /// Answer with gzip-compressed bodies when the client accepts it (unused for now).
    pub gzip: bool,
    /// Name used in the certificate SAN list (IPs of the listeners are added automatically).
    pub tls_names: Vec<String>,
}

impl Default for TapTrackerConfig {
    fn default() -> Self {
        TapTrackerConfig {
            http: Vec::new(),
            https: Vec::new(),
            udp: Vec::new(),
            interval: 60,
            min_interval: None,
            passkey: None,
            peer_id_whitelist: None,
            extra_peers: Vec::new(),
            behaviour: Behaviour::Normal,
            tracker_id: None,
            gzip: false,
            tls_names: Vec::new(),
        }
    }
}

/// One recorded request/response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TapEvent {
    /// Milliseconds since the tracker started.
    pub ts_ms: u64,
    /// `http`, `https` or `udp`.
    pub transport: String,
    pub from: SocketAddr,
    pub to: SocketAddr,
    /// `announce`, `scrape`, `connect`, `other`, `error`.
    pub kind: String,
    /// Hex of the raw request bytes (HTTP head + body, or the UDP datagram).
    pub raw_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<UdpView>,
    /// Hex of the response bytes (HTTP body / UDP datagram).
    pub response_hex: String,
}

/// Parsed view of an HTTP request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpView {
    pub request_line: String,
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    /// Query parameters in wire order, values still percent-encoded.
    pub query: Vec<(String, String)>,
}

/// Parsed view of a UDP tracker datagram.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UdpView {
    pub action: u32,
    pub transaction_id: u32,
    pub connection_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce: Option<UdpAnnounce>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scrape_hashes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UdpAnnounce {
    pub info_hash: String,
    pub peer_id: String,
    pub downloaded: u64,
    pub left: u64,
    pub uploaded: u64,
    pub event: u32,
    pub ip: u32,
    pub key: u32,
    pub num_want: i32,
    pub port: u16,
    /// Extensions (BEP 41) bytes after the fixed part, hex.
    pub extensions_hex: String,
}

#[derive(Clone, Debug)]
struct SwarmPeer {
    addr: SocketAddr,
    peer_id: Vec<u8>,
    left: u64,
    seen: Instant,
}

#[derive(Default)]
struct Swarm {
    torrents: HashMap<[u8; 20], Vec<SwarmPeer>>,
    completed: HashMap<[u8; 20], u64>,
}

impl Swarm {
    fn announce(&mut self, ih: [u8; 20], addr: SocketAddr, peer_id: &[u8], left: u64, event: &str) {
        let peers = self.torrents.entry(ih).or_default();
        peers.retain(|p| p.seen.elapsed() < Duration::from_secs(3600));
        if event == "stopped" {
            peers.retain(|p| p.addr != addr && p.peer_id != peer_id);
            return;
        }
        if event == "completed" {
            *self.completed.entry(ih).or_default() += 1;
        }
        match peers.iter_mut().find(|p| p.addr == addr) {
            Some(p) => {
                p.left = left;
                p.seen = Instant::now();
                p.peer_id = peer_id.to_vec();
            }
            None => peers.push(SwarmPeer {
                addr,
                peer_id: peer_id.to_vec(),
                left,
                seen: Instant::now(),
            }),
        }
    }

    fn counts(&self, ih: &[u8; 20]) -> (u64, u64, u64) {
        let peers = self.torrents.get(ih).map(Vec::as_slice).unwrap_or(&[]);
        let seeds = peers.iter().filter(|p| p.left == 0).count() as u64;
        let leech = peers.len() as u64 - seeds;
        (seeds, leech, self.completed.get(ih).copied().unwrap_or(0))
    }

    fn peers_for(&self, ih: &[u8; 20], exclude: SocketAddr, numwant: usize) -> Vec<SocketAddr> {
        self.torrents
            .get(ih)
            .map(|v| {
                v.iter()
                    .filter(|p| p.addr != exclude)
                    .map(|p| p.addr)
                    .take(numwant)
                    .collect()
            })
            .unwrap_or_default()
    }
}

struct Inner {
    config: TapTrackerConfig,
    /// Runtime-changeable behaviour (starts as `config.behaviour`).
    behaviour: Mutex<Behaviour>,
    start: Instant,
    events: Mutex<Vec<TapEvent>>,
    swarm: Mutex<Swarm>,
    udp_conn_ids: Mutex<HashMap<u64, Instant>>,
    stop: AtomicBool,
}

/// A running tap-tracker.
pub struct TapTracker {
    inner: Arc<Inner>,
    servers: Vec<http::Server>,
    udp_threads: Vec<std::thread::JoinHandle<()>>,
    /// PEM of the test CA (when HTTPS is configured), for clients to trust.
    pub ca_pem: Option<String>,
}

fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

impl TapTracker {
    pub fn start(config: TapTrackerConfig) -> Result<TapTracker> {
        let inner = Arc::new(Inner {
            behaviour: Mutex::new(config.behaviour.clone()),
            config: config.clone(),
            start: Instant::now(),
            events: Mutex::new(Vec::new()),
            swarm: Mutex::new(Swarm::default()),
            udp_conn_ids: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
        });
        let mut servers = Vec::new();
        for addr in &config.http {
            let listener =
                TcpListener::bind(addr).with_context(|| format!("tap-tracker http bind {addr}"))?;
            let inner2 = inner.clone();
            servers.push(http::Server::spawn(listener, move |s, peer| {
                let local = s.local_addr().ok();
                let mut s = s;
                inner2.serve_http(&mut s, peer, local, "http");
            })?);
        }
        let mut ca_pem = None;
        if !config.https.is_empty() {
            let (ca, server_cfg) = make_tls(&config)?;
            ca_pem = Some(ca);
            for addr in &config.https {
                let listener = TcpListener::bind(addr)
                    .with_context(|| format!("tap-tracker https bind {addr}"))?;
                let inner2 = inner.clone();
                let cfg = server_cfg.clone();
                servers.push(http::Server::spawn(listener, move |mut s, peer| {
                    let local = s.local_addr().ok();
                    let mut conn = match rustls::ServerConnection::new(cfg.clone()) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("tls: {e}");
                            return;
                        }
                    };
                    let mut tls = rustls::Stream::new(&mut conn, &mut s);
                    inner2.serve_http(&mut tls, peer, local, "https");
                })?);
            }
        }
        let mut udp_threads = Vec::new();
        for addr in &config.udp {
            let sock =
                UdpSocket::bind(addr).with_context(|| format!("tap-tracker udp bind {addr}"))?;
            sock.set_read_timeout(Some(Duration::from_millis(100)))?;
            let inner2 = inner.clone();
            let local = sock.local_addr()?;
            udp_threads.push(
                std::thread::Builder::new()
                    .name(format!("udp-tracker-{}", local.port()))
                    .spawn(move || inner2.serve_udp(sock, local))?,
            );
        }
        Ok(TapTracker {
            inner,
            servers,
            udp_threads,
            ca_pem,
        })
    }

    /// Snapshot of everything recorded so far.
    pub fn events(&self) -> Vec<TapEvent> {
        self.inner
            .events
            .lock()
            .map(|e| e.clone())
            .unwrap_or_default()
    }

    pub fn announces(&self) -> Vec<TapEvent> {
        self.events()
            .into_iter()
            .filter(|e| e.kind == "announce")
            .collect()
    }

    /// Write all events as JSON lines.
    pub fn save_jsonl(&self, path: &std::path::Path) -> Result<()> {
        let mut out = String::new();
        for e in self.events() {
            out.push_str(&serde_json::to_string(&e)?);
            out.push('\n');
        }
        std::fs::write(path, out)?;
        Ok(())
    }

    /// Wait until `n` events of `kind` have been seen (or a predicate holds).
    pub fn wait_for<F: Fn(&[TapEvent]) -> bool>(&self, timeout: Duration, pred: F) -> bool {
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

    /// Inject a peer into the swarm of `info_hash` (as if it had announced).
    pub fn inject_peer(&self, info_hash: [u8; 20], addr: SocketAddr, left: u64) {
        if let Ok(mut s) = self.inner.swarm.lock() {
            s.announce(info_hash, addr, b"-TAP0000-injectedpeer", left, "");
        }
    }

    /// Change behaviour at runtime (e.g. take the tracker "down").
    pub fn set_behaviour(&self, b: Behaviour) {
        *self.inner.behaviour.lock().unwrap() = b;
    }

    pub fn http_url(&self, idx: usize) -> String {
        let a = self.inner.config.http[idx];
        self.url_for("http", a)
    }
    pub fn https_url(&self, idx: usize) -> String {
        let a = self.inner.config.https[idx];
        self.url_for("https", a)
    }
    pub fn udp_url(&self, idx: usize) -> String {
        let a = self.inner.config.udp[idx];
        self.url_for("udp", a)
    }
    fn url_for(&self, scheme: &str, a: SocketAddr) -> String {
        let host = match a.ip() {
            IpAddr::V4(v) => v.to_string(),
            IpAddr::V6(v) => format!("[{v}]"),
        };
        match &self.inner.config.passkey {
            Some(pk) => format!("{scheme}://{host}:{}/{pk}/announce", a.port()),
            None => format!("{scheme}://{host}:{}/announce", a.port()),
        }
    }
}

impl Drop for TapTracker {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        self.servers.clear();
        for t in self.udp_threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn make_tls(config: &TapTrackerConfig) -> Result<(String, Arc<rustls::ServerConfig>)> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
    };
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "urtorrent test CA");
    ca_params.distinguished_name = dn;
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let mut names: Vec<SanType> = config
        .https
        .iter()
        .map(|a| SanType::IpAddress(a.ip()))
        .collect();
    for n in &config.tls_names {
        names.push(SanType::DnsName(n.clone().try_into()?));
    }
    let mut leaf = CertificateParams::new(Vec::<String>::new())?;
    leaf.subject_alt_names = names;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "tap-tracker");
    leaf.distinguished_name = dn;
    let leaf_key = KeyPair::generate()?;
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key)?;

    let certs = vec![leaf_cert.der().clone(), ca_cert.der().clone()];
    let key = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok((ca_cert.pem(), Arc::new(cfg)))
}

fn announce_key(pk: &Option<String>, path: &str) -> Option<&'static str> {
    let expect_announce = match pk {
        Some(p) => format!("/{p}/announce"),
        None => "/announce".to_string(),
    };
    let expect_scrape = match pk {
        Some(p) => format!("/{p}/scrape"),
        None => "/scrape".to_string(),
    };
    if path == expect_announce {
        Some("announce")
    } else if path == expect_scrape {
        Some("scrape")
    } else {
        None
    }
}

fn compact_peers(peers: &[SocketAddr]) -> (Vec<u8>, Vec<u8>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for p in peers {
        match p.ip() {
            IpAddr::V4(a) => {
                v4.extend_from_slice(&a.octets());
                v4.extend_from_slice(&p.port().to_be_bytes());
            }
            IpAddr::V6(a) => {
                v6.extend_from_slice(&a.octets());
                v6.extend_from_slice(&p.port().to_be_bytes());
            }
        }
    }
    (v4, v6)
}

impl Inner {
    fn record(&self, ev: TapEvent) {
        if let Ok(mut e) = self.events.lock() {
            e.push(ev);
        }
    }

    fn serve_http<S: Read + Write>(
        &self,
        s: &mut S,
        peer: SocketAddr,
        local: Option<SocketAddr>,
        transport: &str,
    ) {
        let local = local.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        loop {
            let req = match http::read_request(s) {
                Ok(Some(r)) => r,
                Ok(None) => return,
                Err(e) => {
                    tracing::debug!("tap-tracker {transport} read from {peer}: {e}");
                    return;
                }
            };
            let ts_ms = now_ms(self.start);
            let close = req.wants_close();
            let (kind, body, status) = self.answer_http(&req, peer);
            let view = HttpView {
                request_line: format!("{} {} {}", req.method, req.target, req.version),
                method: req.method.clone(),
                path: req.path().to_string(),
                version: req.version.clone(),
                headers: req.headers.clone(),
                query: req.query().params,
            };
            self.record(TapEvent {
                ts_ms,
                transport: transport.to_string(),
                from: peer,
                to: local,
                kind: kind.to_string(),
                raw_hex: bencode::hex(&req.raw),
                http: Some(view),
                udp: None,
                response_hex: bencode::hex(&body),
            });
            let behaviour = self.behaviour.lock().unwrap().clone();
            match &behaviour {
                Behaviour::Silent => {
                    std::thread::sleep(Duration::from_secs(120));
                    return;
                }
                Behaviour::Drop => return,
                Behaviour::Redirect(url) => {
                    let _ = http::write_response(
                        s,
                        302,
                        "Found",
                        &[("Location", url), ("Content-Type", "text/plain")],
                        b"",
                    );
                }
                Behaviour::HttpStatus(code) => {
                    let _ = http::write_response(
                        s,
                        *code,
                        "Error",
                        &[("Content-Type", "text/plain")],
                        b"",
                    );
                }
                _ => {
                    let reason = if status == 200 { "OK" } else { "Not Found" };
                    let _ = http::write_response(
                        s,
                        status,
                        reason,
                        &[("Content-Type", "text/plain"), ("Server", "tap-tracker")],
                        &body,
                    );
                }
            }
            if close {
                return;
            }
        }
    }

    fn failure(reason: &str) -> Vec<u8> {
        let mut d = Value::dict();
        d.insert("failure reason", Value::str(reason));
        d.encode()
    }

    /// Returns (kind, body, status).
    fn answer_http(&self, req: &RawRequest, peer: SocketAddr) -> (&'static str, Vec<u8>, u16) {
        let Some(kind) = announce_key(&self.config.passkey, req.path()) else {
            return ("other", b"not found".to_vec(), 404);
        };
        if let Behaviour::Failure(reason) = &*self.behaviour.lock().unwrap() {
            return (kind, Self::failure(reason), 200);
        }
        let q = req.query();
        if kind == "scrape" {
            let hashes: Vec<[u8; 20]> = q
                .params
                .iter()
                .filter(|(k, _)| k == "info_hash")
                .filter_map(|(_, v)| http::percent_decode(v.as_bytes()).try_into().ok())
                .collect();
            let swarm = self.swarm.lock();
            let mut files = Value::dict();
            if let Ok(swarm) = swarm {
                for ih in hashes {
                    let (s, l, c) = swarm.counts(&ih);
                    let mut f = Value::dict();
                    f.insert("complete", Value::Int(s as i64));
                    f.insert("downloaded", Value::Int(c as i64));
                    f.insert("incomplete", Value::Int(l as i64));
                    if let Value::Dict(d) = &mut files {
                        d.insert(ih.to_vec(), f);
                    }
                }
            }
            let mut resp = Value::dict();
            resp.insert("files", files);
            return ("scrape", resp.encode(), 200);
        }
        // announce
        let Some(ih): Option<[u8; 20]> = q.get("info_hash").and_then(|v| v.try_into().ok()) else {
            return ("announce", Self::failure("missing info_hash"), 200);
        };
        let peer_id = q.get("peer_id").unwrap_or_default();
        if let Some(wl) = &self.config.peer_id_whitelist {
            let prefix = String::from_utf8_lossy(&peer_id[..peer_id.len().min(8)]).into_owned();
            if !wl.iter().any(|p| prefix.starts_with(p.as_str())) {
                return ("announce", Self::failure("unregistered client"), 200);
            }
        }
        let port: u16 = q.get_str("port").and_then(|p| p.parse().ok()).unwrap_or(0);
        let left: u64 = q.get_str("left").and_then(|p| p.parse().ok()).unwrap_or(0);
        let event = q.get_str("event").unwrap_or_default();
        let numwant: usize = q
            .get_str("numwant")
            .and_then(|p| p.parse().ok())
            .unwrap_or(50);
        let peer_addr = SocketAddr::new(peer.ip(), port);
        let (seeds, leech, done, peers) = match self.swarm.lock() {
            Ok(mut s) => {
                s.announce(ih, peer_addr, &peer_id, left, &event);
                let (a, b, c) = s.counts(&ih);
                let mut peers = s.peers_for(&ih, peer_addr, numwant);
                for e in &self.config.extra_peers {
                    if !peers.contains(e) && *e != peer_addr {
                        peers.push(*e);
                    }
                }
                (a, b, c, peers)
            }
            Err(_) => (0, 0, 0, Vec::new()),
        };
        let mut resp = Value::dict();
        resp.insert("complete", Value::Int(seeds as i64));
        resp.insert("downloaded", Value::Int(done as i64));
        resp.insert("incomplete", Value::Int(leech as i64));
        resp.insert("interval", Value::Int(i64::from(self.config.interval)));
        if let Some(mi) = self.config.min_interval {
            resp.insert("min interval", Value::Int(i64::from(mi)));
        }
        if let Some(tid) = &self.config.tracker_id {
            resp.insert("tracker id", Value::str(tid));
        }
        let compact = q.get_str("compact").as_deref() != Some("0");
        let (v4, v6) = compact_peers(&peers);
        if compact {
            resp.insert("peers", Value::Bytes(v4));
            if !v6.is_empty() {
                resp.insert("peers6", Value::Bytes(v6));
            }
        } else {
            let list = peers
                .iter()
                .map(|p| {
                    let mut d = Value::dict();
                    d.insert("ip", Value::str(&p.ip().to_string()));
                    d.insert("port", Value::Int(i64::from(p.port())));
                    d
                })
                .collect();
            resp.insert("peers", Value::List(list));
        }
        ("announce", resp.encode(), 200)
    }

    fn serve_udp(&self, sock: UdpSocket, local: SocketAddr) {
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
                    tracing::warn!("udp tracker recv: {e}");
                    continue;
                }
            };
            let pkt = &buf[..n];
            let ts_ms = now_ms(self.start);
            let (kind, view, resp) = self.answer_udp(pkt, from);
            self.record(TapEvent {
                ts_ms,
                transport: "udp".into(),
                from,
                to: local,
                kind: kind.to_string(),
                raw_hex: bencode::hex(pkt),
                http: None,
                udp: view,
                response_hex: bencode::hex(&resp),
            });
            if matches!(
                &*self.behaviour.lock().unwrap(),
                Behaviour::Silent | Behaviour::Drop
            ) {
                continue;
            }
            if !resp.is_empty() {
                let _ = sock.send_to(&resp, from);
            }
        }
    }

    fn udp_error(tid: u32, msg: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&3u32.to_be_bytes());
        out.extend_from_slice(&tid.to_be_bytes());
        out.extend_from_slice(msg.as_bytes());
        out
    }

    fn answer_udp(&self, pkt: &[u8], from: SocketAddr) -> (&'static str, Option<UdpView>, Vec<u8>) {
        if pkt.len() < 16 {
            return ("error", None, Vec::new());
        }
        let conn_id = u64::from_be_bytes(pkt[0..8].try_into().unwrap_or([0; 8]));
        let action = u32::from_be_bytes(pkt[8..12].try_into().unwrap_or([0; 4]));
        let tid = u32::from_be_bytes(pkt[12..16].try_into().unwrap_or([0; 4]));
        let mut view = UdpView {
            action,
            transaction_id: tid,
            connection_id: conn_id,
            announce: None,
            scrape_hashes: Vec::new(),
        };
        match action {
            0 => {
                if conn_id != 0x41727101980 {
                    return ("error", Some(view), Self::udp_error(tid, "bad magic"));
                }
                let new_id = (u64::from(tid) << 32)
                    ^ (self.start.elapsed().as_nanos() as u64)
                    ^ 0x5eed_c0de_1234_5678;
                if let Ok(mut m) = self.udp_conn_ids.lock() {
                    m.insert(new_id, Instant::now());
                }
                let mut out = Vec::new();
                out.extend_from_slice(&0u32.to_be_bytes());
                out.extend_from_slice(&tid.to_be_bytes());
                out.extend_from_slice(&new_id.to_be_bytes());
                ("connect", Some(view), out)
            }
            1 => {
                let valid = self
                    .udp_conn_ids
                    .lock()
                    .map(|m| {
                        m.get(&conn_id)
                            .is_some_and(|t| t.elapsed() < Duration::from_secs(120))
                    })
                    .unwrap_or(false);
                if !valid {
                    return (
                        "announce",
                        Some(view),
                        Self::udp_error(tid, "bad connection id"),
                    );
                }
                if pkt.len() < 98 {
                    return (
                        "announce",
                        Some(view),
                        Self::udp_error(tid, "short announce"),
                    );
                }
                let ih: [u8; 20] = pkt[16..36].try_into().unwrap_or([0; 20]);
                let peer_id = &pkt[36..56];
                let downloaded = u64::from_be_bytes(pkt[56..64].try_into().unwrap_or([0; 8]));
                let left = u64::from_be_bytes(pkt[64..72].try_into().unwrap_or([0; 8]));
                let uploaded = u64::from_be_bytes(pkt[72..80].try_into().unwrap_or([0; 8]));
                let event = u32::from_be_bytes(pkt[80..84].try_into().unwrap_or([0; 4]));
                let ip = u32::from_be_bytes(pkt[84..88].try_into().unwrap_or([0; 4]));
                let key = u32::from_be_bytes(pkt[88..92].try_into().unwrap_or([0; 4]));
                let num_want = i32::from_be_bytes(pkt[92..96].try_into().unwrap_or([0; 4]));
                let port = u16::from_be_bytes(pkt[96..98].try_into().unwrap_or([0; 2]));
                view.announce = Some(UdpAnnounce {
                    info_hash: bencode::hex(&ih),
                    peer_id: bencode::hex(peer_id),
                    downloaded,
                    left,
                    uploaded,
                    event,
                    ip,
                    key,
                    num_want,
                    port,
                    extensions_hex: bencode::hex(&pkt[98..]),
                });
                if let Behaviour::Failure(reason) = &*self.behaviour.lock().unwrap() {
                    return ("announce", Some(view), Self::udp_error(tid, reason));
                }
                let ev = match event {
                    1 => "completed",
                    2 => "started",
                    3 => "stopped",
                    _ => "",
                };
                let peer_addr = SocketAddr::new(from.ip(), port);
                let numwant = if num_want < 0 { 50 } else { num_want as usize };
                let (seeds, leech, peers) = match self.swarm.lock() {
                    Ok(mut s) => {
                        s.announce(ih, peer_addr, peer_id, left, ev);
                        let (a, b, _) = s.counts(&ih);
                        let mut peers = s.peers_for(&ih, peer_addr, numwant);
                        for e in &self.config.extra_peers {
                            if !peers.contains(e) && *e != peer_addr {
                                peers.push(*e);
                            }
                        }
                        (a, b, peers)
                    }
                    Err(_) => (0, 0, Vec::new()),
                };
                let mut out = Vec::new();
                out.extend_from_slice(&1u32.to_be_bytes());
                out.extend_from_slice(&tid.to_be_bytes());
                out.extend_from_slice(&self.config.interval.to_be_bytes());
                out.extend_from_slice(&(leech as u32).to_be_bytes());
                out.extend_from_slice(&(seeds as u32).to_be_bytes());
                let (v4, v6) = compact_peers(&peers);
                // Answer in the address family of the request socket.
                if from.is_ipv6() {
                    out.extend_from_slice(&v6)
                } else {
                    out.extend_from_slice(&v4)
                }
                ("announce", Some(view), out)
            }
            2 => {
                let hashes: Vec<[u8; 20]> = pkt[16..].as_chunks::<20>().0.to_vec();
                view.scrape_hashes = hashes.iter().map(|h| bencode::hex(h)).collect();
                let mut out = Vec::new();
                out.extend_from_slice(&2u32.to_be_bytes());
                out.extend_from_slice(&tid.to_be_bytes());
                if let Ok(s) = self.swarm.lock() {
                    for ih in &hashes {
                        let (seeds, leech, done) = s.counts(ih);
                        out.extend_from_slice(&(seeds as u32).to_be_bytes());
                        out.extend_from_slice(&(done as u32).to_be_bytes());
                        out.extend_from_slice(&(leech as u32).to_be_bytes());
                    }
                }
                ("scrape", Some(view), out)
            }
            _ => ("error", Some(view), Self::udp_error(tid, "unknown action")),
        }
    }
}

/// Helper: build the `Value` for a bencoded tracker response for tests.
pub fn decode_response(hex: &str) -> Option<Value> {
    bencode::decode(&bencode::unhex(hex)?).ok()
}

/// Group announce events by `info_hash` (hex) for assertions.
pub fn announces_by_hash(events: &[TapEvent]) -> BTreeMap<String, Vec<&TapEvent>> {
    let mut m: BTreeMap<String, Vec<&TapEvent>> = BTreeMap::new();
    for e in events.iter().filter(|e| e.kind == "announce") {
        let ih = match (&e.http, &e.udp) {
            (Some(h), _) => h
                .query
                .iter()
                .find(|(k, _)| k == "info_hash")
                .map(|(_, v)| bencode::hex(&http::percent_decode(v.as_bytes())))
                .unwrap_or_default(),
            (None, Some(u)) => u
                .announce
                .as_ref()
                .map(|a| a.info_hash.clone())
                .unwrap_or_default(),
            _ => String::new(),
        };
        m.entry(ih).or_default().push(e);
    }
    m
}
