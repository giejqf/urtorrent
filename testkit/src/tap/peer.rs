// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! `tap-peer`: a scriptable BitTorrent peer that records every byte it
//! receives and can misbehave on purpose. It can act as a seeder (serving a
//! fixture), a leecher (downloading and verifying), or stay silent after the
//! handshake to observe what the other side does on its own.

use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

use super::cipher::CipherStream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::bencode::{self, Value};
use crate::fixtures::Fixture;
use crate::peerwire::{self, FramedReader, Handshake, Msg, reserved};

/// What the tap-peer does after the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Serve the fixture (have all pieces).
    Seeder,
    /// Download the fixture, verifying hashes.
    Leecher,
    /// Send handshake (+ initial messages) and then only observe.
    Silent,
}

/// Deliberate misbehaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Misbehaviour {
    None,
    /// Serve pieces with corrupted data (hash failures).
    CorruptPieces,
    /// Never unchoke / never answer requests.
    Stall,
    /// Send random bytes after the handshake.
    Garbage,
    /// Trickle one byte per 500ms after the handshake.
    SlowLoris,
    /// Close right after sending our handshake.
    CloseAfterHandshake,
    /// Answer with a handshake for a different info-hash.
    WrongInfoHash,
    /// Send a piece message that was never requested, with an out-of-range index.
    ProtocolViolation,
}

/// MSE policy of the tap-peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TapEncryption {
    /// Plaintext only; encrypted connections are recorded as `not_plaintext`.
    Disabled,
    /// Accept both; connect out in plaintext. `prefer_rc4` steers the select.
    Allowed { prefer_rc4: bool },
    /// Require RC4 both ways; connect out with an MSE handshake.
    Forced,
}

/// What the tap saw of an MSE handshake.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MseView {
    pub role: String,
    pub method: String,
    pub pad_after_key: Option<usize>,
    pub pad_crypto: Option<usize>,
    pub crypto_field: Option<u32>,
    pub ia_len: Option<usize>,
}

/// Tap-peer configuration.
#[derive(Clone)]
pub struct TapPeerConfig {
    pub encryption: TapEncryption,
    /// Start outgoing connections with an MSE handshake even when not
    /// forced (to observe the peer's `crypto_select` for `provide = both`).
    pub initiate_mse: bool,
    pub listen: Vec<SocketAddr>,
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub reserved: [u8; 8],
    pub role: Role,
    pub fixture: Option<Arc<Fixture>>,
    /// Our LTEP handshake dictionary (`m`, `v`, `reqq`, ...). `None` = don't send one.
    pub ext_handshake: Option<Value>,
    pub misbehaviour: Misbehaviour,
    /// Hold the connection open this long after the script finishes.
    pub linger: Duration,
    /// Outstanding block requests as a leecher.
    pub pipeline: usize,
    /// Bitfield to advertise when the role is `Silent` (None = have_none/empty).
    pub advertise_pieces: Option<Vec<bool>>,
    /// Local address to bind outgoing connections to.
    pub bind_addr: Option<std::net::IpAddr>,
}

impl TapPeerConfig {
    pub fn new(info_hash: [u8; 20], role: Role) -> TapPeerConfig {
        let mut reserved = [0u8; 8];
        reserved::set(&mut reserved, reserved::LTEP);
        reserved::set(&mut reserved, reserved::FAST);
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let mut peer_id = *b"-TP0001-000000000000";
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tail = format!("{:0>6}{:0>6}", std::process::id() % 1_000_000, n);
        peer_id[8..].copy_from_slice(&tail.as_bytes()[..12]);
        let mut m = Value::dict();
        m.insert("ut_pex", Value::Int(1));
        m.insert("ut_metadata", Value::Int(2));
        let mut ext = Value::dict();
        ext.insert("m", m);
        ext.insert("v", Value::str("tap-peer 0.1"));
        ext.insert("reqq", Value::Int(250));
        TapPeerConfig {
            encryption: TapEncryption::Disabled,
            initiate_mse: false,
            listen: Vec::new(),
            info_hash,
            peer_id,
            reserved,
            role,
            fixture: None,
            ext_handshake: Some(ext),
            misbehaviour: Misbehaviour::None,
            linger: Duration::from_secs(5),
            pipeline: 8,
            advertise_pieces: None,
            bind_addr: None,
        }
    }

    pub fn bind_addr(mut self, a: std::net::IpAddr) -> Self {
        self.bind_addr = Some(a);
        self
    }

    pub fn listen(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.listen = addrs;
        self
    }
    pub fn fixture(mut self, fx: Arc<Fixture>) -> Self {
        self.fixture = Some(fx);
        self
    }
    pub fn misbehave(mut self, m: Misbehaviour) -> Self {
        self.misbehaviour = m;
        self
    }
    pub fn linger(mut self, d: Duration) -> Self {
        self.linger = d;
        self
    }
    pub fn reserved(mut self, r: [u8; 8]) -> Self {
        self.reserved = r;
        self
    }
    pub fn peer_id(mut self, id: [u8; 20]) -> Self {
        self.peer_id = id;
        self
    }
    pub fn ext_handshake(mut self, v: Option<Value>) -> Self {
        self.ext_handshake = v;
        self
    }
    pub fn encryption(mut self, e: TapEncryption) -> Self {
        self.encryption = e;
        self
    }
    pub fn initiate_mse(mut self, on: bool) -> Self {
        self.initiate_mse = on;
        self
    }
}

/// Parsed view of a handshake for captures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeView {
    pub pstr: String,
    pub reserved_hex: String,
    pub reserved_bits: Vec<String>,
    pub info_hash: String,
    pub peer_id_hex: String,
    pub peer_id_text: String,
    pub raw_hex: String,
}

impl HandshakeView {
    fn from(h: &Handshake, raw: &[u8]) -> HandshakeView {
        HandshakeView {
            pstr: String::from_utf8_lossy(&h.pstr).into_owned(),
            reserved_hex: bencode::hex(&h.reserved),
            reserved_bits: reserved::describe(&h.reserved),
            info_hash: bencode::hex(&h.info_hash),
            peer_id_hex: bencode::hex(&h.peer_id),
            peer_id_text: h
                .peer_id
                .iter()
                .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                .collect(),
            raw_hex: bencode::hex(raw),
        }
    }
}

/// One message on the wire, in either direction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerEvent {
    pub ts_ms: u64,
    /// `recv` or `send`.
    pub dir: String,
    pub kind: String,
    pub len: usize,
    pub detail: serde_json::Value,
    /// Raw frame hex for everything except piece payloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_hex: Option<String>,
}

/// Everything recorded for one connection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerCapture {
    pub id: u32,
    /// `in` (they connected to us) or `out`.
    pub direction: String,
    pub remote: SocketAddr,
    pub local: SocketAddr,
    pub opened_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_ms: Option<u64>,
    pub close_reason: String,
    /// Their handshake.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake: Option<HandshakeView>,
    /// Our handshake as sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_handshake: Option<HandshakeView>,
    /// Set when the first bytes were not a plaintext BitTorrent handshake
    /// (an MSE attempt, or garbage).
    pub not_plaintext: bool,
    pub first_bytes_hex: String,
    /// The MSE handshake, when one was completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mse: Option<MseView>,
    pub events: Vec<PeerEvent>,
    /// Pieces fully downloaded and verified (leecher role).
    pub pieces_ok: u32,
    pub pieces_bad: u32,
}

impl PeerCapture {
    pub fn recv(&self) -> impl Iterator<Item = &PeerEvent> {
        self.events.iter().filter(|e| e.dir == "recv")
    }
    pub fn recv_kinds(&self) -> Vec<&str> {
        self.recv().map(|e| e.kind.as_str()).collect()
    }
    /// The first received LTEP handshake dictionary, decoded.
    pub fn ext_handshake(&self) -> Option<&serde_json::Value> {
        self.recv()
            .find(|e| {
                e.kind == "extended" && e.detail.get("ext_id").and_then(|v| v.as_u64()) == Some(0)
            })
            .and_then(|e| e.detail.get("decoded"))
            .and_then(|d| d.get("dict"))
    }
}

struct Shared {
    config: TapPeerConfig,
    start: Instant,
    /// Finished connections.
    captures: Mutex<Vec<PeerCapture>>,
    /// Snapshots of connections still open (so scenarios can observe a
    /// lingering tap without waiting for it to close).
    live: Mutex<std::collections::HashMap<u32, PeerCapture>>,
    next_id: AtomicU32,
    stop: AtomicBool,
}

/// A running tap-peer.
pub struct TapPeer {
    shared: Arc<Shared>,
    threads: Vec<std::thread::JoinHandle<()>>,
    listeners: Vec<SocketAddr>,
}

impl TapPeer {
    pub fn start(config: TapPeerConfig) -> Result<TapPeer> {
        let shared = Arc::new(Shared {
            config: config.clone(),
            start: Instant::now(),
            captures: Mutex::new(Vec::new()),
            live: Mutex::new(std::collections::HashMap::new()),
            next_id: AtomicU32::new(1),
            stop: AtomicBool::new(false),
        });
        let mut threads = Vec::new();
        let mut listeners = Vec::new();
        for addr in &config.listen {
            let l = TcpListener::bind(addr).with_context(|| format!("tap-peer bind {addr}"))?;
            l.set_nonblocking(true)?;
            listeners.push(l.local_addr()?);
            let sh = shared.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("tap-peer-accept".into())
                    .spawn(move || {
                        while !sh.stop.load(Ordering::Relaxed) {
                            match l.accept() {
                                Ok((s, peer)) => {
                                    let sh2 = sh.clone();
                                    let _ = std::thread::Builder::new()
                                        .name("tap-peer-conn".into())
                                        .spawn(move || sh2.handle(s, peer, false));
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    std::thread::sleep(Duration::from_millis(5))
                                }
                                Err(_) => std::thread::sleep(Duration::from_millis(20)),
                            }
                        }
                    })?,
            );
        }
        Ok(TapPeer {
            shared,
            threads,
            listeners,
        })
    }

    pub fn listen_addrs(&self) -> &[SocketAddr] {
        &self.listeners
    }

    /// Ask every connection to end (they record their captures) and wait a
    /// moment for them to do so. The tap can still be queried afterwards.
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(600));
    }

    fn dial(bind: Option<std::net::IpAddr>, addr: SocketAddr) -> Result<TcpStream> {
        let domain = if addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
        if let Some(b) = bind {
            sock.bind(&SocketAddr::new(b, 0).into())?;
        }
        sock.connect_timeout(&addr.into(), Duration::from_secs(10))
            .with_context(|| format!("tap-peer connect {addr}"))?;
        Ok(sock.into())
    }

    /// Connect out to `addr` and run the same script as an initiator.
    /// Returns once the connection has finished.
    pub fn connect(&self, addr: SocketAddr) -> Result<PeerCapture> {
        let s = Self::dial(self.shared.config.bind_addr, addr)?;
        let sh = self.shared.clone();
        let id = sh.handle(s, addr, true);
        Ok(self
            .captures()
            .into_iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| PeerCapture::empty(id, addr)))
    }

    /// Connect out in the background.
    pub fn connect_async(&self, addr: SocketAddr) {
        let sh = self.shared.clone();
        let _ = std::thread::Builder::new()
            .name("tap-peer-out".into())
            .spawn(move || {
                if let Ok(s) = Self::dial(sh.config.bind_addr, addr) {
                    sh.handle(s, addr, true);
                }
            });
    }

    /// Every connection so far: closed ones, then snapshots of open ones,
    /// ordered by id.
    pub fn captures(&self) -> Vec<PeerCapture> {
        let mut v: Vec<PeerCapture> = self
            .shared
            .captures
            .lock()
            .map(|c| c.clone())
            .unwrap_or_default();
        if let Ok(live) = self.shared.live.lock() {
            v.extend(live.values().cloned());
        }
        v.sort_by_key(|c| c.id);
        v
    }

    pub fn wait_for<F: Fn(&[PeerCapture]) -> bool>(&self, timeout: Duration, pred: F) -> bool {
        let start = Instant::now();
        loop {
            if pred(&self.captures()) {
                return true;
            }
            if start.elapsed() > timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn save_jsonl(&self, path: &std::path::Path) -> Result<()> {
        let mut out = String::new();
        for c in self.captures() {
            out.push_str(&serde_json::to_string(&c)?);
            out.push('\n');
        }
        std::fs::write(path, out)?;
        Ok(())
    }
}

impl Drop for TapPeer {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl PeerCapture {
    fn empty(id: u32, remote: SocketAddr) -> PeerCapture {
        PeerCapture {
            id,
            direction: "out".into(),
            remote,
            local: SocketAddr::from(([0, 0, 0, 0], 0)),
            opened_ms: 0,
            closed_ms: None,
            close_reason: "connect failed".into(),
            handshake: None,
            our_handshake: None,
            not_plaintext: false,
            first_bytes_hex: String::new(),
            mse: None,
            events: Vec::new(),
            pieces_ok: 0,
            pieces_bad: 0,
        }
    }
}

/// A small PRNG for pads and DH exponents (the tap-peer is a test tool).
struct TapRng(u64);

impl profile::Rng for TapRng {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
    }
}

/// Per-connection state while the script runs.
struct Conn<'a> {
    sh: &'a Shared,
    cap: PeerCapture,
    stream: CipherStream,
    reader: FramedReader,
    their_hs: Option<Handshake>,
    their_ext: Option<Value>,
    am_choking: bool,
    peer_choking: bool,
    peer_interested: bool,
    // leecher state
    next_block: (u32, u32),
    inflight: usize,
    piece_buf: Vec<u8>,
    piece_have: usize,
    cur_piece: Option<u32>,
    done: bool,
}

impl Shared {
    fn ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Run the script on a connection; returns the capture id.
    fn handle(&self, stream: TcpStream, remote: SocketAddr, initiator: bool) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let local = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
        let _ = stream.set_nodelay(true);
        let cap = PeerCapture {
            id,
            direction: if initiator { "out".into() } else { "in".into() },
            remote,
            local,
            opened_ms: self.ms(),
            closed_ms: None,
            close_reason: String::new(),
            handshake: None,
            our_handshake: None,
            not_plaintext: false,
            first_bytes_hex: String::new(),
            mse: None,
            events: Vec::new(),
            pieces_ok: 0,
            pieces_bad: 0,
        };
        let mut conn = Conn {
            sh: self,
            cap,
            stream: CipherStream::plain(stream),
            reader: FramedReader::new(),
            their_hs: None,
            their_ext: None,
            am_choking: true,
            peer_choking: true,
            peer_interested: false,
            next_block: (0, 0),
            inflight: 0,
            piece_buf: Vec::new(),
            piece_have: 0,
            cur_piece: None,
            done: false,
        };
        let reason = match conn.run(initiator) {
            Ok(r) => r,
            Err(e) => format!("error: {e}"),
        };
        conn.cap.close_reason = reason;
        conn.cap.closed_ms = Some(self.ms());
        let _ = conn.stream.inner().shutdown(std::net::Shutdown::Both);
        if let Ok(mut l) = self.live.lock() {
            l.remove(&id);
        }
        if let Ok(mut c) = self.captures.lock() {
            c.push(conn.cap);
        }
        id
    }
}

impl Conn<'_> {
    /// Publish a snapshot of this open connection (cheap enough: bulk
    /// messages only every 32nd event).
    fn publish(&self, force: bool) {
        if !force && !self.cap.events.len().is_multiple_of(32) {
            return;
        }
        if let Ok(mut l) = self.sh.live.lock() {
            l.insert(self.cap.id, self.cap.clone());
        }
    }

    fn log_send(&mut self, m: &Msg, raw: &[u8]) {
        let raw_hex = match m {
            Msg::Piece { .. } => None,
            _ => Some(bencode::hex(raw)),
        };
        self.cap.events.push(PeerEvent {
            ts_ms: self.sh.ms(),
            dir: "send".into(),
            kind: m.name().into(),
            len: raw.len(),
            detail: m.detail(),
            raw_hex,
        });
        self.publish(!matches!(m, Msg::Piece { .. } | Msg::Request { .. }));
    }

    fn log_recv(&mut self, m: &Msg, raw: &[u8]) {
        let raw_hex = match m {
            Msg::Piece { .. } => None,
            _ => Some(bencode::hex(raw)),
        };
        self.cap.events.push(PeerEvent {
            ts_ms: self.sh.ms(),
            dir: "recv".into(),
            kind: m.name().into(),
            len: raw.len(),
            detail: m.detail(),
            raw_hex,
        });
        self.publish(!matches!(m, Msg::Piece { .. } | Msg::Request { .. }));
    }

    fn send(&mut self, m: Msg) -> io::Result<()> {
        let raw = m.encode();
        self.log_send(&m, &raw);
        peerwire::write_all(&mut self.stream, &raw)
    }

    fn send_handshake(&mut self) -> io::Result<()> {
        let cfg = &self.sh.config;
        let mut ih = cfg.info_hash;
        if cfg.misbehaviour == Misbehaviour::WrongInfoHash {
            ih[0] ^= 0xff;
        }
        let hs = Handshake::new(ih, cfg.peer_id, cfg.reserved);
        let raw = hs.encode();
        self.cap.our_handshake = Some(HandshakeView::from(&hs, &raw));
        self.cap.events.push(PeerEvent {
            ts_ms: self.sh.ms(),
            dir: "send".into(),
            kind: "handshake".into(),
            len: raw.len(),
            detail: serde_json::json!({}),
            raw_hex: Some(bencode::hex(&raw)),
        });
        peerwire::write_all(&mut self.stream, &raw)
    }

    fn recv_handshake(&mut self) -> io::Result<bool> {
        // Peek: is it a plaintext handshake?
        let head = self.reader.peek_fill(&mut self.stream, 20)?.to_vec();
        if head.is_empty() {
            return Ok(false);
        }
        if head.len() >= 20
            && (head[0] != 19 || &head[1..20] != peerwire::PSTR)
            && self.sh.config.encryption != TapEncryption::Disabled
        {
            // An MSE initiator: run the responder over the raw stream, then
            // continue in plaintext terms on the ciphered stream.
            let consumed = self.reader.take_pending();
            return self.mse_respond(consumed);
        }
        if head.len() < 20 || head[0] != 19 || &head[1..20] != peerwire::PSTR {
            // Not plaintext: read whatever arrives for a moment, then give up.
            let _ = self
                .stream
                .inner()
                .set_read_timeout(Some(Duration::from_millis(800)));
            let mut extra = vec![0u8; 4096];
            let mut got = head.clone();
            loop {
                match self.stream.read_raw(&mut extra) {
                    Ok(0) => break,
                    Ok(n) => {
                        got.extend_from_slice(&extra[..n]);
                        if got.len() > 2048 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            self.cap.not_plaintext = true;
            self.cap.first_bytes_hex = bencode::hex(&got[..got.len().min(256)]);
            self.cap.events.push(PeerEvent {
                ts_ms: self.sh.ms(),
                dir: "recv".into(),
                kind: "not_plaintext".into(),
                len: got.len(),
                detail: serde_json::json!({ "bytes": got.len() }),
                raw_hex: Some(bencode::hex(&got[..got.len().min(256)])),
            });
            return Ok(false);
        }
        let Some((hs, raw)) = self.reader.read_handshake(&mut self.stream)? else {
            return Ok(false);
        };
        self.cap.first_bytes_hex = bencode::hex(&raw[..raw.len().min(68)]);
        self.cap.handshake = Some(HandshakeView::from(&hs, &raw));
        self.cap.events.push(PeerEvent { ts_ms: self.sh.ms(), dir: "recv".into(), kind: "handshake".into(), len: raw.len(), detail: serde_json::json!({ "reserved": reserved::describe(&hs.reserved), "peer_id": String::from_utf8_lossy(&hs.peer_id) }), raw_hex: Some(bencode::hex(&raw)) });
        self.publish(true);
        self.their_hs = Some(hs);
        Ok(true)
    }

    fn rng(&self) -> TapRng {
        TapRng(
            (self.sh.ms().wrapping_mul(0x9E37_79B9) ^ u64::from(self.cap.id))
                .wrapping_add(u64::from(std::process::id())),
        )
    }

    fn private_key(&self) -> [u8; 20] {
        let mut k = [0u8; 20];
        let mut r = self.rng();
        for chunk in k.chunks_mut(4) {
            let v = profile::Rng::next_u32(&mut r).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        k
    }

    fn allowed(&self) -> (u32, bool) {
        match self.sh.config.encryption {
            TapEncryption::Disabled => (1, false),
            TapEncryption::Allowed { prefer_rc4 } => (3, prefer_rc4),
            TapEncryption::Forced => (2, true),
        }
    }

    fn record_mse(&mut self, role: &str, o: &mse::Outcome) {
        self.cap.mse = Some(MseView {
            role: role.into(),
            method: format!("{:?}", o.method).to_lowercase(),
            pad_after_key: o.observed.pad_after_key,
            pad_crypto: o.observed.pad_crypto,
            crypto_field: o.observed.crypto_field,
            ia_len: o.observed.ia_len,
        });
        self.cap.events.push(PeerEvent {
            ts_ms: self.sh.ms(),
            dir: "recv".into(),
            kind: "mse".into(),
            len: 0,
            detail: serde_json::to_value(self.cap.mse.as_ref().unwrap()).unwrap_or_default(),
            raw_hex: None,
        });
    }

    /// Run the MSE responder; `initial` are raw bytes already read.
    fn mse_respond(&mut self, initial: Vec<u8>) -> io::Result<bool> {
        let (allowed, prefer_rc4) = self.allowed();
        let mut resp = mse::Responder::new(self.private_key(), allowed, prefer_rc4);
        let mut rng = self.rng();
        let torrents = [self.sh.config.info_hash];
        let mut pending = initial;
        let mut buf = vec![0u8; 4096];
        loop {
            match resp.receive(&pending, &torrents, &mut rng) {
                Ok(Some(outcome)) => {
                    let out = resp.take_outbound();
                    self.stream.write_raw(&out)?;
                    self.record_mse("responder", &outcome);
                    let mse::Outcome {
                        encrypt,
                        decrypt,
                        plaintext,
                        ..
                    } = outcome;
                    self.stream.install(encrypt, decrypt, plaintext);
                    break;
                }
                Ok(None) => {
                    let out = resp.take_outbound();
                    if !out.is_empty() {
                        self.stream.write_raw(&out)?;
                    }
                }
                Err(e) => {
                    self.cap.not_plaintext = true;
                    self.cap.close_reason = format!("mse: {e}");
                    return Ok(false);
                }
            }
            let n = self.stream.read_raw(&mut buf)?;
            if n == 0 {
                return Ok(false);
            }
            pending = buf[..n].to_vec();
        }
        // Now read the peer's (decrypted) handshake normally.
        let Some((hs, raw)) = self.reader.read_handshake(&mut self.stream)? else {
            return Ok(false);
        };
        self.cap.first_bytes_hex = bencode::hex(&raw[..raw.len().min(68)]);
        self.cap.handshake = Some(HandshakeView::from(&hs, &raw));
        self.cap.events.push(PeerEvent {
            ts_ms: self.sh.ms(),
            dir: "recv".into(),
            kind: "handshake".into(),
            len: raw.len(),
            detail: serde_json::json!({ "reserved": reserved::describe(&hs.reserved), "peer_id": String::from_utf8_lossy(&hs.peer_id), "encrypted": true }),
            raw_hex: Some(bencode::hex(&raw)),
        });
        self.publish(true);
        self.their_hs = Some(hs);
        Ok(true)
    }

    /// Run the MSE initiator with our handshake as IA (forced mode, outgoing).
    fn mse_initiate(&mut self) -> io::Result<bool> {
        let cfg = &self.sh.config;
        let hs = Handshake::new(cfg.info_hash, cfg.peer_id, cfg.reserved);
        let raw = hs.encode();
        self.cap.our_handshake = Some(HandshakeView::from(&hs, &raw));
        let (allowed, _) = self.allowed();
        let mut rng = self.rng();
        let mut init = mse::Initiator::new(
            cfg.info_hash,
            self.private_key(),
            raw.clone(),
            allowed,
            &mut rng,
        );
        self.stream.write_raw(&init.take_outbound())?;
        self.cap.events.push(PeerEvent {
            ts_ms: self.sh.ms(),
            dir: "send".into(),
            kind: "handshake".into(),
            len: raw.len(),
            detail: serde_json::json!({ "encrypted": true }),
            raw_hex: Some(bencode::hex(&raw)),
        });
        let mut buf = vec![0u8; 4096];
        loop {
            let n = self.stream.read_raw(&mut buf)?;
            if n == 0 {
                self.cap.close_reason = "closed during mse".into();
                return Ok(false);
            }
            match init.receive(&buf[..n], &mut rng) {
                Ok(Some(outcome)) => {
                    let out = init.take_outbound();
                    if !out.is_empty() {
                        self.stream.write_raw(&out)?;
                    }
                    self.record_mse("initiator", &outcome);
                    let mse::Outcome {
                        encrypt,
                        decrypt,
                        plaintext,
                        ..
                    } = outcome;
                    self.stream.install(encrypt, decrypt, plaintext);
                    return Ok(true);
                }
                Ok(None) => {
                    let out = init.take_outbound();
                    if !out.is_empty() {
                        self.stream.write_raw(&out)?;
                    }
                }
                Err(e) => {
                    self.cap.close_reason = format!("mse: {e}");
                    return Ok(false);
                }
            }
        }
    }

    fn both_ltep(&self) -> bool {
        self.their_hs.as_ref().is_some_and(Handshake::supports_ltep)
            && reserved::has(&self.sh.config.reserved, reserved::LTEP)
    }
    fn both_fast(&self) -> bool {
        self.their_hs.as_ref().is_some_and(Handshake::supports_fast)
            && reserved::has(&self.sh.config.reserved, reserved::FAST)
    }

    fn piece_count(&self) -> usize {
        self.sh
            .config
            .fixture
            .as_ref()
            .map(|f| f.piece_count())
            .unwrap_or(0)
    }

    /// The id we advertised for extension `name` in our LTEP handshake.
    fn our_ext_id(&self, name: &str) -> Option<i64> {
        self.sh
            .config
            .ext_handshake
            .as_ref()?
            .get("m")?
            .get(name)?
            .as_int()
    }

    /// The id the peer advertised for extension `name`.
    fn their_ext_id(&self, name: &str) -> Option<i64> {
        self.their_ext.as_ref()?.get("m")?.get(name)?.as_int()
    }

    /// Answer a `ut_metadata` message (BEP 9).
    fn serve_metadata(&mut self, payload: &[u8]) -> io::Result<()> {
        let Some(their_id) = self.their_ext_id("ut_metadata") else {
            return Ok(());
        };
        let Ok((req, _)) = bencode::decode_prefix(payload) else {
            return Ok(());
        };
        let msg_type = req.get("msg_type").and_then(|v| v.as_int()).unwrap_or(-1);
        let piece = req.get("piece").and_then(|v| v.as_int()).unwrap_or(-1);
        if msg_type != 0 || piece < 0 {
            return Ok(());
        }
        let raw: Option<Vec<u8>> = self.sh.config.fixture.as_ref().and_then(|fx| {
            bencode::value_span(&fx.torrent, b"info")
                .ok()
                .flatten()
                .map(|sp| fx.torrent[sp].to_vec())
        });
        let mut reply = Value::dict();
        let mut data = Vec::new();
        match (&raw, self.sh.config.role) {
            (Some(raw), Role::Seeder) if (piece as usize) * 16384 < raw.len() => {
                let off = piece as usize * 16384;
                let end = (off + 16384).min(raw.len());
                reply.insert("msg_type", Value::Int(1));
                reply.insert("piece", Value::Int(piece));
                reply.insert("total_size", Value::Int(raw.len() as i64));
                data.extend_from_slice(&raw[off..end]);
            }
            _ => {
                reply.insert("msg_type", Value::Int(2));
                reply.insert("piece", Value::Int(piece));
                if let Some(raw) = &raw {
                    reply.insert("total_size", Value::Int(raw.len() as i64));
                }
            }
        }
        let mut out = reply.encode();
        out.extend_from_slice(&data);
        self.send(Msg::Extended {
            id: their_id as u8,
            payload: out,
        })
    }

    fn send_initial(&mut self) -> io::Result<()> {
        let cfg = self.sh.config.clone();
        // libtorrent order for reference: handshake, [ext handshake], bitfield/have_all/have_none.
        // We send the LTEP handshake first if both support it, then our have-state.
        if self.both_ltep()
            && let Some(d) = &cfg.ext_handshake
        {
            let mut d = d.clone();
            if let Some(fx) = &cfg.fixture
                && let Some(sp) = bencode::value_span(&fx.torrent, b"info").ok().flatten()
            {
                d.insert("metadata_size", Value::Int(sp.len() as i64));
            }
            self.send(Msg::Extended {
                id: 0,
                payload: d.encode(),
            })?;
        }
        let n = self.piece_count();
        match cfg.role {
            Role::Seeder => {
                if self.both_fast() {
                    self.send(Msg::HaveAll)?;
                } else {
                    let mut bf = vec![0u8; n.div_ceil(8)];
                    for i in 0..n {
                        bf[i / 8] |= 0x80 >> (i % 8);
                    }
                    self.send(Msg::Bitfield(bf))?;
                }
            }
            Role::Leecher => {
                if self.both_fast() {
                    self.send(Msg::HaveNone)?;
                }
                self.send(Msg::Interested)?;
            }
            Role::Silent => {
                if let Some(p) = &cfg.advertise_pieces {
                    let mut bf = vec![0u8; p.len().div_ceil(8)];
                    for (i, &has) in p.iter().enumerate() {
                        if has {
                            bf[i / 8] |= 0x80 >> (i % 8);
                        }
                    }
                    self.send(Msg::Bitfield(bf))?;
                } else if self.both_fast() {
                    self.send(Msg::HaveNone)?;
                }
            }
        }
        Ok(())
    }

    fn run(&mut self, initiator: bool) -> Result<String> {
        let cfg = self.sh.config.clone();
        if initiator {
            if cfg.encryption == TapEncryption::Forced || cfg.initiate_mse {
                if !self.mse_initiate()? {
                    return Ok(self.cap.close_reason.clone());
                }
            } else {
                self.send_handshake()?;
            }
            if !self.recv_handshake()? {
                return Ok(if self.cap.not_plaintext {
                    "not plaintext".into()
                } else {
                    "closed before handshake".into()
                });
            }
        } else {
            if !self.recv_handshake()? {
                return Ok(if self.cap.not_plaintext {
                    "not plaintext".into()
                } else {
                    "closed before handshake".into()
                });
            }
            self.send_handshake()?;
        }
        if let Some(hs) = &self.their_hs
            && hs.info_hash != cfg.info_hash
            && cfg.misbehaviour != Misbehaviour::WrongInfoHash
        {
            return Ok("info_hash mismatch".into());
        }
        match cfg.misbehaviour {
            Misbehaviour::CloseAfterHandshake => return Ok("script: close after handshake".into()),
            Misbehaviour::Garbage => {
                let junk: Vec<u8> = (0..4096u32)
                    .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
                    .collect();
                self.cap.events.push(PeerEvent {
                    ts_ms: self.sh.ms(),
                    dir: "send".into(),
                    kind: "garbage".into(),
                    len: junk.len(),
                    detail: serde_json::json!({}),
                    raw_hex: None,
                });
                let _ = peerwire::write_all(&mut self.stream, &junk);
            }
            Misbehaviour::SlowLoris => {
                // A valid message, one byte at a time.
                let raw = Msg::Have(0).encode();
                for b in raw {
                    if peerwire::write_all(&mut self.stream, &[b]).is_err() {
                        return Ok("script: slowloris closed by peer".into());
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            Misbehaviour::ProtocolViolation => {
                self.send(Msg::Piece {
                    index: 0xffff_fff0,
                    begin: 0,
                    data: vec![0; 16],
                })?;
            }
            _ => {}
        }
        self.send_initial()?;
        let deadline = Instant::now() + Duration::from_secs(600);
        let mut linger_until: Option<Instant> = None;
        let _ = self
            .stream
            .inner()
            .set_read_timeout(Some(Duration::from_millis(250)));
        loop {
            if self.sh.stop.load(Ordering::Relaxed) {
                return Ok("stopped".into());
            }
            if Instant::now() > deadline {
                return Ok("deadline".into());
            }
            if let Some(t) = linger_until
                && Instant::now() > t
            {
                return Ok("done".into());
            }
            match self.reader.read_msg(&mut self.stream) {
                Ok(Some((m, raw))) => {
                    self.log_recv(&m, &raw);
                    self.on_msg(m)?;
                }
                Ok(None) => return Ok("peer closed".into()),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Ok(format!("read error: {e}")),
            }
            if cfg.role == Role::Leecher && !self.done {
                self.pump_requests()?;
            }
            if self.done && linger_until.is_none() {
                linger_until = Some(Instant::now() + cfg.linger);
            }
        }
    }

    fn on_msg(&mut self, m: Msg) -> Result<()> {
        let cfg = self.sh.config.clone();
        match m {
            Msg::Interested => {
                self.peer_interested = true;
                if cfg.role == Role::Seeder
                    && cfg.misbehaviour != Misbehaviour::Stall
                    && self.am_choking
                {
                    self.am_choking = false;
                    self.send(Msg::Unchoke)?;
                }
            }
            Msg::NotInterested => self.peer_interested = false,
            Msg::Choke => self.peer_choking = true,
            Msg::Unchoke => self.peer_choking = false,
            Msg::Request {
                index,
                begin,
                length,
            } => {
                if cfg.role == Role::Seeder
                    && !self.am_choking
                    && cfg.misbehaviour != Misbehaviour::Stall
                {
                    if let Some(fx) = &cfg.fixture {
                        if (index as usize) < fx.piece_count() && length <= 1 << 17 {
                            let off = u64::from(index) * u64::from(fx.spec.piece_length)
                                + u64::from(begin);
                            let mut data = fx.data_range(off, length as usize);
                            if cfg.misbehaviour == Misbehaviour::CorruptPieces
                                && let Some(b) = data.first_mut()
                            {
                                *b ^= 0x5a;
                            }
                            self.send(Msg::Piece { index, begin, data })?;
                        } else if self.both_fast() {
                            self.send(Msg::Reject {
                                index,
                                begin,
                                length,
                            })?;
                        }
                    }
                } else if self.both_fast() {
                    self.send(Msg::Reject {
                        index,
                        begin,
                        length,
                    })?;
                }
            }
            Msg::Piece { index, begin, data } => {
                if cfg.role == Role::Leecher {
                    self.inflight = self.inflight.saturating_sub(1);
                    if Some(index) == self.cur_piece {
                        let end = begin as usize + data.len();
                        if end <= self.piece_buf.len() {
                            self.piece_buf[begin as usize..end].copy_from_slice(&data);
                            self.piece_have += data.len();
                        }
                        if self.piece_have >= self.piece_buf.len() {
                            self.finish_piece()?;
                        }
                    }
                }
            }
            Msg::Extended { id: 0, payload } => {
                if let Ok(v) = bencode::decode(&payload) {
                    self.their_ext = Some(v);
                }
            }
            // `ut_metadata` (BEP 9) requests under the id we advertised: a
            // seeder with a fixture serves the raw info dictionary in 16 KiB
            // pieces; anything else is rejected (`msg_type 2`).
            Msg::Extended { id, payload }
                if Some(i64::from(id)) == self.our_ext_id("ut_metadata") =>
            {
                self.serve_metadata(&payload)?;
            }
            Msg::HaveAll
            | Msg::Have(_)
            | Msg::Bitfield(_)
            | Msg::HaveNone
            | Msg::AllowedFast(_)
            | Msg::Suggest(_) => {}
            _ => {}
        }
        Ok(())
    }

    fn finish_piece(&mut self) -> Result<()> {
        let Some(fx) = self.sh.config.fixture.clone() else {
            return Ok(());
        };
        let Some(idx) = self.cur_piece else {
            return Ok(());
        };
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(&self.piece_buf);
        let got: [u8; 20] = h.finalize().into();
        if fx.piece_hashes.get(idx as usize) == Some(&got) {
            self.cap.pieces_ok += 1;
            self.send(Msg::Have(idx))?;
        } else {
            self.cap.pieces_bad += 1;
        }
        self.cur_piece = None;
        self.next_block = (idx + 1, 0);
        if (idx as usize + 1) >= fx.piece_count() {
            self.done = true;
            self.send(Msg::NotInterested)?;
        }
        Ok(())
    }

    fn pump_requests(&mut self) -> Result<()> {
        let Some(fx) = self.sh.config.fixture.clone() else {
            return Ok(());
        };
        if self.peer_choking {
            return Ok(());
        }
        let block = 16384u32;
        while self.inflight < self.sh.config.pipeline {
            let (piece, begin) = self.next_block;
            if piece as usize >= fx.piece_count() {
                break;
            }
            let psize = fx.piece_size(piece as usize) as u32;
            if self.cur_piece != Some(piece) {
                self.cur_piece = Some(piece);
                self.piece_buf = vec![0; psize as usize];
                self.piece_have = 0;
            }
            if begin >= psize {
                // all blocks of this piece requested; wait for data
                break;
            }
            let len = (psize - begin).min(block);
            self.send(Msg::Request {
                index: piece,
                begin,
                length: len,
            })?;
            self.inflight += 1;
            self.next_block = (piece, begin + len);
        }
        Ok(())
    }
}

impl Write for Conn<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
