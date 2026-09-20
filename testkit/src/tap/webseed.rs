// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! `tap-webseed`: a GetRight-style (BEP 19) HTTP file server for a fixture
//! that records the raw bytes of every request before answering, so the web
//! seed requests of the oracle and of our client can be compared.

use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::bencode;
use crate::fixtures::Fixture;
use crate::http;

/// One recorded request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebRequest {
    pub ts_ms: u64,
    pub from: SocketAddr,
    pub request_line: String,
    pub path: String,
    /// Headers in wire order, names as sent.
    pub headers: Vec<(String, String)>,
    pub range: Option<String>,
    pub status: u16,
    pub raw_hex: String,
}

/// The server.
pub struct TapWebSeed {
    fixture: Arc<Fixture>,
    /// URL prefix path under which the fixture is served (e.g. `/seed/`).
    prefix: String,
    listeners: Vec<SocketAddr>,
    requests: Arc<Mutex<Vec<WebRequest>>>,
    stop: Arc<AtomicBool>,
    start: Instant,
}

impl TapWebSeed {
    /// Serve `fixture` under `http://<addr><prefix>` on every `addrs`. The
    /// BEP 19 `url-list` entry for a single-file fixture is
    /// `http://<addr><prefix><name>`; for a multi-file fixture it is
    /// `http://<addr><prefix>` (the client appends `<name>/<path>`).
    pub fn start(
        addrs: Vec<SocketAddr>,
        fixture: Arc<Fixture>,
        prefix: &str,
    ) -> Result<TapWebSeed> {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let start = Instant::now();
        let mut listeners = Vec::new();
        for a in addrs {
            let l = TcpListener::bind(a).with_context(|| format!("bind web seed {a}"))?;
            l.set_nonblocking(true)?;
            listeners.push(l.local_addr()?);
            let fx = fixture.clone();
            let prefix = prefix.to_string();
            let reqs = requests.clone();
            let stop2 = stop.clone();
            std::thread::spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    match l.accept() {
                        Ok((mut s, peer)) => {
                            let fx = fx.clone();
                            let prefix = prefix.clone();
                            let reqs = reqs.clone();
                            std::thread::spawn(move || {
                                let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
                                serve(&mut s, peer, &fx, &prefix, &reqs, start);
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        Ok(TapWebSeed {
            fixture,
            prefix: prefix.to_string(),
            listeners,
            requests,
            stop,
            start,
        })
    }

    /// The `url-list` entry to put in the torrent for listener `idx`.
    pub fn url(&self, idx: usize) -> String {
        let a = self.listeners[idx];
        let host = match a.ip() {
            std::net::IpAddr::V4(v4) => format!("{v4}:{}", a.port()),
            std::net::IpAddr::V6(v6) => format!("[{v6}]:{}", a.port()),
        };
        let name = &self.fixture.spec.name;
        if self.fixture.layout.len() == 1 && !self.fixture.spec.multi_file {
            format!(
                "http://{host}{}{}",
                self.prefix,
                http::percent_encode(name.as_bytes())
            )
        } else {
            format!("http://{host}{}", self.prefix)
        }
    }

    pub fn requests(&self) -> Vec<WebRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub fn save_jsonl(&self, path: &std::path::Path) -> Result<()> {
        let mut out = String::new();
        for r in self.requests() {
            out.push_str(&serde_json::to_string(&r)?);
            out.push('\n');
        }
        std::fs::write(path, out)?;
        Ok(())
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

impl Drop for TapWebSeed {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Map a request path to `(offset, len)` in the fixture stream.
fn locate(fx: &Fixture, prefix: &str, path: &str) -> Option<(u64, u64)> {
    let rel = path.strip_prefix(prefix)?;
    let rel = String::from_utf8(http::percent_decode(rel.as_bytes())).ok()?;
    let name = &fx.spec.name;
    if fx.layout.len() == 1 && !fx.spec.multi_file {
        if rel == *name {
            let f = &fx.layout[0];
            return Some((f.offset, f.len));
        }
        return None;
    }
    for f in &fx.layout {
        let full = f.path.join("/");
        if full == rel {
            return Some((f.offset, f.len));
        }
    }
    None
}

fn serve(
    s: &mut std::net::TcpStream,
    peer: SocketAddr,
    fx: &Fixture,
    prefix: &str,
    reqs: &Mutex<Vec<WebRequest>>,
    start: Instant,
) {
    loop {
        let req = match http::read_request(s) {
            Ok(Some(r)) => r,
            _ => return,
        };
        let ts_ms = start.elapsed().as_millis() as u64;
        let range = req.header("Range").map(str::to_string);
        let (status, headers, body): (u16, Vec<(String, String)>, Vec<u8>) =
            match locate(fx, prefix, req.path()) {
                None => (404, vec![], b"not found".to_vec()),
                Some((off, len)) => match parse_range(range.as_deref(), len) {
                    Ok(Some((a, b))) => {
                        let body = fx.data_range(off + a, (b - a + 1) as usize);
                        (
                            206,
                            vec![
                                ("Content-Range".into(), format!("bytes {a}-{b}/{len}")),
                                ("Accept-Ranges".into(), "bytes".into()),
                            ],
                            body,
                        )
                    }
                    Ok(None) => (
                        200,
                        vec![("Accept-Ranges".into(), "bytes".into())],
                        fx.data_range(off, len as usize),
                    ),
                    Err(()) => (
                        416,
                        vec![("Content-Range".into(), format!("bytes */{len}"))],
                        Vec::new(),
                    ),
                },
            };
        reqs.lock().unwrap().push(WebRequest {
            ts_ms,
            from: peer,
            request_line: format!("{} {} {}", req.method, req.target, req.version),
            path: req.path().to_string(),
            headers: req.headers.clone(),
            range,
            status,
            raw_hex: bencode::hex(&req.raw),
        });
        let reason = match status {
            200 => "OK",
            206 => "Partial Content",
            404 => "Not Found",
            _ => "Range Not Satisfiable",
        };
        let hdrs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        if http::write_response(s, status, reason, &hdrs, &body).is_err() {
            return;
        }
        let _ = s.flush();
        if req.wants_close() || req.version == "HTTP/1.0" {
            return;
        }
    }
}

/// `bytes=a-b` (inclusive) within a `len`-byte file.
fn parse_range(range: Option<&str>, len: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(r) = range else {
        return Ok(None);
    };
    let spec = r.strip_prefix("bytes=").ok_or(())?;
    let (a, b) = spec.split_once('-').ok_or(())?;
    let a: u64 = a.parse().map_err(|_| ())?;
    let b: u64 = if b.is_empty() {
        len.saturating_sub(1)
    } else {
        b.parse().map_err(|_| ())?
    };
    if len == 0 || a >= len || b < a {
        return Err(());
    }
    Ok(Some((a, b.min(len - 1))))
}
