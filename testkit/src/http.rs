// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Minimal HTTP/1.1 plumbing for the harness: raw request capture (the whole
//! point of `tap-tracker` is to see the exact bytes a client sends), a tiny
//! server loop, percent-encoding helpers and a query-string parser that keeps
//! parameter order.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Percent-encode every byte outside the RFC 3986 unreserved set (uppercase hex).
pub fn percent_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

/// Percent-decode (`+` is *not* treated as space; trackers use raw encoding).
pub fn percent_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%'
            && i + 2 < s.len()
            && let (Some(h), Some(l)) = (hexval(s[i + 1]), hexval(s[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// A query string parsed into ordered `(raw_key, raw_value)` pairs. Values are
/// kept *raw* (still percent-encoded) so that encoding style can be diffed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pub params: Vec<(String, String)>,
}

impl Query {
    pub fn parse(q: &str) -> Query {
        let params = q
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (p.to_string(), String::new()),
            })
            .collect();
        Query { params }
    }
    /// Raw (still encoded) value of the first occurrence of `key`.
    pub fn raw(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    /// Decoded value of the first occurrence of `key`.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.raw(key).map(|v| percent_decode(v.as_bytes()))
    }
    pub fn get_str(&self, key: &str) -> Option<String> {
        self.get(key)
            .map(|v| String::from_utf8_lossy(&v).into_owned())
    }
    pub fn keys(&self) -> Vec<&str> {
        self.params.iter().map(|(k, _)| k.as_str()).collect()
    }
}

/// One captured HTTP request, raw bytes included.
#[derive(Clone, Debug)]
pub struct RawRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    /// Headers in wire order, names as sent (case preserved).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The exact bytes of the request head and body.
    pub raw: Vec<u8>,
}

impl RawRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }
    pub fn query(&self) -> Query {
        Query::parse(self.target.split_once('?').map(|(_, q)| q).unwrap_or(""))
    }
    pub fn wants_close(&self) -> bool {
        match self.header("connection") {
            Some(v) => v.eq_ignore_ascii_case("close"),
            None => self.version == "HTTP/1.0",
        }
    }
}

/// Read one request from `r`. Returns `Ok(None)` on a clean EOF before any byte.
pub fn read_request<R: Read>(r: &mut R) -> io::Result<Option<RawRequest>> {
    let mut raw = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    // Read the head byte-by-byte-ish: this is test tooling, simplicity wins.
    loop {
        let n = r.read(&mut byte)?;
        if n == 0 {
            if raw.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof in request head",
            ));
        }
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
        if raw.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
    }
    let head = String::from_utf8_lossy(&raw[..raw.len() - 4]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut req = RawRequest {
        method,
        target,
        version,
        headers,
        body: Vec::new(),
        raw,
    };
    let len: usize = req
        .header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if len > 0 {
        let mut body = vec![0u8; len.min(16 << 20)];
        r.read_exact(&mut body)?;
        req.raw.extend_from_slice(&body);
        req.body = body;
    }
    Ok(Some(req))
}

/// Write a simple response.
pub fn write_response<W: Write>(
    w: &mut W,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<()> {
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    w.write_all(out.as_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// A bidirectional byte stream (plain TCP or TLS-wrapped).
pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// A stoppable listener loop that hands each accepted connection to `handle`
/// on its own thread. `handle` receives the (possibly TLS-wrapped) stream and
/// the peer address and is responsible for the keep-alive loop.
pub struct Server {
    stop: Arc<AtomicBool>,
    local: SocketAddr,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    pub fn spawn<F>(listener: TcpListener, handle: F) -> io::Result<Server>
    where
        F: Fn(TcpStream, SocketAddr) + Send + Sync + 'static,
    {
        let local = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = Arc::new(handle);
        let thread = std::thread::Builder::new()
            .name(format!("http-{}", local.port()))
            .spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((s, peer)) => {
                            let _ = s.set_nonblocking(false);
                            let _ = s.set_read_timeout(Some(Duration::from_secs(120)));
                            let h = handle.clone();
                            let _ = std::thread::Builder::new()
                                .name("http-conn".into())
                                .spawn(move || h(s, peer));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(20)),
                    }
                }
            })?;
        Ok(Server {
            stop,
            local,
            thread: Some(thread),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_keeps_order_and_raw_values() {
        let q = Query::parse("info_hash=%01%ab&peer_id=-qB5230-x&port=1&compact=1");
        assert_eq!(q.keys(), vec!["info_hash", "peer_id", "port", "compact"]);
        assert_eq!(q.raw("info_hash"), Some("%01%ab"));
        assert_eq!(q.get("info_hash"), Some(vec![1, 0xab]));
    }

    #[test]
    fn percent_roundtrip() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(percent_decode(percent_encode(&data).as_bytes()), data);
    }

    #[test]
    fn parse_request() {
        let raw = b"GET /announce?a=1 HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\nContent-Length: 3\r\n\r\nabc";
        let req = read_request(&mut &raw[..]).unwrap().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path(), "/announce");
        assert_eq!(req.header("user-agent"), Some("t"));
        assert_eq!(req.body, b"abc");
        assert_eq!(req.raw, raw);
    }
}
