// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! A minimal HTTP/1.1 client over io_uring TCP for tracker announces: resolve,
//! connect (with timeout), optional TLS (rustls, ADR 0003), send the pre-built
//! request, frame the response with `tracker::http`, follow a few redirects.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tracker::Url;
use tracker::http::{Response, ResponseParser};
use uring::{Buffer, TcpStream};

use super::dns::Dns;
use super::tls::{TlsClient, TlsStream};

/// Maximum redirects followed (libtorrent follows 5).
const MAX_REDIRECTS: usize = 5;
/// Connect timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Whole-exchange timeout after connecting.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Which address families we can use for outgoing connections.
#[derive(Debug, Clone, Copy)]
pub struct Families {
    /// We have an IPv4 listen socket / address.
    pub v4: bool,
    /// We have an IPv6 listen socket / address.
    pub v6: bool,
}

impl Families {
    fn allows(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        }
    }

    /// Restrict to one family (one listen endpoint's announce).
    pub fn only(v6: bool) -> Families {
        Families { v4: !v6, v6 }
    }

    /// The listen endpoints, in `Announcer` order: v4 first (if any), then v6.
    pub fn endpoints(&self) -> Vec<bool> {
        let mut v = Vec::new();
        if self.v4 {
            v.push(false);
        }
        if self.v6 {
            v.push(true);
        }
        v
    }
}

/// Perform a GET for `url`, building the request bytes with `build` (so
/// redirects re-render the request against the new URL).
pub async fn get(
    dns: &Dns,
    tls: &TlsClient,
    families: Families,
    url: &Url,
    build: &dyn Fn(&Url) -> Vec<u8>,
) -> Result<Response, String> {
    let mut url = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        if url.scheme != "http" && url.scheme != "https" {
            return Err(format!("unsupported scheme {}", url.scheme));
        }
        let request = build(&url);
        let resp = fetch_once(dns, tls, families, &url, request).await?;
        match resp.redirect() {
            Some(loc) => {
                let next = if loc.starts_with("http://") || loc.starts_with("https://") {
                    Url::parse(loc).map_err(|e| format!("redirect: {e}"))?
                } else {
                    // Relative redirect: same authority.
                    let mut u = url.clone();
                    match loc.split_once('?') {
                        Some((p, q)) => {
                            u.path = p.to_string();
                            u.query = Some(q.to_string());
                        }
                        None => {
                            u.path = loc.to_string();
                            u.query = None;
                        }
                    }
                    u
                };
                tracing::debug!(from = %url.host, to = %next.host, "tracker redirect");
                url = next;
            }
            None => return Ok(resp),
        }
    }
    Err("too many redirects".into())
}

async fn fetch_once(
    dns: &Dns,
    tls: &TlsClient,
    families: Families,
    url: &Url,
    request: Vec<u8>,
) -> Result<Response, String> {
    let addrs = dns
        .resolve(&url.host, url.effective_port())
        .await
        .map_err(|e| format!("resolve {}: {e}", url.host))?;
    let candidates: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| families.allows(a.ip()))
        .collect();
    if candidates.is_empty() {
        return Err(format!(
            "no {} address for {}",
            if families.v6 && !families.v4 {
                "IPv6"
            } else {
                "IPv4"
            },
            url.host
        ));
    }
    let mut last_err = String::new();
    for addr in candidates {
        match uring::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let fut = async {
                    if url.is_tls() {
                        let mut s = TlsStream::connect(tls, stream, &url.host).await?;
                        exchange_tls(&mut s, request).await
                    } else {
                        exchange(&stream, request).await
                    }
                };
                return uring::timeout(RESPONSE_TIMEOUT, fut)
                    .await
                    .map_err(|_| "tracker response timed out".to_string())?;
            }
            Ok(Err(e)) => last_err = format!("connect {addr}: {e}"),
            Err(_) => last_err = format!("connect {addr}: timed out"),
        }
    }
    Err(last_err)
}

async fn exchange(stream: &TcpStream, request: Vec<u8>) -> Result<Response, String> {
    stream
        .send_all(Buffer::from_vec(request))
        .await
        .map_err(|e| format!("send: {e}"))?;
    let mut parser = ResponseParser::new();
    loop {
        let (r, buf) = stream.recv(Buffer::from_vec(vec![0u8; 16 * 1024])).await;
        match r {
            Ok(0) => return parser.finish().map_err(|e| e.to_string()),
            Ok(_) => {
                if let Some(resp) = parser.push(buf.as_slice()).map_err(|e| e.to_string())? {
                    return Ok(resp);
                }
            }
            Err(e) => return Err(format!("recv: {e}")),
        }
    }
}

async fn exchange_tls(stream: &mut TlsStream, request: Vec<u8>) -> Result<Response, String> {
    stream.send_all(&request).await?;
    let mut parser = ResponseParser::new();
    loop {
        let chunk = stream.recv(16 * 1024).await?;
        if chunk.is_empty() {
            return parser.finish().map_err(|e| e.to_string());
        }
        if let Some(resp) = parser.push(&chunk).map_err(|e| e.to_string())? {
            return Ok(resp);
        }
    }
}
