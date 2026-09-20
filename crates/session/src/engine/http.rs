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
    get_with_endpoints(dns, tls, families, url, build)
        .await
        .map(|(r, _)| r)
}

/// [`get`], also returning `(remote, local)` of the connection that carried
/// the final response.
pub async fn get_with_endpoints(
    dns: &Dns,
    tls: &TlsClient,
    families: Families,
    url: &Url,
    build: &dyn Fn(&Url) -> Vec<u8>,
) -> Result<(Response, (SocketAddr, SocketAddr)), String> {
    let mut url = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        if url.scheme != "http" && url.scheme != "https" {
            return Err(format!("unsupported scheme {}", url.scheme));
        }
        let request = build(&url);
        let (resp, endpoints) = fetch_once(dns, tls, families, &url, request).await?;
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
            None => return Ok((resp, endpoints)),
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
) -> Result<(Response, (SocketAddr, SocketAddr)), String> {
    let mut conn = HttpConn::open(dns, tls, families, url).await?;
    let resp = uring::timeout(
        RESPONSE_TIMEOUT,
        conn.request(request, tracker::http::MAX_BODY),
    )
    .await
    .map_err(|_| "tracker response timed out".to_string())??;
    Ok((resp, conn.endpoints))
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
}

/// One HTTP/1.1 connection (plain or TLS) that can carry several requests
/// in sequence (keep-alive), as web seeds use.
pub struct HttpConn {
    stream: Stream,
    /// Bytes read past the last response (a pipelining server).
    pending: Vec<u8>,
    /// The server asked to close after the last response.
    closed: bool,
    /// `(remote, local)` of the TCP connection (external-address votes need
    /// both).
    pub endpoints: (SocketAddr, SocketAddr),
}

impl HttpConn {
    /// Resolve and connect (with TLS for `https`), trying each address of
    /// the allowed families in turn.
    pub async fn open(
        dns: &Dns,
        tls: &TlsClient,
        families: Families,
        url: &Url,
    ) -> Result<HttpConn, String> {
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
                    let local = stream
                        .local_addr()
                        .unwrap_or_else(|_| SocketAddr::new(addr.ip(), 0));
                    let stream = if url.is_tls() {
                        Stream::Tls(Box::new(
                            uring::timeout(
                                CONNECT_TIMEOUT,
                                TlsStream::connect(tls, stream, &url.host),
                            )
                            .await
                            .map_err(|_| "tls handshake timed out".to_string())??,
                        ))
                    } else {
                        Stream::Plain(stream)
                    };
                    return Ok(HttpConn {
                        stream,
                        pending: Vec::new(),
                        closed: false,
                        endpoints: (addr, local),
                    });
                }
                Ok(Err(e)) => last_err = format!("connect {addr}: {e}"),
                Err(_) => last_err = format!("connect {addr}: timed out"),
            }
        }
        Err(last_err)
    }

    /// Whether another request may be sent on this connection.
    pub fn reusable(&self) -> bool {
        !self.closed
    }

    /// Send `request` and read one response (body up to `max_body`).
    pub async fn request(&mut self, request: Vec<u8>, max_body: usize) -> Result<Response, String> {
        if self.closed {
            return Err("connection closed by the server".into());
        }
        match &mut self.stream {
            Stream::Plain(s) => {
                s.send_all(Buffer::from_vec(request))
                    .await
                    .map_err(|e| format!("send: {e}"))?;
            }
            Stream::Tls(s) => s.send_all(&request).await?,
        }
        let mut parser = ResponseParser::with_max_body(max_body);
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            if let Some(resp) = parser.push(&pending).map_err(|e| e.to_string())? {
                return Ok(self.finish_response(resp, &parser));
            }
        }
        loop {
            let chunk: Vec<u8> = match &mut self.stream {
                Stream::Plain(s) => {
                    let (r, buf) = s.recv(Buffer::from_vec(vec![0u8; 16 * 1024])).await;
                    match r {
                        Ok(0) => Vec::new(),
                        Ok(n) => buf.as_slice()[..n as usize].to_vec(),
                        Err(e) => return Err(format!("recv: {e}")),
                    }
                }
                Stream::Tls(s) => s.recv(16 * 1024).await?,
            };
            if chunk.is_empty() {
                self.closed = true;
                return parser.finish().map_err(|e| e.to_string());
            }
            if let Some(resp) = parser.push(&chunk).map_err(|e| e.to_string())? {
                return Ok(self.finish_response(resp, &parser));
            }
        }
    }

    fn finish_response(&mut self, resp: Response, parser: &ResponseParser) -> Response {
        self.pending = parser.leftover().to_vec();
        if resp
            .header("Connection")
            .is_some_and(|c| c.eq_ignore_ascii_case("close"))
        {
            self.closed = true;
        }
        resp
    }
}
