// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! HTTP/1.x response framing for tracker replies: status line, headers,
//! `Content-Length` / `chunked` / read-until-close bodies, and gzip
//! decompression. Bounded everywhere; the transport (sockets over io_uring,
//! rustls for HTTPS) lives in `session`.

use crate::Error;

/// Largest response head (status line + headers) we accept.
pub const MAX_HEAD: usize = 16 * 1024;
/// Largest (decompressed) body we accept.
pub const MAX_BODY: usize = 4 * 1024 * 1024;

/// A complete HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Headers in order (names lower-cased).
    pub headers: Vec<(String, String)>,
    /// Body, decompressed if it was gzip.
    pub body: Vec<u8>,
}

impl Response {
    /// First value of header `name` (lower-case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Whether this is a redirect with a `Location`.
    pub fn redirect(&self) -> Option<&str> {
        if matches!(self.status, 301 | 302 | 303 | 307 | 308) {
            self.header("location")
        } else {
            None
        }
    }
}

#[derive(Debug)]
enum Body {
    Length(usize),
    Chunked,
    UntilClose,
}

#[derive(Debug)]
enum State {
    Head,
    Body(Body),
    Done,
}

/// An incremental response parser. Feed bytes with [`ResponseParser::push`];
/// call [`ResponseParser::finish`] when the connection closes.
#[derive(Debug)]
pub struct ResponseParser {
    buf: Vec<u8>,
    state: State,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    gzip: bool,
}

impl Default for ResponseParser {
    fn default() -> Self {
        ResponseParser::new()
    }
}

impl ResponseParser {
    /// A fresh parser.
    pub fn new() -> ResponseParser {
        ResponseParser {
            buf: Vec::new(),
            state: State::Head,
            status: 0,
            headers: Vec::new(),
            body: Vec::new(),
            gzip: false,
        }
    }

    /// Feed bytes. Returns the response once it is complete.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<Response>, Error> {
        if matches!(self.state, State::Done) {
            return Ok(None);
        }
        self.buf.extend_from_slice(bytes);
        loop {
            match &self.state {
                State::Head => {
                    let Some(end) = find(&self.buf, b"\r\n\r\n") else {
                        if self.buf.len() > MAX_HEAD {
                            return Err(Error::Http("response head too large"));
                        }
                        return Ok(None);
                    };
                    if end > MAX_HEAD {
                        return Err(Error::Http("response head too large"));
                    }
                    let head = self.buf[..end].to_vec();
                    self.buf.drain(..end + 4);
                    let body = self.parse_head(&head)?;
                    self.state = State::Body(body);
                }
                State::Body(Body::Length(n)) => {
                    let n = *n;
                    if n > MAX_BODY {
                        return Err(Error::Http("body too large"));
                    }
                    if self.buf.len() < n {
                        return Ok(None);
                    }
                    self.body = self.buf.drain(..n).collect();
                    return self.complete().map(Some);
                }
                State::Body(Body::Chunked) => {
                    // Parse as many complete chunks as are buffered.
                    loop {
                        let Some(line_end) = find(&self.buf, b"\r\n") else {
                            if self.buf.len() > 64 {
                                return Err(Error::Http("bad chunk size line"));
                            }
                            return Ok(None);
                        };
                        let size_str = std::str::from_utf8(&self.buf[..line_end])
                            .map_err(|_| Error::Http("bad chunk size"))?;
                        let size_str = size_str.split(';').next().unwrap_or("").trim();
                        let size = usize::from_str_radix(size_str, 16)
                            .map_err(|_| Error::Http("bad chunk size"))?;
                        if size == 0 {
                            // Terminator: "0\r\n", optional trailer lines, then a
                            // blank line. Both cases end in "\r\n\r\n" starting at
                            // the size line's CRLF.
                            let Some(i) = find(&self.buf[line_end..], b"\r\n\r\n") else {
                                if self.buf.len() - line_end > MAX_HEAD {
                                    return Err(Error::Http("trailers too large"));
                                }
                                return Ok(None);
                            };
                            self.buf.drain(..line_end + i + 4);
                            return self.complete().map(Some);
                        }
                        let need = line_end + 2 + size + 2;
                        if self.body.len() + size > MAX_BODY {
                            return Err(Error::Http("body too large"));
                        }
                        if self.buf.len() < need {
                            return Ok(None);
                        }
                        self.body
                            .extend_from_slice(&self.buf[line_end + 2..line_end + 2 + size]);
                        if &self.buf[need - 2..need] != b"\r\n" {
                            return Err(Error::Http("bad chunk terminator"));
                        }
                        self.buf.drain(..need);
                    }
                }
                State::Body(Body::UntilClose) => {
                    if self.body.len() + self.buf.len() > MAX_BODY {
                        return Err(Error::Http("body too large"));
                    }
                    self.body.append(&mut self.buf);
                    return Ok(None);
                }
                State::Done => return Ok(None),
            }
        }
    }

    /// The connection closed: complete a read-until-close body, or report a
    /// truncated response.
    pub fn finish(&mut self) -> Result<Response, Error> {
        match &self.state {
            State::Body(Body::UntilClose) => self.complete(),
            State::Done => Err(Error::Http("already complete")),
            _ => Err(Error::Http(
                "connection closed before the response completed",
            )),
        }
    }

    fn parse_head(&mut self, head: &[u8]) -> Result<Body, Error> {
        let text = std::str::from_utf8(head).map_err(|_| Error::Http("non-utf8 head"))?;
        let mut lines = text.split("\r\n");
        let status_line = lines.next().ok_or(Error::Http("empty head"))?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or("");
        if !version.starts_with("HTTP/1.") {
            return Err(Error::Http("not HTTP/1.x"));
        }
        self.status = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or(Error::Http("bad status"))?;
        for line in lines {
            let Some((k, v)) = line.split_once(':') else {
                return Err(Error::Http("bad header line"));
            };
            self.headers
                .push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
        let header = |name: &str| {
            self.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        if let Some(enc) = header("content-encoding") {
            let enc = enc.trim().to_ascii_lowercase();
            if enc == "gzip" || enc == "x-gzip" {
                self.gzip = true;
            } else if enc != "identity" {
                return Err(Error::Http("unsupported content-encoding"));
            }
        }
        // 1xx/204/304 have no body regardless of headers.
        if (100..200).contains(&self.status) || self.status == 204 || self.status == 304 {
            return Ok(Body::Length(0));
        }
        if header("transfer-encoding").is_some_and(|t| t.to_ascii_lowercase().contains("chunked")) {
            return Ok(Body::Chunked);
        }
        if let Some(len) = header("content-length") {
            let n: usize = len
                .trim()
                .parse()
                .map_err(|_| Error::Http("bad content-length"))?;
            return Ok(Body::Length(n));
        }
        Ok(Body::UntilClose)
    }

    fn complete(&mut self) -> Result<Response, Error> {
        self.state = State::Done;
        let body = std::mem::take(&mut self.body);
        let body = if self.gzip { gunzip(&body)? } else { body };
        Ok(Response {
            status: self.status,
            headers: std::mem::take(&mut self.headers),
            body,
        })
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Decompress a gzip member (RFC 1952) with a bounded output size.
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return Err(Error::Http("bad gzip header"));
    }
    let flags = data[3];
    let mut pos = 10usize;
    if flags & 0x04 != 0 {
        // FEXTRA
        if data.len() < pos + 2 {
            return Err(Error::Http("bad gzip extra"));
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        // FNAME
        pos = skip_cstr(data, pos)?;
    }
    if flags & 0x10 != 0 {
        // FCOMMENT
        pos = skip_cstr(data, pos)?;
    }
    if flags & 0x02 != 0 {
        pos += 2; // FHCRC
    }
    if data.len() < pos + 8 {
        return Err(Error::Http("truncated gzip"));
    }
    let deflate = &data[pos..data.len() - 8];
    let isize = u32::from_le_bytes([
        data[data.len() - 4],
        data[data.len() - 3],
        data[data.len() - 2],
        data[data.len() - 1],
    ]) as usize;
    if isize > MAX_BODY {
        return Err(Error::Http("gzip body too large"));
    }
    let out = miniz_oxide::inflate::decompress_to_vec_with_limit(deflate, MAX_BODY)
        .map_err(|_| Error::Http("bad deflate stream"))?;
    Ok(out)
}

fn skip_cstr(data: &[u8], pos: usize) -> Result<usize, Error> {
    data[pos.min(data.len())..]
        .iter()
        .position(|&b| b == 0)
        .map(|i| pos + i + 1)
        .ok_or(Error::Http("bad gzip string field"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn content_length_body_in_pieces() {
        let mut p = ResponseParser::new();
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        for (i, b) in raw.iter().enumerate() {
            let r = p.push(std::slice::from_ref(b)).unwrap();
            if i + 1 < raw.len() {
                assert!(r.is_none());
            } else {
                let r = r.unwrap();
                assert_eq!(r.status, 200);
                assert_eq!(r.body, b"hello");
                assert_eq!(r.header("content-type"), Some("text/plain"));
            }
        }
    }

    #[test]
    fn chunked_body() {
        let mut p = ResponseParser::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let r = p.push(raw).unwrap().unwrap();
        assert_eq!(r.body, b"wikipedia");
        // split at awkward points
        let mut p = ResponseParser::new();
        let mut got = None;
        for chunk in raw.chunks(3) {
            if let Some(r) = p.push(chunk).unwrap() {
                got = Some(r);
            }
        }
        assert_eq!(got.unwrap().body, b"wikipedia");
    }

    #[test]
    fn until_close_body_and_finish() {
        let mut p = ResponseParser::new();
        assert!(p.push(b"HTTP/1.0 200 OK\r\n\r\nabc").unwrap().is_none());
        assert!(p.push(b"def").unwrap().is_none());
        let r = p.finish().unwrap();
        assert_eq!(r.body, b"abcdef");
        let mut q = ResponseParser::new();
        q.push(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
            .unwrap();
        assert!(q.finish().is_err());
    }

    #[test]
    fn redirect_and_errors() {
        let mut p = ResponseParser::new();
        let r = p
            .push(b"HTTP/1.1 302 Found\r\nLocation: http://x/y\r\nContent-Length: 0\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(r.redirect(), Some("http://x/y"));
        assert!(ResponseParser::new().push(b"SSH-2.0\r\n\r\n").is_err());
        assert!(
            ResponseParser::new()
                .push(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n")
                .is_err()
        );
        let mut big = ResponseParser::new();
        assert!(big.push(&vec![b'x'; MAX_HEAD + 1]).is_err());
    }

    #[test]
    fn gzip_roundtrip() {
        let payload = b"d8:intervali1800e5:peers0:e".repeat(50);
        let deflated = miniz_oxide::deflate::compress_to_vec(&payload, 6);
        let mut gz = vec![0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 0xff];
        gz.extend_from_slice(b"name\0");
        gz.extend_from_slice(&deflated);
        gz.extend_from_slice(&0u32.to_le_bytes()); // crc (unchecked)
        gz.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        assert_eq!(gunzip(&gz).unwrap(), payload);
        let mut p = ResponseParser::new();
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            gz.len()
        )
        .into_bytes();
        raw.extend_from_slice(&gz);
        let r = p.push(&raw).unwrap().unwrap();
        assert_eq!(r.body, payload);
        assert!(gunzip(b"not gzip at all!!!").is_err());
    }

    proptest! {
        #[test]
        fn parser_never_panics(chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..16)) {
            let mut p = ResponseParser::new();
            for c in chunks {
                if p.push(&c).is_err() { break; }
            }
            let _ = p.finish();
        }

        #[test]
        fn gunzip_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = gunzip(&data);
        }
    }
}
