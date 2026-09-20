// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Web seeds (BEP 19, GetRight style): each `url-list` entry is served by one
//! task that takes blocks from the picker like a peer that has everything,
//! fetches the covering byte ranges with HTTP `Range` requests over the ring
//! (one kept-alive connection per seed, one request per contiguous file
//! range up to [`MAX_REQUEST`]) and feeds the data through the same verified
//! path as peer blocks. A failing seed backs off and is dropped after
//! [`MAX_FAILURES`] consecutive failures.
//!
//! Request shape follows the oracle (`web_seed_only` capture): `GET <path>
//! HTTP/1.1`, then `Host`, `User-Agent`, `Connection: keep-alive`, `Range:
//! bytes=a-b`. libtorrent asks for whole pieces in ranges up to 16 MiB; ours
//! are capped at [`MAX_REQUEST`] (an accepted L3 difference).
//!
//! URL rules (BEP 19): a single-file torrent fetches the URL itself, or
//! `<url><name>` when the URL ends in `/`; a multi-file torrent fetches
//! `<url>/<name>/<path...>` with every component percent-encoded.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use metainfo::Bitfield;
use tracker::Url;
use tracker::http::Response;
use wire::Request;

use super::Ctx;
use super::torrent::{self, Torrent};
use crate::api::Event;

/// Largest byte range per HTTP request (and response body we buffer).
pub const MAX_REQUEST: u64 = 4 * 1024 * 1024;
/// Consecutive failures after which a web seed is abandoned.
pub const MAX_FAILURES: u32 = 5;
/// Blocks picked per round (one `MAX_REQUEST` worth at 16 KiB).
const BLOCKS_PER_ROUND: usize = (MAX_REQUEST / 16384) as usize;

/// Per-torrent web seed bookkeeping.
#[derive(Default)]
pub struct State {
    /// Running tasks by URL, with their picker key.
    running: HashMap<String, u32>,
    failures: HashMap<String, u32>,
    /// Do not retry a URL before this instant.
    retry_at: HashMap<String, Instant>,
}

impl State {
    /// The URLs whose task uses picker key `key`.
    pub fn running_urls_for(&self, key: u32) -> Vec<String> {
        self.running
            .iter()
            .filter(|(_, k)| **k == key)
            .map(|(u, _)| u.clone())
            .collect()
    }

    /// Never use `url` again (it served bad data).
    pub fn abandon(&mut self, url: &str) {
        self.failures.insert(url.to_string(), MAX_FAILURES);
    }
}

/// Start a task for every web seed that is not running, once the metadata is
/// known and something is left to download.
pub fn start(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) {
    let urls: Vec<String> = {
        let t = torrent.borrow();
        if !t.has_metadata() || t.is_complete() || !t.is_running() {
            return;
        }
        let now = Instant::now();
        t.web_seeds
            .iter()
            .filter(|u| !t.webseed.running.contains_key(*u))
            .filter(|u| t.webseed.failures.get(*u).copied().unwrap_or(0) < MAX_FAILURES)
            .filter(|u| t.webseed.retry_at.get(*u).is_none_or(|r| now >= *r))
            .cloned()
            .collect()
    };
    for url in urls {
        let key = ctx.new_peer_key();
        {
            let mut t = torrent.borrow_mut();
            t.webseed.running.insert(url.clone(), key);
            let all = Bitfield::all_set(t.piece_count());
            t.picker.peer_joined(&all);
        }
        uring::spawn(run(ctx.clone(), torrent.clone(), url, key));
    }
}

/// Stop every web seed task (the torrent completed or stopped).
pub fn stop_all(t: &Torrent) {
    // Tasks observe completion / closing on their next round; nothing to
    // signal explicitly.
    let _ = t;
}

/// The path (and query) to request for `file` of `info` from web seed `url`.
pub fn request_url(url: &str, info: &metainfo::Info, file: usize) -> Option<String> {
    let esc = profile::EscapeStyle::LowerHexRfc3986;
    if info.single_file {
        if url.ends_with('/') {
            Some(format!("{url}{}", esc.escape(info.name.as_bytes())))
        } else {
            Some(url.to_string())
        }
    } else {
        let f = info.files.get(file)?;
        let mut s = url.to_string();
        if !s.ends_with('/') {
            s.push('/');
        }
        // `f.path` already includes the torrent name as its first component.
        let parts: Vec<String> = f
            .path
            .components()
            .iter()
            .map(|c| esc.escape(c.as_bytes()))
            .collect();
        s.push_str(&parts.join("/"));
        Some(s)
    }
}

fn build_request(url: &Url, user_agent: &str, start: u64, end_inclusive: u64) -> Vec<u8> {
    let mut path = url.path.clone();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(q) = &url.query {
        path.push('?');
        path.push_str(q);
    }
    let host = url.host_header(profile::HostPortStyle::OmitDefault);
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nConnection: keep-alive\r\nRange: bytes={start}-{end_inclusive}\r\n\r\n"
    )
    .into_bytes()
}

/// One contiguous HTTP fetch: `[start, end)` of file `file`.
struct Segment {
    file: usize,
    start: u64,
    end: u64,
    /// Torrent-stream offset of `start`.
    torrent_offset: u64,
}

async fn run(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>, url: String, key: u32) {
    let reason = run_inner(&ctx, &torrent, &url, key).await;
    let mut t = torrent.borrow_mut();
    t.webseed.running.remove(&url);
    t.picker.peer_gone(key);
    let all = Bitfield::all_set(t.piece_count());
    t.picker.peer_left(&all);
    tracing::debug!(torrent = t.id.0, url, "web seed task ended: {reason}");
}

async fn run_inner(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, url: &str, key: u32) -> String {
    if let Err(e) = Url::parse(url) {
        let mut t = torrent.borrow_mut();
        t.webseed.failures.insert(url.to_string(), MAX_FAILURES);
        return format!("bad url: {e}");
    }
    let user_agent = ctx.cfg.profile.user_agent;
    // One connection per (redirect-resolved) target URL, kept across rounds.
    let mut conn: Option<(String, super::http::HttpConn)> = None;
    loop {
        let (info, blocks, closing) = {
            let mut t = torrent.borrow_mut();
            if t.closing.is_set() || !t.is_running() || t.is_complete() {
                return "done".into();
            }
            if t.webseed.failures.get(url).copied().unwrap_or(0) >= MAX_FAILURES {
                return "abandoned".into();
            }
            let Some(info) = t.info.clone() else {
                return "no metadata".into();
            };
            let blocks = torrent::pick_contiguous(ctx, &mut t.picker, key, BLOCKS_PER_ROUND);
            (info, blocks, t.closing.clone())
        };
        if blocks.is_empty() {
            match super::local::select2(uring::sleep(Duration::from_secs(1)), closing.wait()).await
            {
                super::local::Either::Left(()) => continue,
                super::local::Either::Right(()) => return "stopped".into(),
            }
        }
        // Coalesce the blocks into contiguous torrent ranges, then into
        // per-file segments.
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut sorted = blocks.clone();
        sorted.sort_by_key(|b| (b.piece, b.offset));
        for b in &sorted {
            let start = u64::from(b.piece) * u64::from(info.piece_length) + u64::from(b.offset);
            let end = start + u64::from(b.length);
            match ranges.last_mut() {
                Some((_, e)) if *e == start => *e = end,
                _ => ranges.push((start, end)),
            }
        }
        let mut segments = Vec::new();
        for (s, e) in ranges {
            for sl in info.slices_for(s, e - s) {
                if sl.padding {
                    continue;
                }
                let mut off = sl.file_offset;
                let end = sl.file_offset + sl.length;
                let file_start = info.files[sl.file_index].offset;
                while off < end {
                    let len = (end - off).min(MAX_REQUEST);
                    segments.push(Segment {
                        file: sl.file_index,
                        start: off,
                        end: off + len,
                        torrent_offset: file_start + off,
                    });
                    off += len;
                }
            }
        }
        // Padding-only blocks (BEP 47) contain zeros and need no fetch.
        let mut received: HashMap<(u32, u32), Vec<u8>> = HashMap::new();
        let mut failed: Option<String> = None;
        for seg in segments {
            let Some(target) = request_url(url, &info, seg.file) else {
                failed = Some("file index out of range".into());
                break;
            };
            let target_url = match Url::parse(&target) {
                Ok(u) => u,
                Err(e) => {
                    failed = Some(format!("bad file url: {e}"));
                    break;
                }
            };
            let request = build_request(&target_url, user_agent, seg.start, seg.end - 1);
            let resp = fetch(ctx, &mut conn, &target, &target_url, request).await;
            match resp {
                Ok(Response {
                    status: 206, body, ..
                }) if body.len() as u64 == seg.end - seg.start => {
                    scatter(&info, &sorted, seg.torrent_offset, &body, &mut received);
                }
                Ok(Response {
                    status: 200, body, ..
                }) if seg.start == 0 && body.len() as u64 == seg.end - seg.start => {
                    // A server that ignores Range but the range was the whole file.
                    scatter(&info, &sorted, seg.torrent_offset, &body, &mut received);
                }
                Ok(r) => {
                    failed = Some(format!("http {} ({} bytes)", r.status, r.body.len()));
                    break;
                }
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
            if torrent.borrow().closing.is_set() {
                return "stopped".into();
            }
        }
        if failed.is_some() {
            conn = None;
        }
        // Deliver complete blocks; release the rest.
        let mut delivered = 0usize;
        for b in &sorted {
            let r = Request {
                index: b.piece,
                begin: b.offset,
                length: b.length,
            };
            let data = match received.remove(&(b.piece, b.offset)) {
                Some(d) if d.len() == b.length as usize => Some(d),
                _ => {
                    // Fully inside padding: zeros.
                    let start =
                        u64::from(b.piece) * u64::from(info.piece_length) + u64::from(b.offset);
                    let all_pad = info
                        .slices_for(start, u64::from(b.length))
                        .iter()
                        .all(|s| s.padding);
                    all_pad.then(|| vec![0u8; b.length as usize])
                }
            };
            match data {
                Some(d) => {
                    torrent::on_block_from(ctx, torrent, key, None, r, d).await;
                    delivered += 1;
                }
                None => {
                    torrent.borrow_mut().picker.release(key, b);
                }
            }
        }
        let mut t = torrent.borrow_mut();
        match failed {
            Some(e) => {
                let n = {
                    let n = t.webseed.failures.entry(url.to_string()).or_insert(0);
                    *n += 1;
                    *n
                };
                let backoff = Duration::from_secs(30 * u64::from(n));
                t.webseed
                    .retry_at
                    .insert(url.to_string(), Instant::now() + backoff);
                let give_up = n >= MAX_FAILURES;
                tracing::warn!(torrent = t.id.0, url, "web seed failed: {e}");
                ctx.emit(Event::WebSeedError {
                    id: t.id,
                    url: url.to_string(),
                    error: e.clone(),
                });
                return if give_up {
                    format!("abandoned after {n} failures: {e}")
                } else {
                    format!("backing off: {e}")
                };
            }
            None => {
                if delivered > 0 {
                    t.webseed.failures.remove(url);
                }
            }
        }
    }
}

/// One request over the kept-alive connection to `target`, reconnecting
/// when the URL changed, the server closed, or the first attempt failed on
/// a stale connection.
async fn fetch(
    ctx: &Rc<Ctx>,
    conn: &mut Option<(String, super::http::HttpConn)>,
    target: &str,
    url: &Url,
    request: Vec<u8>,
) -> Result<Response, String> {
    let max_body = MAX_REQUEST as usize + 1024;
    for attempt in 0..2 {
        let reuse = matches!(conn, Some((t, c)) if t == target && c.reusable());
        if !reuse {
            let c = super::http::HttpConn::open(&ctx.dns, &ctx.tls, ctx.families, url).await?;
            *conn = Some((target.to_string(), c));
        }
        let Some((_, c)) = conn.as_mut() else {
            return Err("no connection".into());
        };
        match uring::timeout(
            super::http::RESPONSE_TIMEOUT,
            c.request(request.clone(), max_body),
        )
        .await
        {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(e)) => {
                *conn = None;
                if attempt == 1 || !reuse {
                    return Err(e);
                }
                // A stale kept-alive connection: retry once on a fresh one.
            }
            Err(_) => {
                *conn = None;
                return Err("web seed response timed out".into());
            }
        }
    }
    Err("web seed request failed".into())
}

/// Split a fetched byte range into the blocks it covers.
fn scatter(
    info: &metainfo::Info,
    blocks: &[picker::Block],
    torrent_offset: u64,
    body: &[u8],
    out: &mut HashMap<(u32, u32), Vec<u8>>,
) {
    let end = torrent_offset + body.len() as u64;
    for b in blocks {
        let bs = u64::from(b.piece) * u64::from(info.piece_length) + u64::from(b.offset);
        let be = bs + u64::from(b.length);
        if bs >= torrent_offset && be <= end {
            let s = (bs - torrent_offset) as usize;
            let e = (be - torrent_offset) as usize;
            out.insert((b.piece, b.offset), body[s..e].to_vec());
        } else if bs < end && be > torrent_offset {
            // Partial overlap (a block straddling files): accumulate.
            let entry = out
                .entry((b.piece, b.offset))
                .or_insert_with(|| vec![0u8; b.length as usize]);
            let s = torrent_offset.max(bs);
            let e = end.min(be);
            let src = &body[(s - torrent_offset) as usize..(e - torrent_offset) as usize];
            entry[(s - bs) as usize..(e - bs) as usize].copy_from_slice(src);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(single: bool) -> metainfo::Info {
        let spec = if single {
            "d6:lengthi100e4:name5:a b.c12:piece lengthi16384e6:pieces20:aaaaaaaaaaaaaaaaaaaae"
        } else {
            "d5:filesld6:lengthi10e4:pathl3:dir5:x y.ceed6:lengthi5e4:pathl1:zeee4:name3:top12:piece lengthi16384e6:pieces20:aaaaaaaaaaaaaaaaaaaae"
        };
        metainfo::Info::from_info_dict(spec.as_bytes()).unwrap()
    }

    #[test]
    fn urls_follow_bep19() {
        let s = info(true);
        assert_eq!(
            request_url("http://h/f.bin", &s, 0).unwrap(),
            "http://h/f.bin"
        );
        assert_eq!(
            request_url("http://h/d/", &s, 0).unwrap(),
            "http://h/d/a%20b.c"
        );
        let m = info(false);
        assert_eq!(
            request_url("http://h/d", &m, 0).unwrap(),
            "http://h/d/top/dir/x%20y.c"
        );
        assert_eq!(
            request_url("http://h/d/", &m, 1).unwrap(),
            "http://h/d/top/z"
        );
        assert!(request_url("http://h/d/", &m, 2).is_none());
    }

    #[test]
    fn range_request_shape() {
        let u = Url::parse("http://h:8000/x/y?z=1").unwrap();
        let r = String::from_utf8(build_request(&u, "ua/1", 5, 9)).unwrap();
        assert_eq!(
            r,
            "GET /x/y?z=1 HTTP/1.1\r\nHost: h:8000\r\nUser-Agent: ua/1\r\nConnection: keep-alive\r\nRange: bytes=5-9\r\n\r\n"
        );
    }
}
