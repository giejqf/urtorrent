// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Shared helpers for the session integration tests: a minimal executor, a
//! torrent generator, a std-thread seeder and a tiny HTTP tracker.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use metainfo::Bitfield;
use wire::{Connection, ConnectionParams, Event as WireEvent, Role};

/// Minimal executor for the API futures (tokio::sync primitives are
/// runtime-agnostic, so a thread-parking waker is all we need).
pub fn block_on<F: Future>(fut: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park_timeout(Duration::from_millis(50)),
        }
    }
}

fn bstr(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(s.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(s);
}

/// Build a single-file torrent and its data.
pub fn make_torrent(
    name: &str,
    size: usize,
    piece_len: usize,
    announce: &str,
) -> (Vec<u8>, Vec<u8>) {
    let mut data = vec![0u8; size];
    let mut x: u32 = 0x1234_5678;
    for b in &mut data {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = x as u8;
    }
    let mut pieces = Vec::new();
    for chunk in data.chunks(piece_len) {
        pieces.extend_from_slice(&storage::sha1(chunk));
    }
    let mut info = Vec::new();
    info.extend_from_slice(b"d");
    bstr(&mut info, b"length");
    info.extend_from_slice(format!("i{size}e").as_bytes());
    bstr(&mut info, b"name");
    bstr(&mut info, name.as_bytes());
    bstr(&mut info, b"piece length");
    info.extend_from_slice(format!("i{piece_len}e").as_bytes());
    bstr(&mut info, b"pieces");
    bstr(&mut info, &pieces);
    info.push(b'e');
    let mut t = Vec::new();
    t.push(b'd');
    bstr(&mut t, b"announce");
    bstr(&mut t, announce.as_bytes());
    bstr(&mut t, b"info");
    t.extend_from_slice(&info);
    t.push(b'e');
    (t, data)
}

/// A seeder speaking through our own sans-IO connection (responder role).
pub fn spawn_seeder(info_hash: [u8; 20], data: Arc<Vec<u8>>, piece_len: usize) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let data = data.clone();
            std::thread::spawn(move || {
                let pieces = data.len().div_ceil(piece_len);
                let mut conn = Connection::new(ConnectionParams {
                    role: Role::Responder,
                    info_hash,
                    our_peer_id: *b"-TS0001-seederseeder",
                    profile: profile::Profile::native(),
                    piece_count: Some(pieces),
                    our_have: Bitfield::all_set(pieces),
                    listen_port: addr.port(),
                    peer_ip: stream.peer_addr().ok().map(|a| a.ip()),
                    metadata_size: None,
                    advertise_port: true,
                    private: false,
                });
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .unwrap();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let events = match conn.receive(&buf[..n]) {
                        Ok(ev) => ev,
                        Err(e) => panic!("seeder: protocol error from our client: {e}"),
                    };
                    for ev in events {
                        match ev {
                            WireEvent::Interested => conn.choke(false),
                            WireEvent::Request(r) => {
                                let start = r.index as usize * piece_len + r.begin as usize;
                                let end = start + r.length as usize;
                                conn.piece(r, &data[start..end]);
                            }
                            _ => {}
                        }
                    }
                    let out = conn.take_outbound();
                    if !out.is_empty() && stream.write_all(&out).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A tiny HTTP tracker recording announces and pointing at `peer`.
pub fn spawn_tracker(peer: SocketAddr, log: Arc<Mutex<Vec<String>>>) -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = vec![0u8; 8192];
            let mut got = Vec::new();
            loop {
                let n = match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                got.extend_from_slice(&buf[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&got).into_owned();
            let line = text.lines().next().unwrap_or("").to_string();
            log.lock().unwrap().push(line.clone());
            let SocketAddr::V4(p) = peer else {
                unreachable!()
            };
            let mut body = b"d8:intervali1800e5:peers6:".to_vec();
            body.extend_from_slice(&p.ip().octets());
            body.extend_from_slice(&p.port().to_be_bytes());
            body.push(b'e');
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    format!("http://{addr}/announce")
}

pub fn event_param(line: &str) -> Option<String> {
    line.split('&')
        .chain(
            line.split('?')
                .nth(1)
                .into_iter()
                .flat_map(|q| q.split('&')),
        )
        .find_map(|kv| {
            kv.strip_prefix("event=")
                .map(|v| v.split(' ').next().unwrap().to_string())
        })
}
