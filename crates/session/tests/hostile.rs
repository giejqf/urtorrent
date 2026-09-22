// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Malformed and malicious peers against a live engine: none of them may
//! crash it, grow it without bound, hold its connection slots, make it
//! serve wrong data or upset its accounting. The parsers are fuzzed
//! separately (`fuzz/`); these drive real sockets end to end.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{block_on, make_torrent};
use session::{AddTorrent, Session, SessionBuilder, TorrentId, TorrentState, TransportPolicy};
use wire::{Handshake, Message, Request};

fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
}

fn builder(n: u8) -> SessionBuilder {
    init_log();
    Session::builder()
        .listen_port(0)
        .listen_v4(Some(Ipv4Addr::new(127, 0, 0, n)))
        .listen_v6(None)
        .transports(TransportPolicy::TcpOnly)
        .lsd(false)
        .dht(false)
}

fn addr_of(n: u8, s: &Session) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, 0, 0, n).into(), s.listen_port())
}

fn wait_state(s: &Session, id: TorrentId, want: TorrentState, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let st = block_on(s.status(id)).unwrap();
        if st.state == want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {want:?}; now {st:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("urt-hostile-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A seeding session for `size` bytes; returns it with the torrent id, the
/// info-hash, the data and the directory.
fn seeder(
    n: u8,
    tag: &str,
    size: usize,
) -> (Session, TorrentId, [u8; 20], Vec<u8>, Vec<u8>, PathBuf) {
    let dir = tmp(tag);
    let (bytes, data) = make_torrent("h.bin", size, 64 * 1024, "http://127.0.0.1:1/x");
    std::fs::write(dir.join("h.bin"), &data).unwrap();
    let info_hash = metainfo::Torrent::parse(&bytes).unwrap().info.info_hash;
    let s = block_on(builder(n).build()).unwrap();
    let id = block_on(s.add_torrent(AddTorrent::metainfo(bytes.clone(), &dir))).unwrap();
    wait_state(&s, id, TorrentState::Seeding, 10);
    (s, id, info_hash, bytes, data, dir)
}

/// Whether the other end closed (or reset) `s` within `secs`.
fn closed_within(s: &mut TcpStream, secs: u64) -> bool {
    s.set_read_timeout(Some(Duration::from_secs(secs))).unwrap();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                return false;
            }
            Err(_) => return true,
        }
    }
}

/// Handshake as a peer with LTEP + fast, wait for the reply.
fn handshake(s: &mut TcpStream, info_hash: [u8; 20]) {
    let hs = Handshake {
        reserved: [0, 0, 0, 0, 0, 0x10, 0, 0x04],
        info_hash,
        peer_id: *b"-XX0001-hostilehostl",
    };
    s.write_all(&hs.encode()).unwrap();
    let mut reply = [0u8; 68];
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.read_exact(&mut reply).unwrap();
    assert_eq!(&reply[28..48], &info_hash);
}

/// Read frames until one satisfies `pred` (or the deadline); the engine's
/// own messages (bitfield, have-all, allowed-fast, LTEP handshake) are
/// skipped over.
fn read_until(s: &mut TcpStream, secs: u64, pred: impl Fn(&[u8]) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 65536];
    loop {
        while buf.len() >= 4 {
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if buf.len() < 4 + len {
                break;
            }
            let body: Vec<u8> = buf.drain(..4 + len).skip(4).collect();
            if pred(&body) {
                return true;
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        s.set_read_timeout(Some(left)).unwrap();
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return false,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

#[test]
fn slow_loris_handshakes_time_out_together_and_a_real_peer_still_gets_through() {
    let (a, a_id, _ih, bytes, data, dir) = seeder(1, "loris", 512 * 1024);
    // Twenty connections trickling one byte a second: gone after the
    // handshake deadline (10 s), not extended by each byte.
    let started = Instant::now();
    let mut victims: Vec<TcpStream> = (0..20)
        .map(|_| TcpStream::connect(addr_of(1, &a)).unwrap())
        .collect();
    let feeder = {
        let mut clones: Vec<TcpStream> = victims.iter().map(|s| s.try_clone().unwrap()).collect();
        std::thread::spawn(move || {
            for _ in 0..30 {
                std::thread::sleep(Duration::from_secs(1));
                for s in &mut clones {
                    let _ = s.write_all(&[19]);
                }
            }
        })
    };
    // Meanwhile a real leecher completes.
    let b = block_on(builder(2).build()).unwrap();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, dir.join("b")))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 30);
    assert_eq!(std::fs::read(dir.join("b/h.bin")).unwrap(), data);
    for v in &mut victims {
        assert!(closed_within(v, 20), "slow loris kept its connection");
    }
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "closed at {:?}, not at the deadline",
        started.elapsed()
    );
    drop(feeder);
    let st = block_on(a.stats()).unwrap();
    assert_eq!(st.connections, 0, "{st:?}");
    assert_eq!(block_on(a.status(a_id)).unwrap().peers, 0);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn idle_connection_flood_is_refused_at_the_connection_limit() {
    let dir = tmp("flood");
    let (bytes, data) = make_torrent("h.bin", 64 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    std::fs::write(dir.join("h.bin"), &data).unwrap();
    let a = block_on(builder(1).max_connections(4).build()).unwrap();
    let id = block_on(a.add_torrent(AddTorrent::metainfo(bytes, &dir))).unwrap();
    wait_state(&a, id, TorrentState::Seeding, 10);
    let mut socks: Vec<TcpStream> = (0..40)
        .map(|_| TcpStream::connect(addr_of(1, &a)).unwrap())
        .collect();
    // Beyond the limit the engine closes at accept; at most four idle
    // handshakes are ever pending.
    std::thread::sleep(Duration::from_millis(500));
    let mut open = 0;
    for s in &mut socks {
        if !closed_within(s, 1) {
            open += 1;
        }
    }
    assert!(open <= 4, "{open} idle connections held past the limit");
    assert!(block_on(a.stats()).unwrap().connections <= 4);
    // They leave at the handshake deadline and the limit is free again.
    std::thread::sleep(Duration::from_secs(11));
    assert_eq!(block_on(a.stats()).unwrap().connections, 0);
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn absurd_length_prefixes_garbage_and_wrong_hashes_end_the_connection_fast() {
    let (a, a_id, ih, _bytes, _data, dir) = seeder(1, "garbage", 256 * 1024);
    // A frame claiming 4 GiB: refused on the prefix, nothing allocated for
    // it.
    let mut s = TcpStream::connect(addr_of(1, &a)).unwrap();
    handshake(&mut s, ih);
    s.write_all(&[0xff, 0xff, 0xff, 0xff, 7]).unwrap();
    assert!(closed_within(&mut s, 5));
    // Random bytes after a valid handshake.
    let mut s = TcpStream::connect(addr_of(1, &a)).unwrap();
    handshake(&mut s, ih);
    let junk: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    s.write_all(&junk).unwrap();
    assert!(closed_within(&mut s, 5));
    // A handshake for a torrent we do not have, and one that is not a
    // handshake at all.
    let mut s = TcpStream::connect(addr_of(1, &a)).unwrap();
    let hs = Handshake {
        reserved: [0; 8],
        info_hash: [0xab; 20],
        peer_id: [b'x'; 20],
    };
    s.write_all(&hs.encode()).unwrap();
    assert!(closed_within(&mut s, 5));
    let mut s = TcpStream::connect(addr_of(1, &a)).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert!(closed_within(&mut s, 15));
    // The engine is untouched.
    let st = block_on(a.status(a_id)).unwrap();
    assert_eq!(st.peers, 0);
    assert_eq!(block_on(a.stats()).unwrap().connections, 0);
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn out_of_range_requests_end_the_connection_without_serving_anything() {
    let (a, a_id, ih, _bytes, _data, dir) = seeder(1, "requests", 256 * 1024 + 100);
    let piece_len = 64 * 1024u32;
    let ask = |s: &mut TcpStream, r: Request| {
        s.write_all(&Message::Interested.to_bytes()).unwrap();
        assert!(read_until(s, 10, |b| b.first() == Some(&1)), "no unchoke");
        s.write_all(&Message::Request(r).to_bytes()).unwrap();
    };
    // Past the end of a full piece.
    let mut s = TcpStream::connect(addr_of(1, &a)).unwrap();
    handshake(&mut s, ih);
    ask(
        &mut s,
        Request {
            index: 0,
            begin: piece_len - 100,
            length: 16 * 1024,
        },
    );
    assert!(closed_within(&mut s, 5), "served a block past the piece");
    // Past the end of the (short) last piece.
    let mut s = TcpStream::connect(addr_of(1, &a)).unwrap();
    handshake(&mut s, ih);
    ask(
        &mut s,
        Request {
            index: 4,
            begin: 0,
            length: 16 * 1024,
        },
    );
    assert!(
        closed_within(&mut s, 5),
        "served a block past the last piece"
    );
    // Index out of range, zero length, oversized length: refused by the
    // protocol layer.
    for r in [
        Request {
            index: 5,
            begin: 0,
            length: 16 * 1024,
        },
        Request {
            index: 0,
            begin: 0,
            length: 0,
        },
        Request {
            index: 0,
            begin: 0,
            length: 1 << 20,
        },
    ] {
        let mut s = TcpStream::connect(addr_of(1, &a)).unwrap();
        handshake(&mut s, ih);
        ask(&mut s, r);
        assert!(closed_within(&mut s, 5), "{r:?} was accepted");
    }
    // Nothing was uploaded to any of them.
    let st = block_on(a.status(a_id)).unwrap();
    assert_eq!(st.uploaded, 0, "{st:?}");
    assert_eq!(st.peers, 0);
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pex_and_tracker_floods_keep_the_peer_list_bounded() {
    let dir = tmp("pexflood");
    let (bytes, _data) = make_torrent("h.bin", 64 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    let info_hash = metainfo::Torrent::parse(&bytes).unwrap().info.info_hash;
    // A leecher (so it wants peers) that nobody can reach: every address the
    // flood hands it goes to the candidate list.
    let b = block_on(builder(2).build()).unwrap();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, dir.join("b")))).unwrap();
    // The attacker connects, completes the LTEP handshake with `ut_pex`,
    // then floods PEX messages with fresh addresses.
    let mut s = TcpStream::connect(addr_of(2, &b)).unwrap();
    handshake(&mut s, info_hash);
    let ext = wire::ExtHandshake {
        m: vec![("ut_pex".into(), 7)],
        ..Default::default()
    };
    s.write_all(
        &Message::Extended {
            id: 0,
            payload: ext.encode(),
        }
        .to_bytes(),
    )
    .unwrap();
    // Learn the id it wants PEX under.
    let pex_id = Arc::new(Mutex::new(None::<u8>));
    {
        let pex_id = pex_id.clone();
        assert!(read_until(&mut s, 10, |b| {
            if b.first() == Some(&20) && b.get(1) == Some(&0) {
                if let Ok(h) = wire::ExtHandshake::parse(&b[2..]) {
                    *pex_id.lock().unwrap() = h.peer_id_for("ut_pex");
                }
                return true;
            }
            false
        }));
    }
    let pex_id = pex_id.lock().unwrap().expect("peer advertises ut_pex");
    let mut n = 0u32;
    let mut dropped_at = None;
    for i in 0..100 {
        let added: Vec<(SocketAddr, u8)> = (0..200)
            .map(|_| {
                n += 1;
                // 10.x.y.z: routable-looking, never dialled successfully.
                let ip = Ipv4Addr::new(10, (n >> 16) as u8, (n >> 8) as u8, n as u8);
                (SocketAddr::new(ip.into(), 6881), 0u8)
            })
            .collect();
        let pex = wire::ext::Pex {
            added,
            dropped: Vec::new(),
        };
        let frame = Message::Extended {
            id: pex_id,
            payload: pex.encode(),
        }
        .to_bytes();
        if s.write_all(&frame).is_err() {
            // libtorrent's rule, ours too: PEX faster than the protocol's
            // cadence gets the peer disconnected. That is the first
            // defence; the list cap below is the second.
            dropped_at = Some(i);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(500));
    let st = block_on(b.status(b_id)).unwrap();
    assert!(
        dropped_at.is_some() || closed_within(&mut s, 2),
        "a PEX flood kept its connection"
    );
    assert!(
        st.peer_list_size <= 3000,
        "peer list grew to {}",
        st.peer_list_size
    );
    assert!(st.peer_list_size > 0, "{st:?}");
    // The manual API is bounded the same way.
    for i in 0..5000u32 {
        let ip = Ipv4Addr::new(11, (i >> 16) as u8, (i >> 8) as u8, i as u8);
        block_on(b.add_peer(b_id, SocketAddr::new(ip.into(), 6881))).unwrap();
    }
    let st = block_on(b.status(b_id)).unwrap();
    assert!(st.peer_list_size <= 3000, "{}", st.peer_list_size);
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn deeply_nested_and_oversized_extension_payloads_are_refused() {
    let (a, a_id, ih, _bytes, _data, dir) = seeder(1, "nested", 128 * 1024);
    // 5000 nested lists as an extended handshake: bounded recursion, not a
    // stack overflow.
    let mut s = TcpStream::connect(addr_of(1, &a)).unwrap();
    handshake(&mut s, ih);
    let mut payload = vec![b'l'; 5000];
    payload.extend(std::iter::repeat_n(b'e', 5000));
    s.write_all(&Message::Extended { id: 0, payload }.to_bytes())
        .unwrap();
    assert!(closed_within(&mut s, 5));
    // An extended message larger than any extension needs.
    let mut s = TcpStream::connect(addr_of(1, &a)).unwrap();
    handshake(&mut s, ih);
    let big = vec![b'd'; 300 * 1024];
    s.write_all(
        &Message::Extended {
            id: 0,
            payload: big,
        }
        .to_bytes(),
    )
    .unwrap();
    assert!(closed_within(&mut s, 5));
    assert_eq!(block_on(a.status(a_id)).unwrap().peers, 0);
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unrequested_pieces_are_dropped_and_counted_not_written() {
    let dir = tmp("unreq");
    let (bytes, data) = make_torrent("h.bin", 256 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    let info_hash = metainfo::Torrent::parse(&bytes).unwrap().info.info_hash;
    let b = block_on(builder(2).build()).unwrap();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, dir.join("b")))).unwrap();
    // A "seed" that never waits for requests: it pushes blocks while still
    // choking (so nothing was, or could have been, requested).
    let mut s = TcpStream::connect(addr_of(2, &b)).unwrap();
    handshake(&mut s, info_hash);
    s.write_all(&Message::HaveAll.to_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    for i in 0..4u32 {
        let mut frame = Vec::new();
        Message::encode_piece_header(&mut frame, i, 0, 16 * 1024);
        frame.extend(std::iter::repeat_n(0xEE, 16 * 1024));
        s.write_all(&frame).unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(st.pieces_have, 0);
    // The payload arrived, so it counts as downloaded, and it was useless,
    // so it counts as redundant: the two cancel out (libtorrent's
    // `incoming_piece` does both) and the torrent gains nothing.
    assert_eq!(st.downloaded, st.redundant, "{st:?}");
    assert!(st.redundant >= 4 * 16 * 1024, "{st:?}");
    assert_eq!(st.total_wanted_done, 0, "{st:?}");
    // The connection survives (libtorrent keeps it, Q23) and a real
    // download can still proceed through it.
    assert_eq!(st.peers, 1, "{st:?}");
    // The garbage is not on disk under the torrent's name.
    let on_disk = std::fs::read(dir.join("b/h.bin")).unwrap_or_default();
    assert!(
        !on_disk.starts_with(&[0xEE; 16]),
        "unrequested block written"
    );
    let _ = data;
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
