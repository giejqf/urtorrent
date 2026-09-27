// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Copy budgets on the data path (`SessionStats::copied_bytes`): a TCP
//! download costs one user-space copy per payload byte, a TCP upload none,
//! a uTP transfer two on each side.
//! The torrent's files are smaller than a block so blocks straddle files
//! (the storage write path must not copy for that either), and the budgets
//! hold with and without a rate limit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate urtorrent_session as session;

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{block_on, make_multi_torrent};
use session::{AddTorrent, Session, SessionBuilder, TorrentState, TransportPolicy};

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
        .lsd(false)
        .dht(false)
}

fn addr_of(n: u8, s: &Session) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, 0, 0, n).into(), s.listen_port())
}

fn wait_state(s: &Session, id: session::TorrentId, want: TorrentState, secs: u64) {
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

/// Files of odd sizes, most smaller than a 16 KiB block, so nearly every
/// block straddles a file boundary.
const FILES: &[(&str, usize)] = &[
    ("a.bin", 10_001),
    ("sub/b.bin", 700_003),
    ("c.bin", 5),
    ("sub/deep/d.bin", 0),
    ("e.bin", 1_300_007),
    ("f.bin", 9_000),
];

fn total() -> u64 {
    FILES.iter().map(|(_, l)| *l as u64).sum()
}

fn seed_dir(dir: &Path, data: &[u8]) -> PathBuf {
    let root = dir.join("a");
    let mut pos = 0;
    for (path, len) in FILES {
        let p = root.join("copies").join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, &data[pos..pos + len]).unwrap();
        pos += len;
    }
    root
}

/// One transfer from `a` (seeder) to `b` (leecher). Returns
/// `(a.copied_bytes, b.copied_bytes)` once `b` has the data on disk.
fn transfer(a: &Session, b: &Session, tag: &str) -> (u64, u64) {
    let dir = std::env::temp_dir().join(format!("urt-copies-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (torrent_bytes, data) =
        make_multi_torrent("copies", FILES, 256 * 1024, "http://127.0.0.1:1/x");
    let a_dir = seed_dir(&dir, &data);
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    wait_state(a, a_id, TorrentState::Seeding, 10);
    let before_a = block_on(a.stats()).unwrap().copied_bytes;
    let before_b = block_on(b.stats()).unwrap().copied_bytes;
    let b_dir = dir.join("b");
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(torrent_bytes, &b_dir))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, a))).unwrap();
    wait_state(b, b_id, TorrentState::Seeding, 120);
    let mut pos = 0;
    for (path, len) in FILES {
        let got = std::fs::read(b_dir.join("copies").join(path)).unwrap();
        assert_eq!(got, &data[pos..pos + len], "{path}");
        pos += len;
    }
    // Every counted byte, whether the connection is still open or not.
    let sa = block_on(a.stats()).unwrap();
    let sb = block_on(b.stats()).unwrap();
    assert_eq!(sb.downloaded, total());
    block_on(b.remove_torrent(b_id)).unwrap();
    block_on(a.remove_torrent(a_id)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let (up, down) = (sa.copied_bytes - before_a, sb.copied_bytes - before_b);
    let n = total() as f64;
    eprintln!(
        "{tag}: {} payload bytes; seeder copied {up} ({:.3}x), leecher copied {down} ({:.3}x)",
        total(),
        up as f64 / n,
        down as f64 / n
    );
    (up, down)
}

/// Slack for what the budgets do not cover: the 13-byte header of every
/// block cut by a receive boundary, control messages, the handshake.
fn slack() -> u64 {
    let blocks = total().div_ceil(16 * 1024);
    blocks * 64 + 64 * 1024
}

#[test]
fn tcp_download_costs_one_copy_per_byte_and_upload_none() {
    let a = block_on(builder(1).transports(TransportPolicy::TcpOnly).build()).unwrap();
    let b = block_on(builder(2).transports(TransportPolicy::TcpOnly).build()).unwrap();
    let (up, down) = transfer(&a, &b, "tcp");
    let n = total();
    assert!(
        down >= n && down <= n + slack(),
        "leecher copied {down} bytes for {n} payload bytes (budget: one copy)"
    );
    assert!(
        up <= slack(),
        "seeder copied {up} bytes for {n} payload bytes (budget: none)"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn rate_limited_tcp_transfer_keeps_the_budget() {
    // Partial sends under a limit slice the batch instead of copying it.
    let a = block_on(
        builder(1)
            .transports(TransportPolicy::TcpOnly)
            .upload_limit(4 << 20)
            .build(),
    )
    .unwrap();
    let b = block_on(
        builder(2)
            .transports(TransportPolicy::TcpOnly)
            .download_limit(4 << 20)
            .build(),
    )
    .unwrap();
    let (up, down) = transfer(&a, &b, "tcp-limited");
    let n = total();
    assert!(
        down >= n && down <= n + slack(),
        "leecher copied {down} of {n}"
    );
    assert!(up <= slack(), "seeder copied {up} of {n}");
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn utp_transfer_costs_two_copies_each_way() {
    let a = block_on(builder(1).transports(TransportPolicy::UtpOnly).build()).unwrap();
    let b = block_on(builder(2).transports(TransportPolicy::UtpOnly).build()).unwrap();
    let (up, down) = transfer(&a, &b, "utp");
    let n = total();
    // Receive: datagram to receive queue, then the framer (uTP packets are
    // smaller than a block, so every block is cut by a chunk boundary).
    // Retransmitted packets are received and dropped without a copy;
    // packets received out of order cost the same one copy.
    assert!(
        down >= 2 * n && down <= 2 * n + slack(),
        "leecher copied {down} bytes for {n} payload bytes (budget: two copies)"
    );
    // Send: write queue to packet (the packet stays in the send window)
    // and packet to the outgoing queue, plus one more per retransmitted
    // packet (few on loopback).
    assert!(
        up >= 2 * n && up <= 2 * n + n / 8 + slack(),
        "seeder copied {up} bytes for {n} payload bytes (budget: two copies)"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn rate_limited_utp_upload_costs_at_most_one_more_copy() {
    // A grant that cuts a chunk batch copies the cut parts into the uTP
    // write queue (whole batches are moved): three copies per byte at worst.
    let a = block_on(
        builder(1)
            .transports(TransportPolicy::UtpOnly)
            .upload_limit(4 << 20)
            .build(),
    )
    .unwrap();
    let b = block_on(builder(2).transports(TransportPolicy::UtpOnly).build()).unwrap();
    let (up, down) = transfer(&a, &b, "utp-limited");
    let n = total();
    assert!(
        down >= 2 * n && down <= 2 * n + slack(),
        "leecher copied {down} of {n} (budget: two copies)"
    );
    assert!(
        up >= 2 * n && up <= 3 * n + n / 8 + slack(),
        "seeder copied {up} of {n} (budget: three copies)"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}
