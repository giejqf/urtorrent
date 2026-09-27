// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! uTP (BEP 29) between engines in one process: a uTP-only leecher dials a
//! default seeder over the UDP listen port, downloads, and both report the
//! connection as uTP; MSE over uTP; the default policy (TCP first) and the
//! fallbacks in both directions; a TCP-only peer that cannot be reached over
//! uTP.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate urtorrent_session as session;

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use common::{block_on, make_torrent};
use session::{
    AddTorrent, EncryptionMode, Event, PeerTransport, Session, SessionBuilder, TorrentState,
    TransportPolicy,
};

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

fn seed_dir(dir: &Path, name: &str, data: &[u8]) -> std::path::PathBuf {
    let d = dir.join(name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("utp.bin"), data).unwrap();
    d
}

/// Run one transfer from `a` (seeder, 127.0.0.1) to `b` (leecher,
/// 127.0.0.2); returns the transports each side saw for the other.
fn transfer(a: &Session, b: &Session, size: usize, tag: &str) -> (PeerTransport, PeerTransport) {
    let dir = std::env::temp_dir().join(format!("urt-utp-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (torrent_bytes, data) = make_torrent("utp.bin", size, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = seed_dir(&dir, "a", &data);
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    wait_state(a, a_id, TorrentState::Seeding, 10);
    let mut a_events = a.events();
    let mut b_events = b.events();
    let b_dir = dir.join("b");
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(torrent_bytes, &b_dir))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, a))).unwrap();
    wait_state(b, b_id, TorrentState::Seeding, 60);
    assert_eq!(std::fs::read(b_dir.join("utp.bin")).unwrap(), data);
    // `PeerDisconnected` carries the final `PeerInfo` (the two seeds part
    // as soon as B completes).
    let transport_seen = |ev: &mut session::EventStream, id| {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match ev.try_recv() {
                Some(Event::PeerDisconnected { id: i, info, .. }) if i == id => {
                    return info.transport;
                }
                Some(_) => {}
                None => {
                    assert!(Instant::now() < deadline, "no PeerDisconnected event");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    };
    let b_saw = transport_seen(&mut b_events, b_id);
    let a_saw = transport_seen(&mut a_events, a_id);
    block_on(b.remove_torrent(b_id)).unwrap();
    block_on(a.remove_torrent(a_id)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (a_saw, b_saw)
}

#[test]
fn utp_only_leecher_downloads_from_a_default_seeder() {
    let a = block_on(builder(1).build()).unwrap();
    let b = block_on(builder(2).transports(TransportPolicy::UtpOnly).build()).unwrap();
    let (a_saw, b_saw) = transfer(&a, &b, 3 << 20, "leech");
    assert_eq!(b_saw, PeerTransport::Utp);
    assert_eq!(a_saw, PeerTransport::Utp);
    let st = block_on(a.stats()).unwrap();
    // The connection may still be finishing its FIN exchange.
    assert!(st.utp_connections <= 1, "{st:?}");
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn mse_over_utp_between_utp_only_peers() {
    let a = block_on(builder(1).transports(TransportPolicy::UtpOnly).build()).unwrap();
    let b = block_on(
        builder(2)
            .transports(TransportPolicy::UtpOnly)
            .encryption(EncryptionMode::Forced)
            .build(),
    )
    .unwrap();
    let (a_saw, b_saw) = transfer(&a, &b, 2 << 20, "mse");
    assert_eq!((a_saw, b_saw), (PeerTransport::Utp, PeerTransport::Utp));
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn default_policy_dials_tcp_first() {
    let a = block_on(builder(1).build()).unwrap();
    let b = block_on(builder(2).build()).unwrap();
    let (a_saw, b_saw) = transfer(&a, &b, 1 << 20, "default");
    assert_eq!((a_saw, b_saw), (PeerTransport::Tcp, PeerTransport::Tcp));
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn prefer_utp_policy_dials_utp_first() {
    // libtorrent's order, on request.
    let a = block_on(builder(1).build()).unwrap();
    let b = block_on(builder(2).transports(TransportPolicy::PreferUtp).build()).unwrap();
    let (a_saw, b_saw) = transfer(&a, &b, 1 << 20, "preferutp");
    assert_eq!((a_saw, b_saw), (PeerTransport::Utp, PeerTransport::Utp));
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn utp_dial_failure_falls_back_to_tcp() {
    // A has uTP off; B prefers uTP: its SYN goes unanswered (3 s) and B
    // reconnects over TCP right away.
    let a = block_on(builder(1).transports(TransportPolicy::TcpOnly).build()).unwrap();
    let b = block_on(builder(2).transports(TransportPolicy::PreferUtp).build()).unwrap();
    let start = Instant::now();
    let (a_saw, b_saw) = transfer(&a, &b, 1 << 20, "fallback");
    assert_eq!((a_saw, b_saw), (PeerTransport::Tcp, PeerTransport::Tcp));
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "{:?}",
        start.elapsed()
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn tcp_failure_falls_back_to_utp() {
    // A is uTP-only (it accepts TCP and drops it); B, on the default policy,
    // dials TCP, sees the connection die before any handshake and retries
    // over uTP at once.
    let a = block_on(builder(1).transports(TransportPolicy::UtpOnly).build()).unwrap();
    let b = block_on(builder(2).build()).unwrap();
    let start = Instant::now();
    let (a_saw, b_saw) = transfer(&a, &b, 1 << 20, "tcpfallback");
    assert_eq!((a_saw, b_saw), (PeerTransport::Utp, PeerTransport::Utp));
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "{:?}",
        start.elapsed()
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn utp_disabled_peer_ignores_syn_and_dial_fails_fast() {
    // A has uTP off entirely; B is uTP-only. B's SYNs are ignored, its dial
    // times out (3 s), and it never gets the data.
    let a = block_on(builder(1).transports(TransportPolicy::TcpOnly).build()).unwrap();
    let b = block_on(builder(2).transports(TransportPolicy::UtpOnly).build()).unwrap();
    let dir = std::env::temp_dir().join(format!("urt-utp-off-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (torrent_bytes, data) = make_torrent("utp.bin", 200_000, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = seed_dir(&dir, "a", &data);
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let b_dir = dir.join("b");
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(torrent_bytes, &b_dir))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    std::thread::sleep(Duration::from_secs(6));
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(st.state, TorrentState::Downloading, "{st:?}");
    assert_eq!(st.pieces_have, 0);
    assert_eq!(block_on(a.stats()).unwrap().utp_connections, 0);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
