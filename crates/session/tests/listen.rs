// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The settings that used to need a new session, changed live: the listen
//! port and addresses (trackers hear `stopped` on the old port and
//! `started` on the new, the new sockets accept, a family switched off
//! drops its peers), the DHT node on and off (tables kept), and the
//! identity profile (new connections carry it, trackers hear the change).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{block_on, event_param, make_torrent, spawn_tracker};
use session::{AddTorrent, Session, SessionBuilder, TorrentId, TorrentState, TransportPolicy};

fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
}

fn builder(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> SessionBuilder {
    init_log();
    Session::builder()
        .listen_port(0)
        .listen_v4(v4)
        .listen_v6(v6)
        .lsd(false)
        .dht(false)
}

fn v4(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, n)
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

fn wait_for(secs: u64, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("urt-listen-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn param(line: &str, key: &str) -> Option<String> {
    line.split('?')
        .nth(1)?
        .split(' ')
        .next()?
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(str::to_string))
}

#[test]
fn set_listen_moves_the_port_and_trackers_hear_stopped_then_started() {
    let dir = tmp("port");
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    // The tracker hands out a dead peer; it is only here to record announces.
    let announce = spawn_tracker(SocketAddr::new(v4(9).into(), 1), log.clone());
    let (bytes, data) = make_torrent("l.bin", 256 * 1024, 64 * 1024, &announce);
    std::fs::write(dir.join("l.bin"), &data).unwrap();
    let a = block_on(builder(Some(v4(1)), None).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let old_port = a.listen_port();
    assert!(wait_for(10, || {
        log.lock()
            .unwrap()
            .iter()
            .any(|l| event_param(l).as_deref() == Some("started"))
    }));

    let new_port = block_on(a.set_listen(0, Some(v4(1)), None)).unwrap();
    assert_ne!(new_port, old_port);
    assert_eq!(a.listen_port(), new_port);
    assert_eq!(block_on(a.settings()).unwrap().listen_port, new_port);
    // `stopped` on the old port, then `started` on the new one.
    assert!(wait_for(10, || {
        log.lock()
            .unwrap()
            .iter()
            .filter(|l| event_param(l).as_deref() == Some("started"))
            .count()
            >= 2
    }));
    let lines = log.lock().unwrap().clone();
    let events: Vec<(String, String)> = lines
        .iter()
        .filter_map(|l| Some((event_param(l)?, param(l, "port")?)))
        .collect();
    assert_eq!(
        events,
        vec![
            ("started".to_string(), old_port.to_string()),
            ("stopped".to_string(), old_port.to_string()),
            ("started".to_string(), new_port.to_string()),
        ],
        "{lines:?}"
    );
    // The old port is closed, the new one serves a leecher.
    assert!(
        TcpStream::connect_timeout(
            &SocketAddr::new(v4(1).into(), old_port),
            Duration::from_millis(500)
        )
        .is_err()
    );
    let b = block_on(builder(Some(v4(2)), None).build()).unwrap();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, dir.join("b")))).unwrap();
    block_on(b.add_peer(b_id, SocketAddr::new(v4(1).into(), new_port))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 30);
    // A failing bind changes nothing: the port is taken by B.
    let r = block_on(a.set_listen(b.listen_port(), Some(v4(2)), None));
    assert!(r.is_err());
    assert_eq!(a.listen_port(), new_port);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn set_listen_adds_and_removes_a_family() {
    let dir = tmp("family");
    let (bytes, data) = make_torrent("f.bin", 8 << 20, 64 * 1024, "http://127.0.0.1:1/x");
    std::fs::write(dir.join("f.bin"), &data).unwrap();
    let a = block_on(
        builder(Some(v4(1)), None)
            .transports(TransportPolicy::TcpOnly)
            .upload_limit(512 * 1024)
            .build(),
    )
    .unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    assert_eq!(block_on(a.settings()).unwrap().listen_v6, None);
    // IPv6 switched on: a v6-only leecher reaches the seeder.
    let port = block_on(a.set_listen(0, Some(v4(1)), Some(Ipv6Addr::LOCALHOST))).unwrap();
    let s = block_on(a.settings()).unwrap();
    assert_eq!(s.listen_v6, Some(Ipv6Addr::LOCALHOST));
    assert_eq!(s.listen_port, port);
    let b = block_on(
        builder(None, Some(Ipv6Addr::LOCALHOST))
            .transports(TransportPolicy::TcpOnly)
            .build(),
    )
    .unwrap();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, dir.join("b")))).unwrap();
    block_on(b.add_peer(b_id, SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port))).unwrap();
    assert!(wait_for(10, || block_on(b.status(b_id))
        .unwrap()
        .downloaded
        > 0));
    // IPv6 switched off again mid-transfer: the v6 peer is dropped and
    // cannot come back; the seeder keeps its port.
    let port2 = block_on(a.set_listen(port, Some(v4(1)), None)).unwrap();
    assert_eq!(port2, port);
    assert!(wait_for(10, || block_on(a.status(a_id)).unwrap().peers == 0));
    block_on(b.add_peer(b_id, SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port))).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(block_on(a.status(a_id)).unwrap().peers, 0);
    assert_ne!(
        block_on(b.status(b_id)).unwrap().state,
        TorrentState::Seeding
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn set_dht_starts_and_stops_the_node_keeping_its_tables() {
    let a = block_on(builder(Some(Ipv4Addr::new(127, 1, 0, 1)), None).build()).unwrap();
    let b = block_on(
        builder(Some(Ipv4Addr::new(127, 2, 0, 1)), None)
            .dht(true)
            .dht_bootstrap_nodes(Vec::new())
            .build(),
    )
    .unwrap();
    assert!(!block_on(a.settings()).unwrap().dht);
    assert_eq!(block_on(a.stats()).unwrap().dht_nodes, 0);
    block_on(a.set_dht(true)).unwrap();
    assert!(block_on(a.settings()).unwrap().dht);
    block_on(a.add_dht_node(SocketAddr::new(
        Ipv4Addr::new(127, 2, 0, 1).into(),
        b.listen_port(),
    )))
    .unwrap();
    assert!(
        wait_for(20, || block_on(a.stats()).unwrap().dht_nodes >= 1),
        "no node learned"
    );
    // Off: no node, no traffic; on again: the table comes back.
    block_on(a.set_dht(false)).unwrap();
    assert!(!block_on(a.settings()).unwrap().dht);
    assert_eq!(block_on(a.stats()).unwrap().dht_nodes, 0);
    block_on(a.set_dht(true)).unwrap();
    assert!(
        wait_for(20, || block_on(a.stats()).unwrap().dht_nodes >= 1),
        "saved table not restored"
    );
    // Idempotent.
    block_on(a.set_dht(true)).unwrap();
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn set_profile_changes_the_identity_new_connections_carry() {
    let dir = tmp("profile");
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let announce = spawn_tracker(SocketAddr::new(v4(9).into(), 1), log.clone());
    let (bytes, data) = make_torrent("p.bin", 256 * 1024, 64 * 1024, &announce);
    std::fs::write(dir.join("p.bin"), &data).unwrap();
    let a = block_on(builder(Some(v4(1)), None).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    assert!(wait_for(10, || !log.lock().unwrap().is_empty()));
    assert_eq!(block_on(a.settings()).unwrap().profile, "native");

    block_on(a.set_profile(profile::Profile::qbt_5_2_3_lt2_0_14())).unwrap();
    assert_eq!(
        block_on(a.settings()).unwrap().profile,
        "qbt_5_2_3_lt2_0_14"
    );
    assert!(wait_for(10, || {
        log.lock()
            .unwrap()
            .iter()
            .filter(|l| event_param(l).as_deref() == Some("started"))
            .count()
            >= 2
    }));
    let lines = log.lock().unwrap().clone();
    let ids: Vec<(String, String)> = lines
        .iter()
        .filter_map(|l| Some((event_param(l)?, param(l, "peer_id")?)))
        .collect();
    assert_eq!(ids.len(), 3, "{lines:?}");
    assert_eq!(ids[0].0, "started");
    assert!(ids[0].1.starts_with("-UR0E00-"), "{ids:?}");
    assert_eq!(ids[1].0, "stopped");
    assert_eq!(ids[1].1, ids[0].1, "stopped under the old id");
    assert_eq!(ids[2].0, "started");
    assert!(ids[2].1.starts_with("-qB5230-"), "{ids:?}");
    // A leecher connecting now sees the qBittorrent identity (the final
    // `PeerInfo` rides on the disconnect event once both are seeds).
    let b = block_on(builder(Some(v4(2)), None).build()).unwrap();
    let mut events = b.events();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, dir.join("b")))).unwrap();
    block_on(b.add_peer(b_id, SocketAddr::new(v4(1).into(), a.listen_port()))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 30);
    let deadline = Instant::now() + Duration::from_secs(10);
    let info = loop {
        match events.try_recv() {
            Some(session::Event::PeerDisconnected { id, info, .. }) if id == b_id => break info,
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "no PeerDisconnected");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    assert_eq!(
        info.client.as_deref(),
        Some("qBittorrent/5.2.3"),
        "{info:?}"
    );
    assert!(
        info.peer_id.is_some_and(|id| id.starts_with(b"-qB5230-")),
        "{info:?}"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
