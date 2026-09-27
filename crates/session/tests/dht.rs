// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The DHT end to end, three engines in one process: a seeder, an idle node
//! and a leecher that finds the seeder through the DHT alone (the tracker
//! URL is dead). Engines sit in distinct loopback /24s because the DHT keeps
//! one node per /24 per bucket and per lookup.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate urtorrent_session as session;

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use common::{block_on, make_torrent};
use session::{AddTorrent, Event, Session, TorrentState};

fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
}

/// An engine on `127.<n>.0.1` with the DHT bootstrapping from `routers`
/// (`Some([])` = no routers at all).
fn session_at(n: u8, routers: Vec<SocketAddr>, state: Option<Vec<u8>>) -> Session {
    init_log();
    let mut b = Session::builder()
        .listen_port(0)
        .listen_v4(Some(Ipv4Addr::new(127, n, 0, 1)))
        .listen_v6(None)
        .lsd(false)
        .dht(true)
        .dht_bootstrap_nodes(routers.iter().map(ToString::to_string).collect());
    if let Some(s) = state {
        b = b.dht_state(s);
    }
    block_on(b.build()).unwrap()
}

fn udp_addr(n: u8, s: &Session) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, n, 0, 1).into(), s.listen_port())
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
            "state {:?}, wanted {want:?}: {st:?}",
            st.state
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for(secs: u64, what: &str, mut pred: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !pred() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn leecher_finds_the_seeder_through_the_dht_only() {
    let dir = std::env::temp_dir().join(format!("urt-dht-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (torrent_bytes, data) = make_torrent("dht.bin", 300_000, 32 * 1024, "http://127.0.0.1:1/x");

    // A: the seeder, also everybody's bootstrap router.
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("dht.bin"), &data).unwrap();
    let a = session_at(1, Vec::new(), None);
    let a_udp = udp_addr(1, &a);
    // C: an idle node bootstrapped from A; it will store A's announce.
    let c = session_at(2, vec![a_udp], None);
    // A learns C through C's bootstrap query and probes it (refresh, ~5 s).
    wait_for(20, "A's table to hold C", || {
        block_on(a.stats()).unwrap().dht_nodes >= 1
    });

    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    // A announces the torrent to the DHT within a few seconds: C stores it.
    wait_for(20, "C to store A's announce", || {
        block_on(c.stats()).unwrap().dht_stored_peers >= 1
    });

    // B: the leecher. Bootstraps from A, learns C, asks C, finds A.
    let b = session_at(3, vec![a_udp], None);
    let mut events = b.events();
    let b_dir = dir.join("b");
    let b_id =
        block_on(b.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &b_dir))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    assert_eq!(std::fs::read(b_dir.join("dht.bin")).unwrap(), data);
    // The peer came from the DHT and the lookup was reported.
    let mut saw_dht_peers = false;
    let mut saw_dht_source = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !(saw_dht_peers && saw_dht_source) {
        match events.try_recv() {
            Some(Event::DhtPeers { id, peers }) if id == b_id && peers > 0 => {
                saw_dht_peers = true;
            }
            Some(Event::PeerConnected { id, .. }) if id == b_id => {
                saw_dht_source = true;
            }
            Some(_) => {}
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    assert!(saw_dht_peers, "no DhtPeers event");
    assert!(saw_dht_source, "no connection on the leecher");
    // (Two seeds part right away, so the peer lists are empty by now; the
    // `PeerConnected` event carries the source.)
    let bs = block_on(b.stats()).unwrap();
    assert!(bs.dht_nodes >= 1, "{bs:?}");

    // A private torrent is never announced: C's store does not grow.
    let stored_before = block_on(c.stats()).unwrap().dht_stored_peers;
    let (priv_bytes, priv_data) =
        make_torrent("priv.bin", 100_000, 32 * 1024, "http://127.0.0.1:1/y");
    let p_dir = dir.join("p");
    std::fs::create_dir_all(&p_dir).unwrap();
    std::fs::write(p_dir.join("priv.bin"), &priv_data).unwrap();
    let priv_torrent = private_copy(&priv_bytes);
    let p_id = block_on(a.add_torrent(AddTorrent::metainfo(priv_torrent, &p_dir))).unwrap();
    wait_state(&a, p_id, TorrentState::Seeding, 10);
    assert!(block_on(a.status(p_id)).unwrap().private);
    std::thread::sleep(Duration::from_secs(8));
    assert_eq!(block_on(c.stats()).unwrap().dht_stored_peers, stored_before);

    // Saved state brings a node up warm: a fourth engine restored from B's
    // state has nodes without ever being given a router.
    let state = block_on(b.dht_state()).unwrap().expect("dht on");
    assert!(!state.is_empty());
    let d = session_at(4, Vec::new(), Some(state));
    wait_for(20, "D to have nodes from saved state", || {
        block_on(d.stats()).unwrap().dht_nodes >= 1
    });

    block_on(d.shutdown()).unwrap();
    block_on(b.shutdown()).unwrap();
    block_on(c.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Insert `7:privatei1e` into the info dictionary (keys stay sorted: it
/// goes after `pieces`).
fn private_copy(torrent: &[u8]) -> Vec<u8> {
    let key = b"6:pieces";
    let at = torrent
        .windows(key.len())
        .position(|w| w == key)
        .expect("pieces key");
    // pieces is `6:pieces<len>:<bytes>`; find the end of the value.
    let mut i = at + key.len();
    let mut len = 0usize;
    while torrent[i] != b':' {
        len = len * 10 + usize::from(torrent[i] - b'0');
        i += 1;
    }
    let end = i + 1 + len;
    let mut out = Vec::with_capacity(torrent.len() + 12);
    out.extend_from_slice(&torrent[..end]);
    out.extend_from_slice(b"7:privatei1e");
    out.extend_from_slice(&torrent[end..]);
    out
}

/// BEP 9 + BEP 5: a magnet link with no tracker (`SHOULD use the DHT`): the
/// leecher looks the info-hash up before it has any metadata, finds the
/// seeder, fetches the metadata over `ut_metadata` and downloads.
#[test]
fn magnet_without_trackers_resolves_through_the_dht() {
    let dir = std::env::temp_dir().join(format!("urt-dht-magnet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (torrent_bytes, data) =
        make_torrent("dhtm.bin", 200_000, 32 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("dhtm.bin"), &data).unwrap();
    let a = session_at(11, Vec::new(), None);
    let a_udp = udp_addr(11, &a);
    let c = session_at(12, vec![a_udp], None);
    wait_for(20, "A's table to hold C", || {
        block_on(a.stats()).unwrap().dht_nodes >= 1
    });
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let hex = bencode::hex(&block_on(a.status(a_id)).unwrap().info_hash);
    wait_for(20, "C to store A's announce", || {
        block_on(c.stats()).unwrap().dht_stored_peers >= 1
    });

    let b = session_at(13, vec![a_udp], None);
    let mut events = b.events();
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let b_id = block_on(b.add_torrent(AddTorrent::magnet(
        format!("magnet:?xt=urn:btih:{hex}&dn=dhtm"),
        &b_dir,
    )))
    .unwrap();
    assert_eq!(
        block_on(b.status(b_id)).unwrap().state,
        TorrentState::FetchingMetadata
    );
    wait_state(&b, b_id, TorrentState::Seeding, 90);
    assert_eq!(std::fs::read(b_dir.join("dhtm.bin")).unwrap(), data);
    let mut saw_dht_peers = false;
    let mut saw_metadata = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !(saw_dht_peers && saw_metadata) {
        match events.try_recv() {
            Some(Event::DhtPeers { id, peers }) if id == b_id && peers > 0 => saw_dht_peers = true,
            Some(Event::MetadataReceived { id }) if id == b_id => saw_metadata = true,
            Some(_) => {}
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    assert!(saw_dht_peers, "no DhtPeers event for the magnet");
    assert!(saw_metadata, "no MetadataReceived event");
    block_on(b.shutdown()).unwrap();
    block_on(c.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
