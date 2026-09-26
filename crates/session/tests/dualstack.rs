// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Dual-stack edge cases between engines in one process (AGENTS.md 5.5):
//! a peer reached over both families keeps exactly one connection, an
//! engine without a family never dials that family's addresses, and
//! v4-mapped IPv6 addresses are normalised to the IPv4 peer they name.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use std::io::{Read, Write};
use std::net::TcpListener;

use common::{block_on, make_torrent};
use session::{AddTorrent, Event, Session, SessionBuilder, TorrentId, TorrentState};

fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
}

fn builder(v4: Option<u8>, v6: bool) -> SessionBuilder {
    init_log();
    Session::builder()
        .listen_port(0)
        .listen_v4(v4.map(|n| Ipv4Addr::new(127, 0, 0, n)))
        .listen_v6(v6.then_some(Ipv6Addr::LOCALHOST))
        .lsd(false)
        .dht(false)
}

fn v4(n: u8, s: &Session) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, 0, 0, n).into(), s.listen_port())
}

fn v6(s: &Session) -> SocketAddr {
    SocketAddr::new(Ipv6Addr::LOCALHOST.into(), s.listen_port())
}

fn mapped(n: u8, s: &Session) -> SocketAddr {
    SocketAddr::new(
        Ipv4Addr::new(127, 0, 0, n).to_ipv6_mapped().into(),
        s.listen_port(),
    )
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

struct Fixture {
    dir: PathBuf,
    torrent: Vec<u8>,
    data: Vec<u8>,
}

impl Fixture {
    fn new(tag: &str, size: usize) -> Fixture {
        Fixture::with_announce(tag, size, "http://127.0.0.1:1/x")
    }

    fn with_announce(tag: &str, size: usize, announce: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("urt-dual-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (torrent, data) = make_torrent("dual.bin", size, 64 * 1024, announce);
        Fixture { dir, torrent, data }
    }

    fn seed(&self, s: &Session) -> TorrentId {
        let d = self.dir.join("a");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("dual.bin"), &self.data).unwrap();
        let id = block_on(s.add_torrent(AddTorrent::metainfo(self.torrent.clone(), &d))).unwrap();
        wait_state(s, id, TorrentState::Seeding, 10);
        id
    }

    fn leech(&self, s: &Session) -> TorrentId {
        block_on(s.add_torrent(AddTorrent::metainfo(
            self.torrent.clone(),
            self.dir.join("b"),
        )))
        .unwrap()
    }

    fn check_leeched(&self) {
        assert_eq!(
            std::fs::read(self.dir.join("b").join("dual.bin")).unwrap(),
            self.data
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An HTTP tracker on 127.0.0.1 answering every announce with the given
/// `peers` (compact IPv4) and `peers6` (compact IPv6) lists.
fn spawn_tracker(peers: Vec<SocketAddr>, peers6: Vec<SocketAddr>) -> String {
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
            let mut body = b"d8:intervali1800e5:peers".to_vec();
            body.extend_from_slice(format!("{}:", peers.len() * 6).as_bytes());
            for p in &peers {
                let IpAddr::V4(ip) = p.ip() else {
                    unreachable!()
                };
                body.extend_from_slice(&ip.octets());
                body.extend_from_slice(&p.port().to_be_bytes());
            }
            body.extend_from_slice(b"6:peers6");
            body.extend_from_slice(format!("{}:", peers6.len() * 18).as_bytes());
            for p in &peers6 {
                let IpAddr::V6(ip) = p.ip() else {
                    unreachable!()
                };
                body.extend_from_slice(&ip.octets());
                body.extend_from_slice(&p.port().to_be_bytes());
            }
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

/// Replay `ev` up to `TorrentFinished` for `id`: the connections live at
/// that moment and every disconnect reason seen before it.
fn live_at_finish(ev: &mut session::EventStream, id: TorrentId) -> (Vec<SocketAddr>, Vec<String>) {
    live_at_finish_from(ev, id, Vec::new())
}

/// [`live_at_finish`] with `live` already connected.
fn live_at_finish_from(
    ev: &mut session::EventStream,
    id: TorrentId,
    mut live: Vec<SocketAddr>,
) -> (Vec<SocketAddr>, Vec<String>) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut reasons = Vec::new();
    loop {
        match ev.try_recv() {
            Some(Event::PeerConnected { id: i, addr, .. }) if i == id => live.push(addr),
            Some(Event::PeerDisconnected {
                id: i,
                addr,
                reason,
                ..
            }) if i == id => {
                live.retain(|a| *a != addr);
                reasons.push(format!("{addr}: {reason}"));
            }
            Some(Event::TorrentFinished { id: i }) if i == id => return (live, reasons),
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "no TorrentFinished; {reasons:?}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Whether a disconnect reason is the dialling side's view of a duplicate
/// being dropped: its own verdict, or the other end's close arriving first,
/// as a FIN or, when that end closed with our requests still unread in its
/// receive buffer, as a reset.
fn dropped_as_duplicate(reason: &str) -> bool {
    reason.ends_with("duplicate peer id")
        || reason.ends_with("peer closed the connection")
        || reason.ends_with("Connection reset by peer (os error 104)")
}

/// Wait for `id`'s `PeerConnected` from `ip`, dropping the events before
/// it; the connection's address.
fn wait_connected(ev: &mut session::EventStream, id: TorrentId, ip: IpAddr) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match ev.try_recv() {
            Some(Event::PeerConnected { id: i, addr, .. }) if i == id && addr.ip() == ip => {
                return addr;
            }
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "no connection from {ip}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

#[test]
fn peer_dialled_over_both_families_keeps_one_connection() {
    // A: 127.0.0.1 + ::1, B: 127.0.0.2 + ::1 (same listen port on both of
    // each engine's addresses). B learns both of A's addresses: the IPv4
    // connection is up on both ends before B dials IPv6, so both ends see
    // the IPv6 handshake as the newcomer and close the IPv4 connection
    // (`..._at_once` below leaves the order to the scheduler). B's download
    // is rate limited so the IPv6 connection comes before the end.
    let a = block_on(builder(Some(1), true).build()).unwrap();
    let b = block_on(builder(Some(2), true).download_limit(2 << 20).build()).unwrap();
    let fx = Fixture::new("both", 4 << 20);
    let a_id = fx.seed(&a);
    let mut a_events = a.events();
    let mut b_events = b.events();
    let b_id = fx.leech(&b);
    block_on(b.add_peer(b_id, v4(1, &a))).unwrap();
    let b_v4 = wait_connected(&mut b_events, b_id, v4(1, &a).ip());
    wait_connected(&mut a_events, a_id, Ipv4Addr::new(127, 0, 0, 2).into());
    block_on(b.add_peer(b_id, v6(&a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    fx.check_leeched();

    // Both ends keep the IPv6 connection (same peer id over both families,
    // both dialled by B), and the other one went as a duplicate, not as an
    // error (B may see A's close first).
    let (b_live, b_reasons) = live_at_finish_from(&mut b_events, b_id, vec![b_v4]);
    assert_eq!(b_live, vec![v6(&a)], "B live at finish; {b_reasons:?}");
    assert_eq!(b_reasons.len(), 1, "{b_reasons:?}");
    assert!(
        b_reasons[0].starts_with(&format!("{}: ", v4(1, &a)))
            && dropped_as_duplicate(&b_reasons[0]),
        "{b_reasons:?}"
    );
    // A's side: the incoming v6 connection from B survives.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut a_live: Vec<SocketAddr> = Vec::new();
    let mut a_reasons = Vec::new();
    loop {
        match a_events.try_recv() {
            Some(Event::PeerConnected { id, addr, .. }) if id == a_id => a_live.push(addr),
            Some(Event::PeerDisconnected {
                id, addr, reason, ..
            }) if id == a_id => {
                a_live.retain(|x| *x != addr);
                a_reasons.push(format!("{addr}: {reason}"));
            }
            Some(_) => {}
            None => {
                if a_reasons.iter().any(|r| r.ends_with("both seeds")) || Instant::now() > deadline
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    assert!(
        a_reasons
            .iter()
            .any(|r| r.starts_with("127.0.0.2:") && r.ends_with("duplicate peer id")),
        "A dropped B's v4 connection as the duplicate; {a_reasons:?}"
    );
    assert!(
        a_reasons
            .iter()
            .any(|r| r.starts_with("[::1]:") && r.ends_with("both seeds")),
        "A's v6 connection lived until B finished; {a_reasons:?}"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn peer_dialled_over_both_families_at_once_keeps_one_connection() {
    // As above with both dials at once: each end may see either handshake
    // first, and the two ends may disagree on the order (docs/quirks.md
    // Q25). A connection refused at its handshake was never reported
    // connected, so it reports no disconnect either. Whatever the order,
    // both ends keep the IPv6 connection and drop the IPv4 one only as a
    // duplicate.
    let a = block_on(builder(Some(1), true).build()).unwrap();
    let b = block_on(builder(Some(2), true).build()).unwrap();
    let fx = Fixture::new("both-at-once", 4 << 20);
    let a_id = fx.seed(&a);
    let mut a_events = a.events();
    let mut b_events = b.events();
    let b_id = fx.leech(&b);
    block_on(b.add_peer(b_id, v4(1, &a))).unwrap();
    block_on(b.add_peer(b_id, v6(&a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    fx.check_leeched();

    let (b_live, b_reasons) = live_at_finish(&mut b_events, b_id);
    assert_eq!(b_live, vec![v6(&a)], "B live at finish; {b_reasons:?}");
    assert!(
        b_reasons.len() <= 1
            && b_reasons
                .iter()
                .all(|r| r.starts_with(&format!("{}: ", v4(1, &a))) && dropped_as_duplicate(r)),
        "{b_reasons:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut a_reasons = Vec::new();
    while !a_reasons.iter().any(|r: &String| r.ends_with("both seeds")) {
        match a_events.try_recv() {
            Some(Event::PeerDisconnected {
                id, addr, reason, ..
            }) if id == a_id => a_reasons.push(format!("{addr}: {reason}")),
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "A: {a_reasons:?}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    // A's IPv6 connection lived until B finished; its IPv4 one, if it was
    // ever reported, went as the duplicate.
    assert!(
        a_reasons.iter().all(|r| {
            (r.starts_with("[::1]:") && r.ends_with("both seeds"))
                || (r.starts_with("127.0.0.2:") && r.ends_with("duplicate peer id"))
        }) && a_reasons
            .iter()
            .filter(|r| r.ends_with("both seeds"))
            .count()
            == 1,
        "{a_reasons:?}"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn v4_only_engine_skips_v6_candidates_and_unmaps_v4_mapped_ones() {
    let a = block_on(builder(Some(1), true).build()).unwrap();
    let b = block_on(builder(Some(2), false).build()).unwrap();
    let fx = Fixture::new("v4only", 1 << 20);
    let a_id = fx.seed(&a);
    let b_id = fx.leech(&b);
    // No IPv6 socket: a v6 candidate is dropped, never dialled (a dial from
    // no local address might even succeed on loopback, but the engine has
    // no v6 identity to speak from).
    block_on(b.add_peer(b_id, v6(&a))).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(block_on(b.peers(b_id)).unwrap().is_empty());
    assert_eq!(block_on(b.stats()).unwrap().connections, 0);
    assert_eq!(block_on(a.stats()).unwrap().connections, 0);
    // `::ffff:127.0.0.1` names the IPv4 peer: dialled over IPv4.
    block_on(b.add_peer(b_id, mapped(1, &a))).unwrap();
    let mut events = b.events();
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    fx.check_leeched();
    let deadline = Instant::now() + Duration::from_secs(10);
    let seen = loop {
        match events.try_recv() {
            Some(Event::PeerDisconnected { id, info, .. }) if id == b_id => break info.addr,
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "no PeerDisconnected");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    assert_eq!(seen, v4(1, &a), "the peer is known by its IPv4 address");
    let _ = a_id;
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn v6_only_engine_skips_v4_candidates_including_mapped_ones() {
    let a = block_on(builder(Some(1), true).build()).unwrap();
    let b = block_on(builder(None, true).build()).unwrap();
    let fx = Fixture::new("v6only", 1 << 20);
    let _a_id = fx.seed(&a);
    let b_id = fx.leech(&b);
    block_on(b.add_peer(b_id, v4(1, &a))).unwrap();
    block_on(b.add_peer(b_id, mapped(1, &a))).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(block_on(b.peers(b_id)).unwrap().is_empty());
    assert_eq!(block_on(b.stats()).unwrap().connections, 0);
    block_on(b.add_peer(b_id, v6(&a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    fx.check_leeched();
    let st = block_on(b.stats()).unwrap();
    assert_eq!(st.downloaded, 1 << 20);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn incoming_and_outgoing_over_different_families_keep_one_connection() {
    // A dials B over IPv4 while B dials A over IPv6 (a swarm where each
    // learned the other from a different family's announce): the same peer
    // id arrives on an incoming and an outgoing connection, and
    // libtorrent's rule (the greater peer id initiates) picks the survivor
    // identically on both ends.
    let a = block_on(builder(Some(1), true).build()).unwrap();
    let b = block_on(builder(Some(2), true).build()).unwrap();
    let fx = Fixture::new("cross", 4 << 20);
    let a_id = fx.seed(&a);
    let mut b_events = b.events();
    let b_id = fx.leech(&b);
    block_on(a.add_peer(a_id, v4(2, &b))).unwrap();
    block_on(b.add_peer(b_id, v6(&a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    fx.check_leeched();
    let (b_live, b_reasons) = live_at_finish(&mut b_events, b_id);
    assert_eq!(
        b_live.len(),
        1,
        "B live at finish: {b_live:?}; {b_reasons:?}"
    );
    assert!(
        b_reasons.len() <= 1 && b_reasons.iter().all(|r| dropped_as_duplicate(r)),
        "{b_reasons:?}"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn tracker_peers_and_peers6_naming_one_seeder_yield_one_connection() {
    // The tracker lists the seeder under both families, plus its IPv4
    // address v4-mapped in `peers6` (some trackers do): B dials v4 and v6
    // once each, the mapped entry is the v4 peer it already knows, and one
    // connection survives.
    let a = block_on(builder(Some(1), true).build()).unwrap();
    let a_port = a.listen_port();
    let announce = spawn_tracker(
        vec![v4(1, &a)],
        vec![
            v6(&a),
            SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped().into(), a_port),
        ],
    );
    let fx = Fixture::with_announce("tracker", 4 << 20, &announce);
    let _a_id = fx.seed(&a);
    let b = block_on(builder(Some(2), true).build()).unwrap();
    let mut b_events = b.events();
    let b_id = fx.leech(&b);
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    fx.check_leeched();
    let (live, reasons) = live_at_finish(&mut b_events, b_id);
    assert_eq!(live, vec![v6(&a)], "{reasons:?}");
    assert!(
        reasons.len() <= 1
            && reasons
                .iter()
                .all(|r| r.starts_with(&format!("{}: ", v4(1, &a))) && dropped_as_duplicate(r)),
        "{reasons:?}"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}
