// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! M6 extensions between engines in one process: magnet links over
//! `ut_metadata`, peer exchange, `upload_only`, web seeds, and the
//! private-torrent guarantee at the API level (the wire-level proof is the
//! `private_no_pex_lsd` lab scenario).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{block_on, make_torrent, spawn_range_server};
use session::{AddTorrent, Event, PeerSource, Session, TorrentState};

fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
}

/// One engine per loopback address (`127.0.0.<n>`): engines allow one
/// connection per IP, like the oracle, so three of them cannot share
/// `127.0.0.1`.
fn session_at(n: u8, lsd: bool) -> Session {
    init_log();
    block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::new(127, 0, 0, n)))
            .listen_v6(None)
            .lsd(lsd)
            .dht(false)
            .build(),
    )
    .unwrap()
}

fn session(lsd: bool) -> Session {
    session_at(1, lsd)
}

/// The listen endpoint of an engine built with `session_at(1, ..)` /
/// `session(..)` (all seeders in these tests live on `127.0.0.1`).
fn addr_of(s: &Session) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), s.listen_port())
}

fn wait_state(
    s: &Session,
    id: session::TorrentId,
    want: TorrentState,
    secs: u64,
) -> session::TorrentStatus {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let st = block_on(s.status(id)).unwrap();
        if st.state == want {
            return st;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {want:?}; now {st:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Collect events until `pred` matches one or `secs` elapse.
fn wait_event(
    ev: &mut session::EventStream,
    secs: u64,
    pred: impl Fn(&Event) -> bool,
) -> Option<Event> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Some(e) = ev.try_recv() {
            if pred(&e) {
                return Some(e);
            }
            continue;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

fn seed_dir(dir: &Path, name: &str, data: &[u8]) -> std::path::PathBuf {
    let d = dir.join(name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("ext.bin"), data).unwrap();
    d
}

/// A seeds from disk; B adds only a magnet link with A as a manual peer,
/// fetches the metadata over `ut_metadata` and downloads. Once B is complete
/// it tells A it is upload-only and the two seeds part.
#[test]
fn magnet_fetches_metadata_and_downloads() {
    let dir = std::env::temp_dir().join(format!("urt-ext-magnet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let size = 600 * 1024 + 13; // 10 pieces of 64 KiB
    let piece_len = 64 * 1024;
    let (torrent_bytes, data) = make_torrent("ext.bin", size, piece_len, "http://127.0.0.1:1/x");
    let a_dir = seed_dir(&dir, "a", &data);
    let a = session(false);
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    let st = wait_state(&a, a_id, TorrentState::Seeding, 10);
    assert_eq!(st.pieces_have, 10);
    let hex = bencode::hex(&st.info_hash);

    let b = session(false);
    let mut b_events = b.events();
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let b_id = block_on(b.add_torrent(AddTorrent::magnet(
        format!("magnet:?xt=urn:btih:{hex}&dn=ext"),
        &b_dir,
    )))
    .unwrap();
    assert_eq!(
        block_on(b.status(b_id)).unwrap().state,
        TorrentState::FetchingMetadata
    );
    block_on(b.add_peer(b_id, addr_of(&a))).unwrap();
    let got = wait_event(&mut b_events, 20, |e| {
        matches!(e, Event::MetadataReceived { .. })
    });
    assert!(got.is_some(), "metadata never arrived");
    let st = wait_state(&b, b_id, TorrentState::Seeding, 30);
    assert!(st.has_metadata);
    assert_eq!(st.name, "ext.bin");
    assert_eq!(st.pieces_total, 10);
    assert_eq!(st.total_size, size as u64);
    assert_eq!(st.downloaded, size as u64);
    assert_eq!(std::fs::read(b_dir.join("ext.bin")).unwrap(), data);
    // Two seeds have nothing to exchange: the connection goes away, and the
    // reason is BEP 21 / both seeds.
    let gone = wait_event(&mut b_events, 10, |e| {
        matches!(e, Event::PeerDisconnected { .. })
    });
    match gone {
        Some(Event::PeerDisconnected { reason, info, .. }) => {
            assert!(
                reason.contains("seeds")
                    || reason.contains("upload-only")
                    || reason.contains("closed"),
                "unexpected reason {reason}"
            );
            assert_eq!(info.source, PeerSource::Manual);
            assert!(info.is_seed);
        }
        other => panic!("expected disconnect, got {other:?}"),
    }
    block_on(a.shutdown()).unwrap();
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A seeds; B and C know only A. A's first `ut_pex` (sent once it has two
/// peers) introduces B and C to each other, and one of them connects to the
/// other with `PeerSource::Pex`.
#[test]
fn pex_introduces_peers() {
    let dir = std::env::temp_dir().join(format!("urt-ext-pex-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let size = 1024 * 1024;
    let piece_len = 64 * 1024;
    let (torrent_bytes, data) = make_torrent("ext.bin", size, piece_len, "http://127.0.0.1:1/x");
    let a_dir = seed_dir(&dir, "a", &data);
    // Slow A down so B and C stay leechers long enough to be introduced (the
    // PEX message queues behind at most one upload backlog, ~2 s here).
    init_log();
    let a = block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::LOCALHOST))
            .listen_v6(None)
            .lsd(false)
            .dht(false)
            .upload_limit(128 * 1024)
            .build(),
    )
    .unwrap();
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    let b = session_at(2, false);
    let c = session_at(3, false);
    let mut b_events = b.events();
    let mut c_events = c.events();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), dir.join("b"))))
        .unwrap();
    let c_id = block_on(c.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), dir.join("c"))))
        .unwrap();
    wait_state(&b, b_id, TorrentState::Downloading, 10);
    wait_state(&c, c_id, TorrentState::Downloading, 10);
    block_on(b.add_peer(b_id, addr_of(&a))).unwrap();
    block_on(c.add_peer(c_id, addr_of(&a))).unwrap();
    let b_pex = wait_event(&mut b_events, 15, |e| matches!(e, Event::PexPeers { .. }));
    let c_pex = wait_event(&mut c_events, 15, |e| matches!(e, Event::PexPeers { .. }));
    assert!(
        b_pex.is_some() && c_pex.is_some(),
        "no PEX received: {b_pex:?} {c_pex:?}"
    );
    // One side dials the other (both may; one connection per IP survives).
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut via_pex = false;
    while Instant::now() < deadline && !via_pex {
        for (s, id) in [(&b, b_id), (&c, c_id)] {
            let peers = block_on(s.peers(id)).unwrap();
            if peers.iter().any(|p| p.source == PeerSource::Pex) {
                via_pex = true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(via_pex, "no connection learned through PEX");
    // Everyone finishes.
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    wait_state(&c, c_id, TorrentState::Seeding, 60);
    assert_eq!(std::fs::read(dir.join("b").join("ext.bin")).unwrap(), data);
    assert_eq!(std::fs::read(dir.join("c").join("ext.bin")).unwrap(), data);
    block_on(a.shutdown()).unwrap();
    block_on(b.shutdown()).unwrap();
    block_on(c.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same three-engine setup with a private torrent: nobody receives PEX,
/// and B never learns about C.
#[test]
fn private_torrent_exchanges_no_peers() {
    let dir = std::env::temp_dir().join(format!("urt-ext-private-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let size = 128 * 1024;
    let piece_len = 32 * 1024;
    let (torrent_bytes, data) = make_private_torrent(size, piece_len);
    let a_dir = seed_dir(&dir, "a", &data);
    let a = session(false);
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    let st = wait_state(&a, a_id, TorrentState::Seeding, 10);
    assert!(st.private);
    let b = session_at(2, false);
    let c = session_at(3, false);
    let mut b_events = b.events();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), dir.join("b"))))
        .unwrap();
    let c_id = block_on(c.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), dir.join("c"))))
        .unwrap();
    block_on(b.add_peer(b_id, addr_of(&a))).unwrap();
    block_on(c.add_peer(c_id, addr_of(&a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 30);
    wait_state(&c, c_id, TorrentState::Seeding, 30);
    // Give a PEX round every chance, then check nothing happened.
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        wait_event(&mut b_events, 1, |e| matches!(
            e,
            Event::PexPeers { .. } | Event::LsdPeer { .. }
        ))
        .is_none(),
        "private torrent saw peer exchange"
    );
    let b_peers = block_on(b.peers(b_id)).unwrap();
    assert!(b_peers.iter().all(|p| p.source != PeerSource::Pex));
    block_on(a.shutdown()).unwrap();
    block_on(b.shutdown()).unwrap();
    block_on(c.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

fn make_private_torrent(size: usize, piece_len: usize) -> (Vec<u8>, Vec<u8>) {
    let (t, data) = make_torrent("ext.bin", size, piece_len, "http://127.0.0.1:1/x");
    // Insert `7:privatei1e` before the closing `e` of the info dict (sorted
    // after `pieces`).
    let mut t = t;
    let end = t.len() - 2; // "e" of info, "e" of root
    t.splice(end..end, b"7:privatei1e".iter().copied());
    (t, data)
}

/// A torrent with a `url-list` and no peers completes from the web seed
/// alone (BEP 19), over HTTP `Range` requests to a tiny std server.
#[test]
fn web_seed_only() {
    let dir = std::env::temp_dir().join(format!("urt-ext-webseed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let size = 1024 * 1024 + 4321; // 17 pieces of 64 KiB
    let piece_len = 64 * 1024;
    let (torrent_bytes, data) = make_torrent("ext.bin", size, piece_len, "http://127.0.0.1:1/x");
    let data = Arc::new(data);
    let (url, hits) = spawn_range_server(data.clone(), "/files/ext.bin");
    // Add `url-list` to the torrent (root dict is sorted: `announce`, `info`,
    // `url-list`).
    let mut t = torrent_bytes.clone();
    t.pop(); // root 'e'
    t.extend_from_slice(format!("8:url-list{}:{}", url.len(), url).as_bytes());
    t.push(b'e');
    let b = session(false);
    let mut events = b.events();
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let id = block_on(b.add_torrent(AddTorrent::metainfo(t, &b_dir))).unwrap();
    assert_eq!(block_on(b.status(id)).unwrap().web_seeds, 1);
    let st = wait_state(&b, id, TorrentState::Seeding, 60);
    assert_eq!(st.downloaded, size as u64);
    assert_eq!(st.peers, 0);
    assert_eq!(std::fs::read(b_dir.join("ext.bin")).unwrap(), *data);
    assert!(
        hits.load(std::sync::atomic::Ordering::Relaxed) >= 2,
        "expected several range requests"
    );
    assert!(wait_event(&mut events, 1, |e| matches!(e, Event::WebSeedError { .. })).is_none());
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// BEP 9 `x.pe` and BEP 53 `so=` in a magnet link: the peer named in the
/// link is dialled without any tracker or manual `add_peer`, the metadata
/// arrives, and only the selected file is downloaded.
#[test]
fn magnet_peer_hint_and_select_only() {
    let dir = std::env::temp_dir().join(format!("urt-ext-so-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let files = [
        ("a.bin", 200_000usize),
        ("b.bin", 300_000),
        ("c.bin", 150_000),
    ];
    let (torrent_bytes, data) =
        common::make_multi_torrent("so", &files, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(a_dir.join("so")).unwrap();
    std::fs::write(a_dir.join("so/a.bin"), &data[..200_000]).unwrap();
    std::fs::write(a_dir.join("so/b.bin"), &data[200_000..500_000]).unwrap();
    std::fs::write(a_dir.join("so/c.bin"), &data[500_000..]).unwrap();
    let a = session(false);
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    let st = wait_state(&a, a_id, TorrentState::Seeding, 10);
    let hex = bencode::hex(&st.info_hash);

    let b = session_at(2, false);
    let mut b_events = b.events();
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let uri = format!(
        "magnet:?xt=urn:btih:{hex}&dn=so&so=2&x.pe=127.0.0.1%3A{}",
        a.listen_port()
    );
    let b_id = block_on(b.add_torrent(AddTorrent::magnet(uri, &b_dir))).unwrap();
    assert!(
        wait_event(&mut b_events, 20, |e| matches!(
            e,
            Event::MetadataReceived { .. }
        ))
        .is_some(),
        "metadata never arrived through the x.pe peer"
    );
    assert!(
        wait_event(&mut b_events, 30, |e| matches!(
            e,
            Event::TorrentFinished { .. }
        ))
        .is_some(),
        "selected file never finished"
    );
    let st = block_on(b.status(b_id)).unwrap();
    let prios: Vec<u8> = st.files.iter().map(|f| f.priority).collect();
    assert_eq!(prios, vec![0, 0, 4], "{:?}", st.files);
    assert_eq!(
        std::fs::read(b_dir.join("so/c.bin")).unwrap(),
        &data[500_000..]
    );
    assert_eq!(st.files[0].done, 0);
    // b.bin only gets the tail of the piece it shares with c.bin.
    assert!(st.files[1].done < 64 * 1024, "{:?}", st.files);
    assert_eq!(st.files[2].done, 150_000);
    // Two upload-only peers part; the x.pe peer shows as a manual one.
    let parted = wait_event(
        &mut b_events,
        10,
        |e| matches!(e, Event::PeerDisconnected { info, .. } if info.source == PeerSource::Manual),
    );
    assert!(
        parted.is_some(),
        "the x.pe peer should be recorded as a manual peer"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
