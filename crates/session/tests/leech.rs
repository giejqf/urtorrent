// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! End-to-end inside one process: the engine leeches a generated torrent from
//! a std-thread seeder (driven by the sans-IO `wire::Connection`) discovered
//! through a tiny HTTP tracker. Asserts the file, the truthful counters, and
//! the `started` / `completed` / `stopped` announce sequence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate urtorrent_session as session;

mod common;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{block_on, event_param, make_torrent, spawn_seeder, spawn_tracker};
use session::{AddTorrent, Event, Session, TorrentState};

#[test]
fn leech_from_seeder_via_tracker() {
    let dir = std::env::temp_dir().join(format!("urt-session-leech-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let size = 3 * 64 * 1024 + 12_345; // 4 pieces, short last one
    let piece_len = 64 * 1024;
    let (torrent_bytes, data) = make_torrent("leech.bin", size, piece_len, "http://placeholder/");
    let meta = metainfo::Torrent::parse(&torrent_bytes).unwrap();
    let data = Arc::new(data);
    let seeder = spawn_seeder(meta.info.info_hash, data.clone(), piece_len);
    let log = Arc::new(Mutex::new(Vec::new()));
    let announce = spawn_tracker(seeder, log.clone());
    let (torrent_bytes, _) = make_torrent("leech.bin", size, piece_len, &announce);

    let session = block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::LOCALHOST))
            .listen_v6(None)
            .dht(false)
            .profile(profile::Profile::qbt_5_2_3_lt2_0_14())
            .build(),
    )
    .expect("engine up (io_uring required)");
    assert_ne!(session.listen_port(), 0);
    let mut events = session.events();
    let id = block_on(
        session.add_torrent(
            AddTorrent::metainfo(torrent_bytes.clone(), dir.join("save"))
                .resume_dir(dir.join("resume")),
        ),
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut finished = false;
    let mut pieces = 0;
    while Instant::now() < deadline && !finished {
        match block_on(events.recv()) {
            Some(Event::PieceFinished { .. }) => pieces += 1,
            Some(Event::TorrentFinished { id: fid }) => {
                assert_eq!(fid, id);
                finished = true;
            }
            Some(Event::TorrentError { error, .. }) => panic!("torrent error: {error}"),
            Some(Event::HashFailed { piece, .. }) => panic!("hash failed on piece {piece}"),
            Some(_) => {}
            None => panic!("event stream closed"),
        }
    }
    assert!(
        finished,
        "download did not finish; log = {:?}",
        log.lock().unwrap()
    );
    assert_eq!(pieces, 4);

    let st = block_on(session.status(id)).unwrap();
    assert_eq!(st.state, TorrentState::Seeding);
    assert_eq!(st.pieces_have, 4);
    assert_eq!(st.left, 0);
    assert_eq!(
        st.downloaded, size as u64,
        "downloaded counts exactly the payload"
    );
    assert_eq!(st.uploaded, 0);
    assert_eq!(st.corrupt, 0);
    assert!(st.complete);
    let on_disk = std::fs::read(dir.join("save").join("leech.bin")).unwrap();
    assert_eq!(on_disk.len(), data.len());
    assert!(on_disk == *data, "file contents differ");

    let peers = block_on(session.peers(id)).unwrap();
    assert!(peers.iter().all(|p| p.downloaded > 0));

    // Wait for the `completed` announce to be logged, then shut down.
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(10)
        && !log
            .lock()
            .unwrap()
            .iter()
            .any(|l| event_param(l) == Some("completed".into()))
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    block_on(session.shutdown()).unwrap();

    let lines = log.lock().unwrap().clone();
    let events: Vec<Option<String>> = lines.iter().map(|l| event_param(l)).collect();
    assert_eq!(
        events,
        vec![
            Some("started".into()),
            Some("completed".into()),
            Some("stopped".into())
        ],
        "announce sequence: {lines:?}"
    );
    // The identity and wire shape come from the profile.
    assert!(lines[0].contains("peer_id=-qB5230-"));
    assert!(
        lines[0].contains("&left=")
            && lines[0].contains("&compact=1&no_peer_id=1&supportcrypto=1&redundant=0")
    );
    // `stopped` is truthful: downloaded = size, left = 0, numwant = 0.
    assert!(lines[2].contains(&format!("downloaded={size}&left=0")));
    assert!(lines[2].contains("numwant=0"));
    // Resume data was written and is complete.
    let resume_files: Vec<_> = std::fs::read_dir(dir.join("resume")).unwrap().collect();
    assert_eq!(resume_files.len(), 1);
    let rd = storage::ResumeData::load(&resume_files[0].as_ref().unwrap().path())
        .unwrap()
        .unwrap();
    assert!(rd.have.is_complete());
    assert_eq!(rd.downloaded, size as u64);

    // Restart with the same save/resume dirs: trusted resume data, no
    // download, counters carried over, seeding right away.
    let session = block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::LOCALHOST))
            .listen_v6(None)
            .dht(false)
            .build(),
    )
    .unwrap();
    let id = block_on(
        session.add_torrent(
            AddTorrent::metainfo(torrent_bytes.clone(), dir.join("save"))
                .resume_dir(dir.join("resume")),
        ),
    )
    .unwrap();
    let st = block_on(session.status(id)).unwrap();
    assert_eq!(st.state, TorrentState::Seeding);
    assert_eq!(st.pieces_have, 4);
    assert_eq!(st.downloaded, size as u64);
    block_on(session.shutdown()).unwrap();

    // Delete the content: the resume data must not be trusted any more
    // (never claim pieces we do not have). The torrent reports the missing
    // content (libtorrent's rejected fast resume) instead of starting over.
    std::fs::remove_file(dir.join("save").join("leech.bin")).unwrap();
    let session = block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::LOCALHOST))
            .listen_v6(None)
            .dht(false)
            .build(),
    )
    .unwrap();
    let id = block_on(
        session.add_torrent(
            AddTorrent::metainfo(torrent_bytes, dir.join("save"))
                .resume_dir(dir.join("resume"))
                .paused(true),
        ),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let st = loop {
        let st = block_on(session.status(id)).unwrap();
        if st.state != TorrentState::Checking || Instant::now() > deadline {
            break st;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(st.state, TorrentState::Error, "{st:?}");
    assert_eq!(st.error_kind, Some(session::ErrorKind::ContentMissing));
    assert_eq!(st.pieces_have, 0);
    assert_eq!(st.left, size as u64);
    assert!(!dir.join("save").join("leech.bin").exists());
    block_on(session.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn add_twice_is_duplicate_and_magnets_wait_for_metadata() {
    let dir = std::env::temp_dir().join(format!("urt-session-dup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (torrent_bytes, _) = make_torrent("dup.bin", 1000, 16384, "http://127.0.0.1:1/announce");
    let session = block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::LOCALHOST))
            .listen_v6(None)
            .dht(false)
            .build(),
    )
    .unwrap();
    let id =
        block_on(session.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &dir))).unwrap();
    assert_eq!(
        block_on(session.add_torrent(AddTorrent::metainfo(torrent_bytes, &dir))),
        Err(session::Error::Duplicate)
    );
    // A magnet for the same info-hash is the same torrent.
    let hex = bencode::hex(&block_on(session.status(id)).unwrap().info_hash);
    assert_eq!(
        block_on(session.add_torrent(AddTorrent::magnet(
            format!("magnet:?xt=urn:btih:{hex}"),
            &dir
        ))),
        Err(session::Error::Duplicate)
    );
    assert!(matches!(
        block_on(session.add_torrent(AddTorrent::magnet("magnet:?dn=nohash", &dir))),
        Err(session::Error::Metainfo(_))
    ));
    // A fresh magnet is accepted and waits for its metadata (BEP 9); until
    // then the size is unknown and `left` is libtorrent's 16 KiB placeholder
    // (docs/quirks.md Q12).
    let magnet = block_on(session.add_torrent(AddTorrent::magnet(
        "magnet:?xt=urn:btih:0102030405060708090a0b0c0d0e0f1011121314&dn=later&tr=http://127.0.0.1:1/announce",
        &dir,
    )))
    .unwrap();
    let ms = block_on(session.status(magnet)).unwrap();
    assert_eq!(ms.state, TorrentState::FetchingMetadata);
    assert!(!ms.has_metadata);
    assert_eq!(ms.name, "later");
    assert_eq!(ms.pieces_total, 0);
    assert_eq!(ms.left, 16 * 1024);
    assert_eq!(ms.trackers.len(), 1);
    block_on(session.remove_torrent(magnet)).unwrap();
    let st = block_on(session.status(id)).unwrap();
    assert_eq!(st.state, TorrentState::Downloading);
    assert_eq!(st.pieces_total, 1);
    block_on(session.pause(id)).unwrap();
    assert_eq!(
        block_on(session.status(id)).unwrap().state,
        TorrentState::Paused
    );
    block_on(session.resume(id)).unwrap();
    assert_eq!(
        block_on(session.status(id)).unwrap().state,
        TorrentState::Downloading
    );
    block_on(session.remove_torrent(id)).unwrap();
    assert_eq!(
        block_on(session.status(id)),
        Err(session::Error::NoSuchTorrent)
    );
    block_on(session.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// L1 lifetime: under the qbt profile every torrent announces its own peer
/// id (as libtorrent does); the native profile uses one per session.
#[test]
fn peer_id_lifetime_follows_the_profile() {
    let dir = std::env::temp_dir().join(format!("urt-session-pid-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (profile, distinct) in [
        (profile::Profile::qbt_5_2_3_lt2_0_14(), true),
        (profile::Profile::native(), false),
    ] {
        let log = Arc::new(Mutex::new(Vec::new()));
        let announce = spawn_tracker("127.0.0.1:1".parse().unwrap(), log.clone());
        let session = block_on(
            Session::builder()
                .listen_port(0)
                .listen_v4(Some(Ipv4Addr::LOCALHOST))
                .listen_v6(None)
                .dht(false)
                .profile(profile.clone())
                .build(),
        )
        .unwrap();
        let (a, _) = make_torrent("a.bin", 5000, 16384, &announce);
        let (b, _) = make_torrent("b.bin", 6000, 16384, &announce);
        block_on(session.add_torrent(AddTorrent::metainfo(a, dir.join(profile.name)))).unwrap();
        block_on(session.add_torrent(AddTorrent::metainfo(b, dir.join(profile.name)))).unwrap();
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(10) && log.lock().unwrap().len() < 2 {
            std::thread::sleep(Duration::from_millis(20));
        }
        block_on(session.shutdown()).unwrap();
        let ids: std::collections::BTreeSet<String> = log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|l| {
                l.split('&')
                    .find_map(|kv| kv.strip_prefix("peer_id=").map(str::to_string))
            })
            .collect();
        assert!(!ids.is_empty(), "no announces: {:?}", log.lock().unwrap());
        assert!(ids.iter().all(|i| i.starts_with(profile.peer_id.prefix)));
        if distinct {
            assert_eq!(
                ids.len(),
                2,
                "qbt profile must use one peer id per torrent: {ids:?}"
            );
        } else {
            assert_eq!(
                ids.len(),
                1,
                "native profile uses one peer id per session: {ids:?}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A peer that hangs up before the handshake (still checking its files,
/// just restarted) is retried at once, not after the full reconnect
/// backoff: libtorrent's `fast_reconnect`.
#[test]
fn a_peer_that_was_not_ready_is_retried_immediately() {
    let dir = std::env::temp_dir().join(format!("urt-fastretry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (torrent_bytes, data) =
        make_torrent("fr.bin", 512 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    let info_hash = metainfo::Torrent::parse(&torrent_bytes)
        .unwrap()
        .info
        .info_hash;
    let data = std::sync::Arc::new(data);
    // The first connection is dropped before a byte is exchanged.
    let seeder = common::spawn_seeder_resetting(info_hash, data.clone(), 64 * 1024, 1);
    let s = block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::LOCALHOST))
            .listen_v6(None)
            .lsd(false)
            .dht(false)
            .build(),
    )
    .unwrap();
    let id = block_on(s.add_torrent(AddTorrent::metainfo(torrent_bytes, &dir))).unwrap();
    block_on(s.add_peer(id, seeder)).unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(30);
    loop {
        let st = block_on(s.status(id)).unwrap();
        if st.state == TorrentState::Seeding {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "not retried within 30s (the backoff is 60s): {st:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(std::fs::read(dir.join("fr.bin")).unwrap(), *data);
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
