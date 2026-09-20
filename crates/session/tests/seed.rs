// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Two engines in one process: A seeds (data on disk, rechecked on add), B
//! leeches from A through a tiny tracker. Covers the upload path, the choker
//! fast path, rate limits, force-recheck after corruption, and pause/resume.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{block_on, make_torrent, spawn_tracker};
use session::{AddTorrent, Event, Session, TorrentState};

fn session(upload_limit: u64) -> Session {
    block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::LOCALHOST))
            .listen_v6(None)
            .upload_limit(upload_limit)
            .build(),
    )
    .unwrap()
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

#[test]
fn seed_to_second_engine_with_rate_limit_recheck_and_pause() {
    let dir = std::env::temp_dir().join(format!("urt-session-seed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();

    let size = 2 * 1024 * 1024 + 777; // 33 pieces of 64 KiB
    let piece_len = 64 * 1024;
    let (_, data) = make_torrent("seed.bin", size, piece_len, "http://placeholder/");
    std::fs::write(dir.join("a").join("seed.bin"), &data).unwrap();

    // Seeder A, upload-limited to 512 KiB/s so the transfer is observable.
    let a = session(512 * 1024);
    let a_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), a.listen_port());
    let log = Arc::new(Mutex::new(Vec::new()));
    let announce = spawn_tracker(a_addr, log.clone());
    let (torrent_bytes, _) = make_torrent("seed.bin", size, piece_len, &announce);
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), dir.join("a"))))
        .unwrap();
    // Rechecked from disk: seeding without downloading anything.
    let st = wait_state(&a, a_id, TorrentState::Seeding, 10);
    assert_eq!(st.pieces_have, 33);
    assert_eq!(st.downloaded, 0);

    // Leecher B.
    let b = session(0);
    let mut b_events = b.events();
    let t0 = Instant::now();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), dir.join("b"))))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_downloaded = 0u64;
    loop {
        match block_on(b_events.recv()).expect("events") {
            Event::TorrentFinished { .. } => break,
            Event::TorrentError { error, .. } => panic!("B error: {error}"),
            Event::HashFailed { piece, .. } => panic!("hash failed {piece}"),
            Event::PieceFinished { .. } => {
                // Counters never go backwards.
                let st = block_on(b.status(b_id)).unwrap();
                assert!(st.downloaded >= last_downloaded);
                last_downloaded = st.downloaded;
            }
            _ => {}
        }
        assert!(Instant::now() < deadline, "B did not finish");
    }
    let elapsed = t0.elapsed();
    // 2 MiB at 512 KiB/s is ~4 s; allow the burst bucket (1 s) and jitter.
    assert!(
        elapsed >= Duration::from_millis(2500),
        "rate limit not honoured: {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(20), "too slow: {elapsed:?}");
    let on_disk = std::fs::read(dir.join("b").join("seed.bin")).unwrap();
    assert!(on_disk == data);
    let sa = block_on(a.status(a_id)).unwrap();
    let sb = block_on(b.status(b_id)).unwrap();
    assert_eq!(sb.downloaded, size as u64);
    assert_eq!(sa.uploaded, size as u64, "A's upload counter is truthful");
    assert_eq!(sa.downloaded, 0);
    assert!(sa.upload_rate > 0 || sa.uploaded > 0);

    // Force recheck on B after corrupting the middle of the file: the have-set
    // shrinks to what verifies, then B refills from A.
    {
        use std::io::{Seek, Write};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("b").join("seed.bin"))
            .unwrap();
        f.seek(std::io::SeekFrom::Start(5 * piece_len as u64 + 100))
            .unwrap();
        f.write_all(&[0xAB; 3000]).unwrap();
        f.sync_all().unwrap();
    }
    block_on(b.set_rate_limits(0, 0)).unwrap();
    block_on(a.set_rate_limits(0, 0)).unwrap();
    block_on(b.force_recheck(b_id)).unwrap();
    let mut saw_partial = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let st = block_on(b.status(b_id)).unwrap();
        if st.pieces_have < 33 {
            saw_partial = true;
        }
        if st.pieces_have == 33 && st.state == TorrentState::Seeding && saw_partial {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "did not recover after recheck: {st:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let on_disk = std::fs::read(dir.join("b").join("seed.bin")).unwrap();
    assert!(on_disk == data, "repaired data differs");
    let sb = block_on(b.status(b_id)).unwrap();
    assert_eq!(
        sb.downloaded,
        size as u64 + piece_len as u64,
        "exactly one piece re-downloaded"
    );

    // Pause / resume on the seeder: stopped announce, peers dropped, then back.
    block_on(a.pause(a_id)).unwrap();
    assert_eq!(
        block_on(a.status(a_id)).unwrap().state,
        TorrentState::Paused
    );
    assert_eq!(block_on(a.status(a_id)).unwrap().peers, 0);
    block_on(a.resume(a_id)).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 5);
    block_on(a.shutdown()).unwrap();
    block_on(b.shutdown()).unwrap();
    let lines = log.lock().unwrap().clone();
    // A: started, (completed? no: added as seed) ... stopped(pause), started(resume), stopped(shutdown)
    let a_events: Vec<String> = lines
        .iter()
        .filter(|l| l.contains(&format!("port={}", a_addr.port())))
        .map(|l| common::event_param(l).unwrap_or_else(|| "regular".into()))
        .collect();
    assert_eq!(
        a_events,
        vec!["started", "stopped", "started", "stopped"],
        "seeder announce sequence: {lines:?}"
    );
    assert!(
        !a_events.contains(&"completed".to_string()),
        "a seed never says completed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// MSE policies between two engines: forced <-> enabled negotiates RC4 after
/// the plaintext attempt is refused (Q3 retry); forced <-> disabled never
/// connects.
#[test]
fn encryption_modes() {
    use session::EncryptionMode;
    let dir = std::env::temp_dir().join(format!("urt-session-mse-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let size = 512 * 1024 + 9;
    let piece_len = 64 * 1024;
    let (_, data) = make_torrent("mse.bin", size, piece_len, "http://placeholder/");

    let mk = |mode: EncryptionMode| {
        block_on(
            Session::builder()
                .listen_port(0)
                .listen_v4(Some(Ipv4Addr::LOCALHOST))
                .listen_v6(None)
                .profile(profile::Profile::qbt_5_2_3_lt2_0_14())
                .encryption(mode)
                .build(),
        )
        .unwrap()
    };
    for (seed_mode, leech_mode, expect_ok) in [
        (EncryptionMode::Forced, EncryptionMode::Enabled, true),
        (EncryptionMode::Enabled, EncryptionMode::Forced, true),
        (EncryptionMode::Forced, EncryptionMode::Forced, true),
        (EncryptionMode::Disabled, EncryptionMode::Enabled, true),
        (EncryptionMode::Forced, EncryptionMode::Disabled, false),
        (EncryptionMode::Disabled, EncryptionMode::Forced, false),
    ] {
        let case = dir.join(format!("{seed_mode:?}-{leech_mode:?}"));
        std::fs::create_dir_all(case.join("a")).unwrap();
        std::fs::create_dir_all(case.join("b")).unwrap();
        std::fs::write(case.join("a").join("mse.bin"), &data).unwrap();
        let a = mk(seed_mode);
        let a_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), a.listen_port());
        let log = Arc::new(Mutex::new(Vec::new()));
        let announce = spawn_tracker(a_addr, log.clone());
        let (torrent_bytes, _) = make_torrent("mse.bin", size, piece_len, &announce);
        let a_id =
            block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), case.join("a"))))
                .unwrap();
        wait_state(&a, a_id, TorrentState::Seeding, 10);
        let b = mk(leech_mode);
        let b_id =
            block_on(b.add_torrent(AddTorrent::metainfo(torrent_bytes, case.join("b")))).unwrap();
        let deadline = Instant::now() + Duration::from_secs(if expect_ok { 30 } else { 6 });
        let mut done = false;
        while Instant::now() < deadline {
            let st = block_on(b.status(b_id)).unwrap();
            if st.complete {
                done = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            done, expect_ok,
            "{seed_mode:?} seed vs {leech_mode:?} leech"
        );
        if expect_ok {
            let peers = block_on(a.peers(a_id)).unwrap();
            let sa = block_on(a.status(a_id)).unwrap();
            assert_eq!(sa.uploaded, size as u64);
            let rc4_expected = matches!(seed_mode, EncryptionMode::Forced)
                || matches!(leech_mode, EncryptionMode::Forced);
            // The seeder may already have dropped the peer (both seeds); if it
            // is still there, its encryption flag must match.
            for p in &peers {
                assert_eq!(
                    p.encrypted, rc4_expected,
                    "{seed_mode:?}/{leech_mode:?}: {p:?}"
                );
            }
            let on_disk = std::fs::read(case.join("b").join("mse.bin")).unwrap();
            assert!(on_disk == data);
        }
        block_on(a.shutdown()).unwrap();
        block_on(b.shutdown()).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
