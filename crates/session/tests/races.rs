// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Operations that overlap work already in flight. The engine is
//! single-threaded, so these are not data races but ordering ones: a task
//! that started before a change and comes back after it must not apply what
//! it computed against the old picture, and nothing may stall or lie
//! because two things happened at once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate urtorrent_session as session;

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{block_on, make_multi_torrent, make_torrent, wait_idle_disk};
use session::{AddTorrent, Session, SessionBuilder, TorrentId, TorrentState};

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
    let dir = std::env::temp_dir().join(format!("urt-races-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Truthfulness after the dust settles: a complete torrent must have every
/// piece, the data on disk must match, and the accounting must add up.
fn assert_sound(s: &Session, id: TorrentId, data: &[u8], path: &std::path::Path) {
    let st = block_on(s.status(id)).unwrap();
    assert_eq!(st.state, TorrentState::Seeding, "{st:?}");
    assert_eq!(st.pieces_have, st.pieces_total, "{st:?}");
    assert_eq!(st.left, 0, "{st:?}");
    assert_eq!(std::fs::read(path).unwrap(), data);
    assert!(
        st.downloaded >= st.total_size,
        "downloaded {} < size {}",
        st.downloaded,
        st.total_size
    );
    assert_eq!(
        st.downloaded - st.corrupt - st.redundant,
        st.total_size,
        "accounting does not add up: {st:?}"
    );
}

#[test]
fn rechecks_during_a_download_do_not_strand_pieces() {
    // A recheck replaces the picture while blocks are in flight and
    // verifies are running. Every stale verdict must be dropped, and the
    // pieces whose bookkeeping the recheck voided must be picked again:
    // the download has to finish, exactly once, with the right data.
    let dir = tmp("recheck");
    let (bytes, data) = make_torrent("r.bin", 16 << 20, 256 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("r.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    let b = block_on(builder(2).download_limit(4 << 20).build()).unwrap();
    let b_dir = dir.join("b");
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, &b_dir))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    // Recheck repeatedly while the download runs.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut rechecks = 0;
    loop {
        let st = block_on(b.status(b_id)).unwrap();
        if st.state == TorrentState::Seeding {
            break;
        }
        assert!(Instant::now() < deadline, "download stalled: {st:?}");
        if st.pieces_have > 0 && rechecks < 6 && st.state == TorrentState::Downloading {
            block_on(b.force_recheck(b_id)).unwrap();
            rechecks += 1;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    assert!(rechecks >= 3, "only {rechecks} rechecks landed");
    assert_sound(&b, b_id, &data, &b_dir.join("r.bin"));
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pause_resume_and_priority_storms_leave_a_sound_torrent() {
    // Everything a frontend can do while blocks are in flight, at once.
    let dir = tmp("storm");
    let files = [
        ("a.bin", 700_003usize),
        ("sub/b.bin", 1_300_007),
        ("c.bin", 500_009),
    ];
    let (bytes, data) = make_multi_torrent("st", &files, 256 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(a_dir.join("st/sub")).unwrap();
    std::fs::write(a_dir.join("st/a.bin"), &data[..700_003]).unwrap();
    std::fs::write(a_dir.join("st/sub/b.bin"), &data[700_003..2_000_010]).unwrap();
    std::fs::write(a_dir.join("st/c.bin"), &data[2_000_010..]).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    let b = block_on(builder(2).download_limit(2 << 20).build()).unwrap();
    let b_dir = dir.join("b");
    let b_id =
        block_on(b.add_torrent(AddTorrent::metainfo(bytes, &b_dir).resume_dir(dir.join("resume"))))
            .unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut round = 0u32;
    loop {
        let st = block_on(b.status(b_id)).unwrap();
        if st.state == TorrentState::Seeding {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "stalled at round {round}: {st:?}"
        );
        match round % 6 {
            0 => block_on(b.set_file_priorities(b_id, vec![4, 0, 7])).unwrap(),
            1 => {
                block_on(b.pause(b_id)).unwrap();
                block_on(b.resume(b_id)).unwrap();
                block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
            }
            2 => block_on(b.set_file_priorities(b_id, vec![1, 4, 4])).unwrap(),
            3 => block_on(b.set_sequential(b_id, round % 12 == 3)).unwrap(),
            4 => block_on(b.save_resume_data(b_id)).unwrap(),
            _ => {
                let _ = block_on(b.pieces(b_id)).unwrap();
                let _ = block_on(b.peers(b_id)).unwrap();
                let _ = block_on(b.resume_data(b_id)).unwrap();
            }
        }
        round += 1;
        std::thread::sleep(Duration::from_millis(100));
    }
    // Whatever the storm left selected, everything is wanted again now and
    // the rest of the torrent must arrive.
    block_on(b.set_file_priorities(b_id, vec![4, 4, 4])).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let st = block_on(b.status(b_id)).unwrap();
        if st.pieces_have == st.pieces_total {
            break;
        }
        assert!(Instant::now() < deadline, "did not finish: {st:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Everything wanted again at the end, so the whole torrent is there.
    let mut pos = 0;
    for (path, len) in files {
        let got = std::fs::read(b_dir.join("st").join(path)).unwrap();
        assert_eq!(got, &data[pos..pos + len], "{path}");
        pos += len;
    }
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(st.pieces_have, st.pieces_total, "{st:?}");
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn moving_and_renaming_while_blocks_are_in_flight_keeps_the_data() {
    let dir = tmp("move");
    let files = [("a.bin", 900_001usize), ("sub/b.bin", 1_100_003)];
    let (bytes, data) = make_multi_torrent("mv", &files, 256 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(a_dir.join("mv/sub")).unwrap();
    std::fs::write(a_dir.join("mv/a.bin"), &data[..900_001]).unwrap();
    std::fs::write(a_dir.join("mv/sub/b.bin"), &data[900_001..]).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    let b = block_on(builder(2).download_limit(1 << 20).build()).unwrap();
    let b_dir = dir.join("b");
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, &b_dir))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    // Wait for data to be moving, then rename and move the storage under it.
    let deadline = Instant::now() + Duration::from_secs(30);
    while block_on(b.status(b_id)).unwrap().downloaded < 256 * 1024 {
        assert!(Instant::now() < deadline, "no progress");
        std::thread::sleep(Duration::from_millis(10));
    }
    block_on(b.rename_file(b_id, 0, "mv/renamed.bin".into())).unwrap();
    let moved = dir.join("moved");
    block_on(b.move_storage(b_id, moved.clone())).unwrap();
    block_on(b.rename_file(b_id, 1, "mv/sub/also.bin".into())).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 90);
    assert_eq!(
        std::fs::read(moved.join("mv/renamed.bin")).unwrap(),
        &data[..900_001]
    );
    assert_eq!(
        std::fs::read(moved.join("mv/sub/also.bin")).unwrap(),
        &data[900_001..]
    );
    assert!(!b_dir.join("mv/a.bin").exists());
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn removing_with_files_while_writes_are_in_flight_leaves_nothing_behind() {
    let dir = tmp("remove");
    let (bytes, data) = make_torrent("d.bin", 8 << 20, 256 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("d.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let b = block_on(builder(2).build()).unwrap();
    let b_dir = dir.join("b");
    let resume = dir.join("resume");
    for round in 0..3 {
        let b_id = block_on(
            b.add_torrent(AddTorrent::metainfo(bytes.clone(), &b_dir).resume_dir(&resume)),
        )
        .unwrap();
        block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while block_on(b.status(b_id)).unwrap().downloaded < 512 * 1024 {
            assert!(Instant::now() < deadline, "no progress in round {round}");
            std::thread::sleep(Duration::from_millis(5));
        }
        // Remove mid-download, with the files: nothing of the torrent may
        // survive, however many writes were on their way to the disk.
        block_on(b.remove_torrent_with_files(b_id)).unwrap();
        assert!(
            !b_dir.join("d.bin").exists(),
            "content file recreated after removal (round {round})"
        );
        assert!(
            std::fs::read_dir(&resume)
                .map(|mut d| d.next().is_none())
                .unwrap_or(true),
            "resume file left behind (round {round})"
        );
        assert!(block_on(b.status(b_id)).is_err());
    }
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn adding_while_shutting_down_is_refused_rather_than_half_done() {
    let dir = tmp("shutdown");
    let (bytes, data) = make_torrent("s.bin", 1 << 20, 256 * 1024, "http://127.0.0.1:1/x");
    std::fs::write(dir.join("s.bin"), &data).unwrap();
    let s = block_on(builder(1).build()).unwrap();
    let first = block_on(s.add_torrent(AddTorrent::metainfo(bytes.clone(), &dir))).unwrap();
    wait_state(&s, first, TorrentState::Seeding, 10);
    // Fire an add and a shutdown at once; whichever order the engine sees
    // them in, the session must end up down and the add must not leave a
    // torrent running behind it.
    let s2 = s.clone();
    let bytes2 = bytes.clone();
    let dir2 = dir.clone();
    let adder = std::thread::spawn(move || {
        block_on(
            s2.add_torrent(
                AddTorrent::magnet(
                    "magnet:?xt=urn:btih:00000000000000000000000000000000000000ff",
                    &dir2,
                )
                .paused(false),
            ),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
        .and(
            block_on(s2.add_torrent(AddTorrent::metainfo(bytes2, &dir2)))
                .map(|_| ())
                .map_err(|e| e.to_string()),
        )
    });
    block_on(s.shutdown()).unwrap();
    let added = adder.join().unwrap();
    // Either the adds got in before the shutdown, or they were refused;
    // never a panic, never a hang.
    if let Err(e) = &added {
        assert!(
            e.contains("shut") || e.contains("duplicate") || e.contains("closed"),
            "unexpected error: {e}"
        );
    }
    // The handle still answers (with errors) after shutdown.
    assert!(block_on(s.statuses()).is_err() || block_on(s.statuses()).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn many_torrents_added_and_removed_concurrently_stay_consistent() {
    // Adds, removes and rechecks interleaved across many torrents: the
    // session's own bookkeeping (counts, ids, the checking gate) must not
    // drift, and every torrent that survives must be sound.
    let dir = tmp("many");
    let n = 12;
    let a = block_on(builder(1).max_checking(2).build()).unwrap();
    let mut fixtures = Vec::new();
    for i in 0..n {
        let (bytes, data) = make_torrent(
            &format!("m{i}.bin"),
            512 * 1024,
            64 * 1024,
            "http://127.0.0.1:1/x",
        );
        let d = dir.join(format!("a{i}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("m{i}.bin")), &data).unwrap();
        fixtures.push((bytes, Arc::new(data), d));
    }
    let mut ids = Vec::new();
    for (bytes, _, d) in &fixtures {
        ids.push(block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), d))).unwrap());
    }
    // Recheck everything while half of them are removed and re-added.
    for (round, id) in ids.iter().enumerate() {
        block_on(a.force_recheck(*id)).unwrap();
        if round % 3 == 0 {
            block_on(a.remove_torrent(*id)).unwrap();
        }
    }
    for (i, (bytes, _, d)) in fixtures.iter().enumerate() {
        if i % 3 == 0 {
            block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), d))).unwrap();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let all = block_on(a.statuses()).unwrap();
        assert_eq!(all.len(), n, "{} torrents", all.len());
        if all.iter().all(|s| s.state == TorrentState::Seeding) {
            for s in &all {
                assert_eq!(s.pieces_have, s.pieces_total, "{s:?}");
                assert_eq!(s.corrupt, 0, "{s:?}");
            }
            break;
        }
        assert!(
            Instant::now() < deadline,
            "not all seeding: {:?}",
            all.iter()
                .map(|s| (s.id, s.state, s.pieces_have))
                .collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // Each completion queues a resume save, so let the queues drain: the
    // point is that every job finishes, not that none was in flight at the
    // moment the last torrent flipped to seeding.
    let stats = wait_idle_disk(&a, 30);
    assert_eq!(stats.torrents, n);
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
