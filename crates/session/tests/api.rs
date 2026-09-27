// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The 0.2.0 API additions: preallocation, find/pause-all/resume-all,
//! tracker add/remove, per-torrent peer caps, time counters in status and
//! resume data, removal with files, session stats.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate urtorrent_session as session;

mod common;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use common::{block_on, make_multi_torrent, wait_idle_disk};
use session::{AddTorrent, Session, TorrentState};

fn session(n: u8) -> Session {
    block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::new(127, 0, 0, n)))
            .listen_v6(None)
            .lsd(false)
            .dht(false)
            .build(),
    )
    .unwrap()
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
            "state {:?}, wanted {want:?}",
            st.state
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn preallocate_find_trackers_caps_times_and_removal() {
    let dir = std::env::temp_dir().join(format!("urt-api-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let files = [("a.bin", 70_000usize), ("sub/b.bin", 130_000)];
    let (torrent_bytes, data) =
        make_multi_torrent("api", &files, 32 * 1024, "http://127.0.0.1:1/x");
    let seed_dir = dir.join("seed");
    std::fs::create_dir_all(seed_dir.join("api/sub")).unwrap();
    std::fs::write(seed_dir.join("api/a.bin"), &data[..70_000]).unwrap();
    std::fs::write(seed_dir.join("api/sub/b.bin"), &data[70_000..]).unwrap();
    let resume_dir = dir.join("resume");

    let a = session(1);
    let a_id = block_on(a.add_torrent(
        AddTorrent::metainfo(torrent_bytes.clone(), &seed_dir).resume_dir(&resume_dir),
    ))
    .unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let info_hash = block_on(a.status(a_id)).unwrap().info_hash;
    assert_eq!(block_on(a.find_torrent(info_hash)), Some(a_id));
    assert_eq!(block_on(a.find_torrent([0u8; 20])), None);

    // Trackers: add to a new tier, then remove; status reflects both.
    block_on(a.add_tracker(a_id, "http://127.0.0.1:2/t".into(), 9)).unwrap();
    assert!(block_on(a.add_tracker(a_id, "http://127.0.0.1:2/t".into(), 0)).is_err());
    let st = block_on(a.status(a_id)).unwrap();
    assert_eq!(st.trackers.len(), 2);
    assert_eq!(st.trackers[1].url, "http://127.0.0.1:2/t");
    assert_eq!(st.trackers[1].tier, 1);
    block_on(a.remove_tracker(a_id, "http://127.0.0.1:1/x".into())).unwrap();
    assert!(block_on(a.remove_tracker(a_id, "http://nope/".into())).is_err());
    let st = block_on(a.status(a_id)).unwrap();
    assert_eq!(st.trackers.len(), 1);
    assert_eq!(st.trackers[0].tier, 0);

    // Preallocated leecher: files exist at full size before any data.
    let b = session(2);
    let b_dir = dir.join("b");
    let b_id = block_on(
        b.add_torrent(
            AddTorrent::metainfo(torrent_bytes.clone(), &b_dir)
                .preallocate(true)
                .paused(true)
                .resume_dir(&resume_dir),
        ),
    )
    .unwrap();
    wait_state(&b, b_id, TorrentState::Paused, 10);
    assert_eq!(
        std::fs::metadata(b_dir.join("api/a.bin")).unwrap().len(),
        70_000
    );
    assert_eq!(
        std::fs::metadata(b_dir.join("api/sub/b.bin"))
            .unwrap()
            .len(),
        130_000
    );
    // Paused: no active time accrues.
    std::thread::sleep(Duration::from_millis(300));
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(st.active_time, Duration::ZERO);
    assert!(st.max_peers.is_none());
    block_on(b.set_max_peers(b_id, Some(3))).unwrap();
    assert_eq!(block_on(b.status(b_id)).unwrap().max_peers, Some(3));

    // resume_all starts it; feed it the seed and let it finish.
    block_on(b.resume_all()).unwrap();
    let a_port = a.listen_port();
    block_on(b.add_peer(b_id, format!("127.0.0.1:{a_port}").parse().unwrap())).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 30);
    let st = block_on(b.status(b_id)).unwrap();
    assert!(st.active_time > Duration::ZERO, "{st:?}");
    assert_eq!(
        std::fs::read(b_dir.join("api/a.bin")).unwrap(),
        &data[..70_000]
    );
    let peers = block_on(b.peers(b_id)).unwrap();
    for p in &peers {
        assert!(p.connected_for > Duration::ZERO);
    }

    // Session stats carry the new counters. Completion queues a resume save
    // (fsync + unfinished readback), so wait for the queues to drain rather
    // than snapshotting them the instant the torrent finishes.
    let stats = wait_idle_disk(&b, 10);
    assert_eq!(stats.recv_buffers, 256);
    assert!(stats.recv_buffers_free <= 256);

    // pause_all folds the clocks into the resume data and stops accrual.
    block_on(b.pause_all()).unwrap();
    wait_state(&b, b_id, TorrentState::Paused, 10);
    let st = block_on(b.status(b_id)).unwrap();
    let frozen = st.active_time;
    assert!(st.seeding_time <= st.active_time);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(block_on(b.status(b_id)).unwrap().active_time, frozen);
    let resume_files: Vec<_> = std::fs::read_dir(&resume_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(!resume_files.is_empty());
    let saved = storage::ResumeData::load(&resume_files[0])
        .unwrap()
        .unwrap();
    assert_eq!(saved.format_version, storage::FORMAT_VERSION);
    assert!(saved.active_time <= frozen.as_secs() + 1);

    // Removal with files: content, parts and resume gone, save path kept.
    block_on(b.remove_torrent_with_files(b_id)).unwrap();
    assert!(!b_dir.join("api/a.bin").exists());
    assert!(!b_dir.join("api/sub").exists());
    assert!(!b_dir.join("api").exists());
    assert!(b_dir.exists());
    assert!(block_on(b.status(b_id)).is_err());
    assert!(std::fs::read_dir(&resume_dir).unwrap().next().is_none());
    // The seeder's files are untouched by a plain remove.
    block_on(a.remove_torrent(a_id)).unwrap();
    assert!(seed_dir.join("api/a.bin").exists());

    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
