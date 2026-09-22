// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Selective download (file priorities with the parts file) and moving
//! storage, between two engines in one process.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use common::{block_on, make_multi_torrent};
use session::{AddTorrent, Event, Session, TorrentState};

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

#[test]
fn selective_download_then_everything_then_move() {
    let dir = std::env::temp_dir().join(format!("urt-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // 64 KiB pieces; b starts and ends mid-piece so two pieces straddle it.
    let files = [
        ("a.bin", 200_000usize),
        ("sub/b.bin", 300_000),
        ("c.bin", 150_000),
    ];
    let (torrent_bytes, data) =
        make_multi_torrent("sel", &files, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(a_dir.join("sel/sub")).unwrap();
    std::fs::write(a_dir.join("sel/a.bin"), &data[..200_000]).unwrap();
    std::fs::write(a_dir.join("sel/sub/b.bin"), &data[200_000..500_000]).unwrap();
    std::fs::write(a_dir.join("sel/c.bin"), &data[500_000..]).unwrap();
    let a = session(1);
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let st = block_on(a.status(a_id)).unwrap();
        if st.state == TorrentState::Seeding {
            assert_eq!(st.files.len(), 3);
            assert!(st.files.iter().all(|f| f.priority == 4 && f.done == f.size));
            break;
        }
        assert!(Instant::now() < deadline, "seeder not ready: {st:?}");
        std::thread::sleep(Duration::from_millis(20));
    }

    // B skips the middle file.
    let b = session(2);
    let mut events = b.events();
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let b_id = block_on(
        b.add_torrent(
            AddTorrent::metainfo(torrent_bytes.clone(), &b_dir)
                .resume_dir(dir.join("b-resume"))
                .file_priorities(vec![4, 0, 4]),
        ),
    )
    .unwrap();
    block_on(b.add_peer(
        b_id,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), a.listen_port()),
    ))
    .unwrap();
    assert!(
        wait_event(&mut events, 30, |e| matches!(
            e,
            Event::TorrentFinished { .. }
        ))
        .is_some(),
        "selective download did not finish"
    );
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(
        st.state,
        TorrentState::Seeding,
        "finished (upload-only) state"
    );
    assert!(st.complete);
    assert!(
        st.pieces_have < st.pieces_total,
        "skipped pieces are not downloaded"
    );
    assert_eq!(st.files[1].priority, 0);
    assert_eq!(st.files[0].done, 200_000);
    assert_eq!(st.files[2].done, 150_000);
    assert!(
        st.files[1].done > 0 && st.files[1].done < 300_000,
        "only the straddling parts: {}",
        st.files[1].done
    );
    assert_eq!(st.total_wanted_done, st.total_wanted);
    assert_eq!(st.total_wanted, 350_000, "wanted = the two wanted files");
    assert!(st.left > 0, "left is truthful: skipped bytes are missing");
    assert!(
        !b_dir.join("sel/sub/b.bin").exists(),
        "skipped file must not be created"
    );
    assert!(
        b_dir.join(".sel.parts").exists(),
        "straddling bytes live in the parts file"
    );
    assert_eq!(
        std::fs::read(b_dir.join("sel/a.bin")).unwrap(),
        &data[..200_000]
    );
    assert_eq!(
        std::fs::read(b_dir.join("sel/c.bin")).unwrap(),
        &data[500_000..]
    );
    // Priorities are persisted.
    block_on(b.save_resume_data(b_id)).unwrap();
    let resume = storage::ResumeData::load(
        &dir.join("b-resume")
            .join(format!("{}.resume", bencode::hex(&st.info_hash))),
    )
    .unwrap()
    .unwrap();
    assert_eq!(resume.file_priorities, vec![4, 0, 4]);

    // Now want everything: the parts are exported and the rest downloads.
    block_on(b.set_file_priorities(b_id, vec![4, 4, 4])).unwrap();
    assert!(
        block_on(b.set_file_priorities(b_id, vec![4, 4])).is_err(),
        "wrong count is rejected"
    );
    assert!(
        wait_event(&mut events, 30, |e| matches!(
            e,
            Event::TorrentFinished { .. }
        ))
        .is_some(),
        "full download did not finish"
    );
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(st.pieces_have, st.pieces_total);
    assert_eq!(st.left, 0);
    assert_eq!(
        std::fs::read(b_dir.join("sel/sub/b.bin")).unwrap(),
        &data[200_000..500_000]
    );

    // Move the content elsewhere; it still verifies from the new place.
    let moved = dir.join("b-moved");
    block_on(b.move_storage(b_id, moved.clone())).unwrap();
    assert!(wait_event(&mut events, 10, |e| matches!(e, Event::StorageMoved { .. })).is_some());
    assert!(moved.join("sel/a.bin").exists() && moved.join("sel/sub/b.bin").exists());
    assert!(!b_dir.join("sel/a.bin").exists());
    assert_eq!(block_on(b.status(b_id)).unwrap().save_path, moved);
    block_on(b.force_recheck(b_id)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let st = block_on(b.status(b_id)).unwrap();
        if st.state == TorrentState::Seeding && st.pieces_have == st.pieces_total {
            break;
        }
        assert!(Instant::now() < deadline, "recheck after move: {st:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        std::fs::read(moved.join("sel/c.bin")).unwrap(),
        &data[500_000..]
    );
    block_on(a.shutdown()).unwrap();
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Preallocation reserves every wanted file at its full size before any
/// byte arrives, leaves a deselected file uncreated (its stray bytes go to
/// the parts file), and reserves that file the moment it becomes wanted.
#[test]
fn preallocation_reserves_wanted_files_and_files_that_become_wanted() {
    let dir = std::env::temp_dir().join(format!("urt-prealloc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let files = [
        ("a.bin", 200_000usize),
        ("sub/b.bin", 300_000),
        ("c.bin", 150_000),
    ];
    let (torrent_bytes, data) =
        make_multi_torrent("pre", &files, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(a_dir.join("pre/sub")).unwrap();
    std::fs::write(a_dir.join("pre/a.bin"), &data[..200_000]).unwrap();
    std::fs::write(a_dir.join("pre/sub/b.bin"), &data[200_000..500_000]).unwrap();
    std::fs::write(a_dir.join("pre/c.bin"), &data[500_000..]).unwrap();
    let a = session(1);
    let a_id =
        block_on(a.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &a_dir))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while block_on(a.status(a_id)).unwrap().state != TorrentState::Seeding {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    // B: preallocated, paused, with the middle file skipped.
    let b = session(2);
    let b_dir = dir.join("b");
    let b_id = block_on(
        b.add_torrent(
            AddTorrent::metainfo(torrent_bytes, &b_dir)
                .preallocate(true)
                .paused(true)
                .file_priorities(vec![4, 0, 4]),
        ),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while block_on(b.status(b_id)).unwrap().state != TorrentState::Paused {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    let len = |p: &str| std::fs::metadata(b_dir.join(p)).map(|m| m.len()).ok();
    assert_eq!(len("pre/a.bin"), Some(200_000));
    assert_eq!(len("pre/c.bin"), Some(150_000));
    assert_eq!(len("pre/sub/b.bin"), None, "a skipped file was created");
    // Space is reserved, not just the size: blocks are allocated (the file
    // system here supports `fallocate`; a sparse file would report none).
    let blocks = std::fs::metadata(b_dir.join("pre/a.bin"))
        .map(|m| std::os::unix::fs::MetadataExt::blocks(&m))
        .unwrap();
    assert!(blocks * 512 >= 200_000, "{blocks} blocks allocated");
    // Wanting the middle file reserves it at once, before any data.
    block_on(b.set_file_priorities(b_id, vec![4, 4, 4])).unwrap();
    assert_eq!(len("pre/sub/b.bin"), Some(300_000));
    // And the download still lands correctly in the reserved files.
    block_on(b.resume(b_id)).unwrap();
    block_on(b.add_peer(
        b_id,
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), a.listen_port()),
    ))
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while block_on(b.status(b_id)).unwrap().state != TorrentState::Seeding {
        assert!(Instant::now() < deadline, "{:?}", block_on(b.status(b_id)));
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        std::fs::read(b_dir.join("pre/a.bin")).unwrap(),
        &data[..200_000]
    );
    assert_eq!(
        std::fs::read(b_dir.join("pre/sub/b.bin")).unwrap(),
        &data[200_000..500_000]
    );
    assert_eq!(
        std::fs::read(b_dir.join("pre/c.bin")).unwrap(),
        &data[500_000..]
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
