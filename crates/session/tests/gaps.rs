// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! What a daemon in front of the library needs (0.12.0): torrents outside
//! the queue start, errored torrents recover, a torrent whose content went
//! missing says so instead of starting over, and removal leaves no resume
//! file behind.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
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

fn builder(n: u8) -> SessionBuilder {
    init_log();
    Session::builder()
        .listen_port(0)
        .listen_v4(Some(Ipv4Addr::new(127, 0, 0, n)))
        .listen_v6(None)
        .transports(TransportPolicy::TcpOnly)
        .lsd(false)
        .dht(false)
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("urt-gaps-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

fn wait_for<F: Fn() -> bool>(what: &str, secs: u64, f: F) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_torrent_outside_the_queue_starts_when_added() {
    // `auto_managed(false)` and not paused: the torrent must run (announce,
    // tick) once its check is done, not merely look Seeding.
    let dir = tmp("unmanaged");
    let log = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_tracker(SocketAddr::from(([127, 0, 0, 9], 9)), log.clone());
    let (bytes, data) = make_torrent("u.bin", 256 * 1024, 64 * 1024, &url);
    std::fs::write(dir.join("u.bin"), &data).unwrap();
    let s = block_on(builder(1).build()).unwrap();
    let id =
        block_on(s.add_torrent(AddTorrent::metainfo(bytes, &dir).auto_managed(false))).unwrap();
    wait_state(&s, id, TorrentState::Seeding, 10);
    wait_for("the started announce", 10, || {
        log.lock()
            .unwrap()
            .iter()
            .any(|l| event_param(l).as_deref() == Some("started"))
    });
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

fn addr_of(n: u8, s: &Session) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, 0, 0, n).into(), s.listen_port())
}

fn status(s: &Session, id: TorrentId) -> session::TorrentStatus {
    block_on(s.status(id)).unwrap()
}

#[test]
fn content_that_went_missing_is_reported_and_comes_back() {
    // A seed's file is deleted between two runs. The resume data vouches for
    // it, so the torrent stops with ContentMissing (libtorrent / qBittorrent
    // "missing files"): nothing announced, nothing created, the resume data
    // kept. Resuming while the file is gone changes nothing; once it is
    // back, resuming seeds without a recheck. Removal deletes the resume
    // file.
    let dir = tmp("missing");
    let resume = dir.join("resume");
    let log = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_tracker(SocketAddr::from(([127, 0, 0, 9], 9)), log.clone());
    let (bytes, data) = make_torrent("m.bin", 512 * 1024, 64 * 1024, &url);
    let file = dir.join("m.bin");
    std::fs::write(&file, &data).unwrap();
    let add = || AddTorrent::metainfo(bytes.clone(), &dir).resume_dir(&resume);
    let s = block_on(builder(1).build()).unwrap();
    let id = block_on(s.add_torrent(add())).unwrap();
    wait_state(&s, id, TorrentState::Seeding, 10);
    block_on(s.shutdown()).unwrap();

    std::fs::remove_file(&file).unwrap();
    log.lock().unwrap().clear();
    let s = block_on(builder(1).build()).unwrap();
    let mut events = s.events();
    let id = block_on(s.add_torrent(add())).unwrap();
    wait_state(&s, id, TorrentState::Error, 10);
    let st = status(&s, id);
    assert_eq!(
        st.error_kind,
        Some(session::ErrorKind::ContentMissing),
        "{st:?}"
    );
    assert!(
        st.error.as_deref().unwrap_or("").contains("m.bin"),
        "{st:?}"
    );
    assert!(
        !file.exists(),
        "nothing is created in place of missing content"
    );
    // The event carries the kind.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match events.try_recv() {
            Some(session::Event::TorrentError { kind, .. }) => {
                assert_eq!(kind, session::ErrorKind::ContentMissing);
                break;
            }
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "no TorrentError event");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    // What the resume data vouched for stands.
    let blob = storage::ResumeData::decode(&block_on(s.resume_data(id)).unwrap()).unwrap();
    assert_eq!(blob.have.count(), st.pieces_total, "{st:?}");

    // Still gone: resuming looks again and stays errored.
    block_on(s.resume(id)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    wait_state(&s, id, TorrentState::Error, 10);
    assert!(!file.exists());
    assert!(
        !log.lock()
            .unwrap()
            .iter()
            .any(|l| event_param(l).as_deref() == Some("started")),
        "a torrent with missing content does not announce"
    );

    // Back: resuming seeds from the resume data, without a recheck.
    std::fs::write(&file, &data).unwrap();
    block_on(s.resume(id)).unwrap();
    wait_state(&s, id, TorrentState::Seeding, 10);
    let st = status(&s, id);
    assert_eq!(st.error_kind, None);
    assert_eq!(st.pieces_have, st.pieces_total);

    // Removal leaves no resume file behind.
    let resume_file = std::fs::read_dir(&resume).unwrap().count();
    assert_eq!(resume_file, 1);
    block_on(s.remove_torrent(id)).unwrap();
    assert_eq!(std::fs::read_dir(&resume).unwrap().count(), 0);
    assert!(file.exists(), "removal without files keeps the content");
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_recheck_accepts_missing_content_and_downloads_it_again() {
    let dir = tmp("missing-recheck");
    let resume = dir.join("resume");
    let (bytes, data) = make_torrent("r.bin", 512 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("r.bin"), &data).unwrap();
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    std::fs::write(b_dir.join("r.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    // B seeded once, then lost its file.
    let add = || AddTorrent::metainfo(bytes.clone(), &b_dir).resume_dir(&resume);
    let b = block_on(builder(2).build()).unwrap();
    let b_id = block_on(b.add_torrent(add())).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 10);
    block_on(b.shutdown()).unwrap();
    std::fs::remove_file(b_dir.join("r.bin")).unwrap();
    let b = block_on(builder(2).build()).unwrap();
    let b_id = block_on(b.add_torrent(add())).unwrap();
    wait_state(&b, b_id, TorrentState::Error, 10);

    // The recheck finds nothing, keeps the torrent running, and it
    // downloads everything again.
    block_on(b.force_recheck(b_id)).unwrap();
    let st = status(&b, b_id);
    assert_eq!(st.error, None, "{st:?}");
    assert_eq!(st.pieces_have, 0, "{st:?}");
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 30);
    assert_eq!(std::fs::read(b_dir.join("r.bin")).unwrap(), data);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_io_error_is_recovered_by_resume_and_by_recheck() {
    // A seed whose file is cut short under it fails its next upload read
    // (ErrorKind::Io). With the file restored, resume brings it back; a
    // second failure is cleared by a recheck.
    let dir = tmp("io");
    let (bytes, data) = make_torrent("io.bin", 512 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    let file = a_dir.join("io.bin");
    std::fs::write(&file, &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    let fail_a_read = |tag: &str| {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .unwrap()
            .set_len(0)
            .unwrap();
        let b_dir = dir.join(tag);
        let b = block_on(builder(2).build()).unwrap();
        let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes.clone(), &b_dir))).unwrap();
        block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
        wait_state(&a, a_id, TorrentState::Error, 20);
        let st = status(&a, a_id);
        assert_eq!(st.error_kind, Some(session::ErrorKind::Io), "{st:?}");
        std::fs::write(&file, &data).unwrap();
        (b, b_id, b_dir)
    };

    let (b, b_id, b_dir) = fail_a_read("b1");
    block_on(a.resume(a_id)).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 30);
    assert_eq!(std::fs::read(b_dir.join("io.bin")).unwrap(), data);
    block_on(b.shutdown()).unwrap();

    let (b, _b_id, _b_dir) = fail_a_read("b2");
    block_on(a.force_recheck(a_id)).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    assert_eq!(status(&a, a_id).pieces_have, status(&a, a_id).pieces_total);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
