// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! What a daemon in front of the library needs. 0.12.0: torrents outside
//! the queue start, errored torrents recover, a torrent whose content went
//! missing says so instead of starting over, removal leaves no resume file
//! behind, torrents hold at their metadata, list views get what they show.
//! 0.13.0: tracker rows per listen endpoint, file completion, piece
//! priorities, banned address ranges. 0.13.5: the queue's slow flag, a
//! queue position set in one call. 0.14.0: tracker replies with their
//! intervals and response time, one tracker reannounced alone, how far a
//! check has got.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    block_on, event_param, make_multi_torrent, make_torrent, spawn_range_server_recording,
    spawn_recording_tracker, spawn_seeder, spawn_tracker,
};
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

fn state(s: &Session, id: TorrentId) -> TorrentState {
    status(s, id).state
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

fn magnet_for(bytes: &[u8], tracker: &str) -> String {
    let hash = metainfo::Torrent::parse(bytes).unwrap().info.info_hash;
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    let tr: String = tracker
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("magnet:?xt=urn:btih:{hex}&tr={tr}")
}

fn events_of(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|l| event_param(l))
        .collect()
}

#[test]
fn a_held_magnet_waits_with_its_metadata_until_released() {
    // The daemon's metadata preview and its stop conditions: the magnet is
    // held once the metadata is in (no file, no check, no piece; stopped as
    // the oracle's "stop condition: metadata received" does), files are
    // excluded and renamed while nothing exists, then release checks and
    // stays paused, and resume downloads into the chosen layout.
    let dir = tmp("hold");
    let files = [("a.bin", 300_000usize), ("b.bin", 400_000)];
    let (bytes, data) = make_multi_torrent("hold", &files, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(a_dir.join("hold")).unwrap();
    std::fs::write(a_dir.join("hold/a.bin"), &data[..300_000]).unwrap();
    std::fs::write(a_dir.join("hold/b.bin"), &data[300_000..]).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    let log = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_tracker(addr_of(1, &a), log.clone());
    let b_dir = dir.join("b");
    let b = block_on(builder(2).build()).unwrap();
    let id = block_on(b.add_torrent(
        AddTorrent::magnet(magnet_for(&bytes, &url), &b_dir).hold_after_metadata(true),
    ))
    .unwrap();
    wait_state(&b, id, TorrentState::Held, 20);
    let st = status(&b, id);
    assert!(st.has_metadata, "{st:?}");
    assert_eq!(st.pieces_have, 0);
    assert!(
        !b_dir.join("hold").exists(),
        "a held torrent creates nothing"
    );
    assert_eq!(block_on(b.files(id)).unwrap().len(), 2);
    let tf = block_on(b.torrent_file(id)).unwrap().unwrap();
    assert_eq!(
        metainfo::Torrent::parse(&tf).unwrap().info.info_hash,
        st.info_hash
    );
    // Stopped like the oracle: the tracker hears `stopped`, peers go.
    wait_for("the stopped announce", 10, || {
        events_of(&log).last().map(String::as_str) == Some("stopped")
    });
    wait_for("the peers to go", 10, || status(&b, id).peers == 0);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(status(&b, id).state, TorrentState::Held);

    // Layout while nothing exists: skip a.bin, move b.bin.
    block_on(b.set_file_priorities(id, vec![0, 4])).unwrap();
    block_on(b.rename_file(id, 1, "hold/kept/b.bin".into())).unwrap();
    assert!(!b_dir.join("hold").exists());

    // Release: checked, then paused; the file exists where it was put.
    block_on(b.release(id)).unwrap();
    wait_state(&b, id, TorrentState::Paused, 10);
    assert!(b_dir.join("hold/kept/b.bin").exists());
    assert!(!b_dir.join("hold/a.bin").exists());
    assert!(matches!(
        block_on(b.release(id)),
        Err(session::Error::Busy(_))
    ));

    // Resume: it downloads what is wanted and seeds.
    let before = events_of(&log).len();
    block_on(b.resume(id)).unwrap();
    wait_state(&b, id, TorrentState::Seeding, 30);
    assert_eq!(
        std::fs::read(b_dir.join("hold/kept/b.bin")).unwrap(),
        &data[300_000..]
    );
    assert!(!b_dir.join("hold/a.bin").exists());
    assert!(events_of(&log)[before..].iter().any(|e| e == "started"));
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_held_torrent_file_is_held_at_once_and_removed_without_trace() {
    let dir = tmp("hold-file");
    let resume = dir.join("resume");
    let (bytes, _) = make_torrent("h.bin", 256 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    let s = block_on(builder(1).build()).unwrap();
    let id = block_on(
        s.add_torrent(
            AddTorrent::metainfo(bytes, &dir)
                .resume_dir(&resume)
                .hold_after_metadata(true),
        ),
    )
    .unwrap();
    assert_eq!(status(&s, id).state, TorrentState::Held);
    // Pausing and resuming-all leave nothing half-started: resume-all
    // releases it like `resume`.
    block_on(s.pause(id)).unwrap();
    assert_eq!(status(&s, id).state, TorrentState::Held);
    assert!(!dir.join("h.bin").exists());
    block_on(s.remove_torrent(id)).unwrap();
    assert!(!dir.join("h.bin").exists());
    assert_eq!(
        std::fs::read_dir(&resume).map(|d| d.count()).unwrap_or(0),
        0,
        "no resume file left behind"
    );
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn statuses_carry_what_a_list_view_shows() {
    // One call per refresh, no per-torrent follow-ups: the tracker summary,
    // the sequential flag, distributed copies and the activity times.
    let dir = tmp("list");
    let (bytes, data) = make_torrent("l.bin", 2 << 20, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("l.bin"), &data).unwrap();
    let a = block_on(builder(1).upload_limit(1 << 20).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let a_st = status(&a, a_id);
    assert_eq!(
        a_st.distributed_copies(),
        None,
        "a seed reports none (libtorrent's -1)"
    );

    let log = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_tracker(addr_of(1, &a), log);
    let (bytes_b, _) = make_torrent("l.bin", 2 << 20, 64 * 1024, &url);
    assert_eq!(
        metainfo::Torrent::parse(&bytes_b).unwrap().info.info_hash,
        metainfo::Torrent::parse(&bytes).unwrap().info.info_hash
    );
    let b_dir = dir.join("b");
    let b = block_on(builder(2).build()).unwrap();
    // Same content, announced to the test tracker (the info dict is the
    // same, so is the info-hash).
    let id =
        block_on(b.add_torrent(AddTorrent::metainfo(bytes_b, &b_dir).sequential(true))).unwrap();
    let find = || {
        block_on(b.statuses())
            .unwrap()
            .into_iter()
            .find(|s| s.id == id)
            .unwrap()
    };
    wait_for("the tracker summary", 10, || {
        find().working_tracker.as_deref() == Some(url.as_str())
    });
    let st = find();
    assert!(st.trackers.is_empty(), "statuses() stays cheap");
    assert_eq!(st.trackers_count, 1);
    assert_eq!((st.swarm_seeders, st.swarm_leechers), (Some(1), Some(0)));
    assert!(st.sequential);
    // While downloading from the seed: at least one full copy (the seed's).
    wait_for("distributed copies", 10, || {
        find().distributed_copies().is_some_and(|c| c >= 1.0)
    });
    wait_state(&b, id, TorrentState::Seeding, 30);
    wait_for("the activity times", 5, || {
        let st = find();
        st.last_download.is_some() && st.last_seen_complete.is_some()
    });
    assert_eq!(find().distributed_copies(), None);
    wait_for("the seed's upload time", 5, || {
        status(&a, a_id).last_upload.is_some()
    });
    // They survive in resume data.
    let r = storage::ResumeData::decode(&block_on(b.resume_data(id)).unwrap()).unwrap();
    assert!(
        r.last_download.is_some() && r.last_seen_complete.is_some(),
        "{r:?}"
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_peer_the_engine_bans_is_reported() {
    // The only supplier of pieces that fail their hash is banned at once
    // (libtorrent trust points), and the caller hears of it.
    let (bytes, data) = make_torrent("ban.bin", 256 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    let hash = metainfo::Torrent::parse(&bytes).unwrap().info.info_hash;
    let mut bad = data.clone();
    for b in bad.iter_mut().step_by(1000) {
        *b ^= 0xff;
    }
    let seeder = spawn_seeder(hash, Arc::new(bad), 64 * 1024);
    let dir = tmp("ban");
    let s = block_on(builder(1).build()).unwrap();
    let mut events = s.events();
    let id = block_on(s.add_torrent(AddTorrent::metainfo(bytes, &dir))).unwrap();
    block_on(s.add_peer(id, seeder)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match events.try_recv() {
            Some(session::Event::PeerBanned {
                id: bid,
                ip,
                reason,
            }) => {
                assert_eq!(bid, id);
                assert_eq!(ip, seeder.ip());
                assert!(reason.contains("hash"), "{reason}");
                break;
            }
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "no PeerBanned event");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn trackers_show_each_listen_endpoint() {
    let dir = tmp("endpoints");
    let log = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_tracker(SocketAddr::from(([127, 0, 0, 9], 9)), log);
    let (bytes, data) = make_torrent("e.bin", 128 * 1024, 64 * 1024, &url);
    std::fs::write(dir.join("e.bin"), &data).unwrap();
    let s = block_on(builder(1).build()).unwrap();
    let id = block_on(s.add_torrent(AddTorrent::metainfo(bytes, &dir))).unwrap();
    wait_for("a working endpoint", 10, || {
        block_on(s.trackers(id))
            .unwrap()
            .first()
            .is_some_and(|t| t.endpoints.first().is_some_and(|e| e.working))
    });
    let t = block_on(s.trackers(id)).unwrap().remove(0);
    assert_eq!(t.endpoints.len(), 1, "IPv4 only: one endpoint");
    assert_eq!(t.endpoints[0].local, addr_of(1, &s));
    assert!(!t.updating && !t.endpoints[0].updating);
    assert_eq!(t.endpoints[0].seeders, Some(1));
    assert!(t.endpoints[0].next_announce_in.is_some());
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn each_file_completes_once_and_piece_priorities_hold_until_files_are_set() {
    let dir = tmp("files");
    let files = [
        ("f0.bin", 150_000usize),
        ("f1.bin", 200_000),
        ("f2.bin", 250_000),
    ];
    let (bytes, data) = make_multi_torrent("fc", &files, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(a_dir.join("fc")).unwrap();
    let mut off = 0;
    for (name, len) in files {
        std::fs::write(a_dir.join("fc").join(name), &data[off..off + len]).unwrap();
        off += len;
    }
    let a = block_on(builder(1).build()).unwrap();
    let mut a_events = a.events();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    // B wants the first two pieces only (f0 is 150 000 bytes: pieces 0-2).
    let b_dir = dir.join("b");
    let b = block_on(builder(2).build()).unwrap();
    let mut events = b.events();
    let id =
        block_on(b.add_torrent(AddTorrent::metainfo(bytes.clone(), &b_dir).paused(true))).unwrap();
    wait_state(&b, id, TorrentState::Paused, 10);
    let n = status(&b, id).pieces_total;
    let mut prios = vec![0u8; n];
    prios[0] = 7;
    prios[1] = 7;
    assert!(matches!(
        block_on(b.set_piece_priorities(id, vec![4; n - 1])),
        Err(session::Error::InvalidArgument(_))
    ));
    block_on(b.set_piece_priorities(id, prios.clone())).unwrap();
    assert_eq!(block_on(b.piece_priorities(id)).unwrap(), prios);
    block_on(b.resume(id)).unwrap();
    block_on(b.add_peer(id, addr_of(1, &a))).unwrap();
    wait_state(&b, id, TorrentState::Seeding, 30);
    assert_eq!(status(&b, id).pieces_have, 2, "only the wanted pieces");

    // The pieces survive in resume data.
    let blob = block_on(b.resume_data(id)).unwrap();
    assert_eq!(
        storage::ResumeData::decode(&blob).unwrap().piece_priorities,
        prios
    );

    // File priorities decide every piece again: everything is wanted.
    block_on(b.set_file_priorities(id, vec![4, 4, 4])).unwrap();
    assert!(
        block_on(b.piece_priorities(id))
            .unwrap()
            .iter()
            .all(|p| *p == 4)
    );
    wait_state(&b, id, TorrentState::Seeding, 30);
    let st = status(&b, id);
    assert_eq!(st.pieces_have, st.pieces_total);

    // Each file completed once, through a verify; the seed found its files
    // by checking, which reports none.
    let mut completed = Vec::new();
    while let Some(e) = events.try_recv() {
        if let session::Event::FileCompleted { id: fid, index } = e {
            assert_eq!(fid, id);
            completed.push(index);
        }
    }
    completed.sort_unstable();
    assert_eq!(completed, vec![0, 1, 2]);
    while let Some(e) = a_events.try_recv() {
        assert!(!matches!(e, session::Event::FileCompleted { .. }), "{e:?}");
    }
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_banned_range_keeps_peers_out_until_lifted() {
    let dir = tmp("ranges");
    let (bytes, data) = make_torrent("r.bin", 256 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("r.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    let b = block_on(builder(2).build()).unwrap();
    let lo: std::net::IpAddr = "127.0.0.0".parse().unwrap();
    let hi: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let v6: std::net::IpAddr = "::1".parse().unwrap();
    assert!(matches!(
        block_on(b.ban_ip_range(lo, v6)),
        Err(session::Error::InvalidArgument(_))
    ));
    assert!(matches!(
        block_on(b.ban_ip_range(hi, lo)),
        Err(session::Error::InvalidArgument(_))
    ));
    block_on(b.ban_ip_range(lo, hi)).unwrap();
    assert_eq!(block_on(b.banned_ip_ranges()).unwrap(), vec![(lo, hi)]);
    let id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, dir.join("b")))).unwrap();
    block_on(b.add_peer(id, addr_of(1, &a))).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let st = status(&b, id);
    assert_eq!((st.peers, st.pieces_have), (0, 0), "{st:?}");

    block_on(b.unban_ip_range(hi, hi)).unwrap();
    assert_eq!(block_on(b.banned_ip_ranges()).unwrap(), vec![(lo, lo)]);
    block_on(b.add_peer(id, addr_of(1, &a))).unwrap();
    wait_state(&b, id, TorrentState::Seeding, 30);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn add_peer_redials_the_metadata_peer_after_a_hold() {
    // ../urtorrentd/docs/gaps.md: after a hold, `add_peer` for the peer the
    // metadata came from waited out the 60 s reconnect backoff (the hold's
    // wind-down ran in that peer's own task and its disconnect landed after
    // `release` / `resume` / `add_peer`). It dials at once, as after an
    // ordinary pause / resume, whether released first or resumed straight
    // from the hold.
    for release_first in [true, false] {
        let dir = tmp(&format!("hold-redial-{release_first}"));
        let (bytes, data) = make_torrent("hr.bin", 512 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
        let a_dir = dir.join("a");
        std::fs::create_dir_all(&a_dir).unwrap();
        std::fs::write(a_dir.join("hr.bin"), &data).unwrap();
        let a = block_on(builder(1).build()).unwrap();
        let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
        wait_state(&a, a_id, TorrentState::Seeding, 10);

        let b = block_on(builder(2).build()).unwrap();
        let hash = metainfo::Torrent::parse(&bytes).unwrap().info.info_hash;
        let hex: String = hash.iter().map(|x| format!("{x:02x}")).collect();
        let id = block_on(
            b.add_torrent(
                AddTorrent::magnet(format!("magnet:?xt=urn:btih:{hex}"), dir.join("b"))
                    .hold_after_metadata(true),
            ),
        )
        .unwrap();
        block_on(b.add_peer(id, addr_of(1, &a))).unwrap();
        wait_state(&b, id, TorrentState::Held, 20);
        if release_first {
            block_on(b.release(id)).unwrap();
            wait_state(&b, id, TorrentState::Paused, 10);
        }
        block_on(b.resume(id)).unwrap();
        block_on(b.add_peer(id, addr_of(1, &a))).unwrap();
        let started = Instant::now();
        wait_state(&b, id, TorrentState::Seeding, 10);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "redialled after {:?}",
            started.elapsed()
        );
        assert_eq!(std::fs::read(dir.join("b/hr.bin")).unwrap(), data);
        block_on(b.shutdown()).unwrap();
        block_on(a.shutdown()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn every_change_the_resume_data_records_marks_it() {
    // ../urtorrentd/docs/gaps.md: a caller storing the blob itself learns of
    // changes only through `needs_resume_save` (libtorrent's
    // `need_save_resume_data`). Each operation that changes what the blob
    // records sets it; one that changes nothing does not; a queue move marks
    // every torrent whose position moved.
    let dir = tmp("dirty");
    let s = block_on(builder(1).build()).unwrap();
    let mut ids = Vec::new();
    for name in ["x.bin", "y.bin", "z.bin"] {
        let (bytes, data) = make_torrent(name, 128 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
        std::fs::write(dir.join(name), &data).unwrap();
        let id = block_on(s.add_torrent(AddTorrent::metainfo(bytes, &dir))).unwrap();
        wait_state(&s, id, TorrentState::Seeding, 10);
        ids.push(id);
    }
    let dirty = |id| status(&s, id).needs_resume_save;
    let save = |id| {
        let _ = block_on(s.resume_data(id)).unwrap();
        assert!(!dirty(id));
    };
    let x = ids[0];
    type Op<'a> = (&'a str, Box<dyn Fn() + 'a>);
    let ops: Vec<Op> = vec![
        (
            "add_tracker",
            Box::new(|| block_on(s.add_tracker(x, "http://127.0.0.1:1/b".into(), 1)).unwrap()),
        ),
        (
            "remove_tracker",
            Box::new(|| block_on(s.remove_tracker(x, "http://127.0.0.1:1/b".into())).unwrap()),
        ),
        (
            "set_sequential",
            Box::new(|| block_on(s.set_sequential(x, true)).unwrap()),
        ),
        (
            "set_torrent_rate_limits",
            Box::new(|| block_on(s.set_torrent_rate_limits(x, 1000, 0)).unwrap()),
        ),
        (
            "set_max_peers",
            Box::new(|| block_on(s.set_max_peers(x, Some(10))).unwrap()),
        ),
        (
            "set_max_uploads",
            Box::new(|| block_on(s.set_max_uploads(x, Some(2))).unwrap()),
        ),
        ("pause", Box::new(|| block_on(s.pause(x)).unwrap())),
        ("resume", Box::new(|| block_on(s.resume(x)).unwrap())),
        (
            "force_resume",
            Box::new(|| block_on(s.force_resume(x)).unwrap()),
        ),
        (
            "set_auto_managed",
            Box::new(|| block_on(s.set_auto_managed(x, true)).unwrap()),
        ),
    ];
    for (name, op) in &ops {
        save(x);
        op();
        assert!(dirty(x), "{name} left needs_resume_save unset");
    }
    // Changing nothing marks nothing.
    save(x);
    block_on(s.set_sequential(x, true)).unwrap();
    block_on(s.set_max_peers(x, Some(10))).unwrap();
    block_on(s.set_auto_managed(x, true)).unwrap();
    assert!(!dirty(x), "a no-op marked the resume data");

    // A queue move marks the moved torrent and every one it shifts.
    for &id in &ids {
        save(id);
    }
    block_on(s.move_in_queue(ids[2], session::QueueMove::Top)).unwrap();
    for &id in &ids {
        assert!(dirty(id), "queue position of {id:?} changed unmarked");
    }
    // Moving the last one down: nothing shifts.
    for &id in &ids {
        save(id);
    }
    let last = ids[1];
    block_on(s.move_in_queue(last, session::QueueMove::Bottom)).unwrap();
    for &id in &ids {
        assert!(!dirty(id), "{id:?} marked though its position stayed");
    }
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn http_trackers_web_seeds_and_peers_leave_from_the_listen_address() {
    // ../urtorrentd/docs/gaps.md: with the listen address on a VPN
    // interface, HTTP(S) announces and web-seed downloads took the default
    // route. Everything outgoing binds to the listen address in use, and
    // follows it when `set_listen` moves it. Loopback shows it: B listens on
    // 127.0.0.2 and 127.0.0.3, the servers are on 127.0.0.1, which an
    // unbound connection would come from.
    let dir = tmp("bind");
    let (tracker, log) = spawn_recording_tracker();
    let (bytes, data) = make_torrent("w.bin", 256 * 1024, 64 * 1024, &tracker);
    let data = Arc::new(data);
    let (seed_url, _hits, seed_from) = spawn_range_server_recording(data.clone(), "/w.bin");
    let b = block_on(builder(2).build()).unwrap();
    let id = block_on(b.add_torrent(AddTorrent::metainfo(bytes.clone(), dir.join("b")))).unwrap();
    block_on(b.add_web_seed(id, seed_url)).unwrap();
    wait_state(&b, id, TorrentState::Seeding, 30);
    wait_for("an announce", 10, || !log.lock().unwrap().is_empty());
    let two: std::net::IpAddr = "127.0.0.2".parse().unwrap();
    assert!(
        log.lock().unwrap().iter().all(|(from, _)| from.ip() == two),
        "{:?}",
        log.lock().unwrap()
    );
    assert!(!seed_from.lock().unwrap().is_empty());
    assert!(
        seed_from.lock().unwrap().iter().all(|a| a.ip() == two),
        "{:?}",
        seed_from.lock().unwrap()
    );

    // Move the listen address: announces and peer dials follow it. (The
    // new `started` can land before `set_listen` returns: count from here.)
    let three = Ipv4Addr::new(127, 0, 0, 3);
    let seen = log.lock().unwrap().len();
    let port = block_on(b.set_listen(0, Some(three), None)).unwrap();
    wait_for("the started announce from the new address", 10, || {
        log.lock().unwrap()[seen..].iter().any(|(from, line)| {
            from.ip() == std::net::IpAddr::V4(three)
                && event_param(line).as_deref() == Some("started")
        })
    });
    // From the new `started` on, everything comes from the new address
    // (an announce already in flight under the old one, the `stopped` owed
    // to it included, may land before).
    {
        let log = log.lock().unwrap();
        let restart = seen
            + log[seen..]
                .iter()
                .position(|(from, line)| {
                    from.ip() == std::net::IpAddr::V4(three)
                        && event_param(line).as_deref() == Some("started")
                })
                .unwrap();
        assert!(
            log[restart..]
                .iter()
                .all(|(from, _)| from.ip() == std::net::IpAddr::V4(three)),
            "{:?}",
            &log[seen..]
        );
    }
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    let (a_bytes, a_data) = make_torrent("p.bin", 128 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    std::fs::write(a_dir.join("p.bin"), &a_data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let mut a_events = a.events();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(a_bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let p_id = block_on(b.add_torrent(AddTorrent::metainfo(a_bytes, dir.join("b2")))).unwrap();
    block_on(b.add_peer(p_id, addr_of(1, &a))).unwrap();
    // The transfer is over in milliseconds and the two seeds part: A's
    // events, not its live peer list, say where B came from.
    let deadline = Instant::now() + Duration::from_secs(10);
    let from = loop {
        match a_events.try_recv() {
            Some(session::Event::PeerConnected {
                addr,
                incoming: true,
                ..
            }) => break addr,
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "B never reached A");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    assert_eq!(
        from.ip(),
        std::net::IpAddr::V4(three),
        "peer dialled from {from}"
    );
    assert_eq!(b.listen_port(), port);
    block_on(a.shutdown()).unwrap();
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_queue_position_is_set_in_one_call() {
    // ../urtorrentd/docs/gaps.md: dragging a row in a queue list puts a
    // torrent at a place in one call. 0 is first, past the end is last, the
    // others shift; the queue is re-planned at once, and only the torrents
    // whose position changed have their resume data marked.
    let dir = tmp("position");
    let s = block_on(
        builder(1)
            .active_limits(session::ActiveLimits {
                downloads: None,
                seeds: Some(1),
                total: None,
                count_slow: false,
            })
            .build(),
    )
    .unwrap();
    let mut ids = Vec::new();
    for name in ["p0.bin", "p1.bin", "p2.bin", "p3.bin"] {
        let (bytes, data) = make_torrent(name, 128 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
        std::fs::write(dir.join(name), &data).unwrap();
        ids.push(block_on(s.add_torrent(AddTorrent::metainfo(bytes, &dir))).unwrap());
    }
    wait_state(&s, ids[0], TorrentState::Seeding, 10);
    for &id in &ids[1..] {
        wait_state(&s, id, TorrentState::Queued, 10);
    }
    let order = || {
        let mut v: Vec<(usize, TorrentId)> = block_on(s.statuses())
            .unwrap()
            .into_iter()
            .map(|st| (st.queue_position, st.id))
            .collect();
        v.sort();
        v.into_iter().map(|(_, id)| id).collect::<Vec<_>>()
    };
    let save_all = || {
        for &id in &ids {
            let _ = block_on(s.resume_data(id)).unwrap();
            assert!(!status(&s, id).needs_resume_save);
        }
    };
    let dirty = || {
        ids.iter()
            .map(|&id| status(&s, id).needs_resume_save)
            .collect::<Vec<_>>()
    };
    let [t0, t1, t2, t3] = [ids[0], ids[1], ids[2], ids[3]];

    // Into the middle: the ones it passes shift down, the first stays put.
    save_all();
    block_on(s.set_queue_position(t3, 1)).unwrap();
    assert_eq!(order(), vec![t0, t3, t1, t2]);
    assert_eq!(dirty(), vec![false, true, true, true]);
    assert_eq!(state(&s, t0), TorrentState::Seeding);

    // To the front: it takes the only seed slot and the old first queues.
    save_all();
    block_on(s.set_queue_position(t2, 0)).unwrap();
    assert_eq!(order(), vec![t2, t0, t3, t1]);
    assert_eq!(dirty(), vec![true, true, true, true]);
    wait_state(&s, t2, TorrentState::Seeding, 10);
    wait_state(&s, t0, TorrentState::Queued, 10);

    // Past the end is last; the first is untouched.
    save_all();
    block_on(s.set_queue_position(t0, 1000)).unwrap();
    assert_eq!(order(), vec![t2, t3, t1, t0]);
    assert_eq!(dirty(), vec![true, true, false, true]);

    // Where it already is: nothing moves, nothing is marked.
    save_all();
    block_on(s.set_queue_position(t3, 1)).unwrap();
    block_on(s.set_queue_position(t0, 3)).unwrap();
    assert_eq!(order(), vec![t2, t3, t1, t0]);
    assert_eq!(dirty(), vec![false; 4]);

    // Positions stay dense after a removal; an unknown torrent is refused.
    block_on(s.remove_torrent(t3)).unwrap();
    assert_eq!(
        block_on(s.set_queue_position(t3, 0)),
        Err(session::Error::NoSuchTorrent)
    );
    block_on(s.set_queue_position(t1, 0)).unwrap();
    assert_eq!(order(), vec![t1, t2, t0]);
    let positions: Vec<usize> = [t1, t2, t0]
        .iter()
        .map(|&id| status(&s, id).queue_position)
        .collect();
    assert_eq!(positions, vec![0, 1, 2]);
    wait_state(&s, t1, TorrentState::Seeding, 10);
    wait_state(&s, t2, TorrentState::Queued, 10);
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_running_torrent_moving_no_data_is_reported_slow() {
    // ../urtorrentd/docs/gaps.md: the queue lets a torrent that has run for
    // 60 s below 2 KiB/s both ways go without a slot (unless `count_slow`),
    // and `TorrentStatus::slow` says which torrents are in that state. Two
    // sessions wait out the same minute: without `count_slow` the stalled
    // first download is slow and the second starts; with it the flag is the
    // same but the second keeps waiting. Once data flows the flag clears and
    // the first counts again, so the second queues again.
    let dir = tmp("slow");
    let (bytes, data) = make_torrent("s0.bin", 2 << 20, 64 * 1024, "http://127.0.0.1:1/x");
    let (bytes1, _) = make_torrent("s1.bin", 2 << 20, 64 * 1024, "http://127.0.0.1:1/x");
    let seed_dir = dir.join("seed");
    std::fs::create_dir_all(&seed_dir).unwrap();
    std::fs::write(seed_dir.join("s0.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &seed_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let limits = |count_slow| session::ActiveLimits {
        downloads: Some(1),
        seeds: None,
        total: None,
        count_slow,
    };
    let b = block_on(
        builder(2)
            .active_limits(limits(false))
            .download_limit(64 * 1024)
            .build(),
    )
    .unwrap();
    let c = block_on(builder(3).active_limits(limits(true)).build()).unwrap();
    let started = Instant::now();
    let mut two = Vec::new();
    for (s, who) in [(&b, "b"), (&c, "c")] {
        let d = dir.join(who);
        std::fs::create_dir_all(&d).unwrap();
        let t0 = block_on(s.add_torrent(AddTorrent::metainfo(bytes.clone(), &d))).unwrap();
        let t1 = block_on(s.add_torrent(AddTorrent::metainfo(bytes1.clone(), &d))).unwrap();
        wait_state(s, t0, TorrentState::Downloading, 10);
        wait_state(s, t1, TorrentState::Queued, 10);
        two.push((t0, t1));
    }
    let [(b0, b1), (c0, c1)] = [two[0], two[1]];
    for (s, id) in [(&b, b0), (&b, b1), (&c, c0), (&c, c1)] {
        assert!(!status(s, id).slow, "{id:?} slow at once");
    }

    // Not before a minute of running: the rates are zero from the start,
    // but a torrent that has just started is not slow yet.
    std::thread::sleep(Duration::from_secs(50).saturating_sub(started.elapsed()));
    assert!(!status(&b, b0).slow && !status(&c, c0).slow, "slow early");
    wait_for("b0 slow", 30, || status(&b, b0).slow);
    wait_for("c0 slow", 10, || status(&c, c0).slow);
    assert!(started.elapsed() >= Duration::from_secs(60));
    // Without count_slow the slot is free and the second download runs
    // (not slow itself: it has just started); with it, it waits.
    wait_state(&b, b1, TorrentState::Downloading, 10);
    assert!(!status(&b, b1).slow);
    assert_eq!(state(&c, c1), TorrentState::Queued);
    assert!(!status(&c, c1).slow, "a queued torrent is never slow");
    let listed = block_on(b.statuses()).unwrap();
    assert!(listed.iter().any(|st| st.id == b0 && st.slow));
    assert!(listed.iter().any(|st| st.id == b1 && !st.slow));

    // Data flows: the flag clears, the first holds its slot again and the
    // second goes back to the queue.
    block_on(b.add_peer(b0, addr_of(1, &a))).unwrap();
    wait_for("b0 moving", 30, || !status(&b, b0).slow);
    wait_state(&b, b1, TorrentState::Queued, 10);
    assert_eq!(state(&b, b0), TorrentState::Downloading);
    block_on(b.shutdown()).unwrap();
    block_on(c.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// An HTTP tracker answering every announce with `body` after `delay`; it
/// records the request lines.
fn spawn_answering_tracker(
    body: &'static [u8],
    delay: Duration,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
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
            let line = String::from_utf8_lossy(&got)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            log2.lock().unwrap().push(line);
            std::thread::sleep(delay);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    (format!("http://{addr}/announce"), log)
}

#[test]
fn a_tracker_reply_says_what_the_tracker_asked_for_and_how_long_it_took() {
    let dir = tmp("reply");
    let (url, _log) = spawn_answering_tracker(
        b"d8:intervali1234e12:min intervali77e5:peers0:e",
        Duration::from_millis(300),
    );
    let (bytes, _) = make_torrent("r.bin", 64 * 1024, 16 * 1024, &url);
    let s = block_on(builder(1).build()).unwrap();
    let mut events = s.events();
    let id = block_on(s.add_torrent(AddTorrent::metainfo(bytes, &dir))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match events.try_recv() {
            Some(session::Event::TrackerReply {
                id: rid,
                url: rurl,
                peers,
                interval,
                min_interval,
                response_time,
                ..
            }) => {
                assert_eq!((rid, rurl.as_str(), peers), (id, url.as_str(), 0));
                assert_eq!(interval, Duration::from_secs(1234));
                assert_eq!(min_interval, Some(Duration::from_secs(77)));
                assert!(
                    response_time >= Duration::from_millis(300)
                        && response_time < Duration::from_secs(10),
                    "{response_time:?}"
                );
                break;
            }
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "no TrackerReply event");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn one_tracker_is_reannounced_alone() {
    // Tier 0 holds a then b, tier 1 holds c. a satisfies tier 0, so b is
    // idle until it is reannounced by hand; then it alone is announced to.
    let dir = tmp("reannounce-one");
    let body: &[u8] = b"d8:intervali1800e5:peers0:e";
    let (a, a_log) = spawn_answering_tracker(body, Duration::ZERO);
    let (b, b_log) = spawn_answering_tracker(body, Duration::ZERO);
    let (c, c_log) = spawn_answering_tracker(body, Duration::ZERO);
    let (bytes, _) = make_torrent("o.bin", 64 * 1024, 16 * 1024, &a);
    let s = block_on(builder(1).build()).unwrap();
    let id = block_on(s.add_torrent(AddTorrent::metainfo(bytes, &dir).paused(true))).unwrap();
    block_on(s.add_tracker(id, b.clone(), 0)).unwrap();
    block_on(s.add_tracker(id, c.clone(), 1)).unwrap();
    block_on(s.resume(id)).unwrap();
    let working = |url: &str| {
        block_on(s.trackers(id))
            .unwrap()
            .iter()
            .any(|t| t.url == url && t.working)
    };
    wait_for("a and c to answer", 10, || working(&a) && working(&c));
    let count = |log: &Arc<Mutex<Vec<String>>>| log.lock().unwrap().len();
    assert_eq!((count(&a_log), count(&b_log), count(&c_log)), (1, 0, 1));

    block_on(s.force_reannounce_tracker(id, b.clone())).unwrap();
    wait_for("b's announce", 10, || working(&b));
    assert_eq!(events_of(&b_log), ["started"]);
    block_on(s.force_reannounce_tracker(id, c.clone())).unwrap();
    wait_for("c's second announce", 10, || count(&c_log) == 2);
    assert_eq!(
        event_param(&c_log.lock().unwrap()[1]),
        None,
        "a regular one"
    );
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        (count(&a_log), count(&b_log), count(&c_log)),
        (1, 1, 2),
        "no tracker but the one asked for"
    );

    assert!(matches!(
        block_on(s.force_reannounce_tracker(id, "http://127.0.0.1:1/nope".into())),
        Err(session::Error::InvalidArgument(_))
    ));
    assert!(matches!(
        block_on(s.force_reannounce_tracker(TorrentId(u64::MAX), a.clone())),
        Err(session::Error::NoSuchTorrent)
    ));
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A single-file torrent of `pieces` pieces whose hashes match nothing:
/// every piece a check looks at is hashed and fails.
fn hashless_torrent(name: &str, pieces: usize, piece_len: usize) -> Vec<u8> {
    let bstr = |out: &mut Vec<u8>, s: &[u8]| {
        out.extend_from_slice(format!("{}:", s.len()).as_bytes());
        out.extend_from_slice(s);
    };
    let mut t = b"d8:announce19:http://127.0.0.1:1/4:infod".to_vec();
    bstr(&mut t, b"length");
    t.extend_from_slice(format!("i{}e", pieces * piece_len).as_bytes());
    bstr(&mut t, b"name");
    bstr(&mut t, name.as_bytes());
    bstr(&mut t, b"piece length");
    t.extend_from_slice(format!("i{piece_len}e").as_bytes());
    bstr(&mut t, b"pieces");
    bstr(&mut t, &vec![0xab; pieces * 20]);
    t.extend_from_slice(b"ee");
    t
}

/// `pieces_checked` while the torrent checks, until it leaves the check.
fn sample_check(s: &Session, id: TorrentId, pieces: usize) -> Vec<usize> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut seen = Vec::new();
    loop {
        let st = status(s, id);
        match st.state {
            TorrentState::Checking => seen.push(st.pieces_checked),
            TorrentState::QueuedForChecking => assert_eq!(st.pieces_checked, 0),
            _ => {
                assert_eq!(st.pieces_checked, 0, "0 outside a check: {st:?}");
                return seen;
            }
        }
        assert!(st.pieces_checked <= pieces);
        assert!(Instant::now() < deadline, "the check never ended");
    }
}

fn assert_progressed(seen: &[usize], pieces: usize) {
    assert!(
        seen.windows(2).all(|w| w[0] <= w[1]),
        "never backwards: {seen:?}"
    );
    assert!(
        seen.iter().any(|&c| c > 0 && c < pieces),
        "a value between the ends: {:?}..{:?} ({} samples)",
        seen.first(),
        seen.last(),
        seen.len()
    );
}

#[test]
fn a_check_reports_how_far_it_has_got() {
    // A sparse file under 4096 small pieces: the check reads and hashes
    // every piece (none verifies) without the test writing the data.
    let dir = tmp("check-progress");
    let (pieces, piece_len) = (4096, 16 * 1024);
    let bytes = hashless_torrent("c.bin", pieces, piece_len);
    std::fs::File::create(dir.join("c.bin"))
        .unwrap()
        .set_len((pieces * piece_len) as u64)
        .unwrap();
    let s = block_on(builder(1).build()).unwrap();
    let started = Instant::now();
    let id = block_on(s.add_torrent(AddTorrent::metainfo(bytes, &dir))).unwrap();
    let seen = sample_check(&s, id, pieces);
    eprintln!(
        "initial check: {:?}, {} samples",
        started.elapsed(),
        seen.len()
    );
    assert_progressed(&seen, pieces);
    let st = status(&s, id);
    assert_eq!((st.state, st.pieces_have), (TorrentState::Downloading, 0));

    // A recheck counts from 0 again.
    let s2 = s.clone();
    let recheck = std::thread::spawn(move || block_on(s2.force_recheck(id)));
    // Polled without a pause: the recheck must not end unseen.
    let deadline = Instant::now() + Duration::from_secs(10);
    while state(&s, id) != TorrentState::Checking {
        assert!(Instant::now() < deadline, "the recheck never started");
    }
    let seen = sample_check(&s, id, pieces);
    recheck.join().unwrap().unwrap();
    assert_progressed(&seen, pieces);
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
