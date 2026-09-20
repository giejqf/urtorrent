// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! End-to-end inside one process: the engine leeches a generated torrent from
//! a std-thread seeder (driven by the sans-IO `wire::Connection`) discovered
//! through a tiny HTTP tracker. Asserts the file, the truthful counters, and
//! the `started` / `completed` / `stopped` announce sequence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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

    // Delete the content: the resume data must not be trusted any more and a
    // recheck finds nothing (never claim pieces we do not have).
    std::fs::remove_file(dir.join("save").join("leech.bin")).unwrap();
    let session = block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::LOCALHOST))
            .listen_v6(None)
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
    let st = block_on(session.status(id)).unwrap();
    assert_eq!(st.state, TorrentState::Paused);
    assert_eq!(st.pieces_have, 0);
    assert_eq!(st.left, size as u64);
    block_on(session.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn add_twice_is_duplicate_and_magnet_is_unsupported() {
    let dir = std::env::temp_dir().join(format!("urt-session-dup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (torrent_bytes, _) = make_torrent("dup.bin", 1000, 16384, "http://127.0.0.1:1/announce");
    let session = block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::LOCALHOST))
            .listen_v6(None)
            .build(),
    )
    .unwrap();
    let id =
        block_on(session.add_torrent(AddTorrent::metainfo(torrent_bytes.clone(), &dir))).unwrap();
    assert_eq!(
        block_on(session.add_torrent(AddTorrent::metainfo(torrent_bytes, &dir))),
        Err(session::Error::Duplicate)
    );
    assert!(matches!(
        block_on(session.add_torrent(AddTorrent {
            source: session::TorrentSource::Magnet(
                "magnet:?xt=urn:btih:0000000000000000000000000000000000000000".into()
            ),
            save_path: dir.clone(),
            resume_dir: None,
            paused: false,
            sequential: false,
        })),
        Err(session::Error::Unsupported(_))
    ));
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
