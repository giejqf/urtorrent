// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! What a daemon (an HTTP API in front of the library) needs and would
//! otherwise have to work around: the `.torrent` back out for persistence,
//! per-piece state for a piece bar, cheap list snapshots, runtime settings,
//! a session-wide ban list, web seeds added and removed live, files renamed
//! in place, and per-torrent settings that survive in resume data.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate urtorrent_session as session;

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{block_on, make_multi_torrent, make_torrent, spawn_range_server};
use session::{
    ActiveLimits, AddTorrent, EncryptionMode, PieceState, Session, SessionBuilder, TorrentId,
    TorrentState, TransportPolicy,
};

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
    let dir = std::env::temp_dir().join(format!("urt-daemon-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A `.torrent` with `comment`, `created by`, `creation date` and a second
/// tracker tier spliced in (the root dict stays sorted).
fn decorated_torrent(size: usize) -> (Vec<u8>, Vec<u8>) {
    let (t, data) = make_torrent("d.bin", size, 64 * 1024, "http://127.0.0.1:1/a");
    // "announce" | "announce-list" | "comment" | "created by" | "creation date" | "info"
    let info_at = t.windows(6).position(|w| w == b"4:info").unwrap();
    let mut out = t[..info_at].to_vec();
    out.extend_from_slice(b"13:announce-listll20:http://127.0.0.1:1/ael20:http://127.0.0.1:1/bee");
    out.extend_from_slice(b"7:comment5:hello");
    out.extend_from_slice(b"10:created by4:test");
    out.extend_from_slice(b"13:creation datei1700000000e");
    out.extend_from_slice(&t[info_at..]);
    (out, data)
}

#[test]
fn torrent_file_round_trips_with_metadata_extras_and_current_trackers() {
    let dir = tmp("torrentfile");
    let (bytes, data) = decorated_torrent(256 * 1024);
    let meta = metainfo::Torrent::parse(&bytes).unwrap();
    std::fs::write(dir.join("d.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &dir))).unwrap();
    wait_state(&a, id, TorrentState::Seeding, 10);
    let st = block_on(a.status(id)).unwrap();
    assert_eq!(st.comment.as_deref(), Some("hello"));
    assert_eq!(st.created_by.as_deref(), Some("test"));
    assert_eq!(st.creation_date, Some(1_700_000_000));
    assert_eq!(st.piece_length, 64 * 1024);
    // Trackers changed live show up in the file; the info-hash is preserved.
    block_on(a.add_tracker(id, "http://127.0.0.1:1/c".into(), 2)).unwrap();
    block_on(a.remove_tracker(id, "http://127.0.0.1:1/b".into())).unwrap();
    block_on(a.add_web_seed(id, "http://127.0.0.1:1/ws/".into())).unwrap();
    let file = block_on(a.torrent_file(id))
        .unwrap()
        .expect("metadata known");
    let back = metainfo::Torrent::parse(&file).unwrap();
    assert_eq!(back.info.info_hash, meta.info.info_hash);
    assert_eq!(back.comment.as_deref(), Some("hello"));
    assert_eq!(back.created_by.as_deref(), Some("test"));
    assert_eq!(back.creation_date, Some(1_700_000_000));
    assert_eq!(back.announce.as_deref(), Some("http://127.0.0.1:1/a"));
    assert_eq!(
        back.announce_list,
        vec![
            vec!["http://127.0.0.1:1/a".to_string()],
            vec!["http://127.0.0.1:1/c".to_string()]
        ]
    );
    assert_eq!(back.url_list, vec!["http://127.0.0.1:1/ws/".to_string()]);
    // The file re-adds on a fresh session (the daemon's restart path).
    block_on(a.shutdown()).unwrap();
    let b = block_on(builder(1).build()).unwrap();
    let id2 = block_on(b.add_torrent(AddTorrent::metainfo(file, &dir))).unwrap();
    wait_state(&b, id2, TorrentState::Seeding, 10);
    let st = block_on(b.status(id2)).unwrap();
    assert_eq!(st.info_hash, meta.info.info_hash);
    assert_eq!(st.trackers.len(), 2);
    assert_eq!(st.web_seed_urls, vec!["http://127.0.0.1:1/ws/".to_string()]);
    // A magnet without metadata has no file yet.
    let m = block_on(b.add_torrent(AddTorrent::magnet(
        "magnet:?xt=urn:btih:0000000000000000000000000000000000000001",
        &dir,
    )))
    .unwrap();
    assert_eq!(block_on(b.torrent_file(m)).unwrap(), None);
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pieces_files_trackers_and_slim_list_snapshots() {
    let dir = tmp("pieces");
    let (bytes, data) = make_torrent("p.bin", 4 << 20, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("p.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let pieces = block_on(a.pieces(a_id)).unwrap();
    assert_eq!(pieces.len(), 64);
    assert!(pieces.iter().all(|p| p.state == PieceState::Have));

    let b = block_on(builder(2).download_limit(512 * 1024).build()).unwrap();
    let b_dir = dir.join("b");
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, &b_dir))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    // Mid-download: some pieces have, some downloading, availability 1 from
    // the seed.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let pieces = block_on(b.pieces(b_id)).unwrap();
        let have = pieces
            .iter()
            .filter(|p| p.state == PieceState::Have)
            .count();
        let downloading = pieces
            .iter()
            .filter(|p| p.state == PieceState::Downloading)
            .count();
        if have > 0 && downloading > 0 && have + downloading < 64 {
            assert!(pieces.iter().all(|p| p.availability == 1), "{pieces:?}");
            break;
        }
        assert!(Instant::now() < deadline, "no mid-download snapshot");
        std::thread::sleep(Duration::from_millis(10));
    }
    // The list snapshot leaves per-file / per-tracker detail out; the
    // per-torrent calls fill it.
    let list = block_on(b.statuses()).unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0].files.is_empty() && list[0].trackers.is_empty());
    assert_eq!(list[0].pieces_total, 64);
    let full = block_on(b.status(b_id)).unwrap();
    assert_eq!(full.files.len(), 1);
    assert_eq!(full.trackers.len(), 1);
    // (`done` moves between two snapshots of a live download.)
    let files = block_on(b.files(b_id)).unwrap();
    assert_eq!(files.len(), full.files.len());
    assert_eq!(files[0].path, full.files[0].path);
    assert_eq!(files[0].size, full.files[0].size);
    assert_eq!(block_on(b.trackers(b_id)).unwrap().len(), 1);
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    assert!(
        block_on(b.pieces(b_id))
            .unwrap()
            .iter()
            .all(|p| p.state == PieceState::Have)
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn runtime_settings_snapshot_and_switches() {
    let dir = tmp("settings");
    let a = block_on(
        builder(1)
            .encryption(EncryptionMode::Disabled)
            .transports(TransportPolicy::TcpOnly)
            .pex(false)
            .build(),
    )
    .unwrap();
    let s = block_on(a.settings()).unwrap();
    assert_eq!(s.listen_port, a.listen_port());
    assert_eq!(s.listen_v4, Some(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(s.listen_v6, None);
    assert!(!s.dht && !s.pex && !s.lsd);
    assert_eq!(s.encryption, EncryptionMode::Disabled);
    assert_eq!(s.transports, TransportPolicy::TcpOnly);
    assert_eq!(s.active_limits, ActiveLimits::UNLIMITED);
    assert_eq!(s.profile, "native");
    block_on(a.set_encryption(EncryptionMode::Forced)).unwrap();
    block_on(a.set_transports(TransportPolicy::PreferTcp)).unwrap();
    block_on(a.set_pex(true)).unwrap();
    block_on(a.set_lsd(true)).unwrap();
    block_on(a.set_rate_limits(1 << 20, 2 << 20)).unwrap();
    block_on(a.set_unchoke_slots(3)).unwrap();
    block_on(a.set_max_connections(42)).unwrap();
    block_on(a.set_max_peers_per_torrent(7)).unwrap();
    let s = block_on(a.settings()).unwrap();
    assert_eq!(s.encryption, EncryptionMode::Forced);
    assert_eq!(s.transports, TransportPolicy::PreferTcp);
    assert!(s.pex && s.lsd);
    assert_eq!((s.upload_limit, s.download_limit), (1 << 20, 2 << 20));
    assert_eq!(
        (s.unchoke_slots, s.max_connections, s.max_peers_per_torrent),
        (3, 42, 7)
    );
    block_on(a.set_lsd(false)).unwrap();
    assert!(!block_on(a.settings()).unwrap().lsd);

    // Encryption switched at runtime governs new connections: a
    // plaintext-only peer is refused by a session forced to MSE after the
    // fact, and accepted again once the policy is relaxed.
    let (bytes, data) = make_torrent("e.bin", 256 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    std::fs::write(dir.join("e.bin"), &data).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let b = block_on(builder(2).encryption(EncryptionMode::Disabled).build()).unwrap();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, dir.join("b")))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(st.state, TorrentState::Downloading, "{st:?}");
    assert_eq!(st.peers, 0, "plaintext refused while forced: {st:?}");
    block_on(a.set_encryption(EncryptionMode::Enabled)).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn session_ban_list_drops_dials_and_accepts() {
    let dir = tmp("ban");
    let (bytes, data) = make_torrent("ban.bin", 2 << 20, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("ban.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let seeder_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let leecher_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    // The leecher bans the seeder before learning it: never dialled.
    let b = block_on(builder(2).download_limit(256 * 1024).build()).unwrap();
    block_on(b.ban_ip(seeder_ip)).unwrap();
    assert_eq!(block_on(b.banned_ips()).unwrap(), vec![seeder_ip]);
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, dir.join("b")))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(block_on(b.status(b_id)).unwrap().peers, 0);
    // Unbanned and added again: connects and downloads.
    block_on(b.unban_ip(seeder_ip)).unwrap();
    assert!(block_on(b.banned_ips()).unwrap().is_empty());
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while block_on(b.status(b_id)).unwrap().downloaded == 0 {
        assert!(Instant::now() < deadline, "no download after unban");
        std::thread::sleep(Duration::from_millis(20));
    }
    // The seeder bans the leecher mid-transfer: the connection drops and
    // the leecher's redials are refused before any handshake.
    block_on(a.ban_ip(leecher_ip)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while block_on(a.status(a_id)).unwrap().peers > 0 {
        assert!(Instant::now() < deadline, "banned peer still connected");
        std::thread::sleep(Duration::from_millis(20));
    }
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(block_on(a.status(a_id)).unwrap().peers, 0);
    assert_ne!(
        block_on(b.status(b_id)).unwrap().state,
        TorrentState::Seeding
    );
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn web_seed_added_at_runtime_completes_the_download() {
    let dir = tmp("webseed");
    let size = 1024 * 1024 + 999;
    let (bytes, data) = make_torrent("ws.bin", size, 64 * 1024, "http://127.0.0.1:1/x");
    let data = Arc::new(data);
    let (url, hits) = spawn_range_server(data.clone(), "/files/ws.bin");
    let b = block_on(builder(2).build()).unwrap();
    let b_dir = dir.join("b");
    let id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, &b_dir))).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        block_on(b.status(id)).unwrap().state,
        TorrentState::Downloading
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), 0);
    block_on(b.add_web_seed(id, url.clone())).unwrap();
    assert_eq!(
        block_on(b.status(id)).unwrap().web_seed_urls,
        vec![url.clone()]
    );
    wait_state(&b, id, TorrentState::Seeding, 60);
    assert_eq!(std::fs::read(b_dir.join("ws.bin")).unwrap(), *data);
    block_on(b.remove_web_seed(id, url)).unwrap();
    assert!(block_on(b.status(id)).unwrap().web_seed_urls.is_empty());
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rename_file_moves_the_file_and_the_name_survives_resume() {
    let dir = tmp("rename");
    let files = [
        ("a.bin", 200_000usize),
        ("sub/b.bin", 300_000),
        ("c.bin", 150_000),
    ];
    let (bytes, data) = make_multi_torrent("rn", &files, 64 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(a_dir.join("rn/sub")).unwrap();
    std::fs::write(a_dir.join("rn/a.bin"), &data[..200_000]).unwrap();
    std::fs::write(a_dir.join("rn/sub/b.bin"), &data[200_000..500_000]).unwrap();
    std::fs::write(a_dir.join("rn/c.bin"), &data[500_000..]).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    // Rename on the seeder: the file moves, the seed keeps serving it.
    block_on(a.rename_file(a_id, 1, "rn/sub/renamed/bee.bin".into())).unwrap();
    assert!(a_dir.join("rn/sub/renamed/bee.bin").exists());
    assert!(!a_dir.join("rn/sub/b.bin").exists());
    let st = block_on(a.status(a_id)).unwrap();
    assert_eq!(st.files[1].path, "rn/sub/renamed/bee.bin");
    assert_eq!(st.state, TorrentState::Seeding);
    // Hostile or clashing names are refused.
    assert!(block_on(a.rename_file(a_id, 0, "../escape.bin".into())).is_err());
    assert!(block_on(a.rename_file(a_id, 0, "rn/c.bin".into())).is_err());
    assert!(block_on(a.rename_file(a_id, 9, "x".into())).is_err());

    // The leecher renames a file before it exists: it is created under the
    // new name, and after a restart with resume data the name sticks.
    let b = block_on(builder(2).build()).unwrap();
    let b_dir = dir.join("b");
    let resume = dir.join("resume");
    let b_id = block_on(
        b.add_torrent(
            AddTorrent::metainfo(bytes.clone(), &b_dir)
                .resume_dir(&resume)
                .sequential(true)
                .upload_limit(12_345)
                .max_uploads(2),
        ),
    )
    .unwrap();
    block_on(b.rename_file(b_id, 0, "first.bin".into())).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    assert_eq!(
        std::fs::read(b_dir.join("first.bin")).unwrap(),
        &data[..200_000]
    );
    assert!(!b_dir.join("rn/a.bin").exists());
    block_on(b.save_resume_data(b_id)).unwrap();
    block_on(b.shutdown()).unwrap();
    let b = block_on(builder(2).build()).unwrap();
    let b_id =
        block_on(b.add_torrent(AddTorrent::metainfo(bytes, &b_dir).resume_dir(&resume))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 10);
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(st.files[0].path, "first.bin");
    assert_eq!(st.pieces_have, st.pieces_total, "no recheck needed: {st:?}");
    // The per-torrent settings came back from the resume data too.
    assert_eq!(st.upload_limit, 12_345);
    assert_eq!(st.max_uploads, Some(2));
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The handle, the event stream and the error type cross tokio task
/// boundaries (a daemon shares one `Session` between request handlers and
/// consumes events on a spawned task).
#[test]
fn handles_are_send_sync_and_errors_are_std_errors() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    fn assert_send<T: Send + 'static>() {}
    fn assert_error<T: std::error::Error + Send + Sync + 'static>() {}
    assert_send_sync::<Session>();
    assert_send::<session::EventStream>();
    assert_error::<session::Error>();
    assert_send_sync::<session::TorrentStatus>();
    assert_send_sync::<session::Event>();
}
