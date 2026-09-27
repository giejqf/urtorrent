// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Resume data as a blob the caller stores (libtorrent's
//! `write_resume_data_buf` / `read_resume_data`): what it carries survives
//! a restart without a `resume_dir`, verified pieces are not rechecked,
//! partly written pieces are not downloaded again, and the dirty flag tells
//! a caller when to fetch a fresh blob.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate urtorrent_session as session;

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::{block_on, make_torrent};
use session::{AddTorrent, PeerSource, Session, SessionBuilder, TorrentId, TorrentState};

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
    let dir = std::env::temp_dir().join(format!("urt-resume-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn blob_round_trip_restores_everything_without_a_resume_dir() {
    let dir = tmp("blob");
    // 1 MiB pieces: a partly written piece is worth keeping.
    let (bytes, data) = make_torrent("r.bin", 8 << 20, 1 << 20, "http://127.0.0.1:1/a");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("r.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);

    // First run: download about half at a limited rate, then take the
    // blob mid-piece and drop the torrent without any resume directory.
    let b = block_on(builder(2).download_limit(2 << 20).build()).unwrap();
    let b_dir = dir.join("b");
    let b_id = block_on(
        b.add_torrent(
            AddTorrent::metainfo(bytes.clone(), &b_dir)
                .sequential(true)
                .upload_limit(4321),
        ),
    )
    .unwrap();
    assert!(!block_on(b.status(b_id)).unwrap().needs_resume_save);
    block_on(b.add_tracker(b_id, "http://127.0.0.1:1/b".into(), 1)).unwrap();
    block_on(b.add_web_seed(b_id, "http://127.0.0.1:1/ws/".into())).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let st = block_on(b.status(b_id)).unwrap();
        if st.pieces_have >= 2 && st.pieces_have <= 5 {
            break;
        }
        assert!(Instant::now() < deadline, "{st:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(block_on(b.status(b_id)).unwrap().needs_resume_save);
    let blob = block_on(b.resume_data(b_id)).unwrap();
    let first = block_on(b.status(b_id)).unwrap();
    assert!(!first.needs_resume_save, "resume_data clears the flag");
    let added_on = first.added_on;
    assert!(added_on > 1_700_000_000);
    block_on(b.remove_torrent(b_id)).unwrap();
    block_on(b.shutdown()).unwrap();

    // What the blob says.
    let r = storage::ResumeData::decode(&blob).unwrap();
    assert_eq!(r.format_version, storage::FORMAT_VERSION);
    assert_eq!(r.have.count(), first.pieces_have);
    assert!(r.sequential);
    assert_eq!(r.upload_limit, 4321);
    assert_eq!(
        r.trackers,
        vec![
            vec!["http://127.0.0.1:1/a".to_string()],
            vec!["http://127.0.0.1:1/b".to_string()]
        ]
    );
    assert_eq!(r.web_seeds, vec!["http://127.0.0.1:1/ws/".to_string()]);
    assert_eq!(r.added_time, added_on);
    assert!(r.peers.contains(&addr_of(1, &a)), "{:?}", r.peers);
    let restored: u64 = r
        .unfinished
        .iter()
        .flat_map(|(_, ranges)| ranges.iter().map(|(s, e)| u64::from(e - s)))
        .sum();
    assert!(!r.unfinished.is_empty(), "a piece was in progress: {r:?}");
    let verified = u64::from(r.have.count() as u32) * (1 << 20);

    // Second run: no resume_dir, the blob alone. No recheck (Downloading
    // straight away with the verified pieces), the peer from the blob is
    // dialled without add_peer, the partial piece is not fetched again.
    let b = block_on(builder(2).build()).unwrap();
    let mut events = b.events();
    let b_id =
        block_on(b.add_torrent(AddTorrent::metainfo(bytes, &b_dir).resume_data(blob))).unwrap();
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(st.pieces_have, first.pieces_have, "{st:?}");
    assert!(st.state == TorrentState::Downloading || st.state == TorrentState::Checking && false);
    assert_eq!(st.added_on, added_on);
    assert_eq!(st.trackers.len(), 2);
    assert_eq!(st.web_seed_urls.len(), 1);
    assert_eq!(st.upload_limit, 4321);
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    let done = block_on(b.status(b_id)).unwrap();
    assert_eq!(std::fs::read(b_dir.join("r.bin")).unwrap(), data);
    // Bytes fetched this run: the torrent minus what came back from the
    // blob (verified pieces and the restored ranges, whole blocks of them),
    // with slack for the partial block at each range end and the end game.
    let size = 8u64 << 20;
    let fetched = done.downloaded - first.downloaded;
    assert!(
        fetched + verified + restored <= size + 64 * 1024 + done.redundant,
        "fetched {fetched} + verified {verified} + restored {restored} > {size}: {done:?}"
    );
    assert!(done.completed_on.is_some());
    // The peer came from the blob.
    let deadline = Instant::now() + Duration::from_secs(10);
    let source = loop {
        match events.try_recv() {
            Some(session::Event::PeerDisconnected { id, info, .. }) if id == b_id => {
                break info.source;
            }
            Some(_) => {}
            None => {
                assert!(Instant::now() < deadline, "no PeerDisconnected");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    assert_eq!(source, PeerSource::Resume);
    // The blob is rejected for another torrent.
    let (other, _) = make_torrent("other.bin", 64 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    let blob2 = block_on(b.resume_data(b_id)).unwrap();
    let o_id =
        block_on(b.add_torrent(AddTorrent::metainfo(other, dir.join("o")).resume_data(blob2)))
            .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(block_on(b.status(o_id)).unwrap().pieces_have, 0);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_fully_written_unverified_piece_is_verified_on_restore() {
    // Every block of a piece written, resume taken before the hash ran:
    // on restore the piece is hashed from disk and counted, not fetched.
    let dir = tmp("verify");
    let (bytes, data) = make_torrent("v.bin", 2 << 20, 256 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("v.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    let b = block_on(builder(2).build()).unwrap();
    let b_dir = dir.join("b");
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes.clone(), &b_dir))).unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 30);
    let blob = block_on(b.resume_data(b_id)).unwrap();
    block_on(b.remove_torrent(b_id)).unwrap();
    block_on(b.shutdown()).unwrap();
    // Forge the situation: the blob claims no verified piece but every
    // byte of every piece written (the data is on disk and correct).
    let mut r = storage::ResumeData::decode(&blob).unwrap();
    let pieces = r.have.len();
    r.have = metainfo::Bitfield::new(pieces);
    r.unfinished = (0..pieces as u32)
        .map(|p| (p, vec![(0u32, 256 * 1024u32)]))
        .collect();
    let forged = r.encode();
    let b = block_on(builder(2).build()).unwrap();
    let b_id =
        block_on(b.add_torrent(AddTorrent::metainfo(bytes, &b_dir).resume_data(forged))).unwrap();
    // No peer at all: completion can only come from the restored bytes.
    wait_state(&b, b_id, TorrentState::Seeding, 30);
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(st.pieces_have, pieces);
    assert_eq!(st.corrupt, 0);
    assert_eq!(std::fs::read(b_dir.join("v.bin")).unwrap(), data);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_restored_ranges_fail_the_hash_and_are_fetched_again() {
    // The blob claims written ranges but the bytes on disk are wrong (a
    // crash in the middle of a write, say): the piece fails its hash when
    // completed and is downloaded again; nothing is claimed to peers.
    let dir = tmp("corrupt");
    let (bytes, data) = make_torrent("c.bin", 1 << 20, 256 * 1024, "http://127.0.0.1:1/x");
    let a_dir = dir.join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::write(a_dir.join("c.bin"), &data).unwrap();
    let a = block_on(builder(1).build()).unwrap();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(bytes.clone(), &a_dir))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    // A file of the right size full of garbage, and a blob claiming the
    // first half of piece 0 is written.
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    std::fs::write(b_dir.join("c.bin"), vec![0x5au8; 1 << 20]).unwrap();
    let mut r = storage::ResumeData::empty(
        metainfo::Torrent::parse(&bytes).unwrap().info.info_hash,
        256 * 1024,
        1 << 20,
        4,
    );
    r.unfinished = vec![(0, vec![(0, 128 * 1024)])];
    let b = block_on(builder(2).build()).unwrap();
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(bytes, &b_dir).resume_data(r.encode())))
        .unwrap();
    block_on(b.add_peer(b_id, addr_of(1, &a))).unwrap();
    wait_state(&b, b_id, TorrentState::Seeding, 60);
    let st = block_on(b.status(b_id)).unwrap();
    assert_eq!(std::fs::read(b_dir.join("c.bin")).unwrap(), data);
    assert!(st.corrupt > 0 || st.downloaded >= 1 << 20, "{st:?}");
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
