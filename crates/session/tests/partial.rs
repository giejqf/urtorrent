// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Seeding from a partial selection: a torrent that downloaded some of its
//! files serves them (the pieces straddling a skipped file read back through
//! the parts file) and advertises exactly what it has; a restart and a check
//! find the same pieces; a complete file that is deselected keeps being
//! seeded, untouched.
//!
//! Layout: `a.bin` 200 000 | `sub/b.bin` 300 000 | `c.bin` 150 000, 64 KiB
//! pieces. Skipping `b.bin` leaves pieces 3 and 7 straddling it (their
//! `b.bin` bytes live in the parts file) and pieces 4-6 wholly inside it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{block_on, make_multi_torrent};
use session::{AddTorrent, Session, SessionBuilder, TorrentId, TorrentState, TransportPolicy};

const PIECE: usize = 64 * 1024;
const FILES: [(&str, usize); 3] = [
    ("a.bin", 200_000),
    ("sub/b.bin", 300_000),
    ("c.bin", 150_000),
];
/// Pieces a `[4, 0, 4]` selection has: 0-3 and 7-9.
const SELECTED: usize = 7;

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

fn addr_of(n: u8, s: &Session) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, 0, 0, n).into(), s.listen_port())
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("urt-partial-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn status(s: &Session, id: TorrentId) -> session::TorrentStatus {
    block_on(s.status(id)).unwrap()
}

fn wait_for<F: Fn() -> bool>(what: &str, secs: u64, f: F) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The torrent and its content.
fn fixture() -> (Vec<u8>, Vec<u8>) {
    make_multi_torrent("sel", &FILES, PIECE, "http://127.0.0.1:1/x")
}

/// Write the whole content under `dir` and seed it from session `n`.
fn full_seed(n: u8, dir: &Path, bytes: &[u8], data: &[u8]) -> (Session, TorrentId) {
    std::fs::create_dir_all(dir.join("sel/sub")).unwrap();
    std::fs::write(dir.join("sel/a.bin"), &data[..200_000]).unwrap();
    std::fs::write(dir.join("sel/sub/b.bin"), &data[200_000..500_000]).unwrap();
    std::fs::write(dir.join("sel/c.bin"), &data[500_000..]).unwrap();
    let s = block_on(builder(n).build()).unwrap();
    let id = block_on(s.add_torrent(AddTorrent::metainfo(bytes.to_vec(), dir))).unwrap();
    wait_for("the full seed", 10, || {
        status(&s, id).state == TorrentState::Seeding
    });
    (s, id)
}

/// Session `n` downloads the `[4, 0, 4]` selection from `from` into `dir`.
fn partial_from(
    n: u8,
    from: SocketAddr,
    dir: &Path,
    bytes: &[u8],
    resume: Option<&Path>,
) -> (Session, TorrentId) {
    let s = block_on(builder(n).build()).unwrap();
    let mut add = AddTorrent::metainfo(bytes.to_vec(), dir).file_priorities(vec![4, 0, 4]);
    if let Some(r) = resume {
        add = add.resume_dir(r);
    }
    let id = block_on(s.add_torrent(add)).unwrap();
    block_on(s.add_peer(id, from)).unwrap();
    wait_for("the selection to finish", 30, || {
        let st = status(&s, id);
        st.state == TorrentState::Seeding && st.pieces_have == SELECTED
    });
    (s, id)
}

/// The partial seed's own view is truthful: the selection done, the
/// skipped file never created, its straddling bytes in the parts file.
fn assert_partial(s: &Session, id: TorrentId, dir: &Path, data: &[u8]) {
    let st = status(s, id);
    assert_eq!(st.pieces_have, SELECTED, "{st:?}");
    assert_eq!(st.total_wanted_done, st.total_wanted);
    assert!(st.left > 0, "the skipped pieces are missing: {st:?}");
    assert!(!dir.join("sel/sub/b.bin").exists());
    assert!(dir.join(".sel.parts").exists());
    assert_eq!(
        std::fs::read(dir.join("sel/a.bin")).unwrap(),
        &data[..200_000]
    );
    assert_eq!(
        std::fs::read(dir.join("sel/c.bin")).unwrap(),
        &data[500_000..]
    );
}

#[test]
fn a_partial_seed_serves_its_selection_and_advertises_only_that() {
    let dir = tmp("serve");
    let (bytes, data) = fixture();
    let (a, _) = full_seed(1, &dir.join("a"), &bytes, &data);
    let b_dir = dir.join("b");
    let (b, b_id) = partial_from(2, addr_of(1, &a), &b_dir, &bytes, None);
    block_on(a.shutdown()).unwrap();
    assert_partial(&b, b_id, &b_dir, &data);
    let b_down = status(&b, b_id).downloaded;

    // C wants everything and has only B: it gets exactly what B has,
    // including the straddling pieces B reads back from its parts file.
    let c_dir = dir.join("c");
    let c = block_on(builder(3).build()).unwrap();
    let c_id = block_on(c.add_torrent(AddTorrent::metainfo(bytes.clone(), &c_dir))).unwrap();
    block_on(c.add_peer(c_id, addr_of(2, &b))).unwrap();
    wait_for("C to get what B has", 30, || {
        status(&c, c_id).pieces_have == SELECTED
    });
    // B advertises its pieces, not the torrent: C sees a peer with seven
    // pieces that is not a seed, and C never gets more.
    let peers = block_on(c.peers(c_id)).unwrap();
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert_eq!(peers[0].pieces, SELECTED, "{peers:?}");
    assert!(!peers[0].is_seed, "{peers:?}");
    std::thread::sleep(Duration::from_millis(500));
    let st = status(&c, c_id);
    assert_eq!(st.pieces_have, SELECTED, "{st:?}");
    assert_eq!(st.state, TorrentState::Downloading, "{st:?}");
    assert_eq!(st.corrupt, 0);
    assert_eq!(
        std::fs::read(c_dir.join("sel/a.bin")).unwrap(),
        &data[..200_000]
    );
    assert_eq!(
        std::fs::read(c_dir.join("sel/c.bin")).unwrap(),
        &data[500_000..]
    );
    // C wants b.bin: its straddling ranges came from B's parts file.
    let c_b = std::fs::read(c_dir.join("sel/sub/b.bin")).unwrap();
    let head = 3 * PIECE + PIECE - 200_000; // end of piece 3 in b.bin
    let tail = 7 * PIECE - 200_000; // start of piece 7 in b.bin
    assert_eq!(&c_b[..head], &data[200_000..200_000 + head]);
    assert_eq!(&c_b[tail..], &data[200_000 + tail..500_000]);
    // B only served: it asked C for nothing.
    assert_eq!(status(&b, b_id).downloaded, b_down);
    assert!(status(&b, b_id).uploaded >= (SELECTED * PIECE - PIECE) as u64);
    block_on(c.shutdown()).unwrap();
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_partial_download_survives_a_restart_and_a_check() {
    let dir = tmp("restart");
    let (bytes, data) = fixture();
    let (a, _) = full_seed(1, &dir.join("a"), &bytes, &data);
    let b_dir = dir.join("b");
    let resume = dir.join("resume");
    let (b, _) = partial_from(2, addr_of(1, &a), &b_dir, &bytes, Some(&resume));
    block_on(a.shutdown()).unwrap();
    block_on(b.shutdown()).unwrap();

    // With the resume data: finished at once, the selection kept.
    let b = block_on(builder(2).build()).unwrap();
    let id =
        block_on(b.add_torrent(AddTorrent::metainfo(bytes.clone(), &b_dir).resume_dir(&resume)))
            .unwrap();
    wait_for("the resumed selection", 10, || {
        status(&b, id).state == TorrentState::Seeding
    });
    let prios: Vec<u8> = status(&b, id).files.iter().map(|f| f.priority).collect();
    assert_eq!(prios, vec![4, 0, 4]);
    assert_partial(&b, id, &b_dir, &data);
    // A forced check reads the straddling pieces through the parts file:
    // it finds the same seven, nothing more, nothing less.
    block_on(b.force_recheck(id)).unwrap();
    wait_for("the recheck", 10, || {
        status(&b, id).state == TorrentState::Seeding
    });
    assert_partial(&b, id, &b_dir, &data);
    block_on(b.remove_torrent(id)).unwrap();

    // Without any resume data: the initial check finds them too (the parts
    // file counts as content on disk).
    let id = block_on(
        b.add_torrent(AddTorrent::metainfo(bytes.clone(), &b_dir).file_priorities(vec![4, 0, 4])),
    )
    .unwrap();
    wait_for("the checked selection", 10, || {
        status(&b, id).state == TorrentState::Seeding
    });
    assert_partial(&b, id, &b_dir, &data);
    block_on(b.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_deselected_complete_file_is_still_seeded_and_left_alone() {
    let dir = tmp("deselect");
    let (bytes, data) = fixture();
    let a_dir = dir.join("a");
    let (a, a_id) = full_seed(1, &a_dir, &bytes, &data);
    // Deselect the complete middle file: the pieces stay ours, the file
    // stays where it is, nothing goes to a parts file.
    block_on(a.set_file_priorities(a_id, vec![4, 0, 4])).unwrap();
    let st = status(&a, a_id);
    assert_eq!(st.pieces_have, st.pieces_total, "{st:?}");
    assert_eq!(st.left, 0);
    assert_eq!(st.state, TorrentState::Seeding);
    assert_eq!(st.total_wanted, 350_000);
    assert!(!a_dir.join(".sel.parts").exists());

    // A leecher wanting everything gets everything from it, b.bin included.
    let c_dir = dir.join("c");
    let c = block_on(builder(3).build()).unwrap();
    let c_id = block_on(c.add_torrent(AddTorrent::metainfo(bytes.clone(), &c_dir))).unwrap();
    block_on(c.add_peer(c_id, addr_of(1, &a))).unwrap();
    wait_for("the full download", 30, || {
        status(&c, c_id).state == TorrentState::Seeding
    });
    assert_eq!(
        std::fs::read(c_dir.join("sel/sub/b.bin")).unwrap(),
        &data[200_000..500_000]
    );

    // Selecting it again changes nothing on disk and downloads nothing.
    let down = status(&a, a_id).downloaded;
    block_on(a.set_file_priorities(a_id, vec![4, 4, 4])).unwrap();
    let st = status(&a, a_id);
    assert_eq!((st.state, st.left), (TorrentState::Seeding, 0));
    assert_eq!(st.downloaded, down);
    assert_eq!(
        std::fs::read(a_dir.join("sel/sub/b.bin")).unwrap(),
        &data[200_000..500_000]
    );
    block_on(c.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
