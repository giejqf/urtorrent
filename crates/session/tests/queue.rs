// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The active-torrent queue (`ActiveLimits`) and the per-torrent /
//! session-wide limits a frontend's preferences map to: queue order and
//! moves, force start, pause taking a torrent out of the queue, seeds
//! limited separately from downloads, per-torrent upload slots and
//! connection caps, runtime changes of the session limits, and the queue
//! fields surviving in resume data.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{block_on, make_torrent};
use session::{
    ActiveLimits, AddTorrent, QueueMove, Session, SessionBuilder, TorrentId, TorrentState,
    TransportPolicy,
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
        .transports(TransportPolicy::TcpOnly)
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

fn state(s: &Session, id: TorrentId) -> TorrentState {
    block_on(s.status(id)).unwrap().state
}

struct Fx {
    dir: PathBuf,
    torrents: Vec<(Vec<u8>, Vec<u8>, String)>,
}

impl Fx {
    fn new(tag: &str, sizes: &[usize]) -> Fx {
        let dir = std::env::temp_dir().join(format!("urt-queue-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let torrents = sizes
            .iter()
            .enumerate()
            .map(|(i, size)| {
                let name = format!("q{i}.bin");
                let (t, d) = make_torrent(&name, *size, 64 * 1024, "http://127.0.0.1:1/x");
                (t, d, name)
            })
            .collect();
        Fx { dir, torrents }
    }

    fn seed_dir(&self, who: &str) -> PathBuf {
        let d = self.dir.join(who);
        std::fs::create_dir_all(&d).unwrap();
        for (_, data, name) in &self.torrents {
            std::fs::write(d.join(name), data).unwrap();
        }
        d
    }

    fn leech_dir(&self, who: &str) -> PathBuf {
        let d = self.dir.join(who);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn add(&self, i: usize, dir: &Path) -> AddTorrent {
        AddTorrent::metainfo(self.torrents[i].0.clone(), dir)
    }

    fn check(&self, i: usize, dir: &Path) {
        assert_eq!(
            std::fs::read(dir.join(&self.torrents[i].2)).unwrap(),
            self.torrents[i].1
        );
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Seed every fixture torrent from `s`.
fn seed_all(s: &Session, fx: &Fx, who: &str) -> Vec<TorrentId> {
    let d = fx.seed_dir(who);
    let ids: Vec<TorrentId> = (0..fx.torrents.len())
        .map(|i| block_on(s.add_torrent(fx.add(i, &d))).unwrap())
        .collect();
    for id in &ids {
        wait_state(s, *id, TorrentState::Seeding, 10);
    }
    ids
}

#[test]
fn download_queue_runs_in_order_and_moves_force_and_pause_apply() {
    let fx = Fx::new("downloads", &[8 << 20, 8 << 20]);
    let a = block_on(builder(1).build()).unwrap();
    let _a_ids = seed_all(&a, &fx, "a");
    let b = block_on(
        builder(2)
            .active_limits(ActiveLimits {
                downloads: Some(1),
                seeds: None,
                total: None,
                count_slow: false,
            })
            .download_limit(1 << 20)
            .build(),
    )
    .unwrap();
    let bd = fx.leech_dir("b");
    // Both added paused: nothing runs, positions follow the add order.
    let t0 = block_on(b.add_torrent(fx.add(0, &bd).paused(true))).unwrap();
    let t1 = block_on(b.add_torrent(fx.add(1, &bd).paused(true))).unwrap();
    for id in [t0, t1] {
        block_on(b.add_peer(id, addr_of(1, &a))).unwrap();
    }
    wait_state(&b, t0, TorrentState::Paused, 10);
    wait_state(&b, t1, TorrentState::Paused, 10);
    let st0 = block_on(b.status(t0)).unwrap();
    let st1 = block_on(b.status(t1)).unwrap();
    assert_eq!((st0.queue_position, st1.queue_position), (0, 1));
    assert!(st0.auto_managed && st1.auto_managed);

    // Second to the top, then both handed to the queue: t1 runs, t0 waits.
    block_on(b.move_in_queue(t1, QueueMove::Top)).unwrap();
    assert_eq!(block_on(b.status(t1)).unwrap().queue_position, 0);
    assert_eq!(block_on(b.status(t0)).unwrap().queue_position, 1);
    block_on(b.resume(t0)).unwrap();
    block_on(b.resume(t1)).unwrap();
    wait_state(&b, t1, TorrentState::Downloading, 10);
    wait_state(&b, t0, TorrentState::Queued, 10);
    assert!(block_on(b.status(t0)).unwrap().auto_managed);

    // Force start bypasses the queue; handing it back queues it again
    // (t1 holds the only slot).
    block_on(b.force_resume(t0)).unwrap();
    wait_state(&b, t0, TorrentState::Downloading, 10);
    assert!(!block_on(b.status(t0)).unwrap().auto_managed);
    block_on(b.set_auto_managed(t0, true)).unwrap();
    wait_state(&b, t0, TorrentState::Queued, 10);

    // Pausing the running one takes it out of the queue's hands and frees
    // the slot for t0. (A stopped torrent's peers are in reconnect backoff,
    // as in libtorrent; `add_peer` dials at once.)
    block_on(b.pause(t1)).unwrap();
    wait_state(&b, t1, TorrentState::Paused, 10);
    assert!(!block_on(b.status(t1)).unwrap().auto_managed);
    wait_state(&b, t0, TorrentState::Downloading, 10);
    block_on(b.add_peer(t0, addr_of(1, &a))).unwrap();
    // t1 stays paused however long t0 takes: the queue never restarts a
    // caller-paused torrent.
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(state(&b, t1), TorrentState::Paused);

    // Resume t1 under the queue: it is first in the queue, so it takes the
    // slot back and t0 waits; once t1 completes (a seed holds no download
    // slot) t0 downloads.
    block_on(b.resume(t1)).unwrap();
    wait_state(&b, t1, TorrentState::Downloading, 10);
    block_on(b.add_peer(t1, addr_of(1, &a))).unwrap();
    wait_state(&b, t0, TorrentState::Queued, 10);
    wait_state(&b, t1, TorrentState::Seeding, 60);
    wait_state(&b, t0, TorrentState::Downloading, 10);
    block_on(b.add_peer(t0, addr_of(1, &a))).unwrap();
    wait_state(&b, t0, TorrentState::Seeding, 60);
    fx.check(0, &bd);
    fx.check(1, &bd);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}

#[test]
fn seed_limit_queues_seeds_by_position_and_lifting_it_starts_them() {
    let fx = Fx::new("seeds", &[256 * 1024, 256 * 1024, 256 * 1024]);
    let a = block_on(
        builder(1)
            .active_limits(ActiveLimits {
                downloads: None,
                seeds: Some(1),
                total: None,
                count_slow: false,
            })
            .build(),
    )
    .unwrap();
    let d = fx.seed_dir("a");
    let ids: Vec<TorrentId> = (0..3)
        .map(|i| block_on(a.add_torrent(fx.add(i, &d))).unwrap())
        .collect();
    wait_state(&a, ids[0], TorrentState::Seeding, 10);
    wait_state(&a, ids[1], TorrentState::Queued, 10);
    wait_state(&a, ids[2], TorrentState::Queued, 10);
    // The last one to the top: it takes the slot, the first is queued.
    block_on(a.move_in_queue(ids[2], QueueMove::Top)).unwrap();
    wait_state(&a, ids[2], TorrentState::Seeding, 10);
    wait_state(&a, ids[0], TorrentState::Queued, 10);
    let positions: Vec<usize> = ids
        .iter()
        .map(|id| block_on(a.status(*id)).unwrap().queue_position)
        .collect();
    assert_eq!(positions, vec![1, 2, 0]);
    // Down / up / bottom.
    block_on(a.move_in_queue(ids[2], QueueMove::Down)).unwrap();
    wait_state(&a, ids[0], TorrentState::Seeding, 10);
    wait_state(&a, ids[2], TorrentState::Queued, 10);
    block_on(a.move_in_queue(ids[2], QueueMove::Up)).unwrap();
    wait_state(&a, ids[2], TorrentState::Seeding, 10);
    block_on(a.move_in_queue(ids[2], QueueMove::Bottom)).unwrap();
    wait_state(&a, ids[0], TorrentState::Seeding, 10);
    wait_state(&a, ids[2], TorrentState::Queued, 10);
    assert_eq!(block_on(a.status(ids[2])).unwrap().queue_position, 2);
    // Two slots, then unlimited.
    block_on(a.set_active_limits(ActiveLimits {
        seeds: Some(2),
        ..ActiveLimits::UNLIMITED
    }))
    .unwrap();
    wait_state(&a, ids[1], TorrentState::Seeding, 10);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(state(&a, ids[2]), TorrentState::Queued);
    block_on(a.set_active_limits(ActiveLimits::UNLIMITED)).unwrap();
    wait_state(&a, ids[2], TorrentState::Seeding, 10);
    block_on(a.shutdown()).unwrap();
}

#[test]
fn queue_fields_survive_in_resume_data() {
    let fx = Fx::new("resume", &[128 * 1024, 128 * 1024]);
    let d = fx.seed_dir("a");
    let resume = fx.dir.join("resume");
    let ids = {
        let a = block_on(builder(1).build()).unwrap();
        let t0 = block_on(a.add_torrent(fx.add(0, &d).resume_dir(&resume))).unwrap();
        let t1 = block_on(a.add_torrent(fx.add(1, &d).resume_dir(&resume))).unwrap();
        wait_state(&a, t0, TorrentState::Seeding, 10);
        wait_state(&a, t1, TorrentState::Seeding, 10);
        block_on(a.move_in_queue(t1, QueueMove::Top)).unwrap();
        block_on(a.set_auto_managed(t0, false)).unwrap();
        block_on(a.save_resume_data(t0)).unwrap();
        block_on(a.save_resume_data(t1)).unwrap();
        block_on(a.shutdown()).unwrap();
        (t0, t1)
    };
    let _ = ids;
    // Re-added in the original order: the saved order and flags come back.
    let a = block_on(builder(1).build()).unwrap();
    let t0 = block_on(a.add_torrent(fx.add(0, &d).resume_dir(&resume))).unwrap();
    let t1 = block_on(a.add_torrent(fx.add(1, &d).resume_dir(&resume))).unwrap();
    wait_state(&a, t0, TorrentState::Seeding, 10);
    wait_state(&a, t1, TorrentState::Seeding, 10);
    let s0 = block_on(a.status(t0)).unwrap();
    let s1 = block_on(a.status(t1)).unwrap();
    assert_eq!((s1.queue_position, s0.queue_position), (0, 1));
    assert!(!s0.auto_managed && s1.auto_managed);
    // The caller's flag wins over the file's.
    let t2 = block_on(
        a.add_torrent(
            AddTorrent::metainfo(fx.torrents[0].0.clone(), fx.leech_dir("c"))
                .resume_dir(fx.dir.join("resume-c"))
                .auto_managed(false),
        ),
    );
    assert!(t2.is_err(), "same info-hash twice is a duplicate");
    block_on(a.shutdown()).unwrap();
}

#[test]
fn per_torrent_upload_slots_cap_the_choker() {
    // Big enough, and slow enough, that nobody completes during the test.
    let fx = Fx::new("uploads", &[16 << 20]);
    let a = block_on(builder(1).upload_limit(256 * 1024).build()).unwrap();
    let ad = fx.seed_dir("a");
    let a_id = block_on(a.add_torrent(fx.add(0, &ad).max_uploads(1))).unwrap();
    wait_state(&a, a_id, TorrentState::Seeding, 10);
    assert_eq!(block_on(a.status(a_id)).unwrap().max_uploads, Some(1));
    let leechers: Vec<(Session, TorrentId)> = (2..=4u8)
        .map(|n| {
            let s = block_on(builder(n).build()).unwrap();
            let id = block_on(s.add_torrent(fx.add(0, &fx.leech_dir(&format!("l{n}"))))).unwrap();
            block_on(s.add_peer(id, addr_of(1, &a))).unwrap();
            (s, id)
        })
        .collect();
    // Three interested peers, one slot: never more than one unchoked.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut max_unchoked = 0;
    let mut interested_seen = 0;
    while Instant::now() < deadline {
        let peers = block_on(a.peers(a_id)).unwrap();
        let unchoked = peers.iter().filter(|p| !p.am_choking).count();
        let interested = peers.iter().filter(|p| p.peer_interested).count();
        max_unchoked = max_unchoked.max(unchoked);
        interested_seen = interested_seen.max(interested);
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(interested_seen, 3, "every leecher was interested");
    assert_eq!(max_unchoked, 1, "the cap held");
    // Lifting the cap lets the session budget apply.
    block_on(a.set_max_uploads(a_id, None)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let peers = block_on(a.peers(a_id)).unwrap();
        if peers.iter().filter(|p| !p.am_choking).count() >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "no second unchoke: {peers:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
    for (s, _) in &leechers {
        block_on(s.shutdown()).unwrap();
    }
    block_on(a.shutdown()).unwrap();
}

#[test]
fn add_time_limits_and_runtime_session_limits_apply() {
    let fx = Fx::new("limits", &[1 << 20]);
    let a = block_on(builder(1).build()).unwrap();
    let c = block_on(builder(3).build()).unwrap();
    let _a = seed_all(&a, &fx, "a");
    let _c = seed_all(&c, &fx, "c");
    // A per-torrent connection cap of one with two seeders known.
    let b = block_on(builder(2).build()).unwrap();
    let bd = fx.leech_dir("b");
    let id = block_on(
        b.add_torrent(
            fx.add(0, &bd)
                .max_peers(1)
                .download_limit(128 * 1024)
                .paused(true),
        ),
    )
    .unwrap();
    wait_state(&b, id, TorrentState::Paused, 10);
    assert_eq!(block_on(b.status(id)).unwrap().max_peers, Some(1));
    block_on(b.add_peer(id, addr_of(1, &a))).unwrap();
    block_on(b.add_peer(id, addr_of(3, &c))).unwrap();
    // Zero unchoke slots on the seeders: only the allowed-fast pieces (BEP
    // 6, five per peer) flow until the slots are restored.
    block_on(a.set_unchoke_slots(0)).unwrap();
    block_on(c.set_unchoke_slots(0)).unwrap();
    block_on(b.resume(id)).unwrap();
    let started = Instant::now();
    std::thread::sleep(Duration::from_millis(2500));
    let st = block_on(b.status(id)).unwrap();
    assert_eq!(st.state, TorrentState::Downloading);
    assert!(
        st.downloaded <= 5 * 64 * 1024,
        "choked everywhere, allowed-fast aside: {st:?}"
    );
    assert!(st.peers <= 1, "one connection at most: {st:?}");
    let peers = block_on(b.peers(id)).unwrap();
    assert!(peers.iter().all(|p| p.peer_choking), "{peers:?}");
    block_on(a.set_unchoke_slots(8)).unwrap();
    block_on(c.set_unchoke_slots(8)).unwrap();
    wait_state(&b, id, TorrentState::Seeding, 60);
    // 1 MiB at 128 KiB/s: the add-time download limit held.
    assert!(
        started.elapsed() >= Duration::from_millis(7000),
        "finished in {:?}",
        started.elapsed()
    );
    fx.check(0, &bd);
    // Runtime per-torrent default and session limits are accepted.
    block_on(b.set_max_peers_per_torrent(20)).unwrap();
    block_on(b.set_max_connections(100)).unwrap();
    block_on(b.shutdown()).unwrap();
    block_on(c.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
}
