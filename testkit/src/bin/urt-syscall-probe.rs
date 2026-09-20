// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! A real-session data-path exercise for `cargo xtask syscalls`: two engines
//! on loopback (one seeding from disk, one leeching through a manual peer),
//! a small transfer, shutdown. Run under `strace -f -Y`, the engine threads
//! (`urt-net`, `urt-disk`, `urt-hash-*`) must issue no epoll/poll/select and no off-ring
//! socket or torrent-file data syscalls (AGENTS.md rule 4). The main thread
//! only prepares the fixture and drives the API; `urt-dns` is allowed
//! anything (blocking `getaddrinfo` is explicitly off the critical path).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use urtorrent::{AddTorrent, Session, TorrentState};

fn block_on<F: Future>(fut: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park_timeout(Duration::from_millis(20)),
        }
    }
}

fn bstr(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(s.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(s);
}

fn make_torrent(name: &str, size: usize, piece_len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut data = vec![0u8; size];
    let mut x: u32 = 0x2545_f491;
    for b in &mut data {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = x as u8;
    }
    let mut pieces = Vec::new();
    for chunk in data.chunks(piece_len) {
        pieces.extend_from_slice(&<sha1::Sha1 as sha1::Digest>::digest(chunk));
    }
    let mut info = Vec::new();
    info.push(b'd');
    bstr(&mut info, b"length");
    info.extend_from_slice(format!("i{size}e").as_bytes());
    bstr(&mut info, b"name");
    bstr(&mut info, name.as_bytes());
    bstr(&mut info, b"piece length");
    info.extend_from_slice(format!("i{piece_len}e").as_bytes());
    bstr(&mut info, b"pieces");
    bstr(&mut info, &pieces);
    info.push(b'e');
    let mut t = Vec::new();
    t.push(b'd');
    bstr(&mut t, b"announce");
    bstr(&mut t, b"http://127.0.0.1:1/x");
    bstr(&mut t, b"info");
    t.extend_from_slice(&info);
    t.push(b'e');
    (t, data)
}

fn session(ip: Ipv4Addr) -> Session {
    block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(ip))
            .listen_v6(None)
            .lsd(false)
            .dht(false)
            .build(),
    )
    .expect("engine")
}

fn main() {
    let dir: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("urt-probe-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&dir);
    let a_dir = dir.join("a");
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::create_dir_all(&b_dir).unwrap();
    let size = 3 * 1024 * 1024 + 4321;
    let (torrent, data) = make_torrent("probe.bin", size, 64 * 1024);
    // Fixture written by the main thread before any engine exists.
    std::fs::write(a_dir.join("probe.bin"), &data).unwrap();

    let a = session(Ipv4Addr::LOCALHOST);
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(torrent.clone(), &a_dir))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let st = block_on(a.status(a_id)).unwrap();
        if st.state == TorrentState::Seeding {
            break;
        }
        assert!(Instant::now() < deadline, "seeder never checked: {st:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    let b = session(Ipv4Addr::new(127, 0, 0, 2));
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(torrent, &b_dir))).unwrap();
    block_on(b.add_peer(
        b_id,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), a.listen_port()),
    ))
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let st = block_on(b.status(b_id)).unwrap();
        if st.complete {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "transfer did not complete: {st:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(std::fs::read(b_dir.join("probe.bin")).unwrap(), data);
    block_on(b.shutdown()).unwrap();
    block_on(a.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    println!("probe: transfer of {size} bytes complete");
}
