// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! A tracker (or a peer) hands us one of our own addresses, typically the
//! other family's while we listen on the unspecified address of both: the
//! connection to ourselves is recognised on the incoming side by the peer id
//! we put on the outgoing one (libtorrent `is_self_connection`, needed
//! under a profile with a fresh id per connection) and by the endpoints,
//! and the address is never dialled again.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{block_on, make_torrent};
use session::{AddTorrent, Event, Session, TorrentState};

/// Captures every log line (the self-connection ends before a peer id is
/// set, so no event reports it; the log does).
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

impl Capture {
    fn count(&self, needle: &str) -> usize {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .matches(needle)
            .count()
    }
}

fn wait_for(secs: u64, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn own_address_from_a_peer_source_is_recognised_and_dropped() {
    let log = Capture::default();
    tracing_subscriber::fmt()
        .with_env_filter("session=debug")
        .with_writer(log.clone())
        .with_ansi(false)
        .init();
    // The qbt profile puts a fresh peer id on every connection, so the
    // wire-level "same id on both ends" check cannot see a self-connection.
    // Listening on the unspecified addresses, the engine does not know its
    // own addresses up front either.
    let s = block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(Ipv4Addr::UNSPECIFIED))
            .listen_v6(Some(Ipv6Addr::UNSPECIFIED))
            .profile(profile::Profile::qbt_5_2_3_lt2_0_14())
            .lsd(false)
            .dht(false)
            .build(),
    )
    .unwrap();
    let dir = std::env::temp_dir().join(format!("urt-selfconn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (torrent, data) = make_torrent("self.bin", 256 * 1024, 64 * 1024, "http://127.0.0.1:1/x");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("self.bin"), &data).unwrap();
    let id = block_on(s.add_torrent(AddTorrent::metainfo(torrent, &dir))).unwrap();
    assert!(wait_for(10, || {
        block_on(s.status(id)).unwrap().state == TorrentState::Seeding
    }));
    let mut events = s.events();
    let port = s.listen_port();
    for own in [
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
    ] {
        block_on(s.add_peer(id, own)).unwrap();
        assert!(
            wait_for(10, || log.count("connected to ourselves") > 0
                && block_on(s.stats()).unwrap().connections == 0),
            "self-connection to {own} not recognised"
        );
        // Learned: the address is not dialled again (no second attempt).
        let before = log.count("connected to ourselves");
        block_on(s.add_peer(id, own)).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            log.count("connected to ourselves"),
            before,
            "{own} was dialled again"
        );
        assert_eq!(block_on(s.stats()).unwrap().connections, 0);
        assert!(block_on(s.peers(id)).unwrap().is_empty());
    }
    // Never a connection as far as the API is concerned.
    while let Some(ev) = events.try_recv() {
        assert!(
            !matches!(
                ev,
                Event::PeerConnected { .. } | Event::PeerDisconnected { .. }
            ),
            "{ev:?}"
        );
    }
    block_on(s.shutdown()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
