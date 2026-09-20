// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Local Service Discovery (BEP 14), libtorrent's `lsd` semantics (ported
//! logic from `src/lsd.cpp`, BSD-3; see `NOTICE`):
//!
//! - One multicast socket per address family on port 6771, groups
//!   `239.192.152.143` / `ff15::efc0:988f`, hop limit 32, loopback on.
//! - An announce is the `BT-SEARCH` datagram below, sent three times (at
//!   once, after 2 s, after another 4 s). Every torrent announces when it
//!   starts, and the session walks its torrents round-robin so each is
//!   re-announced about every five minutes.
//! - A received announce for one of our torrents adds `(source ip, Port)` as
//!   a candidate. Our own announces are recognised by the `cookie`.
//! - Private torrents are never announced and announces for them are
//!   dropped (rule 2; enforced on the wire by `private_no_pex_lsd`).
//!
//! The datagram format lives in `tracker::lsd` (sans-IO, fuzzed).

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use metainfo::InfoHash;
use uring::{Buffer, UdpSocket};

use super::Ctx;
use super::local::{Either, select2};
use super::torrent::{self, Torrent};
use crate::api::{Event, PeerSource};

pub use tracker::lsd::{GROUP_V4, GROUP_V6, PORT};

/// Multicast hop limit.
const HOPS: u8 = 32;
/// Re-announce period for the whole session (`local_service_announce_interval`).
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The LSD sockets (one per family we listen on).
pub struct Lsd {
    sockets: Vec<Rc<UdpSocket>>,
    cookie: u32,
}

impl Lsd {
    /// Open the multicast sockets. A family whose join fails is skipped with
    /// a warning; `None` when neither works.
    pub fn open(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>, cookie: u32) -> Option<Lsd> {
        let mut sockets = Vec::new();
        if let Some(a) = v4 {
            let iface = (!a.is_unspecified()).then_some(IpAddr::V4(a));
            match UdpSocket::bind_multicast(IpAddr::V4(GROUP_V4), PORT, iface, HOPS) {
                Ok(s) => sockets.push(Rc::new(s)),
                Err(e) => tracing::warn!("lsd: ipv4 multicast unavailable: {e}"),
            }
        }
        if v6.is_some() {
            match UdpSocket::bind_multicast(IpAddr::V6(GROUP_V6), PORT, None, HOPS) {
                Ok(s) => sockets.push(Rc::new(s)),
                Err(e) => tracing::warn!("lsd: ipv6 multicast unavailable: {e}"),
            }
        }
        if sockets.is_empty() {
            return None;
        }
        Some(Lsd {
            sockets,
            cookie: cookie & 0x7fff_ffff,
        })
    }

    /// Render the announce datagram for one family.
    pub fn packet(&self, v6: bool, listen_port: u16, info_hash: &InfoHash) -> Vec<u8> {
        tracker::lsd::render(v6, listen_port, info_hash, self.cookie)
    }

    /// Start the receive loops.
    pub fn spawn(&self, ctx: Rc<Ctx>) {
        for s in &self.sockets {
            uring::spawn(receive_loop(ctx.clone(), s.clone()));
        }
    }
}

/// Announce `torrent` now (three datagrams over six seconds), unless LSD is
/// off, the torrent is private, or it is not running.
pub fn announce_now(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) {
    if !ctx.cfg.lsd || ctx.lsd.borrow().is_none() {
        return;
    }
    let ctx = ctx.clone();
    let torrent = torrent.clone();
    uring::spawn(async move {
        for (i, delay) in [0u64, 2, 4].into_iter().enumerate() {
            if delay > 0 {
                uring::sleep(Duration::from_secs(delay)).await;
            }
            let (info_hash, ok) = {
                let t = torrent.borrow();
                (
                    t.info_hash,
                    t.discovery_allowed() && t.is_active() && !t.closing.is_set(),
                )
            };
            if !ok || ctx.closing.is_set() {
                return;
            }
            let sockets: Vec<Rc<UdpSocket>> = match ctx.lsd.borrow().as_ref() {
                Some(l) => l.sockets.clone(),
                None => return,
            };
            for s in sockets {
                let v6 = s.local_addr().is_ipv6();
                let pkt = ctx
                    .lsd
                    .borrow()
                    .as_ref()
                    .map(|l| l.packet(v6, ctx.listen_port, &info_hash));
                let Some(pkt) = pkt else { return };
                let to = if v6 {
                    SocketAddr::new(IpAddr::V6(GROUP_V6), PORT)
                } else {
                    SocketAddr::new(IpAddr::V4(GROUP_V4), PORT)
                };
                let (r, _) = s.send_to(Buffer::from_vec(pkt), to).await;
                if let Err(e) = r {
                    tracing::debug!(attempt = i, "lsd send failed: {e}");
                }
            }
        }
    });
}

/// Receive announces and turn them into candidates.
async fn receive_loop(ctx: Rc<Ctx>, socket: Rc<UdpSocket>) {
    loop {
        let buf = Buffer::from_vec(vec![0u8; 1500]);
        match select2(socket.recv_from(buf), ctx.closing.wait()).await {
            Either::Left((Ok(n), b, Some(from))) => {
                on_datagram(&ctx, &b.as_slice()[..n as usize], from);
            }
            Either::Left((Ok(_), _, None)) => {}
            Either::Left((Err(e), _, _)) => {
                tracing::warn!("lsd recv failed: {e}");
                uring::sleep(Duration::from_millis(500)).await;
            }
            Either::Right(()) => break,
        }
    }
}

fn on_datagram(ctx: &Rc<Ctx>, data: &[u8], from: SocketAddr) {
    let Some(search) = tracker::lsd::parse(data) else {
        return;
    };
    let ours = ctx.lsd.borrow().as_ref().map(|l| l.cookie);
    if search.cookie.is_some() && search.cookie == ours {
        return;
    }
    let peer = SocketAddr::new(from.ip(), search.port);
    for ih in &search.info_hashes {
        let Some(torrent) = ctx.torrent_by_hash(ih) else {
            continue;
        };
        let (added, id) = {
            let mut t = torrent.borrow_mut();
            if !t.discovery_allowed() || !t.is_running() {
                continue;
            }
            (t.add_candidates(ctx, &[peer], PeerSource::Lsd), t.id)
        };
        tracing::debug!(torrent = id.0, %peer, added, "lsd announce");
        ctx.emit(Event::LsdPeer { id, addr: peer });
        if added > 0 {
            torrent::on_new_candidates(ctx, &torrent);
        }
    }
}
