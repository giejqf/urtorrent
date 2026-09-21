// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Peer exchange (BEP 11), with libtorrent's `ut_pex` semantics (ported
//! logic from `src/ut_pex.cpp`, BSD-3; see `NOTICE`), as captured from the
//! oracle in `capture_pex`:
//!
//! - Every peer gets a message at most once a minute, and only while the
//!   torrent has more than one peer. The first message to a peer is the full
//!   list of exchangeable connections (the recipient included); later ones
//!   carry the torrent-wide delta (`added` / `dropped`) that is rebuilt once
//!   a minute, and are skipped when the delta is empty.
//! - Exchangeable: connections past the handshake that we dialled, or that
//!   dialled us *and* told us their listen port (`p`). At most 100 per
//!   message.
//! - Flags: `0x01` the connection is encrypted, `0x02` the peer is a seed
//!   (a complete have-set; BEP 21 upload-only alone does not count, as in
//!   libtorrent), `0x04` the connection runs over uTP, `0x08` it advertised
//!   `ut_holepunch`; `0x10` never (libtorrent only reads it).
//! - Receiving: more than six messages in a minute or a message over 500 KiB
//!   is a protocol violation; `added` feeds the candidate list, an `0x01`
//!   flag makes the first dial encrypted.
//!
//! Private torrents (rule 2) never send, accept or act on PEX: `ut_pex` is
//! absent from their LTEP `m` (docs/quirks.md Q11), so a message under that
//! id is unknown and ignored, and [`tick`] returns before doing anything.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use wire::ext::{Pex, pex_flags};

use super::Ctx;
use super::peer::PeerHandle;
use super::torrent::Torrent;
use crate::api::{EncryptionMode, Event, PeerSource};

/// Minimum spacing between PEX messages to one peer, and the delta rebuild
/// period.
pub const INTERVAL: Duration = Duration::from_secs(60);
/// Most peers per message.
pub const MAX_ENTRIES: usize = 100;
/// Largest message we accept (libtorrent `pex_message_too_large`).
pub const MAX_MESSAGE: usize = 500 * 1024;
/// Messages per minute from one peer beyond which it is flooding us.
pub const MAX_PER_MINUTE: usize = 6;

/// Per-torrent PEX state.
#[derive(Default)]
pub struct State {
    /// When the delta was last rebuilt.
    last_build: Option<Instant>,
    /// The exchangeable set at the last rebuild.
    old: HashSet<SocketAddr>,
    /// The current delta message, and how many peers it names.
    delta: Vec<u8>,
    delta_entries: usize,
}

/// Per-connection PEX state (lives in the [`PeerHandle`]).
#[derive(Default)]
pub struct PeerState {
    /// When we last sent this peer a message.
    pub last_sent: Option<Instant>,
    /// Whether the full list went out already.
    pub sent_full: bool,
    /// Arrival times of the last messages received (flood check).
    pub received: VecDeque<Instant>,
}

/// The address a peer is exchanged under, and its flags.
fn entry(p: &PeerHandle, pieces: usize) -> Option<(SocketAddr, u8)> {
    let addr = p.pex_addr()?;
    let mut flags = 0u8;
    // libtorrent's `is_seed()`: a complete have-set, not BEP 21 upload-only.
    if p.is_seed(pieces) {
        flags |= pex_flags::SEED;
    }
    if p.encrypted.get() {
        flags |= pex_flags::ENCRYPTION;
    }
    if p.holepunch.get() {
        flags |= pex_flags::HOLEPUNCH;
    }
    // libtorrent flags peers it is connected to over uTP.
    if p.transport.get() == crate::api::PeerTransport::Utp {
        flags |= pex_flags::UTP;
    }
    Some((addr, flags))
}

/// The exchangeable connections right now.
fn exchangeable(t: &Torrent) -> Vec<(SocketAddr, u8)> {
    let pieces = t.piece_count();
    let mut v: Vec<(SocketAddr, u8)> = t
        .peers
        .values()
        .filter(|p| p.conn.borrow().is_established())
        .filter_map(|p| entry(p, pieces))
        .collect();
    v.sort_by_key(|(a, _)| *a);
    v
}

/// The once-a-second PEX step for a torrent.
pub fn tick(ctx: &Ctx, t: &mut Torrent, now: Instant) {
    if !ctx.cfg.pex || !t.discovery_allowed() {
        return;
    }
    // Torrent level: rebuild the delta once a minute.
    if t.pex
        .last_build
        .is_none_or(|l| now.duration_since(l) >= INTERVAL)
    {
        t.pex.last_build = Some(now);
        if !t.peers.is_empty() {
            let current = exchangeable(t);
            let dropped: Vec<SocketAddr> = t
                .pex
                .old
                .iter()
                .filter(|a| !current.iter().any(|(c, _)| c == *a))
                .copied()
                .collect();
            let added: Vec<(SocketAddr, u8)> = current
                .iter()
                .filter(|(a, _)| !t.pex.old.contains(a))
                .take(MAX_ENTRIES)
                .copied()
                .collect();
            t.pex.old = current.iter().map(|(a, _)| *a).collect();
            t.pex.delta_entries = added.len() + dropped.len();
            t.pex.delta = Pex { added, dropped }.encode();
        }
    }
    // Peer level: at most one message a minute, and never to a lone peer.
    if t.peers.len() <= 1 {
        return;
    }
    let peers: Vec<Rc<PeerHandle>> = t.peers.values().cloned().collect();
    let full = || {
        let list = exchangeable(t);
        Pex {
            added: list.into_iter().take(MAX_ENTRIES).collect(),
            dropped: Vec::new(),
        }
        .encode()
    };
    for p in peers {
        {
            let conn = p.conn.borrow();
            if !conn.is_established() || !conn.peer_supports("ut_pex") {
                continue;
            }
        }
        let mut st = p.pex.borrow_mut();
        if st
            .last_sent
            .is_some_and(|l| now.duration_since(l) < INTERVAL)
        {
            continue;
        }
        st.last_sent = Some(now);
        let payload = if !st.sent_full {
            st.sent_full = true;
            full()
        } else if t.pex.delta_entries > 0 {
            t.pex.delta.clone()
        } else {
            continue;
        };
        drop(st);
        if p.conn.borrow_mut().extended("ut_pex", &payload) {
            p.out.notify();
        }
    }
}

/// A `ut_pex` message arrived from `handle`.
pub fn on_message(
    ctx: &Rc<Ctx>,
    t: &mut Torrent,
    handle: &Rc<PeerHandle>,
    payload: &[u8],
    now: Instant,
) -> Result<(), String> {
    if payload.len() > MAX_MESSAGE {
        return Err("pex message too large".into());
    }
    {
        let mut st = handle.pex.borrow_mut();
        st.received.push_back(now);
        while st.received.len() > MAX_PER_MINUTE {
            st.received.pop_front();
        }
        if st.received.len() == MAX_PER_MINUTE
            && let Some(oldest) = st.received.front()
            && now.duration_since(*oldest) < INTERVAL
        {
            return Err("too frequent pex messages".into());
        }
    }
    if !ctx.cfg.pex || !t.discovery_allowed() {
        // Silently ignored, as libtorrent does with `disable_pex`.
        return Ok(());
    }
    let pex = Pex::parse(payload).map_err(|e| format!("pex: {e}"))?;
    let addrs: Vec<SocketAddr> = pex.added.iter().map(|(a, _)| *a).collect();
    let added = t.add_candidates(ctx, &addrs, PeerSource::Pex);
    if ctx.cfg.encryption == EncryptionMode::Enabled {
        for (a, f) in &pex.added {
            if f & pex_flags::ENCRYPTION != 0 {
                t.mse_retry.insert(*a);
            }
        }
    }
    for (a, f) in &pex.added {
        if f & pex_flags::UTP != 0 {
            t.utp_failed.remove(a);
        }
    }
    tracing::debug!(
        addr = %handle.addr,
        torrent = t.id.0,
        added,
        dropped = pex.dropped.len(),
        "pex"
    );
    ctx.emit(Event::PexPeers {
        id: t.id,
        from: handle.addr,
        added,
        dropped: pex.dropped.len(),
    });
    Ok(())
}
