// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Metadata exchange (BEP 9, `ut_metadata`) for magnet links, following
//! libtorrent's `ut_metadata` plugin (ported logic from
//! `src/ut_metadata.cpp`, BSD-3; see `NOTICE`):
//!
//! - Fetching: at most two outstanding requests per peer; the least-requested
//!   piece first (piece 0 alone until a peer tells us the size); a piece is
//!   not re-requested within three seconds while its last source is still
//!   connected; peers that said they have no metadata (`metadata_size`
//!   absent) or rejected a request are not asked again for a minute. When
//!   the assembled dictionary does not hash to the info-hash it is thrown
//!   away and every source is penalised for 20-70 s (five minutes when a
//!   single peer supplied everything).
//! - Serving: 16 KiB pieces of the raw info dictionary; requests out of
//!   range or without metadata get `dont_have`; requests are queued (up to
//!   1024) while the peer's outbound queue is over 160 KiB.
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

use sha1::{Digest, Sha1};
use wire::ext::{MAX_METADATA_SIZE, METADATA_PIECE, Metadata};

use super::Ctx;
use super::peer::PeerHandle;
use super::torrent::Torrent;

/// Outstanding metadata requests per peer.
const MAX_OUTSTANDING: usize = 2;
/// Do not ask the same piece again within this while its source is alive.
const REREQUEST_AFTER: Duration = Duration::from_secs(3);
/// Penalty after a `dont_have`.
const DONT_HAVE_PENALTY: Duration = Duration::from_secs(60);
/// Outbound bytes queued beyond which incoming requests wait for the writer.
const SEND_BUFFER_LIMIT: usize = 16 * 1024 * 10;
/// Queued incoming requests beyond which we answer `dont_have`.
const MAX_INCOMING: usize = 1024;

/// The fetch state of a torrent without metadata.
#[derive(Default)]
pub struct Fetch {
    /// Total size once a peer told us (validated).
    size: Option<usize>,
    buf: Vec<u8>,
    pieces: Vec<Piece>,
}

#[derive(Default, Clone)]
struct Piece {
    requests: u32,
    last_request: Option<Instant>,
    /// The peer (key) that supplied it; `None` until received.
    source: Option<u32>,
    have: bool,
}

/// Per-connection state (lives in the [`PeerHandle`]).
#[derive(Default)]
pub struct PeerState {
    /// Pieces requested from this peer, not yet answered.
    pub sent: Vec<u32>,
    /// Do not request from this peer before this instant.
    pub limit: Option<Instant>,
    /// The peer advertised `metadata_size` (it has the metadata).
    pub has_metadata: bool,
    /// Its requests waiting for the outbound queue to drain.
    pub incoming: VecDeque<u32>,
}

impl Fetch {
    /// Learn the size from a peer's handshake (first one wins).
    pub fn set_size(&mut self, size: usize) -> bool {
        if size == 0 || size > MAX_METADATA_SIZE {
            return false;
        }
        if self.size.is_none() {
            self.size = Some(size);
            self.buf = vec![0u8; size];
            self.pieces = vec![Piece::default(); size.div_ceil(METADATA_PIECE)];
        }
        true
    }

    /// The size, if known.
    pub fn size(&self) -> Option<usize> {
        self.size
    }

    /// Choose the next piece to request from a peer (libtorrent
    /// `metadata_request`). `peer_has_metadata` gates the re-request timer so
    /// peers without metadata cannot starve those with it.
    fn pick(
        &mut self,
        peer_has_metadata: bool,
        now: Instant,
        alive: &dyn Fn(u32) -> bool,
    ) -> Option<u32> {
        if self.pieces.is_empty() {
            // Size unknown: ask for piece 0.
            self.pieces.push(Piece::default());
        }
        let (idx, _) = self
            .pieces
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.have)
            .min_by_key(|(_, p)| p.requests)?;
        let p = &mut self.pieces[idx];
        if let Some(last) = p.last_request
            && p.source.is_some_and(alive)
            && now.duration_since(last) < REREQUEST_AFTER
        {
            return None;
        }
        p.requests += 1;
        if peer_has_metadata {
            p.last_request = Some(now);
        }
        Some(idx as u32)
    }

    /// A data piece arrived. `Ok(Some(raw))` when the dictionary is complete.
    fn received(
        &mut self,
        piece: u32,
        total_size: u32,
        data: &[u8],
        source: u32,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        if self.size.is_none() && !self.set_size(total_size as usize) {
            return Err("metadata size out of range");
        }
        let Some(size) = self.size else {
            return Err("no size");
        };
        if total_size as usize != size {
            return Err("total_size inconsistent");
        }
        let piece = piece as usize;
        if piece >= self.pieces.len() {
            return Err("piece out of range");
        }
        let off = piece * METADATA_PIECE;
        if off + data.len() > size {
            return Err("piece overflows metadata");
        }
        self.buf[off..off + data.len()].copy_from_slice(data);
        let p = &mut self.pieces[piece];
        p.have = true;
        p.source = Some(source);
        if self.pieces.iter().all(|p| p.have) {
            Ok(Some(std::mem::take(&mut self.buf)))
        } else {
            Ok(None)
        }
    }

    /// The assembled dictionary failed the hash: start over.
    fn reset(&mut self) -> Vec<u32> {
        let sources: Vec<u32> = self.pieces.iter().filter_map(|p| p.source).collect();
        if let Some(size) = self.size {
            self.buf = vec![0u8; size];
        }
        for p in &mut self.pieces {
            *p = Piece::default();
        }
        sources
    }
}

/// The peer's LTEP handshake arrived: note whether it has metadata and maybe
/// ask for some.
pub fn on_ext_handshake(
    t: &mut Torrent,
    handle: &Rc<PeerHandle>,
    metadata_size: Option<u32>,
    now: Instant,
) {
    {
        let mut st = handle.meta.borrow_mut();
        match metadata_size {
            Some(n) if n > 0 => {
                st.has_metadata = true;
                if !t.has_metadata() && !t.metadata.set_size(n as usize) {
                    tracing::debug!(addr = %handle.addr, n, "metadata_size out of range");
                }
            }
            _ => st.has_metadata = false,
        }
    }
    maybe_request(t, handle, now);
}

/// Send requests while we lack metadata, the peer speaks `ut_metadata`, we
/// have fewer than two outstanding and the peer is not on penalty.
pub fn maybe_request(t: &mut Torrent, handle: &Rc<PeerHandle>, now: Instant) {
    if t.has_metadata() {
        return;
    }
    if !handle.conn.borrow().peer_supports("ut_metadata") {
        return;
    }
    let known_total = t.metadata.size().map(|s| s as u32);
    loop {
        let mut st = handle.meta.borrow_mut();
        if st.sent.len() >= MAX_OUTSTANDING {
            return;
        }
        let allowed = st.has_metadata || st.limit.is_none_or(|l| now > l);
        if !allowed {
            return;
        }
        let peers = &t.peers;
        let alive = |key: u32| peers.contains_key(&key);
        let Some(piece) = t.metadata.pick(st.has_metadata, now, &alive) else {
            return;
        };
        st.sent.push(piece);
        drop(st);
        let payload = Metadata::Request { piece }.encode(known_total);
        handle.conn.borrow_mut().extended("ut_metadata", &payload);
        handle.out.notify();
    }
}

/// A `ut_metadata` message from `handle`.
pub fn on_message(
    ctx: &Rc<Ctx>,
    torrent: &Rc<RefCell<Torrent>>,
    handle: &Rc<PeerHandle>,
    payload: &[u8],
    now: Instant,
) -> Result<(), String> {
    if payload.len() > 17 * 1024 {
        // libtorrent ignores oversize messages.
        return Ok(());
    }
    let msg = Metadata::parse(payload).map_err(|e| format!("ut_metadata: {e}"))?;
    match msg {
        Metadata::Request { piece } => {
            let mut t = torrent.borrow_mut();
            serve(&mut t, handle, piece);
        }
        Metadata::Data {
            piece,
            total_size,
            data,
        } => {
            let complete = {
                let mut t = torrent.borrow_mut();
                let mut st = handle.meta.borrow_mut();
                let Some(pos) = st.sent.iter().position(|p| *p == piece) else {
                    // Unwanted / timed out.
                    return Ok(());
                };
                st.sent.remove(pos);
                drop(st);
                if t.has_metadata() {
                    t.stats.redundant += data.len() as u64;
                    return Ok(());
                }
                match t.metadata.received(piece, total_size, &data, handle.key) {
                    Ok(Some(raw)) => Some(raw),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::debug!(addr = %handle.addr, "ut_metadata data ignored: {e}");
                        None
                    }
                }
            };
            if let Some(raw) = complete {
                let info_hash = torrent.borrow().info_hash;
                let digest: [u8; 20] = Sha1::digest(&raw).into();
                if digest == info_hash {
                    super::torrent::on_metadata(ctx, torrent, raw);
                    return Ok(());
                }
                // Wrong data: penalise every source and start over.
                let mut t = torrent.borrow_mut();
                let sources = t.metadata.reset();
                let single = sources.len() == 1 && t.metadata.pieces.len() == 1;
                tracing::warn!(torrent = t.id.0, "metadata failed its hash check");
                let mut rng = super::rng::RngRef(&ctx.rng);
                for key in sources {
                    if let Some(p) = t.peers.get(&key) {
                        let penalty = if single {
                            Duration::from_secs(5 * 60)
                        } else {
                            Duration::from_secs(20 + u64::from(profile::Rng::below(&mut rng, 50)))
                        };
                        p.meta.borrow_mut().limit = Some(now + penalty);
                    }
                }
            } else {
                let mut t = torrent.borrow_mut();
                maybe_request(&mut t, handle, now);
            }
        }
        Metadata::Reject { piece } => {
            let mut st = handle.meta.borrow_mut();
            let limit = now + DONT_HAVE_PENALTY;
            st.limit = Some(st.limit.map_or(limit, |l| l.max(limit)));
            st.sent.retain(|p| *p != piece);
        }
    }
    Ok(())
}

/// Answer (or queue) a request for a metadata piece.
fn serve(t: &mut Torrent, handle: &Rc<PeerHandle>, piece: u32) {
    let Some(raw) = t.raw_info.clone() else {
        reject(handle, piece, None);
        return;
    };
    let total = raw.len();
    let count = total.div_ceil(METADATA_PIECE);
    if piece as usize >= count {
        reject(handle, piece, Some(total as u32));
        return;
    }
    if handle.conn.borrow().outbound_len() < SEND_BUFFER_LIMIT {
        send_piece(handle, &raw, piece);
    } else {
        let mut st = handle.meta.borrow_mut();
        if st.incoming.len() < MAX_INCOMING {
            st.incoming.push_back(piece);
        } else {
            drop(st);
            reject(handle, piece, Some(total as u32));
        }
    }
}

fn reject(handle: &Rc<PeerHandle>, piece: u32, total: Option<u32>) {
    let payload = Metadata::Reject { piece }.encode(total);
    if handle.conn.borrow_mut().extended("ut_metadata", &payload) {
        handle.out.notify();
    }
}

fn send_piece(handle: &Rc<PeerHandle>, raw: &[u8], piece: u32) {
    let off = piece as usize * METADATA_PIECE;
    let end = (off + METADATA_PIECE).min(raw.len());
    let payload = Metadata::Data {
        piece,
        total_size: raw.len() as u32,
        data: raw[off..end].to_vec(),
    }
    .encode(None);
    if handle.conn.borrow_mut().extended("ut_metadata", &payload) {
        handle.out.notify();
    }
}

/// Once a second: keep fetch requests flowing and drain queued incoming
/// requests as the outbound queue empties.
pub fn tick(t: &mut Torrent, now: Instant) {
    let peers: Vec<Rc<PeerHandle>> = t.peers.values().cloned().collect();
    let raw = t.raw_info.clone();
    for p in &peers {
        if !p.conn.borrow().is_established() {
            continue;
        }
        maybe_request(t, p, now);
        if let Some(raw) = &raw {
            loop {
                if p.conn.borrow().outbound_len() >= SEND_BUFFER_LIMIT {
                    break;
                }
                let next = p.meta.borrow_mut().incoming.pop_front();
                match next {
                    Some(piece) => send_piece(p, raw, piece),
                    None => break,
                }
            }
        }
    }
}
