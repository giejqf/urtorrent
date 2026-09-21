// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Piece extent affinity follows libtorrent-rasterbar (BSD-3-Clause),
// Copyright (c) Arvid Norberg and contributors; see NOTICE.

//! The piece picker: decides which blocks to request from which peer.
//!
//! Policy (libtorrent's defaults as sane starting points, AGENTS.md 6 L3):
//! pieces we are already downloading first (fewer open pieces), then rarest
//! first with a random tie-break, priorities 1..7 above 0 (= skip), optional
//! sequential mode, and end-game (duplicate requests to other peers once every
//! remaining block is already requested) with cancellation of the losers.
//!
//! Piece extent affinity (libtorrent's `piece_extent_affinity`, on by default
//! here): with pieces smaller than 4 MiB, a few recently started 4 MiB
//! extents are finished before rarest-first chooses the next one, so the
//! disk sees runs of contiguous writes rather than 16 KiB scattered over the
//! whole file (which leaves the kernel's writeback with random I/O). Piece
//! order is L3 behaviour; the oracle ships the option off.
//!
//! Pure state: no I/O, no clock, randomness injected through
//! [`profile::Rng`]. The session owns the mapping from its peers to
//! [`PeerKey`]s and turns [`Block`]s into wire requests.
//!
//! Every hot query is O(1) or proportional to what it returns, never to the
//! piece count: completion, bytes left and end-game come from counters kept
//! up to date by every state change, and `pick` walks an index (partial
//! pieces in one list, untouched wanted pieces bucketed by priority and
//! availability, plus an ordered set for sequential mode) instead of
//! scanning every piece.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use metainfo::Bitfield;
use profile::Rng;

/// The request granularity every client uses.
pub const BLOCK_SIZE: u32 = 16 * 1024;

/// Opaque per-peer identifier chosen by the caller.
pub type PeerKey = u32;

/// A block to request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Block {
    /// Piece index.
    pub piece: u32,
    /// Byte offset within the piece.
    pub offset: u32,
    /// Length in bytes (`BLOCK_SIZE` except possibly the torrent's last block).
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BlockState {
    Free,
    Requested(Vec<PeerKey>),
    Received,
}

/// Where a piece sits in the pick index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loc {
    /// Have, or priority 0: not a candidate.
    None,
    /// Being downloaded (block state allocated): `open[slot]`.
    Open,
    /// Untouched and wanted: `fresh[prio][avail][slot]`.
    Fresh { prio: u8, avail: u32 },
}

#[derive(Debug, Clone)]
struct Piece {
    availability: u32,
    priority: u8,
    have: bool,
    /// Allocated once the piece is being downloaded.
    blocks: Option<Vec<BlockState>>,
    free: u32,
    received: u32,
    loc: Loc,
    /// Index within its `Loc` container.
    slot: u32,
}

impl Piece {
    fn wanted(&self) -> bool {
        !self.have && self.priority > 0
    }
}

/// What happened to a received block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// The block was wanted and is now marked received. `cancel` lists other
    /// peers that had the same block outstanding (end-game duplicates);
    /// `piece_complete` says every block of the piece is in.
    Accepted {
        /// Other peers to send `cancel` to for this block.
        cancel: Vec<PeerKey>,
        /// Whether the piece is now fully received (ready to hash).
        piece_complete: bool,
    },
    /// Already had it, piece already complete, or unwanted: wasted bytes.
    Redundant,
}

/// The picker for one torrent.
#[derive(Debug, Clone)]
pub struct Picker {
    pieces: Vec<Piece>,
    piece_length: u32,
    total_length: u64,
    sequential: bool,
    /// Wanted blocks not requested by anyone and not received.
    free_blocks: u64,
    have_count: usize,
    /// Pieces with priority > 0, and how many of those we have.
    wanted_count: usize,
    wanted_have: usize,
    /// Bytes of pieces we have, and of wanted pieces we have / in total.
    have_bytes: u64,
    wanted_bytes: u64,
    wanted_have_bytes: u64,
    /// Pieces only one peer may download (after a hash failure with several
    /// suppliers, so the next failure has a single culprit).
    exclusive: std::collections::HashMap<usize, PeerKey>,
    /// Pieces being downloaded.
    open: Vec<usize>,
    /// Untouched wanted pieces: `fresh[priority][availability]`.
    fresh: Vec<Vec<Vec<usize>>>,
    /// Untouched wanted pieces *someone has* ordered by `(7 - priority,
    /// index)`, for sequential picking. Pieces with availability 0 are only
    /// in `fresh[prio][0]`, which no pick path visits: nobody can serve them.
    fresh_seq: std::collections::BTreeSet<(u8, usize)>,
    /// Extents (runs of `extent_len` pieces) we recently started downloading
    /// and prefer to finish, oldest first; at most `MAX_RECENT_EXTENTS`.
    recent_extents: Vec<usize>,
    /// Whether extent affinity is on (it never applies to pieces of 4 MiB or
    /// more, nor in sequential mode).
    extent_affinity: bool,
}

/// Size of a piece extent for affinity purposes (libtorrent
/// `max_piece_affinity_extent`, 4 MiB expressed in blocks there).
const EXTENT_BYTES: u64 = 4 << 20;
/// How many extents are kept "recent" (libtorrent hardcodes 5).
const MAX_RECENT_EXTENTS: usize = 5;

/// Maximum distinct pieces one `pick` call opens (keeps a single call cheap).
const MAX_PIECES_PER_PICK: usize = 16;

/// The fixed inputs of one `pick` call.
struct PickCtx<'a> {
    peer: PeerKey,
    has: &'a dyn Fn(usize) -> bool,
    /// Pieces already opened by this call.
    used: &'a [usize],
    end_game: bool,
    sequential: bool,
}

impl Picker {
    /// A picker for `piece_count` pieces of `piece_length` bytes (`total_length`
    /// fixes the last piece's size), nothing downloaded, all priorities normal.
    pub fn new(piece_count: usize, piece_length: u32, total_length: u64) -> Picker {
        let mut p = Picker {
            pieces: vec![
                Piece {
                    availability: 0,
                    priority: 4,
                    have: false,
                    blocks: None,
                    free: 0,
                    received: 0,
                    loc: Loc::None,
                    slot: 0,
                };
                piece_count
            ],
            piece_length: piece_length.max(1),
            total_length,
            sequential: false,
            free_blocks: 0,
            have_count: 0,
            wanted_count: 0,
            wanted_have: 0,
            have_bytes: 0,
            wanted_bytes: 0,
            wanted_have_bytes: 0,
            exclusive: std::collections::HashMap::new(),
            open: Vec::new(),
            fresh: vec![Vec::new(); 8],
            fresh_seq: std::collections::BTreeSet::new(),
            recent_extents: Vec::new(),
            extent_affinity: true,
        };
        p.rebuild();
        p
    }

    /// Turn piece extent affinity on or off (default on).
    pub fn set_extent_affinity(&mut self, on: bool) {
        self.extent_affinity = on;
        if !on {
            self.recent_extents.clear();
        }
    }

    /// Pieces per extent, or `None` when a single piece is already 4 MiB.
    fn extent_len(&self) -> Option<usize> {
        let n = (EXTENT_BYTES / u64::from(self.piece_length)) as usize;
        (self.extent_affinity && n >= 2).then_some(n)
    }

    /// The pieces of extent `e`.
    fn extent_range(&self, e: usize, len: usize) -> std::ops::Range<usize> {
        let begin = e * len;
        begin..(begin + len).min(self.pieces.len())
    }

    /// We started downloading `piece`: remember its extent so the next picks
    /// stay nearby (libtorrent `record_downloading_piece`). Not recorded when
    /// the extent mixes priorities (probably a file boundary) or when we have
    /// every other piece of it already.
    fn record_downloading_piece(&mut self, piece: usize) {
        let Some(len) = self.extent_len() else {
            return;
        };
        let e = piece / len;
        if self.recent_extents.contains(&e) || self.recent_extents.len() >= MAX_RECENT_EXTENTS {
            return;
        }
        let prio = self.pieces[piece].priority;
        let mut have_all_others = true;
        for i in self.extent_range(e, len) {
            if i == piece {
                continue;
            }
            let p = &self.pieces[i];
            if p.priority != prio {
                return;
            }
            if !p.have {
                have_all_others = false;
            }
        }
        if have_all_others {
            return;
        }
        self.recent_extents.push(e);
    }

    /// A pickable piece from the oldest recent extent that has one: a piece
    /// already being downloaded before an untouched one (our "partial first"
    /// rule keeps holding inside the extent), lowest index otherwise.
    /// Extents we have completely are dropped on the way.
    fn pick_in_recent_extents(&mut self, c: &PickCtx<'_>) -> Option<usize> {
        let len = self.extent_len()?;
        let mut found = None;
        let mut keep = Vec::with_capacity(self.recent_extents.len());
        for &e in &self.recent_extents {
            let mut have_all = true;
            let mut fresh = None;
            for i in self.extent_range(e, len) {
                let p = &self.pieces[i];
                have_all &= p.have;
                if found.is_some() || !p.wanted() || !self.eligible(i, c) {
                    continue;
                }
                if p.blocks.is_some() {
                    found = Some(i);
                } else if fresh.is_none() {
                    fresh = Some(i);
                }
            }
            found = found.or(fresh);
            if !have_all {
                keep.push(e);
            }
        }
        self.recent_extents = keep;
        found
    }

    // --- geometry ---

    /// Number of pieces.
    pub fn piece_count(&self) -> usize {
        self.pieces.len()
    }

    /// Length of piece `i` in bytes.
    pub fn piece_size(&self, i: usize) -> u32 {
        let start = i as u64 * u64::from(self.piece_length);
        self.total_length
            .saturating_sub(start)
            .min(u64::from(self.piece_length)) as u32
    }

    /// Number of blocks in piece `i`.
    pub fn blocks_in(&self, i: usize) -> u32 {
        self.piece_size(i).div_ceil(BLOCK_SIZE).max(1)
    }

    fn block_at(&self, piece: usize, b: u32) -> Block {
        let offset = b * BLOCK_SIZE;
        let length = (self.piece_size(piece) - offset).min(BLOCK_SIZE);
        Block {
            piece: piece as u32,
            offset,
            length,
        }
    }

    fn block_index(&self, block: &Block) -> Option<(usize, u32)> {
        let piece = block.piece as usize;
        if piece >= self.pieces.len() || !block.offset.is_multiple_of(BLOCK_SIZE) {
            return None;
        }
        let b = block.offset / BLOCK_SIZE;
        if b >= self.blocks_in(piece) || self.block_at(piece, b).length != block.length {
            return None;
        }
        Some((piece, b))
    }

    // --- counters and index maintenance ---

    /// Free (unrequested, unreceived) blocks of a wanted piece.
    fn free_in(&self, i: usize) -> u64 {
        let p = &self.pieces[i];
        match &p.blocks {
            Some(_) => u64::from(p.free),
            None => u64::from(self.blocks_in(i)),
        }
    }

    /// Recompute every counter and the whole index (bulk changes only).
    fn rebuild(&mut self) {
        self.free_blocks = 0;
        self.have_count = 0;
        self.wanted_count = 0;
        self.wanted_have = 0;
        self.have_bytes = 0;
        self.wanted_bytes = 0;
        self.wanted_have_bytes = 0;
        self.open.clear();
        for b in &mut self.fresh {
            b.clear();
        }
        self.fresh_seq.clear();
        for i in 0..self.pieces.len() {
            let size = u64::from(self.piece_size(i));
            let p = &self.pieces[i];
            if p.have {
                self.have_count += 1;
                self.have_bytes += size;
            }
            if p.priority > 0 {
                self.wanted_count += 1;
                self.wanted_bytes += size;
                if p.have {
                    self.wanted_have += 1;
                    self.wanted_have_bytes += size;
                }
            }
            if p.wanted() {
                self.free_blocks += self.free_in(i);
            }
            self.pieces[i].loc = Loc::None;
            self.place(i);
        }
    }

    /// Put piece `i` where its state says it belongs (removing it from where
    /// it was).
    fn place(&mut self, i: usize) {
        self.unplace(i);
        let p = &self.pieces[i];
        let loc = if !p.wanted() {
            Loc::None
        } else if p.blocks.is_some() {
            Loc::Open
        } else {
            Loc::Fresh {
                prio: p.priority,
                avail: p.availability,
            }
        };
        match loc {
            Loc::None => {}
            Loc::Open => {
                self.pieces[i].slot = self.open.len() as u32;
                self.open.push(i);
            }
            Loc::Fresh { prio, avail } => {
                let by_prio = &mut self.fresh[prio as usize];
                if by_prio.len() <= avail as usize {
                    by_prio.resize(avail as usize + 1, Vec::new());
                }
                let bucket = &mut by_prio[avail as usize];
                self.pieces[i].slot = bucket.len() as u32;
                bucket.push(i);
                if avail > 0 {
                    self.fresh_seq.insert((7 - prio, i));
                }
            }
        }
        self.pieces[i].loc = loc;
    }

    /// Remove piece `i` from its container.
    fn unplace(&mut self, i: usize) {
        let (loc, slot) = (self.pieces[i].loc, self.pieces[i].slot as usize);
        match loc {
            Loc::None => return,
            Loc::Open => {
                let last = self.open.len() - 1;
                self.open.swap_remove(slot);
                if slot != last {
                    let moved = self.open[slot];
                    self.pieces[moved].slot = slot as u32;
                }
            }
            Loc::Fresh { prio, avail } => {
                let bucket = &mut self.fresh[prio as usize][avail as usize];
                let last = bucket.len() - 1;
                bucket.swap_remove(slot);
                if slot != last {
                    let moved = bucket[slot];
                    self.pieces[moved].slot = slot as u32;
                }
                if avail > 0 {
                    self.fresh_seq.remove(&(7 - prio, i));
                }
            }
        }
        self.pieces[i].loc = Loc::None;
    }

    // --- our state ---

    /// Replace our have-set (from storage / resume). Resets block bookkeeping
    /// for pieces we now have.
    pub fn set_have(&mut self, have: &Bitfield) {
        for (i, p) in self.pieces.iter_mut().enumerate() {
            p.have = have.get(i);
            if p.have {
                p.blocks = None;
                p.free = 0;
                p.received = 0;
            }
        }
        self.rebuild();
    }

    /// Only `peer` may download piece `i` from now on (until the piece
    /// verifies, fails again, or the peer leaves).
    pub fn set_exclusive(&mut self, i: usize, peer: PeerKey) {
        if i < self.pieces.len() {
            self.exclusive.insert(i, peer);
        }
    }

    /// The peer piece `i` is reserved for, if any.
    pub fn exclusive(&self, i: usize) -> Option<PeerKey> {
        self.exclusive.get(&i).copied()
    }

    /// Piece `i` verified: we have it.
    pub fn piece_verified(&mut self, i: usize) {
        self.exclusive.remove(&i);
        if i >= self.pieces.len() {
            return;
        }
        if self.pieces[i].wanted() {
            self.free_blocks -= self.free_in(i);
        }
        let size = u64::from(self.piece_size(i));
        let p = &mut self.pieces[i];
        if !p.have {
            p.have = true;
            self.have_count += 1;
            self.have_bytes += size;
            if p.priority > 0 {
                self.wanted_have += 1;
                self.wanted_have_bytes += size;
            }
        }
        p.blocks = None;
        p.free = 0;
        p.received = 0;
        self.place(i);
    }

    /// Piece `i` failed its hash: every block goes back to free (the caller
    /// attributes blame to the peers that supplied it).
    pub fn piece_failed(&mut self, i: usize) {
        self.exclusive.remove(&i);
        if i >= self.pieces.len() {
            return;
        }
        if self.pieces[i].wanted() {
            self.free_blocks -= self.free_in(i);
        }
        let p = &mut self.pieces[i];
        p.blocks = None;
        p.free = 0;
        p.received = 0;
        if self.pieces[i].wanted() {
            self.free_blocks += self.free_in(i);
        }
        self.place(i);
    }

    /// Set the priority of piece `i` (0 = do not download, 1..7).
    pub fn set_priority(&mut self, i: usize, priority: u8) {
        if i >= self.pieces.len() {
            return;
        }
        let priority = priority.min(7);
        let size = u64::from(self.piece_size(i));
        if self.pieces[i].wanted() {
            self.free_blocks -= self.free_in(i);
        }
        {
            let p = &self.pieces[i];
            if p.priority > 0 {
                self.wanted_count -= 1;
                self.wanted_bytes -= size;
                if p.have {
                    self.wanted_have -= 1;
                    self.wanted_have_bytes -= size;
                }
            }
        }
        self.pieces[i].priority = priority;
        {
            let p = &self.pieces[i];
            if p.priority > 0 {
                self.wanted_count += 1;
                self.wanted_bytes += size;
                if p.have {
                    self.wanted_have += 1;
                    self.wanted_have_bytes += size;
                }
            }
        }
        if self.pieces[i].wanted() {
            self.free_blocks += self.free_in(i);
        }
        self.place(i);
    }

    /// Priority of piece `i`.
    pub fn priority(&self, i: usize) -> u8 {
        self.pieces.get(i).map_or(0, |p| p.priority)
    }

    /// Download in index order instead of rarest-first.
    pub fn set_sequential(&mut self, sequential: bool) {
        self.sequential = sequential;
    }

    /// Whether sequential mode is on.
    pub fn sequential(&self) -> bool {
        self.sequential
    }

    /// Pieces we have.
    pub fn have_count(&self) -> usize {
        self.have_count
    }

    /// Whether piece `i` is ours.
    pub fn have(&self, i: usize) -> bool {
        self.pieces.get(i).is_some_and(|p| p.have)
    }

    /// Our have-set as a bitfield.
    pub fn have_bitfield(&self) -> Bitfield {
        let mut bf = Bitfield::new(self.pieces.len());
        for (i, p) in self.pieces.iter().enumerate() {
            if p.have {
                bf.set(i);
            }
        }
        bf
    }

    /// Whether every *wanted* piece is ours.
    pub fn is_complete(&self) -> bool {
        self.wanted_have == self.wanted_count
    }

    /// Whether every piece is ours (a true seed).
    pub fn is_seed(&self) -> bool {
        self.have_count == self.pieces.len()
    }

    /// Bytes of the whole torrent we do not have yet (the announce `left`).
    pub fn bytes_left(&self) -> u64 {
        self.total_length.saturating_sub(self.have_bytes)
    }

    /// Bytes of wanted pieces we do not have yet.
    pub fn wanted_bytes_left(&self) -> u64 {
        self.wanted_bytes.saturating_sub(self.wanted_have_bytes)
    }

    /// Bytes of pieces with priority > 0, and those of them we have.
    pub fn wanted_totals(&self) -> (u64, u64) {
        (self.wanted_bytes, self.wanted_have_bytes)
    }

    /// Whether we are in end-game: nothing left to request except blocks
    /// already outstanding elsewhere.
    pub fn end_game(&self) -> bool {
        self.free_blocks == 0 && !self.is_complete()
    }

    // --- peer availability ---

    fn set_availability(&mut self, i: usize, avail: u32) {
        let p = &self.pieces[i];
        if p.availability == avail {
            return;
        }
        let Loc::Fresh { prio, avail: old } = p.loc else {
            self.pieces[i].availability = avail;
            return;
        };
        // Move between availability buckets of the same priority without
        // going through `place`: `fresh_seq` only cares whether anyone has
        // the piece.
        let slot = p.slot as usize;
        let by_prio = &mut self.fresh[prio as usize];
        let bucket = &mut by_prio[old as usize];
        let last = bucket.len() - 1;
        bucket.swap_remove(slot);
        if slot != last {
            let moved = bucket[slot];
            self.pieces[moved].slot = slot as u32;
        }
        if by_prio.len() <= avail as usize {
            by_prio.resize(avail as usize + 1, Vec::new());
        }
        let bucket = &mut by_prio[avail as usize];
        let p = &mut self.pieces[i];
        p.slot = bucket.len() as u32;
        p.availability = avail;
        p.loc = Loc::Fresh { prio, avail };
        bucket.push(i);
        match (old == 0, avail == 0) {
            (true, false) => {
                self.fresh_seq.insert((7 - prio, i));
            }
            (false, true) => {
                self.fresh_seq.remove(&(7 - prio, i));
            }
            _ => {}
        }
    }

    /// A peer with this bitfield joined (or sent its bitfield).
    pub fn peer_joined(&mut self, has: &Bitfield) {
        for i in has.iter_set() {
            if i < self.pieces.len() {
                let a = self.pieces[i].availability + 1;
                self.set_availability(i, a);
            }
        }
    }

    /// A peer with this bitfield left (or replaced its bitfield).
    pub fn peer_left(&mut self, had: &Bitfield) {
        for i in had.iter_set() {
            if i < self.pieces.len() {
                let a = self.pieces[i].availability.saturating_sub(1);
                self.set_availability(i, a);
            }
        }
    }

    /// A peer announced one more piece (`have`).
    pub fn peer_has(&mut self, i: usize) {
        if i < self.pieces.len() {
            let a = self.pieces[i].availability + 1;
            self.set_availability(i, a);
        }
    }

    /// How many peers have piece `i`.
    pub fn availability(&self, i: usize) -> u32 {
        self.pieces.get(i).map_or(0, |p| p.availability)
    }

    // --- requests ---

    fn ensure_blocks(&mut self, piece: usize) {
        let n = self.blocks_in(piece);
        if self.pieces[piece].blocks.is_none() {
            let p = &mut self.pieces[piece];
            p.blocks = Some(vec![BlockState::Free; n as usize]);
            p.free = n;
            p.received = 0;
            self.place(piece);
        }
    }

    /// Blocks of `piece` this peer could request: free ones, or (end-game)
    /// ones requested only by others.
    fn pickable(&self, piece: usize, peer: PeerKey, end_game: bool) -> bool {
        let p = &self.pieces[piece];
        match &p.blocks {
            None => true,
            Some(blocks) => {
                p.free > 0
                    || (end_game
                        && blocks
                            .iter()
                            .any(|b| matches!(b, BlockState::Requested(by) if !by.contains(&peer))))
            }
        }
    }

    /// Whether the peer may pick `piece` at all (has it, not reserved for
    /// someone else, not already opened in this call, something to request).
    fn eligible(&self, piece: usize, c: &PickCtx<'_>) -> bool {
        (c.has)(piece)
            && !c.used.contains(&piece)
            && (self.exclusive.is_empty()
                || !self.exclusive.get(&piece).is_some_and(|k| *k != c.peer))
            && self.pickable(piece, c.peer, c.end_game)
    }

    /// Choose up to `want` blocks for `peer`, whose have-set is `has`.
    /// Returned blocks are marked requested by `peer`; the caller must later
    /// report each as received, or release it with [`Picker::release`] /
    /// [`Picker::peer_gone`].
    pub fn pick(
        &mut self,
        peer: PeerKey,
        has: &dyn Fn(usize) -> bool,
        want: usize,
        rng: &mut dyn Rng,
    ) -> Vec<Block> {
        let sequential = self.sequential;
        self.pick_mode(peer, has, want, rng, sequential, Vec::new())
    }

    /// [`Picker::pick`] that first takes free blocks from `preferred` (in
    /// order; pieces the peer suggested, BEP 6 `suggest piece`), skipping
    /// pieces the peer lacks or we do not want, then falls back to the
    /// normal strategy for the rest.
    pub fn pick_preferring(
        &mut self,
        peer: PeerKey,
        has: &dyn Fn(usize) -> bool,
        want: usize,
        preferred: &[usize],
        rng: &mut dyn Rng,
    ) -> Vec<Block> {
        let mut out = Vec::with_capacity(want);
        let mut used: Vec<usize> = Vec::new();
        for &piece in preferred {
            if out.len() >= want || used.len() >= MAX_PIECES_PER_PICK {
                break;
            }
            if piece >= self.pieces.len()
                || used.contains(&piece)
                || !self.pieces[piece].wanted()
                || !has(piece)
            {
                continue;
            }
            used.push(piece);
            if self.pieces[piece].blocks.is_none() {
                self.record_downloading_piece(piece);
            }
            self.ensure_blocks(piece);
            self.take_free_blocks(piece, peer, want, &mut out);
        }
        if out.len() < want {
            let sequential = self.sequential;
            let rest = want - out.len();
            out.extend(self.pick_mode(peer, has, rest, rng, sequential, used));
        }
        out
    }

    /// Append the free blocks of `piece` to `out` (up to `want` in total),
    /// marking them requested by `peer`.
    fn take_free_blocks(&mut self, piece: usize, peer: PeerKey, want: usize, out: &mut Vec<Block>) {
        let n = self.blocks_in(piece);
        for b in 0..n {
            if out.len() >= want {
                break;
            }
            let free = matches!(
                self.pieces[piece]
                    .blocks
                    .as_ref()
                    .and_then(|v| v.get(b as usize)),
                Some(BlockState::Free)
            );
            if free {
                out.push(self.block_at(piece, b));
                self.mark_requested(piece, b, peer);
            }
        }
    }

    /// [`Picker::pick`] preferring the lowest-index pieces regardless of the
    /// torrent's mode: contiguous ranges for web seeds (BEP 19), which fetch
    /// byte ranges rather than blocks.
    pub fn pick_contiguous(
        &mut self,
        peer: PeerKey,
        has: &dyn Fn(usize) -> bool,
        want: usize,
        rng: &mut dyn Rng,
    ) -> Vec<Block> {
        self.pick_mode(peer, has, want, rng, true, Vec::new())
    }

    /// The best partial (open) piece for the peer: highest priority, then
    /// rarest (or lowest index when sequential), random tie-break.
    fn best_open(&self, c: &PickCtx<'_>, rng: &mut dyn Rng) -> Option<(u64, usize)> {
        let mut best: Option<(u64, usize)> = None;
        let mut ties = 0u32;
        for &i in &self.open {
            if !self.eligible(i, c) {
                continue;
            }
            let p = &self.pieces[i];
            let key = if c.sequential {
                ((7 - u64::from(p.priority)) << 40) | (i as u64)
            } else {
                ((7 - u64::from(p.priority)) << 40) | u64::from(p.availability)
            };
            match best {
                None => {
                    best = Some((key, i));
                    ties = 1;
                }
                Some((bk, _)) if key < bk => {
                    best = Some((key, i));
                    ties = 1;
                }
                Some((bk, _)) if key == bk && !c.sequential => {
                    ties += 1;
                    if rng.below(ties) == 0 {
                        best = Some((key, i));
                    }
                }
                _ => {}
            }
        }
        best
    }

    /// The best untouched piece for the peer at a priority strictly above
    /// `above_prio` (partial pieces win ties at equal priority): rarest
    /// first, random within a bucket; or lowest index when sequential.
    fn best_fresh(
        &self,
        c: &PickCtx<'_>,
        above_prio: u8,
        rng: &mut dyn Rng,
    ) -> Option<(u64, usize)> {
        if c.sequential {
            // `fresh_seq` is ordered by (7 - priority, index): the first
            // eligible entry above the bound is the answer.
            for &(inv, i) in &self.fresh_seq {
                let prio = 7 - inv;
                if prio <= above_prio {
                    return None;
                }
                if self.eligible(i, c) {
                    return Some(((u64::from(inv) << 40) | (i as u64), i));
                }
            }
            return None;
        }
        for prio in ((above_prio + 1)..=7).rev() {
            let by_avail = &self.fresh[prio as usize];
            // Availability 0 is skipped: no peer can have those pieces (the
            // caller keeps availability in step with the peers' have-sets,
            // web seeds included).
            for (avail, bucket) in by_avail.iter().enumerate().skip(1) {
                if bucket.is_empty() {
                    continue;
                }
                // Random start, first eligible piece from there.
                let n = bucket.len();
                let start = rng.below(n as u32) as usize;
                for k in 0..n {
                    let i = bucket[(start + k) % n];
                    if self.eligible(i, c) {
                        let key = ((7 - u64::from(prio)) << 40) | avail as u64;
                        return Some((key, i));
                    }
                }
            }
        }
        None
    }

    fn pick_mode(
        &mut self,
        peer: PeerKey,
        has: &dyn Fn(usize) -> bool,
        want: usize,
        rng: &mut dyn Rng,
        sequential: bool,
        mut used: Vec<usize>,
    ) -> Vec<Block> {
        let mut out = Vec::with_capacity(want);
        let end_game = self.end_game();
        while out.len() < want && used.len() < MAX_PIECES_PER_PICK {
            let c = PickCtx {
                peer,
                has,
                used: &used,
                end_game,
                sequential,
            };
            // Recently started extents first (rarest-first mode only), then
            // partial pieces at equal priority; a fresh piece only wins with
            // a strictly higher priority (or, in sequential mode, a lower
            // index at the same priority).
            let affine = if sequential {
                None
            } else {
                self.pick_in_recent_extents(&c)
            };
            let piece = if let Some(i) = affine {
                i
            } else {
                let partial = self.best_open(&c, rng);
                let bound = partial.map_or(0, |(_, i)| self.pieces[i].priority);
                let fresh = if sequential {
                    // Sequential: index decides within a priority, so compare
                    // keys.
                    self.best_fresh(&c, bound.saturating_sub(1), rng)
                } else {
                    self.best_fresh(&c, bound, rng)
                };
                match (partial, fresh) {
                    (None, None) => break,
                    (Some((_, i)), None) => i,
                    (None, Some((_, i))) => i,
                    // Sequential: the lower key (priority, then index) wins.
                    (Some((kp, ip)), Some((kf, jf))) if sequential => {
                        if kf < kp {
                            jf
                        } else {
                            ip
                        }
                    }
                    // Rarest-first: `best_fresh` only returned a piece at a
                    // strictly higher priority than the partial one.
                    (Some(_), Some((_, jf))) => jf,
                }
            };
            used.push(piece);
            if self.pieces[piece].blocks.is_none() {
                self.record_downloading_piece(piece);
            }
            self.ensure_blocks(piece);
            // First pass: free blocks. Second pass (end-game): duplicates,
            // fewest requesters first.
            self.take_free_blocks(piece, peer, want, &mut out);
            if end_game && out.len() < want {
                let mut dups: Vec<(usize, u32)> = Vec::new();
                if let Some(blocks) = &self.pieces[piece].blocks {
                    for (b, st) in blocks.iter().enumerate() {
                        if let BlockState::Requested(by) = st
                            && !by.contains(&peer)
                        {
                            dups.push((by.len(), b as u32));
                        }
                    }
                }
                dups.sort_unstable();
                for (_, b) in dups {
                    if out.len() >= want {
                        break;
                    }
                    out.push(self.block_at(piece, b));
                    self.mark_requested(piece, b, peer);
                }
            }
        }
        out
    }

    fn mark_requested(&mut self, piece: usize, b: u32, peer: PeerKey) {
        let p = &mut self.pieces[piece];
        let Some(blocks) = p.blocks.as_mut() else {
            return;
        };
        let Some(st) = blocks.get_mut(b as usize) else {
            return;
        };
        match st {
            BlockState::Free => {
                *st = BlockState::Requested(vec![peer]);
                p.free -= 1;
                self.free_blocks = self.free_blocks.saturating_sub(1);
            }
            BlockState::Requested(by) => {
                if !by.contains(&peer) {
                    by.push(peer);
                }
            }
            BlockState::Received => {}
        }
    }

    /// A block arrived from `peer`.
    pub fn block_received(&mut self, peer: PeerKey, block: &Block) -> Received {
        let Some((piece, b)) = self.block_index(block) else {
            return Received::Redundant;
        };
        if self.pieces[piece].have || self.pieces[piece].priority == 0 {
            return Received::Redundant;
        }
        self.ensure_blocks(piece);
        let p = &mut self.pieces[piece];
        let Some(blocks) = p.blocks.as_mut() else {
            return Received::Redundant;
        };
        let st = &mut blocks[b as usize];
        let cancel = match std::mem::replace(st, BlockState::Received) {
            BlockState::Received => {
                *st = BlockState::Received;
                return Received::Redundant;
            }
            BlockState::Free => {
                // Unrequested but wanted (e.g. after a choke dropped the
                // bookkeeping): still useful.
                p.free -= 1;
                self.free_blocks = self.free_blocks.saturating_sub(1);
                Vec::new()
            }
            BlockState::Requested(by) => by.into_iter().filter(|k| *k != peer).collect(),
        };
        p.received += 1;
        let piece_complete = p.received == blocks.len() as u32;
        Received::Accepted {
            cancel,
            piece_complete,
        }
    }

    /// `peer` no longer has `block` outstanding (timeout, reject, cancel).
    pub fn release(&mut self, peer: PeerKey, block: &Block) {
        let Some((piece, b)) = self.block_index(block) else {
            return;
        };
        let p = &mut self.pieces[piece];
        let Some(blocks) = p.blocks.as_mut() else {
            return;
        };
        if let BlockState::Requested(by) = &mut blocks[b as usize] {
            by.retain(|k| *k != peer);
            if by.is_empty() {
                blocks[b as usize] = BlockState::Free;
                p.free += 1;
                if p.priority > 0 && !p.have {
                    self.free_blocks += 1;
                }
            }
        }
        self.maybe_drop_empty(piece);
    }

    /// `peer` disconnected: release everything it had outstanding. Returns the
    /// released blocks.
    pub fn peer_gone(&mut self, peer: PeerKey) -> Vec<Block> {
        self.exclusive.retain(|_, k| *k != peer);
        let mut released = Vec::new();
        // Only open pieces have block state.
        let open: Vec<usize> = self.open.clone();
        for piece in open {
            let n = self.blocks_in(piece);
            let Some(blocks) = self.pieces[piece].blocks.as_ref() else {
                continue;
            };
            let hits: Vec<u32> = (0..n)
                .filter(|b| {
                    matches!(blocks.get(*b as usize), Some(BlockState::Requested(by)) if by.contains(&peer))
                })
                .collect();
            for b in hits {
                let block = self.block_at(piece, b);
                self.release(peer, &block);
                released.push(block);
            }
        }
        released
    }

    /// Blocks `peer` currently has outstanding according to the picker.
    pub fn outstanding_for(&self, peer: PeerKey) -> Vec<Block> {
        let mut v = Vec::new();
        for &piece in &self.open {
            if let Some(blocks) = &self.pieces[piece].blocks {
                for (b, st) in blocks.iter().enumerate() {
                    if let BlockState::Requested(by) = st
                        && by.contains(&peer)
                    {
                        v.push(self.block_at(piece, b as u32));
                    }
                }
            }
        }
        v
    }

    /// A piece with no requested or received blocks needs no bookkeeping.
    fn maybe_drop_empty(&mut self, piece: usize) {
        let drop = matches!(&self.pieces[piece].blocks, Some(blocks) if blocks.iter().all(|b| *b == BlockState::Free));
        if drop {
            let p = &mut self.pieces[piece];
            p.blocks = None;
            p.free = 0;
            p.received = 0;
            self.place(piece);
        }
    }

    /// Number of pieces currently being downloaded (block state allocated).
    pub fn open_pieces(&self) -> usize {
        self.open.len()
    }

    /// The pieces with requests or blocks in flight (a download in
    /// progress), in no particular order.
    pub fn open_piece_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.open.iter().copied()
    }

    /// Recompute every counter from scratch and check the index against the
    /// piece states. Test-only: this is the O(pieces) walk the counters exist
    /// to avoid.
    #[cfg(test)]
    fn check_invariants(&self) -> Result<(), String> {
        let mut fresh_seen = 0usize;
        let mut fresh_seq = std::collections::BTreeSet::new();
        for (prio, by_avail) in self.fresh.iter().enumerate() {
            for (avail, bucket) in by_avail.iter().enumerate() {
                for (slot, &i) in bucket.iter().enumerate() {
                    let p = &self.pieces[i];
                    if p.loc
                        != (Loc::Fresh {
                            prio: prio as u8,
                            avail: avail as u32,
                        })
                        || p.slot as usize != slot
                        || p.priority as usize != prio
                        || p.availability as usize != avail
                        || !p.wanted()
                        || p.blocks.is_some()
                    {
                        return Err(format!("fresh index wrong for piece {i}: {p:?}"));
                    }
                    fresh_seen += 1;
                    if avail > 0 {
                        fresh_seq.insert((7 - prio as u8, i));
                    }
                }
            }
        }
        if fresh_seq != self.fresh_seq {
            return Err("fresh_seq out of sync".into());
        }
        for (slot, &i) in self.open.iter().enumerate() {
            let p = &self.pieces[i];
            if p.loc != Loc::Open || p.slot as usize != slot || !p.wanted() || p.blocks.is_none() {
                return Err(format!("open index wrong for piece {i}: {p:?}"));
            }
        }
        let mut free = 0u64;
        let (mut hc, mut wc, mut wh, mut hb, mut wb, mut whb) = (0, 0, 0, 0u64, 0u64, 0u64);
        let mut candidates = 0usize;
        for (i, p) in self.pieces.iter().enumerate() {
            let size = u64::from(self.piece_size(i));
            if p.have {
                hc += 1;
                hb += size;
            }
            if p.priority > 0 {
                wc += 1;
                wb += size;
                if p.have {
                    wh += 1;
                    whb += size;
                }
            }
            if p.wanted() {
                candidates += 1;
                match &p.blocks {
                    None => free += u64::from(self.blocks_in(i)),
                    Some(blocks) => {
                        let f = blocks.iter().filter(|b| **b == BlockState::Free).count() as u32;
                        let r = blocks
                            .iter()
                            .filter(|b| **b == BlockState::Received)
                            .count() as u32;
                        if f != p.free || r != p.received {
                            return Err(format!("block counters wrong for piece {i}"));
                        }
                        free += u64::from(f);
                    }
                }
            } else if p.loc != Loc::None {
                return Err(format!("unwanted piece {i} is indexed"));
            }
        }
        if candidates != fresh_seen + self.open.len() {
            return Err(format!(
                "index covers {} pieces, {candidates} wanted",
                fresh_seen + self.open.len()
            ));
        }
        let got = (
            self.free_blocks,
            self.have_count,
            self.wanted_count,
            self.wanted_have,
            self.have_bytes,
            self.wanted_bytes,
            self.wanted_have_bytes,
        );
        let want = (free, hc, wc, wh, hb, wb, whb);
        if got != want {
            return Err(format!("counters {got:?} != recount {want:?}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    struct Lcg(u64);
    impl profile::Rng for Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }
    }

    fn all(_: usize) -> bool {
        true
    }

    #[test]
    fn geometry() {
        let p = Picker::new(3, 32 * 1024, 70 * 1024 + 5);
        assert_eq!(p.piece_size(0), 32 * 1024);
        assert_eq!(p.piece_size(2), 6 * 1024 + 5);
        assert_eq!(p.blocks_in(0), 2);
        assert_eq!(p.blocks_in(2), 1);
        assert_eq!(
            p.block_at(2, 0),
            Block {
                piece: 2,
                offset: 0,
                length: 6 * 1024 + 5
            }
        );
        assert_eq!(p.bytes_left(), 70 * 1024 + 5);
        assert_eq!(p.free_blocks, 5);
    }

    #[test]
    fn picks_rarest_and_partial_first() {
        let mut p = Picker::new(4, BLOCK_SIZE * 2, u64::from(BLOCK_SIZE) * 8);
        let mut rng = Lcg(1);
        // piece 2 is rare (1 peer), others have 3.
        let mut bf = Bitfield::all_set(4);
        p.peer_joined(&bf);
        bf.clear(2);
        p.peer_joined(&bf);
        p.peer_joined(&bf);
        let got = p.pick(1, &all, 1, &mut rng);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].piece, 2);
        // Next pick prefers finishing piece 2 (partial) over new pieces.
        let got = p.pick(1, &all, 1, &mut rng);
        assert_eq!(got[0].piece, 2);
        assert_eq!(got[0].offset, BLOCK_SIZE);
        // Then spreads to others; never re-issues outstanding blocks.
        let more = p.pick(1, &all, 10, &mut rng);
        assert_eq!(more.len(), 6);
        assert!(more.iter().all(|b| b.piece != 2));
        assert!(p.pick(1, &all, 10, &mut rng).is_empty());
        assert_eq!(p.outstanding_for(1).len(), 8);
    }

    /// BEP 6 `suggest piece`: suggested pieces the peer has come first, then
    /// the normal strategy; pieces the peer lacks or we have are skipped.
    #[test]
    fn preferred_pieces_come_first() {
        let mut p = Picker::new(6, BLOCK_SIZE * 2, u64::from(BLOCK_SIZE) * 12);
        let mut rng = Lcg(3);
        let bf = Bitfield::all_set(6);
        p.peer_joined(&bf);
        // Piece 4 is suggested but the peer lacks it; 3 is suggested and
        // available; 5 we already have.
        let has = |i: usize| i != 4;
        let mut have = Bitfield::new(6);
        have.set(5);
        p.set_have(&have);
        let got = p.pick_preferring(1, &has, 3, &[4, 5, 3], &mut rng);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].piece, 3);
        assert_eq!(got[1].piece, 3);
        assert_ne!(got[2].piece, 4);
        assert_ne!(got[2].piece, 5);
        p.check_invariants().unwrap();
    }

    #[test]
    fn receive_verify_and_fail() {
        let mut p = Picker::new(2, BLOCK_SIZE * 2, u64::from(BLOCK_SIZE) * 4);
        let mut rng = Lcg(2);
        p.peer_joined(&Bitfield::all_set(2));
        let blocks = p.pick(7, &all, 2, &mut rng);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].piece, blocks[1].piece);
        let piece = blocks[0].piece as usize;
        let r = p.block_received(7, &blocks[0]);
        assert_eq!(
            r,
            Received::Accepted {
                cancel: vec![],
                piece_complete: false
            }
        );
        assert_eq!(p.block_received(7, &blocks[0]), Received::Redundant);
        let r = p.block_received(7, &blocks[1]);
        assert_eq!(
            r,
            Received::Accepted {
                cancel: vec![],
                piece_complete: true
            }
        );
        // Hash fails: blocks become free again and get re-picked.
        p.piece_failed(piece);
        assert_eq!(p.open_pieces(), 0);
        let again = p.pick(8, &|i| i == piece, 4, &mut rng);
        assert_eq!(again.len(), 2);
        for b in &again {
            p.block_received(8, b);
        }
        p.piece_verified(piece);
        assert!(p.have(piece));
        assert_eq!(p.have_count(), 1);
        assert!(!p.is_complete());
        assert_eq!(p.bytes_left(), u64::from(BLOCK_SIZE) * 2);
        // A block for a piece we have is redundant.
        assert_eq!(p.block_received(8, &again[0]), Received::Redundant);
    }

    #[test]
    fn end_game_duplicates_and_cancels() {
        let mut p = Picker::new(1, BLOCK_SIZE, u64::from(BLOCK_SIZE));
        let mut rng = Lcg(3);
        p.peer_joined(&Bitfield::all_set(1));
        let a = p.pick(1, &all, 4, &mut rng);
        assert_eq!(a.len(), 1);
        assert!(p.end_game(), "everything outstanding");
        // Peer 2 gets the same block as a duplicate; peer 1 does not get it twice.
        assert!(p.pick(1, &all, 4, &mut rng).is_empty());
        let b = p.pick(2, &all, 4, &mut rng);
        assert_eq!(b, a);
        let r = p.block_received(2, &b[0]);
        assert_eq!(
            r,
            Received::Accepted {
                cancel: vec![1],
                piece_complete: true
            }
        );
        // The loser's copy is redundant.
        assert_eq!(p.block_received(1, &a[0]), Received::Redundant);
    }

    #[test]
    fn peer_gone_releases_and_priorities_skip() {
        let mut p = Picker::new(3, BLOCK_SIZE, u64::from(BLOCK_SIZE) * 3);
        let mut rng = Lcg(4);
        p.peer_joined(&Bitfield::all_set(3));
        p.set_priority(1, 0);
        let got = p.pick(5, &all, 10, &mut rng);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|b| b.piece != 1));
        assert_eq!(p.free_blocks, 0);
        let released = p.peer_gone(5);
        assert_eq!(released.len(), 2);
        assert_eq!(p.free_blocks, 2);
        assert_eq!(p.open_pieces(), 0);
        assert!(p.outstanding_for(5).is_empty());
        // wanted vs total left
        assert_eq!(p.wanted_bytes_left(), u64::from(BLOCK_SIZE) * 2);
        assert_eq!(p.bytes_left(), u64::from(BLOCK_SIZE) * 3);
        // High priority wins over rarity.
        p.set_priority(2, 7);
        let mut rare = Bitfield::new(3);
        rare.set(0);
        p.peer_joined(&rare);
        p.peer_joined(&rare);
        let got = p.pick(6, &all, 1, &mut rng);
        assert_eq!(got[0].piece, 2);
    }

    #[test]
    fn exclusive_piece_goes_to_one_peer_until_resolved() {
        let mut p = Picker::new(2, BLOCK_SIZE, u64::from(BLOCK_SIZE) * 2);
        let mut rng = Lcg(11);
        p.peer_joined(&Bitfield::all_set(2));
        p.set_exclusive(0, 7);
        let got = p.pick(1, &all, 4, &mut rng);
        assert_eq!(got.iter().map(|b| b.piece).collect::<Vec<_>>(), vec![1]);
        let got7 = p.pick(7, &all, 4, &mut rng);
        assert_eq!(got7.iter().map(|b| b.piece).collect::<Vec<_>>(), vec![0]);
        assert_eq!(p.exclusive(0), Some(7));
        // The exclusive peer leaves: its block is free for anyone again.
        p.peer_gone(7);
        assert_eq!(p.exclusive(0), None);
        let got = p.pick(1, &all, 4, &mut rng);
        assert_eq!(got.iter().map(|b| b.piece).collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn sequential_is_in_order() {
        let mut p = Picker::new(5, BLOCK_SIZE, u64::from(BLOCK_SIZE) * 5);
        p.set_sequential(true);
        let mut rng = Lcg(9);
        p.peer_joined(&Bitfield::all_set(5));
        let got = p.pick(1, &all, 5, &mut rng);
        assert_eq!(
            got.iter().map(|b| b.piece).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn set_have_from_resume() {
        let mut p = Picker::new(4, BLOCK_SIZE, u64::from(BLOCK_SIZE) * 4);
        let mut have = Bitfield::new(4);
        have.set(0);
        have.set(3);
        p.set_have(&have);
        assert_eq!(p.have_count(), 2);
        assert_eq!(p.free_blocks, 2);
        assert_eq!(p.have_bitfield(), have);
        let mut rng = Lcg(5);
        p.peer_joined(&Bitfield::all_set(4));
        let got = p.pick(1, &all, 10, &mut rng);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|b| b.piece == 1 || b.piece == 2));
    }

    proptest! {
        /// Random peers picking and receiving eventually completes the torrent,
        /// never picks owned/unavailable pieces, and never hands the same block
        /// to a peer twice while outstanding.
        #[test]
        fn converges_without_double_requests(
            pieces in 1usize..24,
            blocks_per_piece in 1u32..5,
            peers in 1u32..5,
            seed in any::<u64>(),
        ) {
            let plen = BLOCK_SIZE * blocks_per_piece;
            let total = u64::from(plen) * pieces as u64 - 100;
            let mut p = Picker::new(pieces, plen, total);
            let mut rng = Lcg(seed);
            // Each peer has a random subset; union must be everything.
            let mut sets: Vec<Bitfield> = Vec::new();
            for k in 0..peers {
                let mut bf = Bitfield::new(pieces);
                for i in 0..pieces {
                    if profile::Rng::below(&mut rng, 3) != 0 || k == 0 { bf.set(i); }
                }
                p.peer_joined(&bf);
                sets.push(bf);
            }
            let mut outstanding: Vec<Vec<Block>> = vec![Vec::new(); peers as usize];
            let mut steps = 0;
            while !p.is_complete() {
                steps += 1;
                prop_assert!(steps < 10_000, "did not converge");
                let k = profile::Rng::below(&mut rng, peers) as usize;
                let has = sets[k].clone();
                let got = p.pick(k as u32, &|i| has.get(i), 3, &mut rng);
                for b in &got {
                    prop_assert!(!p.have(b.piece as usize));
                    prop_assert!(has.get(b.piece as usize));
                    prop_assert!(!outstanding[k].contains(b), "double request");
                    if !p.end_game() {
                        for other in &outstanding {
                            prop_assert!(!other.contains(b) || std::ptr::eq(other, &outstanding[k]));
                        }
                    }
                    outstanding[k].push(*b);
                }
                // Deliver one outstanding block from a random peer.
                if let Some(b) = outstanding[k].pop()
                    && let Received::Accepted { cancel, piece_complete } = p.block_received(k as u32, &b)
                {
                    for c in cancel {
                        outstanding[c as usize].retain(|x| *x != b);
                    }
                    if piece_complete {
                        p.piece_verified(b.piece as usize);
                    }
                }
            }
            prop_assert_eq!(p.bytes_left(), 0);
            prop_assert!(p.is_seed());
            p.check_invariants().map_err(TestCaseError::fail)?;
        }

        /// Any interleaving of the mutating operations keeps the cached
        /// counters equal to a full recount and the pick index consistent
        /// with the piece states.
        #[test]
        fn counters_and_index_match_recount(
            pieces in 1usize..40,
            blocks_per_piece in 1u32..4,
            ops in prop::collection::vec((0u8..10, any::<u32>(), any::<u32>()), 1..300),
        ) {
            let plen = BLOCK_SIZE * blocks_per_piece;
            let total = u64::from(plen) * pieces as u64 - 7;
            let mut p = Picker::new(pieces, plen, total);
            let mut rng = Lcg(ops.len() as u64);
            let mut out: Vec<(PeerKey, Block)> = Vec::new();
            for (op, a, b) in ops {
                let i = a as usize % pieces;
                let peer = b % 4;
                match op {
                    0 => { p.peer_has(i); }
                    1 => {
                        let mut bf = Bitfield::new(pieces);
                        for k in 0..pieces { if (b >> (k % 32)) & 1 == 1 { bf.set(k); } }
                        p.peer_joined(&bf);
                    }
                    2 => {
                        let mut bf = Bitfield::new(pieces);
                        for k in 0..pieces { if (a >> (k % 32)) & 1 == 1 { bf.set(k); } }
                        p.peer_left(&bf);
                    }
                    3 => p.set_priority(i, (b % 9) as u8),
                    4 => {
                        p.set_sequential(b % 2 == 0);
                        for blk in p.pick(peer, &all, 1 + (b % 5) as usize, &mut rng) {
                            out.push((peer, blk));
                        }
                    }
                    5 => if !out.is_empty() {
                        let (k, blk) = out.swap_remove(b as usize % out.len());
                        if let Received::Accepted { cancel, piece_complete } = p.block_received(k, &blk) {
                            for c in cancel { out.retain(|(k2, x)| !(*k2 == c && *x == blk)); }
                            if piece_complete && b % 3 != 0 { p.piece_verified(blk.piece as usize); }
                            else if piece_complete { p.piece_failed(blk.piece as usize); out.retain(|(_, x)| x.piece != blk.piece); }
                        }
                    }
                    6 => if !out.is_empty() {
                        let (k, blk) = out.swap_remove(b as usize % out.len());
                        p.release(k, &blk);
                    }
                    7 => { p.peer_gone(peer); out.retain(|(k, _)| *k != peer); }
                    8 => {
                        let mut bf = Bitfield::new(pieces);
                        for k in 0..pieces { if (a >> (k % 32)) & 1 == 1 { bf.set(k); } }
                        p.set_have(&bf);
                        out.retain(|(_, x)| !bf.get(x.piece as usize));
                    }
                    _ => p.set_exclusive(i, peer),
                }
                p.check_invariants().map_err(TestCaseError::fail)?;
                // The public O(1) views agree with a recount too.
                let have_bytes: u64 = (0..pieces).filter(|k| p.have(*k)).map(|k| u64::from(p.piece_size(k))).sum();
                prop_assert_eq!(p.bytes_left(), total - have_bytes);
                let wanted_left: u64 = (0..pieces)
                    .filter(|k| !p.have(*k) && p.priority(*k) > 0)
                    .map(|k| u64::from(p.piece_size(k)))
                    .sum();
                prop_assert_eq!(p.wanted_bytes_left(), wanted_left);
                prop_assert_eq!(p.is_complete(), wanted_left == 0);
            }
        }
    }

    /// With small pieces, picks stay within a few 4 MiB extents instead of
    /// scattering 16 KiB writes over the whole file; with affinity off (or
    /// large pieces) the rarest-first tie-break is random.
    #[test]
    fn extent_affinity_keeps_picks_local() {
        let pieces = 8192; // 128 MiB of 16 KiB pieces = 32 extents of 256
        let all_set = Bitfield::all_set(pieces);
        let run = |affinity: bool, seed: u64| {
            let mut p = Picker::new(pieces, BLOCK_SIZE, u64::from(BLOCK_SIZE) * pieces as u64);
            p.set_extent_affinity(affinity);
            p.peer_joined(&all_set);
            let mut rng = Lcg(seed);
            let mut extents = std::collections::BTreeSet::new();
            // 40 picks of 8 blocks = 320 pieces = 1.25 extents' worth.
            for k in 0..40u32 {
                for b in p.pick(k % 3, &all, 8, &mut rng) {
                    extents.insert(b.piece as usize / 256);
                    if let Received::Accepted {
                        piece_complete: true,
                        ..
                    } = p.block_received(k % 3, &b)
                    {
                        p.piece_verified(b.piece as usize);
                    }
                }
            }
            p.check_invariants().unwrap();
            extents.len()
        };
        assert!(run(true, 1) <= 3, "affinity: {} extents", run(true, 1));
        assert!(run(false, 1) >= 10, "random: {} extents", run(false, 1));
        // 4 MiB pieces: affinity is moot and never records anything.
        let mut big = Picker::new(64, 4 << 20, 64 << 22);
        big.peer_joined(&Bitfield::all_set(64));
        let mut rng = Lcg(3);
        big.pick(0, &all, 4, &mut rng);
        assert!(big.recent_extents.is_empty());
        assert_eq!(big.have_count(), 0);
    }

    /// A seed joining or leaving touches every wanted piece once, with no
    /// ordered-set churn: 200 000 pieces in a few milliseconds even in debug.
    #[test]
    fn bulk_availability_updates_are_cheap() {
        let pieces = 200_000;
        let mut p = Picker::new(
            pieces,
            BLOCK_SIZE * 4,
            u64::from(BLOCK_SIZE) * 4 * pieces as u64,
        );
        let all = Bitfield::all_set(pieces);
        let started = std::time::Instant::now();
        for _ in 0..10 {
            p.peer_joined(&all);
        }
        for _ in 0..5 {
            p.peer_left(&all);
        }
        let elapsed = started.elapsed();
        assert_eq!(p.availability(0), 5);
        assert_eq!(p.availability(pieces - 1), 5);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "15 bulk updates took {elapsed:?}"
        );
        p.check_invariants().unwrap();
    }

    /// Picking from a 200 000-piece torrent with a partial swarm does not
    /// walk every piece: a pick costs the candidates ahead of the peer's
    /// pieces in rarest-first order (as in libtorrent), never the pieces
    /// nobody has, so thousands of picks finish quickly even unoptimised.
    /// Like the engine, the test only picks from a peer that still has
    /// something we want.
    #[test]
    fn pick_cost_is_independent_of_piece_count() {
        let pieces = 200_000;
        let mut p = Picker::new(
            pieces,
            BLOCK_SIZE * 4,
            u64::from(BLOCK_SIZE) * 4 * pieces as u64,
        );
        let mut rng = Lcg(7);
        // Two peers have every piece with index % 3 != 0; a third has 1000 of
        // the others (rare); the rest (~65 000) nobody has.
        let mut bf = Bitfield::new(pieces);
        for i in 0..pieces {
            if i % 3 != 0 {
                bf.set(i);
            }
        }
        p.peer_joined(&bf);
        p.peer_joined(&bf);
        let mut rare = Bitfield::new(pieces);
        for i in 0..1000 {
            rare.set(i * 3);
        }
        p.peer_joined(&rare);
        let started = std::time::Instant::now();
        let mut picked = 0;
        let mut rare_done = 0;
        let (has_bf, has_rare) = (|i: usize| bf.get(i), |i: usize| rare.get(i));
        for k in 0..4000u32 {
            let from_rare = k % 2 == 1 && rare_done < 1000;
            let has: &dyn Fn(usize) -> bool = if from_rare { &has_rare } else { &has_bf };
            let got = p.pick(k % 16, has, 8, &mut rng);
            assert!(!got.is_empty());
            picked += got.len();
            for b in got {
                if let Received::Accepted {
                    piece_complete: true,
                    ..
                } = p.block_received(k % 16, &b)
                {
                    p.piece_verified(b.piece as usize);
                    if b.piece % 3 == 0 {
                        rare_done += 1;
                    }
                }
            }
        }
        // The rare peer's pieces were preferred (availability 1) and are all in.
        assert_eq!(rare_done, 1000);
        assert!(picked > 0);
        assert!(!p.is_complete());
        assert_eq!(p.have_count(), p.have_bitfield().count());
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "picks took {elapsed:?}"
        );
        p.check_invariants().unwrap();
    }
}
