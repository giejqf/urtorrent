// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The piece picker: decides which blocks to request from which peer.
//!
//! Policy (libtorrent's defaults as sane starting points, AGENTS.md 6 L3):
//! pieces we are already downloading first (fewer open pieces), then rarest
//! first with a random tie-break, priorities 1..7 above 0 (= skip), optional
//! sequential mode, and end-game (duplicate requests to other peers once every
//! remaining block is already requested) with cancellation of the losers.
//!
//! Pure state: no I/O, no clock, randomness injected through
//! [`profile::Rng`]. The session owns the mapping from its peers to
//! [`PeerKey`]s and turns [`Block`]s into wire requests.

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

#[derive(Debug, Clone)]
struct Piece {
    availability: u32,
    priority: u8,
    have: bool,
    /// Allocated once the piece is being downloaded.
    blocks: Option<Vec<BlockState>>,
    free: u32,
    received: u32,
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
    /// Pieces only one peer may download (after a hash failure with several
    /// suppliers, so the next failure has a single culprit).
    exclusive: std::collections::HashMap<usize, PeerKey>,
}

/// Maximum distinct pieces one `pick` call opens (keeps a single call cheap).
const MAX_PIECES_PER_PICK: usize = 16;

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
                };
                piece_count
            ],
            piece_length: piece_length.max(1),
            total_length,
            sequential: false,
            free_blocks: 0,
            have_count: 0,
            exclusive: std::collections::HashMap::new(),
        };
        p.recount_free();
        p
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

    fn recount_free(&mut self) {
        let mut free = 0u64;
        for i in 0..self.pieces.len() {
            let p = &self.pieces[i];
            if p.have || p.priority == 0 {
                continue;
            }
            free += match &p.blocks {
                Some(_) => u64::from(p.free),
                None => u64::from(self.blocks_in(i)),
            };
        }
        self.free_blocks = free;
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
        self.have_count = self.pieces.iter().filter(|p| p.have).count();
        self.recount_free();
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
        let Some(p) = self.pieces.get_mut(i) else {
            return;
        };
        if !p.have {
            p.have = true;
            self.have_count += 1;
        }
        p.blocks = None;
        p.free = 0;
        p.received = 0;
        self.recount_free();
    }

    /// Piece `i` failed its hash: every block goes back to free (the caller
    /// attributes blame to the peers that supplied it).
    pub fn piece_failed(&mut self, i: usize) {
        self.exclusive.remove(&i);
        let Some(p) = self.pieces.get_mut(i) else {
            return;
        };
        p.blocks = None;
        p.free = 0;
        p.received = 0;
        self.recount_free();
    }

    /// Set the priority of piece `i` (0 = do not download, 1..7).
    pub fn set_priority(&mut self, i: usize, priority: u8) {
        if let Some(p) = self.pieces.get_mut(i) {
            p.priority = priority.min(7);
            self.recount_free();
        }
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
        self.pieces.iter().all(|p| p.have || p.priority == 0)
    }

    /// Whether every piece is ours (a true seed).
    pub fn is_seed(&self) -> bool {
        self.have_count == self.pieces.len()
    }

    /// Bytes of the whole torrent we do not have yet (the announce `left`).
    pub fn bytes_left(&self) -> u64 {
        (0..self.pieces.len())
            .filter(|&i| !self.pieces[i].have)
            .map(|i| u64::from(self.piece_size(i)))
            .sum()
    }

    /// Bytes of wanted pieces we do not have yet.
    pub fn wanted_bytes_left(&self) -> u64 {
        (0..self.pieces.len())
            .filter(|&i| !self.pieces[i].have && self.pieces[i].priority > 0)
            .map(|i| u64::from(self.piece_size(i)))
            .sum()
    }

    /// Whether we are in end-game: nothing left to request except blocks
    /// already outstanding elsewhere.
    pub fn end_game(&self) -> bool {
        self.free_blocks == 0 && !self.is_complete()
    }

    // --- peer availability ---

    /// A peer with this bitfield joined (or sent its bitfield).
    pub fn peer_joined(&mut self, has: &Bitfield) {
        for i in has.iter_set() {
            if let Some(p) = self.pieces.get_mut(i) {
                p.availability += 1;
            }
        }
    }

    /// A peer with this bitfield left (or replaced its bitfield).
    pub fn peer_left(&mut self, had: &Bitfield) {
        for i in had.iter_set() {
            if let Some(p) = self.pieces.get_mut(i) {
                p.availability = p.availability.saturating_sub(1);
            }
        }
    }

    /// A peer announced one more piece (`have`).
    pub fn peer_has(&mut self, i: usize) {
        if let Some(p) = self.pieces.get_mut(i) {
            p.availability += 1;
        }
    }

    /// How many peers have piece `i`.
    pub fn availability(&self, i: usize) -> u32 {
        self.pieces.get(i).map_or(0, |p| p.availability)
    }

    // --- requests ---

    fn ensure_blocks(&mut self, piece: usize) {
        let n = self.blocks_in(piece);
        let p = &mut self.pieces[piece];
        if p.blocks.is_none() {
            p.blocks = Some(vec![BlockState::Free; n as usize]);
            p.free = n;
            p.received = 0;
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
        self.pick_mode(peer, has, want, rng, sequential)
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
        self.pick_mode(peer, has, want, rng, true)
    }

    fn pick_mode(
        &mut self,
        peer: PeerKey,
        has: &dyn Fn(usize) -> bool,
        want: usize,
        rng: &mut dyn Rng,
        sequential: bool,
    ) -> Vec<Block> {
        let mut out = Vec::with_capacity(want);
        let mut used: Vec<usize> = Vec::new();
        let end_game = self.end_game();
        while out.len() < want && used.len() < MAX_PIECES_PER_PICK {
            // Best candidate: highest priority, partial first, rarest, random
            // tie-break (or lowest index in sequential mode).
            let mut best: Option<(u64, usize)> = None;
            let mut ties = 0u32;
            for i in 0..self.pieces.len() {
                let p = &self.pieces[i];
                if p.have || p.priority == 0 || !has(i) || used.contains(&i) {
                    continue;
                }
                if self.exclusive.get(&i).is_some_and(|k| *k != peer) {
                    continue;
                }
                if !self.pickable(i, peer, end_game) {
                    continue;
                }
                let partial = u64::from(p.blocks.is_none());
                let key = if sequential {
                    ((7 - u64::from(p.priority)) << 40) | (i as u64)
                } else {
                    ((7 - u64::from(p.priority)) << 40)
                        | (partial << 32)
                        | u64::from(p.availability)
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
                    Some((bk, _)) if key == bk && !sequential => {
                        ties += 1;
                        if rng.below(ties) == 0 {
                            best = Some((key, i));
                        }
                    }
                    _ => {}
                }
            }
            let Some((_, piece)) = best else { break };
            used.push(piece);
            self.ensure_blocks(piece);
            let n = self.blocks_in(piece);
            // First pass: free blocks. Second pass (end-game): duplicates,
            // fewest requesters first.
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
        for piece in 0..self.pieces.len() {
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
        for piece in 0..self.pieces.len() {
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
        let p = &mut self.pieces[piece];
        if let Some(blocks) = &p.blocks
            && blocks.iter().all(|b| *b == BlockState::Free)
        {
            p.blocks = None;
            p.free = 0;
            p.received = 0;
        }
    }

    /// Number of pieces currently being downloaded (block state allocated).
    pub fn open_pieces(&self) -> usize {
        self.pieces.iter().filter(|p| p.blocks.is_some()).count()
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
        }
    }
}
