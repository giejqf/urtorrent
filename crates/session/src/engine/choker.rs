// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The choker, as a pure function over peer snapshots (AGENTS.md 6 L3: sane
//! and in libtorrent's ballpark, not a mimicry target).
//!
//! - **Leeching torrents** (libtorrent `fixed_slots_choker`): interested peers
//!   ranked by what they upload to us; the top `slots - 1` are unchoked, plus
//!   one *optimistic* unchoke rotated every 30 s among the rest, round-robin
//!   by how long ago each was last unchoked.
//! - **Seeding torrents** (libtorrent `round_robin` seed choker): interested
//!   peers unchoked in rotation, longest-waiting first, so every leecher gets
//!   a turn.
//!
//! The session runs one round every [`UNCHOKE_INTERVAL`] across all torrents
//! with a session-wide slot budget, and unchokes immediately when a peer
//! becomes interested while a slot is free.

use std::time::{Duration, Instant};

/// How often the choker re-evaluates (libtorrent `unchoke_interval`).
pub const UNCHOKE_INTERVAL: Duration = Duration::from_secs(15);
/// How often the optimistic slot rotates (libtorrent
/// `optimistic_unchoke_interval`).
pub const OPTIMISTIC_INTERVAL: Duration = Duration::from_secs(30);
/// Session-wide unchoke slots (libtorrent `unchoke_slots_limit`).
pub const DEFAULT_SLOTS: usize = 8;

/// One peer as the choker sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Caller's key.
    pub key: u64,
    /// The peer wants our data.
    pub interested: bool,
    /// We currently choke it.
    pub choked: bool,
    /// When we last unchoked it (never = `None`).
    pub last_unchoke: Option<Instant>,
    /// Bytes it sent us in the last round (leech ranking).
    pub download_rate: u64,
    /// The peer's torrent is complete on our side (seed choker applies).
    pub seeding: bool,
    /// The peer is itself a seed (never worth a slot).
    pub peer_is_seed: bool,
}

/// What to do after a round.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Decision {
    /// Peers to unchoke.
    pub unchoke: Vec<u64>,
    /// Peers to choke.
    pub choke: Vec<u64>,
    /// The peer chosen as this round's optimistic unchoke, if any.
    pub optimistic: Option<u64>,
}

/// Run one choking round.
///
/// `slots` is the session-wide budget; `current_optimistic` the peer holding
/// the optimistic slot; `rotate_optimistic` whether that slot must move on.
pub fn round(
    peers: &[Candidate],
    slots: usize,
    current_optimistic: Option<u64>,
    rotate_optimistic: bool,
) -> Decision {
    let mut d = Decision::default();
    let mut eligible: Vec<&Candidate> = peers
        .iter()
        .filter(|p| p.interested && !p.peer_is_seed)
        .collect();
    if slots == 0 || eligible.is_empty() {
        d.choke = peers.iter().filter(|p| !p.choked).map(|p| p.key).collect();
        return d;
    }
    // Ranking: leeching torrents by upload to us (desc); seeding torrents
    // round-robin (never-unchoked first, then longest since last unchoke).
    // Peers on seeding torrents rank below active leech partners.
    let key = |p: &Candidate| -> (u8, u64) {
        if p.seeding {
            let waited = p.last_unchoke.map_or(u64::MAX, |t| t.elapsed().as_secs());
            (1, u64::MAX - waited)
        } else {
            (0, u64::MAX - p.download_rate)
        }
    };
    eligible.sort_by_key(|p| key(p));
    let regular_slots = if slots == 1 { 1 } else { slots - 1 };
    let mut unchoked: Vec<u64> = eligible.iter().take(regular_slots).map(|p| p.key).collect();
    // Optimistic slot (only when there is a slot to spare).
    if slots > 1 {
        let rest: Vec<&Candidate> = eligible
            .iter()
            .copied()
            .filter(|p| !unchoked.contains(&p.key))
            .collect();
        let keep_current =
            current_optimistic.filter(|k| !rotate_optimistic && rest.iter().any(|p| p.key == *k));
        let chosen = keep_current.or_else(|| {
            // Round-robin: the peer that has waited longest (never unchoked
            // first, then oldest last_unchoke).
            rest.iter()
                .filter(|p| Some(p.key) != current_optimistic || rest.len() == 1)
                .min_by_key(|p| {
                    p.last_unchoke
                        .map_or((0u8, 0u64), |t| (1, u64::MAX - t.elapsed().as_secs()))
                })
                .map(|p| p.key)
        });
        if let Some(k) = chosen {
            unchoked.push(k);
            d.optimistic = Some(k);
        }
    }
    for p in peers {
        let want = unchoked.contains(&p.key);
        if want && p.choked {
            d.unchoke.push(p.key);
        } else if !want && !p.choked {
            d.choke.push(p.key);
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(key: u64, interested: bool, choked: bool, rate: u64) -> Candidate {
        Candidate {
            key,
            interested,
            choked,
            last_unchoke: None,
            download_rate: rate,
            seeding: false,
            peer_is_seed: false,
        }
    }

    #[test]
    fn leech_ranks_by_rate_and_keeps_an_optimistic_slot() {
        let peers = vec![
            cand(1, true, true, 100),
            cand(2, true, true, 500),
            cand(3, true, true, 50),
            cand(4, true, true, 0),
            cand(5, false, true, 9000), // not interested: never unchoked
        ];
        let d = round(&peers, 3, None, true);
        // two regular slots: 2 and 1; one optimistic among {3, 4}
        assert!(d.unchoke.contains(&2) && d.unchoke.contains(&1));
        assert_eq!(d.unchoke.len(), 3);
        assert!(d.optimistic.is_some_and(|k| k == 3 || k == 4));
        assert!(!d.unchoke.contains(&5));
        assert!(d.choke.is_empty());
    }

    #[test]
    fn chokes_when_rank_drops_and_uninterested() {
        let peers = vec![
            cand(1, true, false, 10),
            cand(2, true, false, 20),
            cand(3, true, true, 30),
            cand(4, false, false, 0),
        ];
        let d = round(&peers, 2, None, true);
        // One regular slot goes to 3 (best rate); the optimistic slot stays
        // with one of the already-unchoked 1/2; the other and 4 (not
        // interested) are choked.
        assert_eq!(d.unchoke, vec![3]);
        let opt = d.optimistic.unwrap();
        assert!(opt == 1 || opt == 2);
        assert!(d.choke.contains(&4));
        assert!(d.choke.contains(&(3 - opt)));
        assert_eq!(d.choke.len(), 2);
    }

    #[test]
    fn seed_round_robin_rotates() {
        let t0 = Instant::now();
        let mut peers: Vec<Candidate> = (1..=4)
            .map(|k| Candidate {
                key: k,
                interested: true,
                choked: true,
                last_unchoke: None,
                download_rate: 0,
                seeding: true,
                peer_is_seed: false,
            })
            .collect();
        let d = round(&peers, 2, None, true);
        assert_eq!(d.unchoke.len(), 2);
        // Mark those as unchoked recently; the others must get the next turn.
        for k in &d.unchoke {
            let p = peers.iter_mut().find(|p| p.key == *k).unwrap();
            p.choked = false;
            p.last_unchoke = Some(t0);
        }
        let d2 = round(&peers, 2, d.optimistic, true);
        assert_eq!(d2.unchoke.len(), 2);
        assert!(d2.unchoke.iter().all(|k| !d.unchoke.contains(k)));
        assert_eq!(d2.choke.len(), 2);
    }

    #[test]
    fn seeds_never_get_slots_and_zero_slots_chokes_all() {
        let mut p = cand(1, true, false, 0);
        p.peer_is_seed = true;
        let d = round(&[p.clone()], 4, None, true);
        assert_eq!(d.choke, vec![1]);
        p.peer_is_seed = false;
        let d = round(&[p], 0, None, true);
        assert_eq!(d.choke, vec![1]);
    }

    #[test]
    fn optimistic_is_kept_between_rotations() {
        let peers = vec![
            cand(1, true, true, 100),
            cand(2, true, true, 0),
            cand(3, true, true, 0),
        ];
        let d = round(&peers, 2, None, true);
        let opt = d.optimistic.unwrap();
        let again = round(&peers, 2, Some(opt), false);
        assert_eq!(again.optimistic, Some(opt));
    }
}
