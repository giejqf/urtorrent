// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Limits, expiry, the reply sampling and the BEP 33 filters follow
// libtorrent-rasterbar's dht_storage.cpp (BSD-3-Clause), Copyright (c) Arvid
// Norberg and contributors; see NOTICE.

//! What other nodes announce to us: peers per info-hash (with the BEP 33
//! scrape filters and the BEP 51 info-hash sample).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use profile::Rng;

use crate::id::NodeId;
use crate::krpc::Reply;

/// Torrents we keep peers for (libtorrent `dht_max_torrents`).
pub const MAX_TORRENTS: usize = 2000;
/// Peers per torrent per family (`dht_max_peers`).
pub const MAX_PEERS: usize = 500;
/// Peers in one `get_peers` reply (`dht_max_peers_reply`); a quarter for v6.
pub const MAX_PEERS_REPLY: usize = 100;
/// Peers not re-announced within 1.5 × this are dropped.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// BEP 51 sample refresh interval (seconds, as advertised).
pub const SAMPLE_INTERVAL: i64 = 21600;
/// BEP 51 sample size.
pub const SAMPLE_COUNT: usize = 20;

#[derive(Debug, Clone)]
struct PeerEntry {
    added: Instant,
    addr: SocketAddr,
    seed: bool,
}

#[derive(Debug, Default, Clone)]
struct TorrentEntry {
    name: Vec<u8>,
    /// Sorted by address then port.
    peers4: Vec<PeerEntry>,
    peers6: Vec<PeerEntry>,
}

fn key(p: &SocketAddr) -> (IpAddr, u16) {
    (p.ip(), p.port())
}

/// The peer store.
#[derive(Debug, Clone, Default)]
pub struct PeerStore {
    map: HashMap<NodeId, TorrentEntry>,
    peers: usize,
    sample: Vec<NodeId>,
    sample_at: Option<Instant>,
}

/// BEP 33 bloom filter over `sha1(address bytes)`: 256 bytes, two bits per
/// entry taken from the hash's first four bytes.
fn bloom_set(filter: &mut [u8; 256], ip: IpAddr) {
    let h = match ip {
        IpAddr::V4(a) => <sha1::Sha1 as sha1::Digest>::digest(a.octets()),
        IpAddr::V6(a) => <sha1::Sha1 as sha1::Digest>::digest(a.octets()),
    };
    let bits = 256 * 8;
    let i1 = (usize::from(h[0]) | (usize::from(h[1]) << 8)) % bits;
    let i2 = (usize::from(h[2]) | (usize::from(h[3]) << 8)) % bits;
    filter[i1 / 8] |= 1 << (i1 & 7);
    filter[i2 / 8] |= 1 << (i2 & 7);
}

impl PeerStore {
    /// `(torrents, peers)` stored.
    pub fn counts(&self) -> (usize, usize) {
        (self.map.len(), self.peers)
    }

    /// Store `announce_peer` from `addr` (the announcer's address and the
    /// port it named).
    pub fn announce_peer(
        &mut self,
        info_hash: NodeId,
        addr: SocketAddr,
        name: Option<&[u8]>,
        seed: bool,
        now: Instant,
    ) {
        let entry = match self.map.get_mut(&info_hash) {
            Some(e) => e,
            None => {
                if self.map.len() >= MAX_TORRENTS {
                    return;
                }
                self.map.entry(info_hash).or_default()
            }
        };
        if let Some(n) = name
            && entry.name.is_empty()
            && !n.is_empty()
        {
            entry.name = n[..n.len().min(100)].to_vec();
        }
        let list = if addr.is_ipv4() {
            &mut entry.peers4
        } else {
            &mut entry.peers6
        };
        let peer = PeerEntry {
            added: now,
            addr,
            seed,
        };
        match list.binary_search_by(|p| key(&p.addr).cmp(&key(&addr))) {
            Ok(i) => list[i] = peer,
            Err(i) => {
                if list.len() >= MAX_PEERS {
                    return;
                }
                list.insert(i, peer);
                self.peers += 1;
            }
        }
    }

    /// Fill `reply` for a `get_peers` from `requester`: `values` (a random
    /// sample, seeds excluded when `noseed`) or the BEP 33 filters when
    /// `scrape`, plus `n`. Returns `true` when the torrent's list is full and
    /// the requester is not in it — the caller then withholds the token so
    /// announces spill to neighbouring nodes (libtorrent).
    pub fn get_peers(
        &self,
        info_hash: &NodeId,
        noseed: bool,
        scrape: bool,
        requester: IpAddr,
        reply: &mut Reply,
        rng: &mut dyn Rng,
    ) -> bool {
        let Some(t) = self.map.get(info_hash) else {
            return self.map.len() >= MAX_TORRENTS;
        };
        let list = if requester.is_ipv4() {
            &t.peers4
        } else {
            &t.peers6
        };
        if !t.name.is_empty() {
            reply.name = Some(t.name.clone());
        }
        if scrape {
            let mut downloaders = [0u8; 256];
            let mut seeds = [0u8; 256];
            for p in list {
                if p.seed {
                    bloom_set(&mut seeds, p.addr.ip());
                } else {
                    bloom_set(&mut downloaders, p.addr.ip());
                }
            }
            reply.bf_peers = Some(downloaders.to_vec());
            reply.bf_seeds = Some(seeds.to_vec());
        } else {
            let mut to_pick = MAX_PEERS_REPLY;
            if !list.is_empty() && requester.is_ipv6() {
                to_pick /= 4;
            }
            let mut candidates = list.iter().filter(|p| !(noseed && p.seed)).count();
            to_pick = to_pick.min(candidates);
            // Reservoir-style: each candidate is taken with probability
            // to_pick / candidates-left (libtorrent's loop).
            for p in list {
                if to_pick == 0 {
                    break;
                }
                if noseed && p.seed {
                    continue;
                }
                let c = candidates as u32;
                candidates -= 1;
                if rng.below(c) > to_pick as u32 {
                    continue;
                }
                reply.values.push(p.addr);
                to_pick -= 1;
            }
        }
        if list.len() < MAX_PEERS {
            return false;
        }
        !list.iter().any(|p| p.addr.ip() == requester)
    }

    /// Drop peers not re-announced for 1.5 × the announce interval and
    /// torrents left without peers (libtorrent runs this every 2 minutes).
    pub fn tick(&mut self, now: Instant) {
        let cutoff = ANNOUNCE_INTERVAL * 3 / 2;
        let mut removed = 0usize;
        self.map.retain(|_, t| {
            for list in [&mut t.peers4, &mut t.peers6] {
                let before = list.len();
                list.retain(|p| now.duration_since(p.added) <= cutoff);
                removed += before - list.len();
            }
            !(t.peers4.is_empty() && t.peers6.is_empty())
        });
        self.peers -= removed.min(self.peers);
    }

    /// BEP 51 `sample_infohashes` reply: `(interval, total torrents,
    /// samples)`. The sample is re-drawn once per interval.
    pub fn sample(&mut self, now: Instant, rng: &mut dyn Rng) -> (i64, i64, Vec<NodeId>) {
        let count = SAMPLE_COUNT.min(self.map.len());
        let fresh = self
            .sample_at
            .is_some_and(|t| now.duration_since(t).as_secs() < SAMPLE_INTERVAL as u64)
            && self.sample.len() >= SAMPLE_COUNT;
        if !fresh {
            self.sample.clear();
            let mut to_pick = count;
            let mut candidates = self.map.len();
            for h in self.map.keys() {
                if to_pick == 0 {
                    break;
                }
                let c = candidates as u32;
                candidates -= 1;
                if rng.below(c) > to_pick as u32 {
                    continue;
                }
                self.sample.push(*h);
                to_pick -= 1;
            }
            self.sample_at = Some(now);
        }
        (SAMPLE_INTERVAL, self.map.len() as i64, self.sample.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u64);
    impl Rng for Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (self.0 >> 33) as u32
        }
    }

    fn ep(n: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4([10, 0, 0, n].into()), 6881)
    }

    #[test]
    fn announce_get_peers_and_expiry() {
        let mut s = PeerStore::default();
        let t0 = Instant::now();
        let ih = NodeId([1; 20]);
        s.announce_peer(ih, ep(1), Some(b"name"), false, t0);
        s.announce_peer(ih, ep(2), None, true, t0);
        s.announce_peer(ih, ep(2), None, true, t0); // duplicate: replaced
        assert_eq!(s.counts(), (1, 2));
        let mut rng = Lcg(5);
        let mut r = Reply::default();
        let full = s.get_peers(&ih, false, false, ep(9).ip(), &mut r, &mut rng);
        assert!(!full);
        assert_eq!(r.values.len(), 2);
        assert_eq!(r.name.as_deref(), Some(&b"name"[..]));
        let mut r = Reply::default();
        s.get_peers(&ih, true, false, ep(9).ip(), &mut r, &mut rng);
        assert_eq!(r.values, vec![ep(1)], "noseed drops the seed");
        let mut r = Reply::default();
        s.get_peers(&ih, false, true, ep(9).ip(), &mut r, &mut rng);
        assert_eq!(r.bf_peers.as_ref().map(Vec::len), Some(256));
        assert!(r.values.is_empty());
        // Unknown hash: nothing, not full.
        let mut r = Reply::default();
        assert!(!s.get_peers(&NodeId([2; 20]), false, false, ep(9).ip(), &mut r, &mut rng));
        assert!(r.values.is_empty());
        // Expiry.
        s.tick(t0 + ANNOUNCE_INTERVAL);
        assert_eq!(s.counts(), (1, 2));
        s.tick(t0 + ANNOUNCE_INTERVAL * 2);
        assert_eq!(s.counts(), (0, 0));
    }

    #[test]
    fn reply_is_bounded_and_full_lists_withhold_tokens() {
        let mut s = PeerStore::default();
        let t0 = Instant::now();
        let ih = NodeId([1; 20]);
        for i in 0..MAX_PEERS as u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000 + i));
            s.announce_peer(ih, SocketAddr::new(ip, 1), None, false, t0);
        }
        // One more than the cap is refused.
        s.announce_peer(ih, ep(200), None, false, t0);
        assert_eq!(s.counts().1, MAX_PEERS);
        let mut rng = Lcg(9);
        let mut r = Reply::default();
        let full = s.get_peers(&ih, false, false, ep(200).ip(), &mut r, &mut rng);
        assert!(full, "requester not in the full list");
        assert_eq!(r.values.len(), MAX_PEERS_REPLY);
        let in_list = IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0003));
        let mut r = Reply::default();
        assert!(!s.get_peers(&ih, false, false, in_list, &mut r, &mut rng));
        let (interval, num, samples) = s.sample(t0, &mut rng);
        assert_eq!((interval, num), (SAMPLE_INTERVAL, 1));
        assert_eq!(samples, vec![ih]);
    }
}
