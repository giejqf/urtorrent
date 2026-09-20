// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// The routing table's rules (bucket layout and sizes, replacement cache,
// pinged / confirmed states, one node per IP and per /24 or /64, split and
// refresh policy) follow libtorrent-rasterbar's routing_table.cpp
// (BSD-3-Clause), Copyright (c) Arvid Norberg and contributors; see NOTICE.

//! The Kademlia routing table.
//!
//! Buckets are indexed by the length of the common prefix with our id;
//! bucket `i` holds nodes whose first differing bit is bit `i`, the last
//! bucket holds everything closer. The first buckets are larger (libtorrent's
//! "extended routing table": 128, 64, 32, 16, then 8 live nodes) and each
//! bucket keeps up to 8 replacements. Nodes we have only heard about (from
//! another node's reply) are *unpinged* and only ever sit in the replacement
//! list; a node enters the live list once it answered us. One node per IP
//! address in the whole table, one per /24 (v4) or /64 (v6) per bucket.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::id::{NodeId, verify_id};

/// Live nodes per bucket beyond the first four (BEP 5's `k`).
pub const BUCKET_SIZE: usize = 8;
/// Nodes with this many consecutive timeouts are dropped (libtorrent
/// `dht_max_fail_count`).
pub const MAX_FAIL_COUNT: u8 = 20;
/// Deepest bucket index (bit position) the table can split to.
const MAX_BUCKETS: usize = 159;

/// One node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEntry {
    /// Its id.
    pub id: NodeId,
    /// Its UDP endpoint.
    pub addr: SocketAddr,
    /// Smoothed round trip time in ms; `None` until it answered.
    pub rtt: Option<u16>,
    /// `None` = never pinged (heard about only); otherwise consecutive
    /// timeouts.
    timeouts: Option<u8>,
    /// Its id matches its address (BEP 42) or the address is local.
    pub verified: bool,
    /// When we first learned of it.
    pub first_seen: Instant,
    /// When we last sent it a query (`None` = never).
    pub last_queried: Option<Instant>,
}

impl NodeEntry {
    /// A node we heard about (unpinged).
    pub fn heard(id: NodeId, addr: SocketAddr, now: Instant) -> NodeEntry {
        NodeEntry {
            id,
            addr,
            rtt: None,
            timeouts: None,
            verified: verify_id(&id, addr.ip()),
            first_seen: now,
            last_queried: None,
        }
    }

    /// A node that answered us with round trip `rtt`.
    pub fn seen(id: NodeId, addr: SocketAddr, rtt: u16, now: Instant) -> NodeEntry {
        NodeEntry {
            id,
            addr,
            rtt: Some(rtt),
            timeouts: Some(0),
            verified: verify_id(&id, addr.ip()),
            first_seen: now,
            last_queried: Some(now),
        }
    }

    /// Has ever answered.
    pub fn pinged(&self) -> bool {
        self.timeouts.is_some()
    }

    /// Answered and no timeout since.
    pub fn confirmed(&self) -> bool {
        self.timeouts == Some(0)
    }

    /// Consecutive timeouts (0 when never pinged).
    pub fn fail_count(&self) -> u8 {
        self.timeouts.unwrap_or(0)
    }

    fn timed_out(&mut self) {
        if let Some(t) = &mut self.timeouts
            && *t < 0xfe
        {
            *t += 1;
        }
    }

    fn set_pinged(&mut self) {
        if self.timeouts.is_none() {
            self.timeouts = Some(0);
        }
    }

    fn update_rtt(&mut self, new_rtt: u16) {
        self.rtt = Some(match self.rtt {
            None => new_rtt,
            Some(old) => (u32::from(old) * 2 / 3 + u32::from(new_rtt) / 3) as u16,
        });
    }

    /// libtorrent's ordering for replacement decisions: verified first,
    /// then lower rtt (unknown rtt sorts last).
    fn rank(&self) -> (bool, u16) {
        (!self.verified, self.rtt.unwrap_or(u16::MAX))
    }
}

#[derive(Debug, Default, Clone)]
struct Bucket {
    live: Vec<NodeEntry>,
    replacements: Vec<NodeEntry>,
}

/// Whether two addresses share a /24 (v4) or /64 (v6).
fn same_cidr(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => (u32::from(x) ^ u32::from(y)) <= 0xff,
        (IpAddr::V6(x), IpAddr::V6(y)) => x.octets()[..8] == y.octets()[..8],
        _ => false,
    }
}

/// The routing table of one node (one address family).
#[derive(Debug, Clone)]
pub struct RoutingTable {
    id: NodeId,
    v6: bool,
    buckets: Vec<Bucket>,
    /// Every address in the table (live or replacement), for the one-node-
    /// per-IP rule.
    ips: HashSet<IpAddr>,
    /// Bootstrap routers: never stored as nodes.
    routers: HashSet<SocketAddr>,
    /// Cached `depth()`.
    depth: usize,
}

/// Result of an insertion attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddStatus {
    Failed,
    Added,
    NeedSplit,
}

impl RoutingTable {
    /// An empty table for `id` over one address family.
    pub fn new(id: NodeId, v6: bool) -> RoutingTable {
        RoutingTable {
            id,
            v6,
            buckets: Vec::new(),
            ips: HashSet::new(),
            routers: HashSet::new(),
            depth: 0,
        }
    }

    /// Our id.
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// Live nodes allowed in bucket `i` (extended table: 128, 64, 32, 16,
    /// then 8).
    pub fn bucket_limit(&self, i: usize) -> usize {
        match i {
            0 => BUCKET_SIZE * 16,
            1 => BUCKET_SIZE * 8,
            2 => BUCKET_SIZE * 4,
            3 => BUCKET_SIZE * 2,
            _ => BUCKET_SIZE,
        }
    }

    /// Number of buckets in use.
    pub fn num_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// `(live nodes, replacements, confirmed live nodes)`.
    pub fn size(&self) -> (usize, usize, usize) {
        let mut live = 0;
        let mut rep = 0;
        let mut confirmed = 0;
        for b in &self.buckets {
            live += b.live.len();
            rep += b.replacements.len();
            confirmed += b.live.iter().filter(|n| n.confirmed()).count();
        }
        (live, rep, confirmed)
    }

    /// Whether any live node exists.
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.live.is_empty())
    }

    /// Bootstrap routers (never part of the table).
    pub fn routers(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.routers.iter().copied()
    }

    /// Register a bootstrap router.
    pub fn add_router(&mut self, addr: SocketAddr) {
        self.routers.insert(addr);
    }

    /// Whether `addr` is one of our routers.
    pub fn is_router(&self, addr: SocketAddr) -> bool {
        self.routers.contains(&addr)
    }

    /// libtorrent's `depth`: how many leading buckets are at least half full.
    pub fn depth(&mut self) -> usize {
        let n = self.buckets.len();
        if n == 0 {
            self.depth = 0;
            return 0;
        }
        if self.depth >= n {
            self.depth = n - 1;
        }
        while self.depth < n - 1 && self.buckets[self.depth + 1].live.len() >= BUCKET_SIZE / 2 {
            self.depth += 1;
        }
        while self.depth > 0 && self.buckets[self.depth - 1].live.len() < BUCKET_SIZE / 2 {
            self.depth -= 1;
        }
        self.depth
    }

    /// Whether bucket `i` has no room in its live list or its replacements.
    pub fn is_full(&self, i: usize) -> bool {
        match self.buckets.get(i) {
            None => false,
            Some(b) => b.live.len() >= self.bucket_limit(i) && b.replacements.len() >= BUCKET_SIZE,
        }
    }

    /// Bucket index for `id`.
    fn bucket_index(&self, id: &NodeId) -> usize {
        let n = self.buckets.len().max(1);
        (159 - self.id.distance_exp(id) as usize).min(n - 1)
    }

    fn ensure_first_bucket(&mut self) {
        if self.buckets.is_empty() {
            self.buckets.push(Bucket::default());
        }
    }

    fn native(&self, addr: SocketAddr) -> bool {
        addr.is_ipv6() == self.v6
    }

    /// Locate a node by endpoint anywhere in the table:
    /// `(bucket, in_replacements, index)`.
    fn find_by_ep(&self, ep: SocketAddr) -> Option<(usize, bool, usize)> {
        for (bi, b) in self.buckets.iter().enumerate() {
            if let Some(i) = b.replacements.iter().position(|n| n.addr == ep) {
                return Some((bi, true, i));
            }
            if let Some(i) = b.live.iter().position(|n| n.addr == ep) {
                return Some((bi, false, i));
            }
        }
        None
    }

    fn remove_at(&mut self, bi: usize, rep: bool, i: usize) {
        let b = &mut self.buckets[bi];
        let n = if rep {
            b.replacements.remove(i)
        } else {
            b.live.remove(i)
        };
        self.ips.remove(&n.addr.ip());
    }

    /// Promote pinged replacements into a bucket's live list while there is
    /// room (best first).
    fn fill_from_replacements(&mut self, bi: usize) {
        let limit = self.bucket_limit(bi);
        let b = &mut self.buckets[bi];
        if b.live.len() >= limit {
            return;
        }
        b.replacements.sort_by_key(NodeEntry::rank);
        while b.live.len() < limit {
            let Some(i) = b.replacements.iter().position(NodeEntry::pinged) else {
                break;
            };
            let n = b.replacements.remove(i);
            b.live.push(n);
        }
    }

    fn prune_empty_bucket(&mut self) {
        if let Some(last) = self.buckets.last()
            && last.live.is_empty()
            && last.replacements.is_empty()
            && self.buckets.len() > 1
        {
            self.buckets.pop();
        }
    }

    /// A node we heard about from another node's reply.
    pub fn heard_about(&mut self, id: NodeId, addr: SocketAddr, now: Instant) {
        if !self.acceptable(&id, addr) {
            return;
        }
        self.add_node(NodeEntry::heard(id, addr, now));
    }

    /// A node answered one of our queries (`rtt` in ms). Returns whether it
    /// ended up in the table.
    pub fn node_seen(&mut self, id: NodeId, addr: SocketAddr, rtt: u16, now: Instant) -> bool {
        if !self.acceptable(&id, addr) {
            return false;
        }
        self.add_node(NodeEntry::seen(id, addr, rtt, now))
    }

    /// libtorrent `verify_node_address`: a routable, native-family address
    /// with a sane port.
    fn acceptable(&self, id: &NodeId, addr: SocketAddr) -> bool {
        if *id == self.id || addr.port() == 0 || !self.native(addr) {
            return false;
        }
        match addr.ip() {
            IpAddr::V4(a) => !(a.is_unspecified() || a.is_multicast() || a.is_broadcast()),
            IpAddr::V6(a) => !(a.is_unspecified() || a.is_multicast()),
        }
    }

    /// Insert or refresh `e` (libtorrent `add_node`, including bucket splits).
    pub fn add_node(&mut self, e: NodeEntry) -> bool {
        let mut s = self.add_node_impl(e.clone());
        if s == AddStatus::Failed {
            return false;
        }
        if s == AddStatus::Added {
            return true;
        }
        while s == AddStatus::NeedSplit {
            self.split_bucket();
            if self.buckets.len() > 50 {
                return self.add_node_impl(e) == AddStatus::Added;
            }
            let last = self.buckets.len() - 1;
            if self.buckets[last].live.len() > self.bucket_limit(last) {
                continue;
            }
            s = self.add_node_impl(e.clone());
            if self.buckets[last].live.is_empty()
                && self.buckets.len() > 1
                && s != AddStatus::NeedSplit
            {
                // A split that moved nothing across: undo the empty tail.
                if self.buckets[last].replacements.is_empty() {
                    self.buckets.pop();
                }
            }
            if s == AddStatus::Failed {
                return false;
            }
            if s == AddStatus::Added {
                return true;
            }
        }
        false
    }

    fn add_node_impl(&mut self, mut e: NodeEntry) -> AddStatus {
        if !self.native(e.addr) || self.routers.contains(&e.addr) {
            return AddStatus::Failed;
        }
        // One node per IP.
        if self.ips.contains(&e.addr.ip()) {
            match self.find_by_ep(e.addr) {
                None => {
                    // Same IP, different port: not allowed (restrict_routing_ips).
                    return AddStatus::Failed;
                }
                Some((bi, rep, i)) => {
                    let list = if rep {
                        &mut self.buckets[bi].replacements
                    } else {
                        &mut self.buckets[bi].live
                    };
                    let existing = &mut list[i];
                    if existing.id == e.id {
                        existing.timeouts = existing.timeouts.map(|_| 0);
                        if e.pinged() {
                            if let Some(r) = e.rtt {
                                existing.update_rtt(r);
                            }
                            existing.last_queried = e.last_queried;
                            existing.set_pinged();
                        }
                        self.fill_from_replacements(bi);
                        self.prune_empty_bucket();
                        return AddStatus::Added;
                    }
                    if existing.id.is_zero() {
                        self.remove_at(bi, rep, i);
                    } else if !e.pinged() {
                        // A different id at a known endpoint, unconfirmed: ignore.
                        return AddStatus::Failed;
                    } else {
                        // The node at this endpoint changed id: drop it and
                        // let the newcomer prove itself later.
                        self.remove_at(bi, rep, i);
                        self.fill_from_replacements(bi);
                        let now = e.last_queried.unwrap_or(e.first_seen);
                        for n in &mut self.buckets[bi].live {
                            if n.last_queried
                                .is_some_and(|t| t + Duration::from_secs(300) < now)
                            {
                                n.last_queried = None;
                            }
                        }
                        self.prune_empty_bucket();
                        return AddStatus::Failed;
                    }
                }
            }
        }
        if e.id == self.id {
            return AddStatus::Failed;
        }
        self.ensure_first_bucket();
        let bi = self.bucket_index(&e.id);
        let limit = self.bucket_limit(bi);
        // Already in the bucket?
        if let Some(j) = self.buckets[bi].live.iter().position(|n| n.id == e.id) {
            let n = &mut self.buckets[bi].live[j];
            if n.addr != e.addr {
                return AddStatus::Failed;
            }
            n.timeouts = n.timeouts.map(|_| 0);
            if let Some(r) = e.rtt {
                n.update_rtt(r);
            }
            return AddStatus::Added;
        }
        if let Some(j) = self.buckets[bi]
            .replacements
            .iter()
            .position(|n| n.id == e.id)
        {
            let n = &mut self.buckets[bi].replacements[j];
            if n.addr != e.addr {
                return AddStatus::Failed;
            }
            n.timeouts = n.timeouts.map(|_| 0);
            if let Some(r) = e.rtt {
                n.update_rtt(r);
            }
            e = self.buckets[bi].replacements.remove(j);
            self.ips.remove(&e.addr.ip());
        }
        // One node per /24 (v4) or /64 (v6) per bucket.
        {
            let b = &self.buckets[bi];
            let clash = b
                .live
                .iter()
                .chain(b.replacements.iter())
                .any(|n| same_cidr(n.addr.ip(), e.addr.ip()));
            if clash {
                return AddStatus::Failed;
            }
        }
        if e.pinged() && self.buckets[bi].live.len() < limit {
            self.ips.insert(e.addr.ip());
            self.buckets[bi].live.push(e);
            return AddStatus::Added;
        }
        let last_bucket = bi + 1 == self.buckets.len();
        let can_split = last_bucket
            && self.buckets.len() < MAX_BUCKETS
            && (e.verified && mostly_verified(&self.buckets[bi].live))
            && e.confirmed()
            && (bi == 0 || self.buckets[bi - 1].live.len() > 1)
            && !all_in_same_half(&self.buckets[bi].live, &e.id, bi);
        if can_split {
            return AddStatus::NeedSplit;
        }
        if e.confirmed() {
            // Replace a failing live node, or a worse one (unverified / slower).
            let b = &mut self.buckets[bi];
            if let Some((j, _)) = b
                .live
                .iter()
                .enumerate()
                .max_by_key(|(_, n)| n.fail_count())
                .filter(|(_, n)| n.fail_count() > 0)
            {
                self.ips.remove(&b.live[j].addr.ip());
                self.ips.insert(e.addr.ip());
                b.live[j] = e;
                return AddStatus::Added;
            }
            if let Some((j, _)) = b
                .live
                .iter()
                .enumerate()
                .max_by_key(|(_, n)| n.rank())
                .filter(|(_, n)| e.rank() < n.rank())
            {
                let old = std::mem::replace(&mut b.live[j], e);
                self.ips.remove(&old.addr.ip());
                self.ips.insert(b.live[j].addr.ip());
                // The displaced node goes to the replacements if there is room.
                if b.replacements.len() < BUCKET_SIZE {
                    self.ips.insert(old.addr.ip());
                    b.replacements.push(old);
                }
                return AddStatus::Added;
            }
        }
        // Replacement cache.
        let b = &mut self.buckets[bi];
        if let Some(j) = b.replacements.iter().position(|n| n.id == e.id) {
            if b.replacements[j].addr == e.addr {
                b.replacements[j].set_pinged();
            }
            return AddStatus::Added;
        }
        if b.replacements.len() >= BUCKET_SIZE {
            match b.replacements.iter().position(|n| !n.pinged()) {
                Some(j) => {
                    let old = b.replacements.remove(j);
                    self.ips.remove(&old.addr.ip());
                }
                None => {
                    // Replace a failing or worse replacement.
                    if let Some((j, _)) = b
                        .replacements
                        .iter()
                        .enumerate()
                        .max_by_key(|(_, n)| (n.fail_count(), n.rank()))
                        .filter(|(_, n)| n.fail_count() > 0 || e.rank() < n.rank())
                    {
                        let old = std::mem::replace(&mut b.replacements[j], e);
                        self.ips.remove(&old.addr.ip());
                        self.ips.insert(b.replacements[j].addr.ip());
                        return AddStatus::Added;
                    }
                    return AddStatus::Failed;
                }
            }
        }
        self.ips.insert(e.addr.ip());
        b.replacements.push(e);
        AddStatus::Added
    }

    /// Split the last bucket in two (libtorrent `split_bucket`).
    fn split_bucket(&mut self) {
        let bi = self.buckets.len() - 1;
        let limit = self.bucket_limit(bi);
        let new_limit = self.bucket_limit(bi + 1);
        self.buckets.push(Bucket::default());
        let (old, new) = {
            let (a, b) = self.buckets.split_at_mut(bi + 1);
            (&mut a[bi], &mut b[0])
        };
        // Nodes sharing one more prefix bit with us move to the new bucket.
        let id = self.id;
        let mut i = 0;
        while i < old.live.len() {
            if (id.distance_exp(&old.live[i].id) as usize) >= 159 - bi {
                i += 1;
            } else {
                let n = old.live.remove(i);
                new.live.push(n);
            }
        }
        if old.live.len() > limit {
            let extra = old.live.split_off(limit);
            old.replacements.extend(extra);
        }
        let mut j = 0;
        while j < old.replacements.len() {
            let stays = (id.distance_exp(&old.replacements[j].id) as usize) >= 159 - bi;
            if stays {
                if !old.replacements[j].pinged() || old.live.len() >= limit {
                    j += 1;
                    continue;
                }
                let n = old.replacements.remove(j);
                old.live.push(n);
            } else {
                let n = old.replacements.remove(j);
                if n.pinged() && new.live.len() < new_limit {
                    new.live.push(n);
                } else {
                    new.replacements.push(n);
                }
            }
        }
    }

    /// A query to `id` at `ep` timed out (libtorrent `node_failed`).
    pub fn node_failed(&mut self, id: &NodeId, ep: SocketAddr) {
        if *id == self.id || self.buckets.is_empty() {
            return;
        }
        let bi = self.bucket_index(id);
        let b = &mut self.buckets[bi];
        let Some(j) = b.live.iter().position(|n| n.id == *id) else {
            if let Some(j) = b.replacements.iter().position(|n| n.id == *id)
                && b.replacements[j].addr == ep
            {
                b.replacements[j].timed_out();
            }
            return;
        };
        if b.live[j].addr != ep {
            return;
        }
        if b.replacements.is_empty() {
            b.live[j].timed_out();
            if b.live[j].fail_count() >= MAX_FAIL_COUNT || !b.live[j].pinged() {
                let n = b.live.remove(j);
                self.ips.remove(&n.addr.ip());
            }
            return;
        }
        let n = b.live.remove(j);
        self.ips.remove(&n.addr.ip());
        self.fill_from_replacements(bi);
        self.prune_empty_bucket();
    }

    /// The `count` closest nodes to `target` (confirmed only unless
    /// `include_failed`), from the target's bucket outwards
    /// (libtorrent `find_node`).
    pub fn find_node(&self, target: &NodeId, include_failed: bool, count: usize) -> Vec<NodeEntry> {
        let count = if count == 0 { BUCKET_SIZE } else { count };
        let mut out: Vec<NodeEntry> = Vec::new();
        if self.buckets.is_empty() {
            return out;
        }
        let bi = self.bucket_index(target);
        let take = |out: &mut Vec<NodeEntry>, b: &Bucket, unsorted_from: usize| -> bool {
            for n in &b.live {
                if include_failed || n.confirmed() {
                    out.push(n.clone());
                }
            }
            if out.len() >= count {
                if out.len() > count {
                    out[unsorted_from..].sort_by_key(|n| n.id.distance(target));
                    out.truncate(count);
                }
                return true;
            }
            false
        };
        for i in bi..self.buckets.len() {
            let from = out.len();
            if take(&mut out, &self.buckets[i], from) {
                return out;
            }
        }
        for i in (0..bi).rev() {
            let from = out.len();
            if take(&mut out, &self.buckets[i], from) {
                return out;
            }
        }
        out
    }

    /// The node most in need of a refresh ping: never-queried first, then
    /// least recently queried, from the deepest bucket up; an unpinged
    /// replacement of a bucket with room also qualifies. Marks it queried at
    /// `now` (libtorrent `next_refresh`).
    pub fn next_refresh(&mut self, now: Instant) -> Option<(NodeId, SocketAddr)> {
        let n = self.buckets.len();
        let mut candidate: Option<(usize, bool, usize)> = None;
        'outer: for bi in (0..n).rev() {
            for (i, node) in self.buckets[bi].live.iter().enumerate() {
                if node.id == self.id {
                    continue;
                }
                if node.last_queried.is_none() {
                    candidate = Some((bi, false, i));
                    break 'outer;
                }
                let better = match candidate {
                    None => true,
                    Some((cb, cr, ci)) => {
                        let c = if cr {
                            &self.buckets[cb].replacements[ci]
                        } else {
                            &self.buckets[cb].live[ci]
                        };
                        node.last_queried < c.last_queried
                    }
                };
                if better {
                    candidate = Some((bi, false, i));
                }
            }
            if (bi == n - 1 || self.buckets[bi].live.len() < self.bucket_limit(bi))
                && let Some(i) = self.buckets[bi]
                    .replacements
                    .iter()
                    .position(|e| !e.pinged() && e.last_queried.is_none())
            {
                candidate = Some((bi, true, i));
                break 'outer;
            }
        }
        let (bi, rep, i) = candidate?;
        let node = if rep {
            &mut self.buckets[bi].replacements[i]
        } else {
            &mut self.buckets[bi].live[i]
        };
        node.last_queried = Some(now);
        Some((node.id, node.addr))
    }

    /// Every live node, deepest bucket first (for persistence).
    pub fn live_nodes(&self) -> Vec<NodeEntry> {
        self.buckets
            .iter()
            .rev()
            .flat_map(|b| b.live.iter().cloned())
            .collect()
    }

    /// Replace our id (BEP 42 update after learning the external address):
    /// every node is re-inserted under the new geometry.
    pub fn set_id(&mut self, id: NodeId) {
        self.id = id;
        self.ips.clear();
        let old = std::mem::take(&mut self.buckets);
        for b in &old {
            for n in &b.live {
                self.add_node(n.clone());
            }
        }
        for b in &old {
            for n in &b.replacements {
                self.add_node(n.clone());
            }
        }
    }
}

/// libtorrent `mostly_verified_nodes`: at least two thirds of the bucket
/// carry BEP 42 ids (an empty bucket counts as verified).
fn mostly_verified(b: &[NodeEntry]) -> bool {
    let verified = b.iter().filter(|n| n.verified).count();
    if verified == 0 && !b.is_empty() {
        return false;
    }
    verified >= b.len() * 2 / 3
}

/// Whether `id` and every node of `b` fall on the same side of bit
/// `bucket_index` (a split would move nothing).
fn all_in_same_half(b: &[NodeEntry], id: &NodeId, bucket_index: usize) -> bool {
    let side = id.bit(bucket_index);
    b.iter().all(|n| n.id.bit(bucket_index) == side)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(prefix: u8, tail: u8) -> NodeId {
        let mut b = [tail; 20];
        b[0] = prefix;
        NodeId(b)
    }

    fn addr(n: u32, port: u16) -> SocketAddr {
        // Distinct /24s so the CIDR rule does not interfere.
        SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 | (n << 8) | 1)),
            port,
        )
    }

    #[test]
    fn heard_nodes_are_replacements_until_they_answer() {
        let now = Instant::now();
        let mut t = RoutingTable::new(id(0x00, 0), false);
        t.heard_about(id(0x80, 1), addr(1, 6881), now);
        assert_eq!(t.size(), (0, 1, 0));
        assert!(t.find_node(&id(0x80, 1), false, 8).is_empty());
        assert!(t.node_seen(id(0x80, 1), addr(1, 6881), 20, now));
        assert_eq!(t.size(), (1, 0, 1));
        assert_eq!(t.find_node(&id(0x80, 1), false, 8).len(), 1);
        // Same IP, other port: refused.
        assert!(!t.node_seen(id(0x81, 2), addr(1, 6882), 20, now));
        // Same /24 in the same bucket: refused.
        let same24 = SocketAddr::new(IpAddr::V4([10, 0, 1, 2].into()), 6881);
        assert!(!t.node_seen(id(0x82, 3), same24, 20, now));
        assert_eq!(t.size(), (1, 0, 1));
    }

    #[test]
    fn buckets_split_and_stay_bounded() {
        let now = Instant::now();
        let mut t = RoutingTable::new(id(0x00, 0), false);
        // Fill with nodes spread over the id space (all "verified": local IPs).
        let mut n = 1u32;
        for p in 0..=255u8 {
            for k in 0..2u8 {
                t.node_seen(id(p, k), addr(n, 6881), 30, now);
                n += 1;
            }
        }
        let (live, _, _) = t.size();
        assert!(t.num_buckets() > 1, "no split happened");
        for bi in 0..t.num_buckets() {
            assert!(t.buckets[bi].live.len() <= t.bucket_limit(bi));
            // Replacement lists are bounded on insertion; a split may spill
            // a bucket's surplus into them (as in libtorrent).
            assert!(t.buckets[bi].replacements.len() <= 128);
        }
        assert!(live <= 128 + 64 + 32 + 16 + 8 * 20);
        // The closest nodes to a target are the ones sharing its prefix.
        let close = t.find_node(&id(0x01, 0), false, 8);
        assert_eq!(close.len(), 8);
        assert!(close.iter().all(|e| e.id.0[0] <= 0x07), "{close:?}");
        // Failures evict once the replacement list is empty and the count is high.
        let victim = close[0].clone();
        for _ in 0..MAX_FAIL_COUNT {
            t.node_failed(&victim.id, victim.addr);
        }
        assert!(
            t.find_node(&victim.id, true, 300)
                .iter()
                .all(|e| e.id != victim.id)
        );
    }

    #[test]
    fn refresh_picks_never_queried_first() {
        let now = Instant::now();
        let mut t = RoutingTable::new(id(0x00, 0), false);
        t.node_seen(id(0x80, 1), addr(1, 6881), 20, now);
        t.node_seen(id(0x40, 2), addr(2, 6881), 20, now);
        t.buckets[0].live[0].last_queried = None;
        let first = t.next_refresh(now + Duration::from_secs(1)).unwrap();
        assert_eq!(first.0, id(0x80, 1));
        // Then the least recently queried.
        let second = t.next_refresh(now + Duration::from_secs(2)).unwrap();
        assert_eq!(second.0, id(0x40, 2));
        // Routers are never nodes.
        t.add_router(addr(9, 6881));
        assert!(!t.node_seen(id(0x20, 9), addr(9, 6881), 5, now));
    }

    #[test]
    fn set_id_reinserts_everything() {
        let now = Instant::now();
        let mut t = RoutingTable::new(id(0x00, 0), false);
        for n in 1..40u32 {
            t.node_seen(id(n as u8 * 6, n as u8), addr(n, 6881), 20, now);
        }
        let before = t.size().0;
        t.set_id(id(0xff, 7));
        assert_eq!(t.size().0, before);
        assert_eq!(t.id(), id(0xff, 7));
    }
}
