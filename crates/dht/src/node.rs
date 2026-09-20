// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// The lookup algorithm (branching, short and hard timeouts, result cap,
// per-prefix filtering, announce to the closest token holders), bootstrap and
// refresh policy, and request handling follow libtorrent-rasterbar's
// traversal_algorithm.cpp, get_peers.cpp, find_data.cpp, refresh.cpp,
// rpc_manager.cpp and node.cpp (BSD-3-Clause), Copyright (c) Arvid Norberg and
// contributors; see NOTICE.

//! One DHT node (one address family): the sans-IO orchestrator.
//!
//! Feed it datagrams ([`Node::incoming`]) and time ([`Node::tick`]), ask it
//! for lookups ([`Node::announce`], [`Node::get_peers`]) and drain what it
//! wants done ([`Node::poll_action`]): datagrams to send, peers found,
//! external-address votes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use profile::Rng;

use crate::blocker::DosBlocker;
use crate::id::{NodeId, SecretIds, closer, generate_id, is_local, prefix_mask, verify_id};
use crate::krpc::{self, ErrorMsg, Message, Query, QueryMsg, Reply, ResponseMsg, Want, code};
use crate::storage::PeerStore;
use crate::table::{BUCKET_SIZE, NodeEntry, RoutingTable};
use crate::token::Tokens;

/// Outstanding queries per node before new ones are dropped.
const MAX_OUTSTANDING: usize = 1024;
/// A query unanswered this long fails (libtorrent `rpc_manager` `timeout`).
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// A query unanswered this long widens the lookup (`short_timeout`).
pub const SHORT_TIMEOUT: Duration = Duration::from_secs(1);
/// Routing-table refresh cadence (libtorrent `dht_tracker` refresh timer).
pub const REFRESH_EVERY: Duration = Duration::from_secs(5);
/// Re-bootstrap when the table stayed shallow this long (`node::tick`).
const SELF_REFRESH_EVERY: Duration = Duration::from_secs(10 * 60);
/// Peer-store expiry sweep cadence (`node::connection_timeout`).
const STORAGE_TICK: Duration = Duration::from_secs(2 * 60);
/// Lookup results kept (libtorrent caps the sorted list at 100).
const MAX_RESULTS: usize = 100;
/// Concurrent queries per lookup (`dht_search_branching`).
const BRANCHING: i8 = 5;

/// Tunables and identity data (from the profile).
#[derive(Debug, Clone)]
pub struct Config {
    /// The `v` stamped on every message (the oracle: `LT` + 2.0.14 as two
    /// bytes). `None` omits it.
    pub version: Option<Vec<u8>>,
    /// BEP 43 read-only node: we never answer queries and mark ours `ro`.
    pub read_only: bool,
    /// Skip nodes of a /24 (v4) or /64 (v6) already in a lookup
    /// (`dht_restrict_search_ips`).
    pub restrict_search_ips: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: None,
            read_only: false,
            restrict_search_ips: true,
        }
    }
}

/// Identifies a lookup started by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LookupId(pub u32);

/// Something the node wants done or reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a datagram.
    Send {
        /// Destination.
        to: SocketAddr,
        /// The encoded message.
        payload: Vec<u8>,
    },
    /// Peers learned for a torrent (possibly duplicates across replies).
    Peers {
        /// The lookup that found them.
        lookup: LookupId,
        /// The torrent.
        info_hash: NodeId,
        /// Peer endpoints.
        peers: Vec<SocketAddr>,
    },
    /// A lookup finished (after its announces were sent, if any).
    LookupDone {
        /// The lookup.
        lookup: LookupId,
        /// Nodes that answered.
        responses: u32,
        /// Nodes we announced to.
        announced: u32,
    },
    /// A node told us our external address (BEP 42 vote).
    ExternalIp {
        /// Our address as it saw it.
        ip: IpAddr,
        /// Who said so.
        from: IpAddr,
    },
    /// The bootstrap lookup finished; the table has this many live nodes.
    Bootstrapped {
        /// Live nodes in the routing table.
        nodes: usize,
    },
}

/// Counters for status reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Live routing-table nodes.
    pub nodes: usize,
    /// Replacement-cache nodes.
    pub replacements: usize,
    /// Queries awaiting a reply.
    pub outstanding: usize,
    /// Lookups in progress.
    pub lookups: usize,
    /// Torrents in the peer store.
    pub torrents: usize,
    /// Peers in the peer store.
    pub peers: usize,
    /// Datagrams received.
    pub messages_in: u64,
    /// Datagrams sent.
    pub messages_out: u64,
    /// Datagrams dropped (flood, malformed).
    pub dropped: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// Part of a lookup.
    Lookup(LookupId),
    /// `announce_peer` after a lookup.
    Announce(LookupId),
    /// A refresh / add-node probe: replies feed the table only.
    Probe,
}

#[derive(Debug, Clone)]
struct Outstanding {
    to: SocketAddr,
    /// The node we think we are talking to (`None` for routers / unknown).
    id: Option<NodeId>,
    sent: Instant,
    short_fired: bool,
    purpose: Purpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupKind {
    /// libtorrent's `bootstrap`: `get_peers` for our own (secret) id, `bs: 1`
    /// to routers.
    Bootstrap,
    /// `get_peers` for a torrent, optionally announcing afterwards.
    GetPeers,
}

#[derive(Debug, Clone)]
struct Announce {
    port: u16,
    seed: bool,
    implied_port: bool,
}

#[derive(Debug, Clone)]
struct Candidate {
    id: NodeId,
    addr: SocketAddr,
    queried: bool,
    alive: bool,
    failed: bool,
    short_timeout: bool,
    /// Router / caller-supplied with no id (a random one stands in).
    no_id: bool,
    initial: bool,
}

#[derive(Debug, Clone)]
struct Lookup {
    kind: LookupKind,
    target: NodeId,
    noseed: bool,
    announce: Option<Announce>,
    results: Vec<Candidate>,
    invoke_count: i32,
    branch_factor: i8,
    responses: u32,
    tokens: HashMap<NodeId, Vec<u8>>,
    prefixes4: HashSet<u32>,
    prefixes6: HashSet<u64>,
    /// Announces still in flight after the traversal ended.
    announces_pending: u32,
    announced: u32,
    traversal_done: bool,
}

impl Lookup {
    fn new(kind: LookupKind, target: NodeId, noseed: bool, announce: Option<Announce>) -> Lookup {
        Lookup {
            kind,
            target,
            noseed,
            announce,
            results: Vec::new(),
            invoke_count: 0,
            branch_factor: BRANCHING,
            responses: 0,
            tokens: HashMap::new(),
            prefixes4: HashSet::new(),
            prefixes6: HashSet::new(),
            announces_pending: 0,
            announced: 0,
            traversal_done: false,
        }
    }

    fn position(&self, id: &NodeId) -> Option<usize> {
        self.results.iter().position(|c| c.id == *id)
    }

    /// Insert `id`/`addr` in distance order (libtorrent `add_entry`).
    fn add_entry(
        &mut self,
        id: NodeId,
        addr: SocketAddr,
        initial: bool,
        restrict_ips: bool,
        rng: &mut dyn Rng,
    ) {
        let no_id = id.is_zero();
        let id = if no_id { NodeId::random(rng) } else { id };
        if !no_id && self.results.iter().any(|c| c.id == id) {
            return;
        }
        if !no_id && restrict_ips && !initial {
            let fresh = match addr.ip() {
                IpAddr::V4(a) => self.prefixes4.insert(u32::from(a) & 0xffff_ff00),
                IpAddr::V6(a) => {
                    let o = a.octets();
                    let mut p = [0u8; 8];
                    p.copy_from_slice(&o[..8]);
                    self.prefixes6.insert(u64::from_be_bytes(p))
                }
            };
            if !fresh {
                return;
            }
        }
        let c = Candidate {
            id,
            addr,
            queried: false,
            alive: false,
            failed: false,
            short_timeout: false,
            no_id,
            initial,
        };
        if no_id {
            // Unknown distance: append (routers are queried in turn anyway).
            self.results.push(c);
        } else {
            let target = self.target;
            let pos = self
                .results
                .partition_point(|x| closer(&x.id, &id, &target) == std::cmp::Ordering::Less);
            self.results.insert(pos, c);
        }
        if self.results.len() > MAX_RESULTS {
            for c in self.results.drain(MAX_RESULTS..) {
                if c.queried && !c.failed && !c.alive {
                    self.invoke_count -= 1;
                    if c.short_timeout {
                        self.branch_factor -= 1;
                    }
                }
            }
        }
    }

    /// libtorrent `add_requests` (aggressive mode): keep `branch_factor`
    /// queries outstanding among the closest unqueried candidates until
    /// `BUCKET_SIZE` alive results are in front. Returns the candidates to
    /// query now and whether the traversal is complete.
    fn add_requests(&mut self) -> (Vec<usize>, bool) {
        let mut results_target = BUCKET_SIZE as i32;
        let mut outstanding = 0i32;
        let mut invoke = Vec::new();
        for (i, c) in self.results.iter_mut().enumerate() {
            if results_target <= 0 || outstanding >= i32::from(self.branch_factor.max(1)) {
                break;
            }
            if c.alive {
                results_target -= 1;
                continue;
            }
            if c.queried {
                if !c.failed {
                    outstanding += 1;
                }
                continue;
            }
            c.queried = true;
            invoke.push(i);
            self.invoke_count += 1;
            outstanding += 1;
        }
        let done = (results_target == 0 && outstanding == 0) || self.invoke_count == 0;
        (invoke, done)
    }
}

/// The node.
pub struct Node {
    cfg: Config,
    v6: bool,
    id: NodeId,
    table: RoutingTable,
    tokens: Tokens,
    store: PeerStore,
    blocker: DosBlocker,
    secrets: SecretIds,
    outstanding: HashMap<(u16, SocketAddr), Outstanding>,
    lookups: HashMap<LookupId, Lookup>,
    next_lookup: u32,
    actions: VecDeque<Action>,
    last_refresh: Instant,
    last_self_refresh: Option<Instant>,
    last_storage_tick: Instant,
    bootstrap_lookup: Option<LookupId>,
    stats: Stats,
}

impl Node {
    /// A node with a random id (replaced by a BEP 42 id once the external
    /// address is known, see [`Node::set_external_ip`]).
    pub fn new(cfg: Config, v6: bool, now: Instant, rng: &mut dyn Rng) -> Node {
        let id = NodeId::random(rng);
        Node::with_id(cfg, v6, id, now, rng)
    }

    /// A node restoring a saved id.
    pub fn with_id(cfg: Config, v6: bool, id: NodeId, now: Instant, rng: &mut dyn Rng) -> Node {
        Node {
            cfg,
            v6,
            id,
            table: RoutingTable::new(id, v6),
            tokens: Tokens::new(now, rng),
            store: PeerStore::default(),
            blocker: DosBlocker::default(),
            secrets: SecretIds::new(rng),
            outstanding: HashMap::new(),
            lookups: HashMap::new(),
            next_lookup: 1,
            actions: VecDeque::new(),
            last_refresh: now,
            last_self_refresh: None,
            last_storage_tick: now,
            bootstrap_lookup: None,
            stats: Stats::default(),
        }
    }

    /// Our id.
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// The routing table.
    pub fn table(&self) -> &RoutingTable {
        &self.table
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        let (nodes, replacements, _) = self.table.size();
        let (torrents, peers) = self.store.counts();
        Stats {
            nodes,
            replacements,
            outstanding: self.outstanding.len(),
            lookups: self.lookups.len(),
            torrents,
            peers,
            ..self.stats
        }
    }

    /// Next queued action.
    pub fn poll_action(&mut self) -> Option<Action> {
        self.actions.pop_front()
    }

    /// When `tick` next has work (refresh cadence or the earliest timeout).
    pub fn next_wakeup(&self, now: Instant) -> Instant {
        let mut t = self.last_refresh + REFRESH_EVERY;
        for o in self.outstanding.values() {
            let next = if o.short_fired {
                o.sent + TIMEOUT
            } else {
                o.sent + SHORT_TIMEOUT
            };
            if next < t {
                t = next;
            }
        }
        t.max(now)
    }

    /// Our external address became known (or changed): adopt a BEP 42 id
    /// unless the current one already fits (libtorrent `update_node_id`).
    pub fn set_external_ip(&mut self, ip: IpAddr, rng: &mut dyn Rng) -> bool {
        if verify_id(&self.id, ip) {
            return false;
        }
        let id = generate_id(ip, rng);
        self.id = id;
        self.table.set_id(id);
        true
    }

    /// Register a bootstrap router (used by [`Node::bootstrap`]; never a
    /// routing-table node).
    pub fn add_router(&mut self, addr: SocketAddr) {
        if addr.is_ipv6() == self.v6 {
            self.table.add_router(addr);
        }
    }

    /// A node we were told about (peer-wire `port` message, saved state):
    /// probe it so it can enter the table (libtorrent `add_node` →
    /// `send_single_refresh`).
    pub fn add_node(&mut self, addr: SocketAddr, now: Instant, rng: &mut dyn Rng) {
        if addr.is_ipv6() != self.v6 || addr.port() == 0 {
            return;
        }
        let bucket = self.table.num_buckets();
        self.send_single_refresh(addr, bucket, None, now, rng);
    }

    /// Start the bootstrap lookup from the routers and whatever the table
    /// holds (libtorrent `node::bootstrap`).
    pub fn bootstrap(&mut self, now: Instant, rng: &mut dyn Rng) -> LookupId {
        let mut target = self.id;
        self.secrets.make_secret(&mut target, rng);
        let mut l = Lookup::new(LookupKind::Bootstrap, target, false, None);
        let routers: Vec<SocketAddr> = self.table.routers().collect();
        for r in routers {
            l.add_entry(NodeId::ZERO, r, true, self.cfg.restrict_search_ips, rng);
        }
        self.last_self_refresh = Some(now);
        let id = self.start_lookup(l, now, rng);
        self.bootstrap_lookup = Some(id);
        id
    }

    /// Look a torrent up and announce our `port` to the closest nodes
    /// (libtorrent `node::announce`: one `get_peers` traversal, then
    /// `announce_peer` to up to 8 token holders). `seed` sets `noseed` on the
    /// lookup and `seed: 1` on the announces.
    pub fn announce(
        &mut self,
        info_hash: NodeId,
        port: u16,
        seed: bool,
        implied_port: bool,
        now: Instant,
        rng: &mut dyn Rng,
    ) -> LookupId {
        let l = Lookup::new(
            LookupKind::GetPeers,
            info_hash,
            seed,
            Some(Announce {
                port,
                seed,
                implied_port,
            }),
        );
        self.start_lookup(l, now, rng)
    }

    /// Look a torrent up without announcing.
    pub fn get_peers(
        &mut self,
        info_hash: NodeId,
        noseed: bool,
        now: Instant,
        rng: &mut dyn Rng,
    ) -> LookupId {
        let l = Lookup::new(LookupKind::GetPeers, info_hash, noseed, None);
        self.start_lookup(l, now, rng)
    }

    fn start_lookup(&mut self, mut l: Lookup, now: Instant, rng: &mut dyn Rng) -> LookupId {
        let id = LookupId(self.next_lookup);
        self.next_lookup = self.next_lookup.wrapping_add(1).max(1);
        // Seed with the closest nodes we know (find_data::start), then the
        // routers if that is thin (traversal_algorithm::start).
        if l.results.is_empty() {
            for n in self.table.find_node(&l.target, true, BUCKET_SIZE) {
                l.add_entry(n.id, n.addr, true, self.cfg.restrict_search_ips, rng);
            }
        }
        if l.results.len() < 3 {
            let routers: Vec<SocketAddr> = self.table.routers().collect();
            for r in routers {
                l.add_entry(NodeId::ZERO, r, true, self.cfg.restrict_search_ips, rng);
            }
        }
        self.lookups.insert(id, l);
        self.drive_lookup(id, now, rng);
        id
    }

    /// Send the next queries of lookup `id`; finish it when complete.
    fn drive_lookup(&mut self, id: LookupId, now: Instant, rng: &mut dyn Rng) {
        let Some(mut l) = self.lookups.remove(&id) else {
            return;
        };
        if !l.traversal_done {
            let (invoke, done) = l.add_requests();
            for i in invoke {
                let c = l.results[i].clone();
                let q = match l.kind {
                    LookupKind::Bootstrap => {
                        let mut target = self.id;
                        self.secrets.make_secret(&mut target, rng);
                        Query::GetPeers {
                            info_hash: target,
                            noseed: false,
                            scrape: false,
                            bootstrap: c.initial,
                        }
                    }
                    LookupKind::GetPeers => Query::GetPeers {
                        info_hash: l.target,
                        noseed: l.noseed,
                        scrape: false,
                        bootstrap: false,
                    },
                };
                let expect = (!c.no_id).then_some(c.id);
                if !self.send_query(c.addr, expect, q, Purpose::Lookup(id), now, rng) {
                    l.results[i].failed = true;
                    l.invoke_count -= 1;
                }
            }
            if done {
                l.traversal_done = true;
                self.finish_traversal(id, &mut l, now, rng);
            }
        }
        if l.traversal_done && l.announces_pending == 0 {
            let responses = l.responses;
            let announced = l.announced;
            if self.bootstrap_lookup == Some(id) {
                self.bootstrap_lookup = None;
                let (nodes, _, _) = self.table.size();
                self.actions.push_back(Action::Bootstrapped { nodes });
            }
            self.actions.push_back(Action::LookupDone {
                lookup: id,
                responses,
                announced,
            });
            return;
        }
        self.lookups.insert(id, l);
    }

    /// The traversal converged: announce to the closest token holders, or
    /// (bootstrap) probe the nodes we learned about but never asked.
    fn finish_traversal(&mut self, id: LookupId, l: &mut Lookup, now: Instant, rng: &mut dyn Rng) {
        match l.kind {
            LookupKind::Bootstrap => {
                let unqueried: Vec<SocketAddr> = l
                    .results
                    .iter()
                    .filter(|c| !c.queried)
                    .map(|c| c.addr)
                    .collect();
                for addr in unqueried {
                    self.add_node(addr, now, rng);
                }
            }
            LookupKind::GetPeers => {
                if let Some(a) = l.announce.clone() {
                    let mut n = BUCKET_SIZE;
                    let targets: Vec<(NodeId, SocketAddr, Vec<u8>)> = l
                        .results
                        .iter()
                        .filter(|c| c.alive)
                        .filter_map(|c| l.tokens.get(&c.id).map(|t| (c.id, c.addr, t.clone())))
                        .take_while(|_| {
                            let more = n > 0;
                            n = n.saturating_sub(1);
                            more
                        })
                        .collect();
                    for (nid, addr, token) in targets {
                        let q = Query::AnnouncePeer {
                            info_hash: l.target,
                            port: a.port,
                            token,
                            seed: a.seed,
                            implied_port: a.implied_port,
                            name: None,
                        };
                        if self.send_query(addr, Some(nid), q, Purpose::Announce(id), now, rng) {
                            l.announces_pending += 1;
                            l.announced += 1;
                        }
                    }
                }
            }
        }
    }

    /// Refresh probe to `addr` for `bucket` (libtorrent `send_single_refresh`):
    /// `ping` when the bucket is full, else `get_peers` for a random id in
    /// the bucket's range so the reply brings usable nodes.
    fn send_single_refresh(
        &mut self,
        addr: SocketAddr,
        bucket: usize,
        id: Option<NodeId>,
        now: Instant,
        rng: &mut dyn Rng,
    ) {
        let bucket = bucket.min(159);
        let q = if self.table.is_full(bucket) {
            Query::Ping
        } else {
            let mask = prefix_mask(bucket as u32 + 1);
            let mut target = self.secrets.random(rng);
            for i in 0..20 {
                target.0[i] = (target.0[i] & !mask.0[i]) | (self.id.0[i] & mask.0[i]);
            }
            Query::GetPeers {
                info_hash: target,
                noseed: false,
                scrape: false,
                bootstrap: false,
            }
        };
        self.send_query(addr, id, q, Purpose::Probe, now, rng);
    }

    /// Build, register and queue a query. `false` if it could not be sent.
    fn send_query(
        &mut self,
        to: SocketAddr,
        expect: Option<NodeId>,
        query: Query,
        purpose: Purpose,
        now: Instant,
        rng: &mut dyn Rng,
    ) -> bool {
        if self.outstanding.len() >= MAX_OUTSTANDING || to.is_ipv6() != self.v6 {
            return false;
        }
        let mut tid = (rng.next_u32() & 0xffff) as u16;
        let mut tries = 0;
        while self.outstanding.contains_key(&(tid, to)) {
            tid = tid.wrapping_add(1);
            tries += 1;
            if tries > 16 {
                return false;
            }
        }
        let want = if to.is_ipv6() != self.v6 {
            vec![if self.v6 { Want::V6 } else { Want::V4 }]
        } else {
            Vec::new()
        };
        let msg = QueryMsg {
            tid: tid.to_be_bytes().to_vec(),
            id: self.id,
            query,
            read_only: self.cfg.read_only,
            want,
            version: self.cfg.version.clone(),
        };
        let payload = krpc::encode_query(&msg);
        self.outstanding.insert(
            (tid, to),
            Outstanding {
                to,
                id: expect,
                sent: now,
                short_fired: false,
                purpose,
            },
        );
        self.stats.messages_out += 1;
        self.actions.push_back(Action::Send { to, payload });
        true
    }

    /// Time passed: request timeouts, the 5-second refresh, token rotation,
    /// peer-store expiry, periodic re-bootstrap of a shallow table.
    pub fn tick(&mut self, now: Instant, rng: &mut dyn Rng) {
        // Timeouts.
        let mut timed_out = Vec::new();
        let mut short = Vec::new();
        for (key, o) in &mut self.outstanding {
            let age = now.saturating_duration_since(o.sent);
            if age >= TIMEOUT {
                timed_out.push(*key);
            } else if age >= SHORT_TIMEOUT && !o.short_fired {
                o.short_fired = true;
                short.push(*key);
            }
        }
        for key in short {
            if let Some(o) = self.outstanding.get(&key).cloned()
                && let Purpose::Lookup(lid) = o.purpose
                && let Some(l) = self.lookups.get_mut(&lid)
                && let Some(c) = o.id.and_then(|id| l.position(&id)).or_else(|| {
                    l.results
                        .iter()
                        .position(|c| c.addr == o.to && c.queried && !c.alive)
                })
            {
                let c = &mut l.results[c];
                if !c.short_timeout && l.branch_factor < i8::MAX {
                    l.branch_factor += 1;
                    c.short_timeout = true;
                }
                self.drive_lookup(lid, now, rng);
            }
        }
        for key in timed_out {
            if let Some(o) = self.outstanding.remove(&key) {
                self.on_failure(o, now, rng);
            }
        }
        // Refresh.
        if now.duration_since(self.last_refresh) >= REFRESH_EVERY {
            self.last_refresh = now;
            let shallow = self.table.depth() < 4;
            let due = self
                .last_self_refresh
                .is_none_or(|t| now.duration_since(t) >= SELF_REFRESH_EVERY);
            if shallow && due && self.bootstrap_lookup.is_none() {
                self.bootstrap(now, rng);
            } else if let Some((id, addr)) = self.table.next_refresh(now) {
                let bucket = 159 - self.id.distance_exp(&id) as usize;
                self.send_single_refresh(addr, bucket, Some(id), now, rng);
            }
        }
        self.tokens.tick(now, rng);
        if now.duration_since(self.last_storage_tick) >= STORAGE_TICK {
            self.last_storage_tick = now;
            self.store.tick(now);
        }
    }

    /// A query failed (timeout or error reply).
    fn on_failure(&mut self, o: Outstanding, now: Instant, rng: &mut dyn Rng) {
        if let Some(id) = o.id {
            self.table.node_failed(&id, o.to);
        }
        match o.purpose {
            Purpose::Lookup(lid) => {
                if let Some(l) = self.lookups.get_mut(&lid) {
                    let pos = o.id.and_then(|id| l.position(&id)).or_else(|| {
                        l.results
                            .iter()
                            .position(|c| c.addr == o.to && c.queried && !c.alive && !c.failed)
                    });
                    if let Some(i) = pos {
                        let c = &mut l.results[i];
                        c.failed = true;
                        if c.short_timeout {
                            l.branch_factor -= 1;
                            if l.branch_factor <= 0 {
                                l.branch_factor = 1;
                            }
                        }
                    }
                    l.invoke_count -= 1;
                    self.drive_lookup(lid, now, rng);
                }
            }
            Purpose::Announce(lid) => {
                if let Some(l) = self.lookups.get_mut(&lid) {
                    l.announces_pending = l.announces_pending.saturating_sub(1);
                    self.drive_lookup(lid, now, rng);
                }
            }
            Purpose::Probe => {}
        }
    }

    /// A datagram arrived from `from`. `foreign` is the other family's
    /// routing table, for `want` (`None` when we have no such node).
    pub fn incoming(
        &mut self,
        from: SocketAddr,
        bytes: &[u8],
        now: Instant,
        rng: &mut dyn Rng,
        foreign: Option<&RoutingTable>,
    ) {
        self.stats.messages_in += 1;
        if bytes.len() <= 20 || bytes.first() != Some(&b'd') || bytes.last() != Some(&b'e') {
            self.stats.dropped += 1;
            return;
        }
        if !self.blocker.incoming(from.ip(), now) {
            self.stats.dropped += 1;
            return;
        }
        let msg = match krpc::decode(bytes) {
            Ok(m) => m,
            Err(krpc::DecodeError::Argument(text)) => {
                // A query whose arguments libtorrent rejects with an error.
                if let Some((tid, id)) = krpc::decode_query_head(bytes) {
                    if !self.cfg.read_only {
                        let head = id.map(|_| (self.id, from));
                        self.reply_error(from, &tid, code::PROTOCOL, text.as_bytes(), head);
                    }
                } else {
                    self.stats.dropped += 1;
                }
                return;
            }
            Err(_) => {
                self.stats.dropped += 1;
                return;
            }
        };
        match msg {
            Message::Query(q) => {
                if self.cfg.read_only {
                    return;
                }
                self.on_query(from, q, now, rng, foreign);
            }
            Message::Response(r) => self.on_response(from, r, now, rng),
            Message::Error(e) => self.on_error(from, e, now, rng),
        }
    }

    fn reply_error(
        &mut self,
        to: SocketAddr,
        tid: &[u8],
        code: i64,
        message: &[u8],
        head: Option<(NodeId, SocketAddr)>,
    ) {
        let payload = krpc::encode_error(tid, code, message, head, self.cfg.version.as_deref());
        self.stats.messages_out += 1;
        self.actions.push_back(Action::Send { to, payload });
    }

    /// Nodes for a reply: the requester's family unless `want` says otherwise
    /// (libtorrent `write_nodes_entries`).
    fn nodes_for(
        &self,
        target: &NodeId,
        want: &[Want],
        from: SocketAddr,
        foreign: Option<&RoutingTable>,
        reply: &mut Reply,
    ) {
        let own = self.table.find_node(target, false, BUCKET_SIZE);
        let own_pairs: Vec<(NodeId, SocketAddr)> =
            own.into_iter().map(|n| (n.id, n.addr)).collect();
        let foreign_pairs = |t: &RoutingTable| -> Vec<(NodeId, SocketAddr)> {
            t.find_node(target, false, BUCKET_SIZE)
                .into_iter()
                .map(|n| (n.id, n.addr))
                .collect()
        };
        if want.is_empty() {
            if from.is_ipv6() == self.v6 {
                if self.v6 {
                    reply.nodes6 = own_pairs;
                } else {
                    reply.nodes = own_pairs;
                }
            } else if let Some(f) = foreign {
                if self.v6 {
                    reply.nodes = foreign_pairs(f);
                } else {
                    reply.nodes6 = foreign_pairs(f);
                }
            }
            return;
        }
        for w in want {
            match (w, self.v6) {
                (Want::V4, false) | (Want::V6, true) => {
                    if self.v6 {
                        reply.nodes6 = own_pairs.clone();
                    } else {
                        reply.nodes = own_pairs.clone();
                    }
                }
                (Want::V4, true) => {
                    if let Some(f) = foreign {
                        reply.nodes = foreign_pairs(f);
                    }
                }
                (Want::V6, false) => {
                    if let Some(f) = foreign {
                        reply.nodes6 = foreign_pairs(f);
                    }
                }
            }
        }
    }

    fn on_query(
        &mut self,
        from: SocketAddr,
        q: QueryMsg,
        now: Instant,
        rng: &mut dyn Rng,
        foreign: Option<&RoutingTable>,
    ) {
        if !q.read_only {
            self.table.heard_about(q.id, from, now);
        }
        let mut reply = Reply {
            id: self.id,
            port: Some(from.port()),
            ..Reply::default()
        };
        match &q.query {
            Query::Ping => {}
            Query::FindNode { target } => {
                self.nodes_for(target, &q.want, from, foreign, &mut reply);
            }
            Query::GetPeers {
                info_hash,
                noseed,
                scrape,
                ..
            } => {
                self.nodes_for(info_hash, &q.want, from, foreign, &mut reply);
                let full =
                    self.store
                        .get_peers(info_hash, *noseed, *scrape, from.ip(), &mut reply, rng);
                if !full {
                    reply.token = Some(self.tokens.generate(from.ip(), info_hash).to_vec());
                }
            }
            Query::AnnouncePeer {
                info_hash,
                port,
                token,
                seed,
                implied_port,
                name,
            } => {
                let port = if *implied_port { from.port() } else { *port };
                if !self.tokens.verify(token, from.ip(), info_hash) {
                    self.reply_error(
                        from,
                        &q.tid,
                        code::PROTOCOL,
                        b"invalid token",
                        Some((self.id, from)),
                    );
                    return;
                }
                // A valid token proves the address: let the node in.
                self.table.node_seen(q.id, from, u16::MAX, now);
                self.store.announce_peer(
                    *info_hash,
                    SocketAddr::new(from.ip(), port),
                    name.as_deref(),
                    *seed,
                    now,
                );
            }
            Query::SampleInfohashes { target } => {
                reply.samples = Some(self.store.sample(now, rng));
                self.nodes_for(target, &q.want, from, foreign, &mut reply);
            }
            Query::Get { target } => {
                // BEP 44 items are not stored: nodes and a token, like
                // libtorrent answers when it holds no item.
                reply.token = Some(self.tokens.generate(from.ip(), target).to_vec());
                self.nodes_for(target, &q.want, from, foreign, &mut reply);
            }
            Query::Unknown { target, .. } => match target {
                Some(t) => self.nodes_for(t, &q.want, from, foreign, &mut reply),
                None => {
                    self.reply_error(
                        from,
                        &q.tid,
                        code::PROTOCOL,
                        b"unknown message",
                        Some((self.id, from)),
                    );
                    return;
                }
            },
        }
        let payload = krpc::encode_response(&q.tid, from, &reply, self.cfg.version.as_deref());
        self.stats.messages_out += 1;
        self.actions.push_back(Action::Send { to: from, payload });
    }

    fn take_outstanding(&mut self, from: SocketAddr, tid: &[u8]) -> Option<Outstanding> {
        if tid.len() != 2 {
            return None;
        }
        let tid = u16::from_be_bytes([tid[0], tid[1]]);
        self.outstanding.remove(&(tid, from))
    }

    fn on_response(&mut self, from: SocketAddr, r: ResponseMsg, now: Instant, rng: &mut dyn Rng) {
        let Some(o) = self.take_outstanding(from, &r.tid) else {
            return;
        };
        if let Some(ip) = r.ip
            && !is_local(from.ip())
        {
            self.actions.push_back(Action::ExternalIp {
                ip: ip.ip(),
                from: from.ip(),
            });
        }
        let rtt = now
            .saturating_duration_since(o.sent)
            .as_millis()
            .min(0xfffe) as u16;
        let id = r.reply.id;
        // Nodes in the reply: heard about.
        for (nid, addr) in r.reply.nodes.iter().chain(r.reply.nodes6.iter()) {
            self.table.heard_about(*nid, *addr, now);
        }
        match o.purpose {
            Purpose::Lookup(lid) => {
                let mut deliver: Option<Vec<SocketAddr>> = None;
                if let Some(l) = self.lookups.get_mut(&lid) {
                    // The candidate we queried (by id, else by address for
                    // routers whose id we did not know).
                    let pos = o.id.and_then(|x| l.position(&x)).or_else(|| {
                        l.results
                            .iter()
                            .position(|c| c.addr == from && c.queried && !c.alive)
                    });
                    if let Some(i) = pos {
                        let c = &mut l.results[i];
                        if c.no_id {
                            c.id = id;
                            c.no_id = false;
                        }
                        c.alive = true;
                        if c.short_timeout {
                            l.branch_factor -= 1;
                        }
                    }
                    l.responses += 1;
                    l.invoke_count -= 1;
                    if let Some(t) = &r.reply.token {
                        l.tokens.insert(id, t.clone());
                    }
                    if !r.reply.values.is_empty() && l.kind == LookupKind::GetPeers {
                        deliver = Some(r.reply.values.clone());
                    }
                    let restrict = self.cfg.restrict_search_ips;
                    for (nid, addr) in r.reply.nodes.iter().chain(r.reply.nodes6.iter()) {
                        if addr.is_ipv6() == self.v6 {
                            l.add_entry(*nid, *addr, false, restrict, rng);
                        }
                    }
                    if let Some(peers) = deliver {
                        let info_hash = l.target;
                        self.actions.push_back(Action::Peers {
                            lookup: lid,
                            info_hash,
                            peers,
                        });
                    }
                }
                self.table.node_seen(id, from, rtt, now);
                self.drive_lookup(lid, now, rng);
            }
            Purpose::Announce(lid) => {
                self.table.node_seen(id, from, rtt, now);
                if let Some(l) = self.lookups.get_mut(&lid) {
                    l.announces_pending = l.announces_pending.saturating_sub(1);
                }
                self.drive_lookup(lid, now, rng);
            }
            Purpose::Probe => {
                self.table.node_seen(id, from, rtt, now);
            }
        }
    }

    fn on_error(&mut self, from: SocketAddr, e: ErrorMsg, now: Instant, rng: &mut dyn Rng) {
        let Some(o) = self.take_outstanding(from, &e.tid) else {
            return;
        };
        tracing::debug!(%from, code = e.code, msg = %String::from_utf8_lossy(&e.message), "dht error reply");
        self.on_failure(o, now, rng);
    }

    /// Live nodes for persistence (deepest bucket first).
    pub fn saved_nodes(&self) -> Vec<SocketAddr> {
        self.table
            .live_nodes()
            .into_iter()
            .map(|n| n.addr)
            .collect()
    }

    /// Whether the table has a single live node.
    pub fn has_nodes(&self) -> bool {
        !self.table.is_empty()
    }

    /// The closest known nodes to `target` (diagnostics).
    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<NodeEntry> {
        self.table.find_node(target, true, count)
    }
}
