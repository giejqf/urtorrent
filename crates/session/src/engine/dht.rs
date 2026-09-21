// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// The announce round-robin follows libtorrent-rasterbar's session_impl.cpp
// (`on_dht_announce`, `update_dht_announce_interval`) (BSD-3-Clause),
// Copyright (c) Arvid Norberg and contributors; see NOTICE.

//! The DHT (BEP 5) in the engine: one sans-IO [`dht::Node`] per listen
//! family, fed by the UDP demultiplexer and the session ticker; peers it
//! finds go to torrents, its address votes to the external-address voter,
//! its announces run round-robin over the (non-private) torrents.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use dht::{Action, LookupId, Node, NodeId};

use super::Ctx;
use super::external_ip::Source;
use super::rng::RngRef;
use crate::api::{Event, PeerSource, TorrentId};

/// Every torrent is announced once per this interval (libtorrent
/// `dht_announce_interval`), spread evenly.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// A newly added (or just finished) torrent is announced within this long.
const FIRST_ANNOUNCE_WITHIN: Duration = Duration::from_secs(4);

struct Family {
    v6: bool,
    node: Node,
    /// Lookups we started, by torrent.
    lookups: HashMap<LookupId, TorrentId>,
}

/// The DHT service.
pub struct Dht {
    families: RefCell<Vec<Family>>,
    /// Our UDP port (the listen port).
    port: u16,
    /// Bootstrap routers as configured (`host:port`).
    routers: Vec<String>,
    /// Torrents to announce soon (new / finished), then the round-robin.
    pending: RefCell<VecDeque<TorrentId>>,
    next_announce: RefCell<Instant>,
    next_index: RefCell<usize>,
    started: RefCell<bool>,
}

impl Dht {
    /// Create the nodes (one per listen family). `state` restores saved
    /// ids / nodes (see [`Dht::state`]).
    pub fn new(
        ctx_cfg: &super::EngineConfig,
        v4: bool,
        v6: bool,
        port: u16,
        state: Option<&[u8]>,
        rng: &super::rng::Rng,
        now: Instant,
    ) -> Dht {
        let cfg = dht::Config {
            version: Some(ctx_cfg.profile.dht.version.to_vec()),
            read_only: ctx_cfg.dht_read_only,
            restrict_search_ips: true,
        };
        let saved = state.and_then(SavedState::decode);
        let mut r = RngRef(rng);
        let mut families = Vec::new();
        for is_v6 in [false, true] {
            if (is_v6 && !v6) || (!is_v6 && !v4) {
                continue;
            }
            let saved_id = saved
                .as_ref()
                .and_then(|s| if is_v6 { s.id6 } else { s.id4 });
            let node = match saved_id {
                Some(id) => Node::with_id(cfg.clone(), is_v6, id, now, &mut r),
                None => Node::new(cfg.clone(), is_v6, now, &mut r),
            };
            families.push(Family {
                v6: is_v6,
                node,
                lookups: HashMap::new(),
            });
        }
        let routers = match &ctx_cfg.dht_bootstrap_nodes {
            Some(list) => list.clone(),
            None => ctx_cfg
                .profile
                .dht
                .bootstrap_nodes
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        };
        let d = Dht {
            families: RefCell::new(families),
            port,
            routers,
            pending: RefCell::new(VecDeque::new()),
            next_announce: RefCell::new(now),
            next_index: RefCell::new(0),
            started: RefCell::new(false),
        };
        if let Some(s) = saved {
            let mut fams = d.families.borrow_mut();
            for f in fams.iter_mut() {
                let nodes = if f.v6 { &s.nodes6 } else { &s.nodes4 };
                for n in nodes {
                    f.node.add_node(*n, now, &mut r);
                }
            }
        }
        d
    }

    /// Resolve the routers (blocking DNS on the helper thread) and bootstrap.
    pub async fn start(self: &Rc<Self>, ctx: &Rc<Ctx>) {
        if *self.started.borrow() {
            return;
        }
        *self.started.borrow_mut() = true;
        let mut resolved: Vec<SocketAddr> = Vec::new();
        for r in &self.routers {
            let (host, port) = match r.rsplit_once(':') {
                Some((h, p)) => (h.trim_matches(['[', ']']), p.parse::<u16>().unwrap_or(6881)),
                None => (r.as_str(), 6881),
            };
            match ctx.dns.resolve(host, port).await {
                Ok(addrs) => resolved.extend(addrs),
                Err(e) => tracing::debug!(router = r, "dht router did not resolve: {e}"),
            }
        }
        let now = Instant::now();
        {
            let mut fams = self.families.borrow_mut();
            let mut rng = RngRef(&ctx.rng);
            for f in fams.iter_mut() {
                for a in &resolved {
                    f.node.add_router(*a);
                }
                f.node.bootstrap(now, &mut rng);
            }
        }
        self.drain(ctx);
    }

    /// Our DHT port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// A datagram from the listen port's UDP socket that looks like KRPC.
    pub fn incoming(&self, ctx: &Rc<Ctx>, from: SocketAddr, pkt: &[u8], v6: bool) {
        let now = Instant::now();
        {
            let mut fams = self.families.borrow_mut();
            let mut rng = RngRef(&ctx.rng);
            // The other family's table answers `want` for the foreign family.
            let Some(i) = fams.iter().position(|f| f.v6 == v6) else {
                return;
            };
            let (head, tail) = fams.split_at_mut(i);
            let Some((own, rest)) = tail.split_first_mut() else {
                return;
            };
            let foreign = head
                .iter()
                .chain(rest.iter())
                .find(|f| f.v6 != v6)
                .map(|f| f.node.table());
            own.node.incoming(from, pkt, now, &mut rng, foreign);
        }
        self.drain(ctx);
    }

    /// A peer told us its DHT port (BEP 5 `port` message).
    pub fn add_node(&self, ctx: &Rc<Ctx>, addr: SocketAddr) {
        let now = Instant::now();
        {
            let mut fams = self.families.borrow_mut();
            let mut rng = RngRef(&ctx.rng);
            for f in fams.iter_mut() {
                if f.v6 == addr.is_ipv6() {
                    f.node.add_node(addr, now, &mut rng);
                }
            }
        }
        self.drain(ctx);
    }

    /// A torrent joined or finished: announce it soon.
    pub fn announce_soon(&self, id: TorrentId) {
        let mut p = self.pending.borrow_mut();
        if !p.contains(&id) {
            p.push_back(id);
        }
        let mut next = self.next_announce.borrow_mut();
        let soon = Instant::now() + FIRST_ANNOUNCE_WITHIN;
        if *next > soon {
            *next = soon;
        }
    }

    /// Our external address for a family became known: adopt a BEP 42 id.
    pub fn external_ip(&self, ctx: &Ctx, ip: IpAddr) {
        {
            let mut fams = self.families.borrow_mut();
            let mut rng = RngRef(&ctx.rng);
            for f in fams.iter_mut() {
                if f.v6 == ip.is_ipv6() && f.node.set_external_ip(ip, &mut rng) {
                    tracing::info!(%ip, id = %f.node.id().hex(), "dht node id follows the external address (BEP 42)");
                }
            }
        }
    }

    /// The once-a-second tick: node timers and the announce round-robin.
    pub fn tick(&self, ctx: &Rc<Ctx>, now: Instant) {
        {
            let mut fams = self.families.borrow_mut();
            let mut rng = RngRef(&ctx.rng);
            for f in fams.iter_mut() {
                f.node.tick(now, &mut rng);
            }
        }
        if *self.started.borrow() && now >= *self.next_announce.borrow() {
            self.announce_next(ctx, now);
        }
        self.drain(ctx);
    }

    /// libtorrent `on_dht_announce`: pending torrents first, otherwise the
    /// next torrent in id order; the delay spreads every torrent's announce
    /// over the interval.
    fn announce_next(&self, ctx: &Rc<Ctx>, now: Instant) {
        let mut ids: Vec<TorrentId> = ctx.torrents.borrow().keys().copied().collect();
        ids.sort();
        let n = ids.len().max(1);
        let mut delay = ANNOUNCE_INTERVAL / n as u32;
        if delay < Duration::from_secs(1) {
            delay = Duration::from_secs(1);
        }
        let pending_left;
        let pick = {
            let mut p = self.pending.borrow_mut();
            let mut pick = None;
            while let Some(id) = p.pop_front() {
                if ids.contains(&id) {
                    pick = Some(id);
                    break;
                }
            }
            pending_left = !p.is_empty();
            pick
        };
        if pending_left {
            delay = delay.min(FIRST_ANNOUNCE_WITHIN);
        }
        *self.next_announce.borrow_mut() = now + delay;
        let id = match pick {
            Some(id) => id,
            None => {
                if ids.is_empty() {
                    return;
                }
                let mut i = self.next_index.borrow_mut();
                *i %= ids.len();
                let id = ids[*i];
                *i += 1;
                id
            }
        };
        self.announce_torrent(ctx, id, now);
    }

    fn announce_torrent(&self, ctx: &Rc<Ctx>, id: TorrentId, now: Instant) {
        let Some(t) = ctx.torrent(id) else { return };
        let (info_hash, seed) = {
            let t = t.borrow();
            // Never for private torrents (BEP 27) or paused ones, nor while
            // the files are being checked; a magnet link without metadata
            // announces (as a leecher) so the lookup finds the peers to
            // fetch it from (BEP 9: "SHOULD use the DHT"), as libtorrent
            // does. `seed` only for a true seed.
            if t.private || !t.is_running() || t.checking {
                return;
            }
            let seed = t.has_metadata() && t.picker.is_seed();
            (NodeId(t.info_hash()), seed)
        };
        let mut fams = self.families.borrow_mut();
        let mut rng = RngRef(&ctx.rng);
        // `implied_port` whenever incoming uTP is on (libtorrent: the DHT node
        // then records our UDP source port, the one uTP is reachable on).
        let implied_port = ctx.transports().utp_incoming() && ctx.utp.is_some();
        for f in fams.iter_mut() {
            let l = f
                .node
                .announce(info_hash, self.port, seed, implied_port, now, &mut rng);
            f.lookups.insert(l, id);
        }
    }

    /// Hand every queued node action to the engine.
    fn drain(&self, ctx: &Rc<Ctx>) {
        let mut sends: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let mut peers: Vec<(TorrentId, Vec<SocketAddr>)> = Vec::new();
        let mut votes: Vec<(bool, IpAddr, IpAddr)> = Vec::new();
        let mut events: Vec<Event> = Vec::new();
        {
            let mut fams = self.families.borrow_mut();
            for f in fams.iter_mut() {
                while let Some(a) = f.node.poll_action() {
                    match a {
                        Action::Send { to, payload } => sends.push((to, payload)),
                        Action::Peers {
                            lookup, peers: p, ..
                        } => {
                            if let Some(id) = f.lookups.get(&lookup) {
                                peers.push((*id, p));
                            }
                        }
                        Action::LookupDone { lookup, .. } => {
                            f.lookups.remove(&lookup);
                        }
                        Action::ExternalIp { ip, from } => votes.push((f.v6, ip, from)),
                        Action::Bootstrapped { nodes } => {
                            tracing::info!(nodes, v6 = f.v6, "dht bootstrapped");
                            events.push(Event::DhtBootstrapped { nodes });
                        }
                    }
                }
            }
        }
        for (to, payload) in sends {
            ctx.udp.send_raw(to, payload);
        }
        for (id, list) in peers {
            if let Some(t) = ctx.torrent(id) {
                let added = t.borrow_mut().add_candidates(ctx, &list, PeerSource::Dht);
                if added > 0 {
                    super::torrent::on_new_candidates(ctx, &t);
                }
                events.push(Event::DhtPeers {
                    id,
                    peers: list.len(),
                });
            }
        }
        for (v6, ip, from) in votes {
            let local = if v6 {
                ctx.cfg.listen_v6.map(IpAddr::V6)
            } else {
                ctx.cfg.listen_v4.map(IpAddr::V4)
            };
            if let Some(local) = local {
                ctx.cast_external_vote(local, ip, Source::Dht, from);
            }
        }
        for e in events {
            ctx.emit(e);
        }
    }

    /// Counters over both families.
    pub fn stats(&self) -> dht::Stats {
        let fams = self.families.borrow();
        let mut s = dht::Stats::default();
        for f in fams.iter() {
            let t = f.node.stats();
            s.nodes += t.nodes;
            s.replacements += t.replacements;
            s.outstanding += t.outstanding;
            s.lookups += t.lookups;
            s.torrents += t.torrents;
            s.peers += t.peers;
            s.messages_in += t.messages_in;
            s.messages_out += t.messages_out;
            s.dropped += t.dropped;
        }
        s
    }

    /// Persistable state: node ids and live nodes (bencoded).
    pub fn state(&self) -> Vec<u8> {
        let fams = self.families.borrow();
        let mut s = SavedState::default();
        for f in fams.iter() {
            if f.v6 {
                s.id6 = Some(f.node.id());
                s.nodes6 = f.node.saved_nodes();
            } else {
                s.id4 = Some(f.node.id());
                s.nodes4 = f.node.saved_nodes();
            }
        }
        s.encode()
    }
}

/// `{ "id4": 20 bytes, "id6": 20 bytes, "nodes": compact v4 endpoints,
/// "nodes6": compact v6 endpoints, "v": 1 }`.
#[derive(Debug, Default)]
struct SavedState {
    id4: Option<NodeId>,
    id6: Option<NodeId>,
    nodes4: Vec<SocketAddr>,
    nodes6: Vec<SocketAddr>,
}

impl SavedState {
    fn encode(&self) -> Vec<u8> {
        use bencode::Value;
        let mut n4 = Vec::new();
        for a in &self.nodes4 {
            dht::krpc::compact_endpoint(*a, &mut n4);
        }
        let mut n6 = Vec::new();
        for a in &self.nodes6 {
            dht::krpc::compact_endpoint(*a, &mut n6);
        }
        let mut entries: Vec<(&[u8], Value<'_>)> = Vec::new();
        if let Some(id) = &self.id4 {
            entries.push((b"id4", Value::Bytes(&id.0)));
        }
        if let Some(id) = &self.id6 {
            entries.push((b"id6", Value::Bytes(&id.0)));
        }
        entries.push((b"nodes", Value::Bytes(&n4)));
        entries.push((b"nodes6", Value::Bytes(&n6)));
        entries.push((b"v", Value::Int(1)));
        bencode::to_bytes(&Value::Dict { entries, raw: b"" })
    }

    fn decode(bytes: &[u8]) -> Option<SavedState> {
        use bencode::Value;
        let v = bencode::from_bytes(bytes).ok()?;
        let id = |k: &str| -> Option<NodeId> {
            let b = v.get_str(k)?.as_bytes()?;
            (b.len() == 20).then(|| {
                let mut id = [0u8; 20];
                id.copy_from_slice(b);
                NodeId(id)
            })
        };
        let eps = |k: &str, step: usize| -> Vec<SocketAddr> {
            v.get_str(k)
                .and_then(Value::as_bytes)
                .map(|b| {
                    b.chunks_exact(step)
                        .filter_map(dht::krpc::parse_endpoint)
                        .take(2000)
                        .collect()
                })
                .unwrap_or_default()
        };
        Some(SavedState {
            id4: id("id4"),
            id6: id("id6"),
            nodes4: eps("nodes", 6),
            nodes6: eps("nodes6", 18),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_state_round_trips() {
        let s = SavedState {
            id4: Some(NodeId([1; 20])),
            id6: None,
            nodes4: vec![
                "10.0.0.1:6881".parse().unwrap(),
                "10.0.0.2:1".parse().unwrap(),
            ],
            nodes6: vec!["[fd00::1]:6881".parse().unwrap()],
        };
        let back = SavedState::decode(&s.encode()).unwrap();
        assert_eq!(back.id4, s.id4);
        assert_eq!(back.id6, None);
        assert_eq!(back.nodes4, s.nodes4);
        assert_eq!(back.nodes6, s.nodes6);
        assert!(SavedState::decode(b"garbage").is_none());
    }
}
