// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! A simulated network of `Node`s: datagrams are routed between nodes by
//! address, time is a counter. Exercises bootstrap, lookups, announces,
//! timeouts and refresh without a socket.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use dht::krpc::{Message, Query};
use dht::{Action, Config, LookupId, Node, NodeId};
use profile::Rng;

struct Lcg(u64);
impl Rng for Lcg {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
    }
}

/// Node `n` lives at `10.<n>.0.1:6881` (its own /24, like the lab).
fn addr(n: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4([10, n, 0, 1].into()), 6881)
}

struct Net {
    nodes: HashMap<SocketAddr, Node>,
    /// Addresses that never answer.
    dead: HashSet<SocketAddr>,
    now: Instant,
    rng: Lcg,
    /// Every datagram delivered: (from, to, decoded).
    log: Vec<(SocketAddr, SocketAddr, Message)>,
    events: Vec<(SocketAddr, Action)>,
}

impl Net {
    fn new(n: u8, version: Option<Vec<u8>>) -> Net {
        let now = Instant::now();
        let mut rng = Lcg(99);
        let mut nodes = HashMap::new();
        for i in 1..=n {
            let cfg = Config {
                version: version.clone(),
                ..Config::default()
            };
            nodes.insert(addr(i), Node::new(cfg, false, now, &mut rng));
        }
        Net {
            nodes,
            dead: HashSet::new(),
            now,
            rng,
            log: Vec::new(),
            events: Vec::new(),
        }
    }

    fn node(&mut self, n: u8) -> &mut Node {
        self.nodes.get_mut(&addr(n)).unwrap()
    }

    /// Deliver every queued datagram until nothing moves.
    fn settle(&mut self) {
        for _ in 0..200 {
            let mut moved = false;
            let addrs: Vec<SocketAddr> = self.nodes.keys().copied().collect();
            for a in addrs {
                let mut sends = Vec::new();
                {
                    let node = self.nodes.get_mut(&a).unwrap();
                    while let Some(act) = node.poll_action() {
                        match act {
                            Action::Send { to, payload } => sends.push((to, payload)),
                            other => self.events.push((a, other)),
                        }
                    }
                }
                for (to, payload) in sends {
                    moved = true;
                    if let Ok(m) = dht::krpc::decode(&payload) {
                        self.log.push((a, to, m));
                    }
                    if self.dead.contains(&to) {
                        continue;
                    }
                    if let Some(dst) = self.nodes.get_mut(&to) {
                        dst.incoming(a, &payload, self.now, &mut self.rng, None);
                    }
                }
            }
            if !moved {
                break;
            }
        }
    }

    /// Advance time in 1 s steps, ticking every node and delivering traffic.
    fn advance(&mut self, secs: u64) {
        for _ in 0..secs {
            self.now += Duration::from_secs(1);
            let addrs: Vec<SocketAddr> = self.nodes.keys().copied().collect();
            for a in addrs {
                let now = self.now;
                self.nodes.get_mut(&a).unwrap().tick(now, &mut self.rng);
            }
            self.settle();
        }
    }

    fn events_of(&self, n: u8) -> Vec<&Action> {
        self.events
            .iter()
            .filter(|(a, _)| *a == addr(n))
            .map(|(_, e)| e)
            .collect()
    }

    fn queries_from_to(&self, from: u8, to: u8) -> Vec<&Query> {
        self.log
            .iter()
            .filter(|(f, t, _)| *f == addr(from) && *t == addr(to))
            .filter_map(|(_, _, m)| match m {
                Message::Query(q) => Some(&q.query),
                _ => None,
            })
            .collect()
    }
}

/// Bring up a small network: node 1 is the router everybody bootstraps from.
/// A querier is only *heard about* by the router (a replacement until it
/// answers a refresh probe, one every 5 s), so time passes between joins —
/// as in libtorrent, a cold router hands out nobody it has not pinged.
fn small_network(n: u8) -> Net {
    let mut net = Net::new(n, Some(b"UR\x00\x04".to_vec()));
    for i in 2..=n {
        let now = net.now;
        net.node(i).add_router(addr(1));
        net.node(i).bootstrap(now, &mut Lcg(u64::from(i)));
        net.settle();
        net.advance(6);
    }
    net
}

#[test]
fn bootstrap_learns_the_network_and_marks_router_queries() {
    let mut net = small_network(6);
    // Every node knows the others that bootstrapped before it (and the
    // router knows everyone: they all queried it).
    let (nodes, _, _) = net.node(1).table().size();
    assert_eq!(nodes, 5, "router table");
    let (nodes6, _, _) = net.node(6).table().size();
    assert!(nodes6 >= 3, "late joiner learned {nodes6} nodes");
    // Routers are never table entries.
    assert!(
        net.node(6)
            .closest(&NodeId::ZERO, 50)
            .iter()
            .all(|e| e.addr != addr(1))
    );
    // The first query to the router carries `bs: 1` and our `v`.
    let first = net
        .log
        .iter()
        .find(|(f, t, _)| *f == addr(2) && *t == addr(1))
        .map(|(_, _, m)| m.clone())
        .unwrap();
    let Message::Query(q) = first else { panic!() };
    assert!(matches!(
        q.query,
        Query::GetPeers {
            bootstrap: true,
            ..
        }
    ));
    assert_eq!(q.version.as_deref(), Some(&b"UR\x00\x04"[..]));
    assert_eq!(q.tid.len(), 2);
    // Bootstrap completion was reported.
    assert!(
        net.events_of(6)
            .iter()
            .any(|e| matches!(e, Action::Bootstrapped { nodes } if *nodes > 0))
    );
}

#[test]
fn announce_then_lookup_finds_the_peer() {
    let mut net = small_network(6);
    let ih = NodeId([0xab; 20]);
    let rng_seed = Lcg(7);
    let mut rng = rng_seed;
    let now = net.now;
    let lookup = net.node(2).announce(ih, 51413, false, false, now, &mut rng);
    net.settle();
    let done = net
        .events_of(2)
        .into_iter()
        .find(|e| matches!(e, Action::LookupDone { lookup: l, .. } if *l == lookup))
        .cloned()
        .unwrap();
    let Action::LookupDone { announced, .. } = done else {
        panic!()
    };
    assert!(announced >= 3, "announced to {announced} nodes");
    // announce_peer went out with our port and seed: 0; the router (node 1)
    // is never announced to (not a table node), the others may be.
    assert!(
        net.queries_from_to(2, 1)
            .iter()
            .all(|q| !matches!(q, Query::AnnouncePeer { .. }))
    );
    let announce = net
        .log
        .iter()
        .find_map(|(f, _, m)| match m {
            Message::Query(q) if *f == addr(2) && matches!(q.query, Query::AnnouncePeer { .. }) => {
                Some(q.query.clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(matches!(
        announce,
        Query::AnnouncePeer {
            port: 51413,
            seed: false,
            implied_port: false,
            ..
        }
    ));
    // A fresh node looks the torrent up and gets node 2's endpoint.
    let now = net.now;
    let l2 = net.node(6).get_peers(ih, false, now, &mut rng);
    net.settle();
    let peers: Vec<SocketAddr> = net
        .events_of(6)
        .into_iter()
        .filter_map(|e| match e {
            Action::Peers { lookup, peers, .. } if *lookup == l2 => Some(peers.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(
        peers.contains(&SocketAddr::new(addr(2).ip(), 51413)),
        "{peers:?}"
    );
    // A seed's lookup asks for `noseed` and announces `seed: 1`.
    let now = net.now;
    net.node(3).announce(ih, 1, true, false, now, &mut rng);
    net.settle();
    assert!(net.log.iter().any(|(f, _, m)| *f == addr(3)
        && matches!(m, Message::Query(q) if matches!(q.query, Query::GetPeers { noseed: true, .. }))));
    assert!(net.log.iter().any(|(f, _, m)| *f == addr(3)
        && matches!(m, Message::Query(q) if matches!(q.query, Query::AnnouncePeer { seed: true, .. }))));
}

#[test]
fn dead_nodes_time_out_and_the_lookup_still_completes() {
    let mut net = small_network(6);
    net.dead.insert(addr(4));
    net.dead.insert(addr(5));
    let ih = NodeId([0x11; 20]);
    let now = net.now;
    let mut rng = Lcg(3);
    let l = net.node(2).get_peers(ih, false, now, &mut rng);
    net.settle();
    // Not done yet if a dead node was among the closest; time passes.
    net.advance(20);
    let done = net
        .events_of(2)
        .into_iter()
        .any(|e| matches!(e, Action::LookupDone { lookup, .. } if *lookup == l));
    assert!(done, "lookup never finished");
    assert_eq!(net.node(2).stats().lookups, 0);
}

#[test]
fn refresh_probes_every_five_seconds_and_tokens_gate_announces() {
    let mut net = small_network(4);
    let before = net.log.len();
    net.advance(11);
    let probes = net.log.len() - before;
    assert!(
        probes >= 2,
        "expected refresh traffic, saw {probes} datagrams"
    );
    // A forged announce with a bad token is refused with libtorrent's error.
    let bad = dht::krpc::encode_query(&dht::krpc::QueryMsg {
        tid: vec![1, 2],
        id: NodeId([5; 20]),
        query: Query::AnnouncePeer {
            info_hash: NodeId([1; 20]),
            port: 1,
            token: b"nope".to_vec(),
            seed: false,
            implied_port: false,
            name: None,
        },
        read_only: false,
        want: Vec::new(),
        version: None,
    });
    let from: SocketAddr = "10.200.0.1:7000".parse().unwrap();
    let now = net.now;
    let mut rng = Lcg(1);
    let node = net.node(1);
    node.incoming(from, &bad, now, &mut rng, None);
    let Some(Action::Send { to, payload }) = node.poll_action() else {
        panic!("no reply")
    };
    assert_eq!(to, from);
    let Message::Error(e) = dht::krpc::decode(&payload).unwrap() else {
        panic!()
    };
    assert_eq!(e.code, 203);
    assert_eq!(e.message, b"invalid token");
    assert_eq!(e.ip, Some(from));
    // Garbage and floods are dropped silently.
    node.incoming(from, b"li1ee", now, &mut rng, None);
    assert!(node.poll_action().is_none());
    let ping = dht::krpc::encode_query(&dht::krpc::QueryMsg {
        tid: vec![9, 9],
        id: NodeId([6; 20]),
        query: Query::Ping,
        read_only: false,
        want: Vec::new(),
        version: None,
    });
    let flooder: SocketAddr = "10.201.0.1:7000".parse().unwrap();
    let mut answered = 0;
    for _ in 0..200 {
        node.incoming(flooder, &ping, now, &mut rng, None);
        if node.poll_action().is_some() {
            answered += 1;
        }
    }
    assert!(answered < 60, "flood was answered {answered} times");
}

#[test]
fn lookup_ids_and_wakeups_are_sane() {
    let mut net = small_network(3);
    let now = net.now;
    let mut rng = Lcg(4);
    let a = net.node(2).get_peers(NodeId([1; 20]), false, now, &mut rng);
    let b = net.node(2).get_peers(NodeId([2; 20]), false, now, &mut rng);
    assert_ne!(a, b);
    assert!(net.node(2).next_wakeup(now) >= now);
    assert!(net.node(2).next_wakeup(now) <= now + Duration::from_secs(5));
    let _: LookupId = a;
}
