// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Two connection tables joined by a simulated network (latency, loss,
//! reordering): data integrity in both directions, the close handshake, and
//! the wire shapes the oracle capture showed (SYN fields, first packets,
//! MTU probe sizes, selective acks).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use profile::Rng;
use utp::{Clock, Config, Header, Incoming, Key, Manager, PacketType, State};

struct TestRng(u32);
impl Rng for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.0
    }
}

struct InFlight {
    at: Instant,
    from: SocketAddr,
    to: SocketAddr,
    data: Vec<u8>,
}

/// Every packet seen by the network, for shape assertions.
#[derive(Clone, Debug)]
struct Seen {
    from: SocketAddr,
    header: Header,
    len: usize,
    payload_len: usize,
    sack_len: Option<usize>,
}

struct Net {
    now: Instant,
    a_addr: SocketAddr,
    b_addr: SocketAddr,
    a: Manager,
    b: Manager,
    wire: Vec<InFlight>,
    latency: Duration,
    /// Drop one in `loss` packets (0 = none).
    loss: u32,
    /// Reorder one in `reorder` packets by delaying it (0 = none).
    reorder: u32,
    rng: TestRng,
    seen: Vec<Seen>,
    counter: u32,
}

impl Net {
    fn new(v6: bool, latency_ms: u64) -> Net {
        Net::with_config(v6, latency_ms, Config::default())
    }

    fn with_config(v6: bool, latency_ms: u64, cfg: Config) -> Net {
        let now = Instant::now();
        let clock = Clock::new(now, 5_000_000);
        let (a_addr, b_addr): (SocketAddr, SocketAddr) = if v6 {
            (
                "[fd77:1:a::1]:6881".parse().unwrap(),
                "[fd77:1:b::1]:6881".parse().unwrap(),
            )
        } else {
            (
                "10.1.10.1:6881".parse().unwrap(),
                "10.1.11.1:6881".parse().unwrap(),
            )
        };
        Net {
            now,
            a_addr,
            b_addr,
            a: Manager::new(cfg.clone(), clock, true, 200),
            b: Manager::new(cfg, clock, true, 200),
            wire: Vec::new(),
            latency: Duration::from_millis(latency_ms),
            loss: 0,
            reorder: 0,
            rng: TestRng(99),
            seen: Vec::new(),
            counter: 0,
        }
    }

    fn collect(&mut self) {
        for (side, addr) in [(0, self.a_addr), (1, self.b_addr)] {
            let m = if side == 0 { &mut self.a } else { &mut self.b };
            for (to, o) in m.poll_outgoing() {
                let h = Header::parse(&o.data).unwrap();
                let mut sack_len = None;
                let off = utp::header::walk_extensions(&h, &o.data, |t, b| {
                    if t == 1 {
                        sack_len = Some(b.len());
                    }
                })
                .unwrap();
                self.seen.push(Seen {
                    from: addr,
                    header: h,
                    len: o.data.len(),
                    payload_len: o.data.len() - off,
                    sack_len,
                });
                self.counter += 1;
                // Pseudo-random (not periodic: a fixed period can align with
                // retransmissions and drop the same packet every time).
                let roll = self
                    .counter
                    .wrapping_mul(2_654_435_761)
                    .rotate_left(13)
                    .wrapping_mul(0x9E37_79B9);
                if self.loss != 0 && roll.is_multiple_of(self.loss) && h.ty == PacketType::Data {
                    continue;
                }
                let mut at = self.now + self.latency;
                if self.reorder != 0 && (roll >> 8).is_multiple_of(self.reorder) {
                    at += self.latency * 2;
                }
                self.wire.push(InFlight {
                    at,
                    from: addr,
                    to,
                    data: o.data,
                });
            }
        }
    }

    /// Deliver everything due, then run the drained hooks.
    fn deliver(&mut self) {
        let now = self.now;
        self.wire.sort_by_key(|p| p.at);
        let mut due = Vec::new();
        let mut rest = Vec::new();
        for p in self.wire.drain(..) {
            if p.at <= now {
                due.push(p);
            } else {
                rest.push(p);
            }
        }
        self.wire = rest;
        let (mut a_touched, mut b_touched) = (false, false);
        for p in due {
            if p.to == self.a_addr {
                self.a.incoming(p.from, &p.data, now, &mut self.rng);
                a_touched = true;
            } else {
                self.b.incoming(p.from, &p.data, now, &mut self.rng);
                b_touched = true;
            }
        }
        if a_touched {
            self.a.drained(now);
        }
        if b_touched {
            self.b.drained(now);
        }
    }

    fn step(&mut self, dt: Duration) {
        self.deliver();
        self.a.tick(self.now);
        self.b.tick(self.now);
        self.collect();
        self.now += dt;
    }
}

fn connect(net: &mut Net) -> (Key, Key) {
    let ka = net.a.connect(net.b_addr, net.now, &mut net.rng);
    let mut kb = None;
    for _ in 0..100 {
        net.step(Duration::from_millis(1));
        if let Some(k) = net.b.take_new_connections().pop() {
            kb = Some(k);
        }
        if net.a.get(ka).map(utp::Socket::state) == Some(State::Connected) && kb.is_some() {
            break;
        }
    }
    let kb = kb.expect("B accepted");
    assert_eq!(net.a.get(ka).unwrap().state(), State::Connected);
    assert_eq!(net.b.get(kb).unwrap().state(), State::Connected);
    (ka, kb)
}

/// Push `total` pseudo-random bytes from `from` to `to`; returns the bytes
/// received at `to`.
fn transfer(
    net: &mut Net,
    from: (bool, Key),
    to: (bool, Key),
    total: usize,
    max_ms: u64,
) -> Vec<u8> {
    let data: Vec<u8> = (0..total).map(|i| (i * 7 + i / 251) as u8).collect();
    let mut sent = 0usize;
    let mut got = Vec::new();
    let deadline = net.now + Duration::from_millis(max_ms);
    while got.len() < total {
        assert!(
            net.now < deadline,
            "transfer stalled at {} / {total}",
            got.len()
        );
        {
            let m = if from.0 { &mut net.a } else { &mut net.b };
            let s = m.get_mut(from.1).unwrap();
            while sent < total && s.write_buffer_size() < 256 * 1024 {
                let n = (total - sent).min(16 * 1024);
                s.write(data[sent..sent + n].to_vec(), net.now);
                sent += n;
            }
        }
        net.step(Duration::from_millis(1));
        let m = if to.0 { &mut net.a } else { &mut net.b };
        let s = m.get_mut(to.1).unwrap();
        while let Some(c) = s.read() {
            got.extend_from_slice(&c);
        }
    }
    assert_eq!(got, data);
    got
}

#[test]
fn handshake_shapes_match_the_capture() {
    let mut net = Net::new(false, 1);
    let (ka, kb) = connect(&mut net);
    // A wrote nothing yet: SYN, SYN-ACK (ST_STATE) only.
    let syn = net.seen[0].clone();
    assert_eq!(syn.header.ty, PacketType::Syn);
    assert_eq!(syn.header.wnd_size, 0);
    assert_eq!(syn.header.ack_nr, 0);
    assert_eq!(syn.header.extension, 0);
    assert_eq!(syn.len, 20);
    assert_eq!(syn.header.connection_id, ka.0); // our recv id
    let ack = net.seen[1].clone();
    assert_eq!(ack.from, net.b_addr);
    assert_eq!(ack.header.ty, PacketType::State);
    assert_eq!(ack.header.connection_id, syn.header.connection_id);
    assert_eq!(ack.header.ack_nr, syn.header.seq_nr);
    assert_eq!(ack.header.wnd_size, 1024 * 1024);
    assert_eq!(kb.0, syn.header.connection_id.wrapping_add(1));
    assert_eq!(net.seen.len(), 2);
    // A sends a 68-byte handshake: ST_DATA with id = recv_id + 1 and ack =
    // B's seq - 1 (a STATE consumes no sequence number).
    net.a.get_mut(ka).unwrap().write(vec![0x13; 68], net.now);
    net.step(Duration::from_millis(1));
    let data = net.seen[2].clone();
    assert_eq!(data.from, net.a_addr);
    assert_eq!(data.header.ty, PacketType::Data);
    assert_eq!(
        data.header.connection_id,
        syn.header.connection_id.wrapping_add(1)
    );
    assert_eq!(data.header.seq_nr, syn.header.seq_nr.wrapping_add(1));
    assert_eq!(data.header.ack_nr, ack.header.seq_nr.wrapping_sub(1));
    assert_eq!(data.header.wnd_size, 1024 * 1024);
    assert_eq!(data.payload_len, 68);
    // B acks it with a STATE (nothing to send); the seq is unchanged.
    net.step(Duration::from_millis(1));
    net.step(Duration::from_millis(1));
    let st = net.seen[3].clone();
    assert_eq!(st.from, net.b_addr);
    assert_eq!(st.header.ty, PacketType::State);
    assert_eq!(st.header.seq_nr, ack.header.seq_nr);
    assert_eq!(st.header.ack_nr, data.header.seq_nr);
    let mut b_chunks = Vec::new();
    while let Some(c) = net.b.get_mut(kb).unwrap().read() {
        b_chunks.push(c);
    }
    assert_eq!(b_chunks, vec![vec![0x13; 68]]);
}

#[test]
fn bulk_transfer_probes_the_mtu_like_the_oracle() {
    let mut net = Net::new(false, 1);
    let (ka, kb) = connect(&mut net);
    transfer(&mut net, (true, ka), (false, kb), 4 << 20, 60_000);
    let sizes: BTreeMap<usize, usize> = net
        .seen
        .iter()
        .filter(|s| s.from == net.a_addr && s.header.ty == PacketType::Data)
        .fold(BTreeMap::new(), |mut m, s| {
            *m.entry(s.payload_len).or_default() += 1;
            m
        });
    // The binary search from floor 548 towards ceiling 1472 (UDP payload):
    // payload = mtu - 20; probes at the mid-point, everything else at the
    // floor. Same steps as the capture of libtorrent 2.0.14.
    for want in [
        528, 990, 1221, 1336, 1394, 1423, 1437, 1444, 1448, 1450, 1451,
    ] {
        assert!(
            sizes.contains_key(&want),
            "no {want}-byte payloads: {sizes:?}"
        );
    }
    assert_eq!(*sizes.keys().max().unwrap(), 1451);
    // Once found, the path MTU is used for the bulk of the transfer.
    assert_eq!(
        sizes.iter().max_by_key(|(_, n)| **n).map(|(s, _)| *s),
        Some(1451)
    );
    let largest = net.seen.iter().map(|s| s.len).max().unwrap();
    assert_eq!(largest, 1471);
}

#[test]
fn v6_mtu_ceiling() {
    let mut net = Net::new(true, 1);
    let (ka, kb) = connect(&mut net);
    transfer(&mut net, (true, ka), (false, kb), 4 << 20, 60_000);
    let largest = net.seen.iter().map(|s| s.len).max().unwrap();
    assert_eq!(largest, 1451); // 1500 - 40 - 8 - 1
}

#[test]
fn both_directions_then_close() {
    let mut net = Net::new(false, 2);
    let (ka, kb) = connect(&mut net);
    transfer(&mut net, (true, ka), (false, kb), 300_000, 30_000);
    transfer(&mut net, (false, kb), (true, ka), 200_000, 30_000);
    // A closes with a reason; B sees EOF, reads the reason, closes too.
    net.a.get_mut(ka).unwrap().set_close_reason(6);
    net.a.detach(ka, net.now);
    let mut b_eof = false;
    for _ in 0..200 {
        net.step(Duration::from_millis(1));
        if let Some(s) = net.b.get(kb)
            && s.at_eof()
        {
            b_eof = true;
            assert_eq!(s.incoming_close_reason(), Some(6));
            break;
        }
    }
    assert!(b_eof, "B never saw EOF");
    net.b.detach(kb, net.now);
    // A is gone as soon as its FIN is acked (the table is ticked every
    // step here); B's FIN then goes unanswered and B gives up after the
    // FIN resends (libtorrent lingers up to a tick and would ack it).
    for _ in 0..5000 {
        net.step(Duration::from_millis(1));
        if net.a.is_empty() && net.b.is_empty() {
            break;
        }
    }
    assert!(net.a.is_empty(), "A still holds the socket");
    assert!(net.b.is_empty(), "B still holds the socket");
    // A's FIN carried the close reason extension and had no payload.
    let fins: Vec<&Seen> = net
        .seen
        .iter()
        .filter(|s| s.header.ty == PacketType::Fin)
        .collect();
    assert!(
        fins.len() >= 2,
        "{:?}",
        fins.iter().map(|f| f.from).collect::<Vec<_>>()
    );
    assert_eq!(fins[0].from, net.a_addr);
    assert_eq!(fins[0].header.extension, 3);
    assert_eq!(fins[0].payload_len, 0);
    assert!(fins.iter().any(|f| f.from == net.b_addr));
}

#[test]
fn simultaneous_close_like_two_seeds() {
    let mut net = Net::new(false, 1);
    let (ka, kb) = connect(&mut net);
    transfer(&mut net, (true, ka), (false, kb), 100_000, 30_000);
    net.a.get_mut(ka).unwrap().set_close_reason(6);
    net.b.get_mut(kb).unwrap().set_close_reason(6);
    net.a.detach(ka, net.now);
    net.b.detach(kb, net.now);
    for _ in 0..500 {
        net.step(Duration::from_millis(1));
        if net.a.is_empty() && net.b.is_empty() {
            break;
        }
    }
    assert!(net.a.is_empty() && net.b.is_empty());
    // Exactly one FIN each, each acked by a STATE carrying the close
    // reason (the capture's `fin ext[3]` / `state ext[3]` pairs).
    let tail: Vec<&Seen> = net.seen.iter().rev().take(4).collect();
    let fins = tail
        .iter()
        .filter(|s| s.header.ty == PacketType::Fin)
        .count();
    let states = tail
        .iter()
        .filter(|s| s.header.ty == PacketType::State && s.header.extension == 3)
        .count();
    assert_eq!((fins, states), (2, 2), "{tail:?}");
    assert_eq!(
        net.seen
            .iter()
            .filter(|s| s.header.ty == PacketType::Fin)
            .count(),
        2
    );
}

#[test]
fn survives_loss_and_reordering() {
    let mut net = Net::new(false, 3);
    net.loss = 37;
    net.reorder = 11;
    let (ka, kb) = connect(&mut net);
    transfer(&mut net, (true, ka), (false, kb), 2 << 20, 120_000);
    let sacks: BTreeSet<usize> = net.seen.iter().filter_map(|s| s.sack_len).collect();
    assert!(
        !sacks.is_empty(),
        "reordering never produced a selective ack"
    );
    let st = net.a.get(ka).unwrap().stats();
    assert!(st.resends > 0);
}

#[test]
fn syn_to_a_dead_port_times_out() {
    let mut net = Net::new(false, 1);
    net.b = Manager::new(Config::default(), net.a.clock_for_test(), false, 0);
    let ka = net.a.connect(net.b_addr, net.now, &mut net.rng);
    let mut closed = false;
    for _ in 0..8000 {
        net.step(Duration::from_millis(1));
        let s = net.a.get(ka).unwrap();
        if s.state() == State::Closed {
            closed = true;
            assert_eq!(s.error(), Some(utp::Error::TimedOut));
            break;
        }
    }
    assert!(closed);
    // One SYN, no resend: libtorrent gives up on an unconfirmed peer at the
    // first (3 s) timeout.
    let syns = net
        .seen
        .iter()
        .filter(|s| s.header.ty == PacketType::Syn)
        .count();
    assert_eq!(syns, 1);
    // Detached, it is freed on the next tick.
    net.a.detach(ka, net.now);
    net.a.tick(net.now);
    assert!(net.a.is_empty());
}

#[test]
fn incoming_disabled_ignores_syn() {
    let mut net = Net::new(false, 1);
    net.b = Manager::new(Config::default(), net.a.clock_for_test(), false, 0);
    net.a.connect(net.b_addr, net.now, &mut net.rng);
    net.step(Duration::from_millis(1));
    net.step(Duration::from_millis(1));
    assert!(net.b.is_empty());
    assert_eq!(net.seen.len(), 1);
    let mut rng = TestRng(1);
    // A stray non-SYN packet is ignored without a reset.
    let mut pkt = vec![0x01, 0];
    pkt.extend_from_slice(&[0; 18]);
    assert_eq!(
        net.b.incoming(net.a_addr, &pkt, net.now, &mut rng),
        Incoming::Ignored
    );
    assert!(net.b.poll_outgoing().is_empty());
}

#[test]
fn garbage_never_panics() {
    let mut net = Net::new(false, 1);
    let (ka, kb) = connect(&mut net);
    let mut rng = TestRng(3);
    let mut junk = TestRng(5);
    for _ in 0..5000 {
        let len = (junk.next_u32() % 64) as usize;
        let mut pkt: Vec<u8> = (0..len).map(|_| junk.next_u32() as u8).collect();
        if len >= 4 {
            // Mostly plausible headers aimed at the live connection.
            pkt[0] = (pkt[0] & 0xf0) | 1;
            let id = if junk.next_u32().is_multiple_of(2) {
                ka.0
            } else {
                kb.0
            };
            pkt[2..4].copy_from_slice(&id.to_be_bytes());
        }
        net.a.incoming(net.b_addr, &pkt, net.now, &mut rng);
        net.b.incoming(net.a_addr, &pkt, net.now, &mut rng);
        net.step(Duration::from_millis(1));
    }
    let _ = VecDeque::<u8>::new();
}

/// libtorrent drops payload that arrives in the same receive round as the
/// FIN when the reader was idle; data from an earlier round survives.
#[test]
fn data_in_the_fin_round_is_dropped_like_libtorrent() {
    // Same round: A writes and closes at once.
    let mut net = Net::new(false, 1);
    let (ka, kb) = connect(&mut net);
    net.a.get_mut(ka).unwrap().write(b"have!".to_vec(), net.now);
    net.a.detach(ka, net.now);
    for _ in 0..50 {
        net.step(Duration::from_millis(1));
        if net.b.get(kb).is_some_and(utp::Socket::at_eof) {
            break;
        }
    }
    let b = net.b.get_mut(kb).unwrap();
    assert!(b.at_eof());
    assert_eq!(b.read(), None, "payload delivered alongside the FIN");

    // Separate rounds: the data lands, then the FIN a few rounds later.
    let mut net = Net::new(false, 1);
    let (ka, kb) = connect(&mut net);
    net.a.get_mut(ka).unwrap().write(b"have!".to_vec(), net.now);
    for _ in 0..10 {
        net.step(Duration::from_millis(1));
    }
    net.a.detach(ka, net.now);
    for _ in 0..50 {
        net.step(Duration::from_millis(1));
        if net
            .b
            .get(kb)
            .is_some_and(|s| s.receive_buffer_size() > 0 && s.state() != State::Connected)
            || net.b.get(kb).is_none()
        {
            break;
        }
    }
    let b = net.b.get_mut(kb).unwrap();
    assert_eq!(b.read(), Some(b"have!".to_vec()));
    assert!(b.at_eof());
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(12))]

    /// Any mix of latency, loss and reordering delivers the bytes intact in
    /// both directions and the connection closes cleanly. The resend limit
    /// is raised: with libtorrent's three strikes, heavy random loss kills a
    /// connection legitimately now and then (as it would in libtorrent).
    #[test]
    fn transfers_survive_any_network(
        latency_ms in 1u64..6,
        loss in proptest::option::of(5u32..40),
        reorder in proptest::option::of(3u32..15),
        size in 1usize..200_000,
        v6 in proptest::bool::ANY,
    ) {
        let cfg = Config {
            num_resends: 50,
            ..Config::default()
        };
        let mut net = Net::with_config(v6, latency_ms, cfg);
        net.loss = loss.unwrap_or(0);
        net.reorder = reorder.unwrap_or(0);
        let (ka, kb) = connect(&mut net);
        transfer(&mut net, (true, ka), (false, kb), size, 120_000);
        transfer(&mut net, (false, kb), (true, ka), size / 2 + 1, 120_000);
        net.a.detach(ka, net.now);
        for _ in 0..8000 {
            net.step(Duration::from_millis(1));
            if net.a.is_empty() && net.b.get(kb).is_some_and(utp::Socket::at_eof) {
                break;
            }
        }
        proptest::prop_assert!(net.b.get(kb).is_some_and(utp::Socket::at_eof));
        // Sequence numbers, windows and buffers stayed consistent.
        let s = net.b.get(kb).unwrap();
        proptest::prop_assert_eq!(s.bytes_in_flight(), 0);
    }
}
