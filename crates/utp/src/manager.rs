// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
//
// Ported in part from libtorrent's `utp_socket_manager`
// (src/utp_socket_manager.cpp, Copyright (c) 2009-2022 Arvid Norberg and
// contributors; BSD-3-Clause). See NOTICE.

//! All uTP connections behind one UDP port: connection-id allocation,
//! demultiplexing, SYN acceptance, deferred acks and the MTU restriction
//! learnt from dead connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use profile::Rng;

use crate::header::{Header, PacketType, is_utp};
use crate::socket::{Clock, Config, Notify, Outgoing, Socket};

/// A connection's key: `(recv_id, remote address)`.
pub type Key = (u16, SocketAddr);

/// What [`Manager::incoming`] did with a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incoming {
    /// Delivered to an existing connection.
    Handled(Key),
    /// A SYN opened a new connection; the owner should adopt it.
    New(Key),
    /// Not uTP, not ours, or refused.
    Ignored,
}

/// The connection table.
pub struct Manager {
    cfg: Config,
    clock: Clock,
    sockets: HashMap<Key, Socket>,
    /// The connection the previous datagram went to (the common case is a
    /// run of packets for one socket; its ack stays deferred through the
    /// run).
    last: Option<Key>,
    /// The connection holding a deferred ack.
    deferred_ack: Option<Key>,
    /// Sockets touched this receive round (readable/writable wakeups happen
    /// once the round is drained, like libtorrent's `socket_drained`).
    touched: Vec<Key>,
    /// `copied_bytes` of the sockets already removed from the table.
    retired_copied: u64,
    /// Whether SYNs are accepted.
    incoming_enabled: bool,
    /// SYN flood guard: no new connections beyond this many sockets.
    max_sockets: usize,
    /// The three most recent MTU restrictions (max wins).
    restrict_mtu: [u16; 3],
    mtu_idx: usize,
    new_connections: Vec<Key>,
}

impl Manager {
    /// A manager with `cfg` for every connection.
    pub fn new(cfg: Config, clock: Clock, incoming_enabled: bool, max_sockets: usize) -> Manager {
        Manager {
            cfg,
            clock,
            sockets: HashMap::new(),
            last: None,
            deferred_ack: None,
            touched: Vec::new(),
            retired_copied: 0,
            incoming_enabled,
            max_sockets,
            restrict_mtu: [u16::MAX; 3],
            mtu_idx: 0,
            new_connections: Vec::new(),
        }
    }

    /// Number of live connections.
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Whether there are no connections.
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }

    /// Payload bytes copied in user space by every socket this table ever
    /// held (see [`Stats::copied_bytes`]).
    ///
    /// [`Stats::copied_bytes`]: crate::Stats::copied_bytes
    pub fn copied_bytes(&self) -> u64 {
        self.retired_copied
            + self
                .sockets
                .values()
                .map(|s| s.stats().copied_bytes)
                .sum::<u64>()
    }

    /// The connection for `key`.
    pub fn get(&self, key: Key) -> Option<&Socket> {
        self.sockets.get(&key)
    }

    /// The connection for `key`, mutably.
    pub fn get_mut(&mut self, key: Key) -> Option<&mut Socket> {
        self.sockets.get_mut(&key)
    }

    /// Keys of every connection.
    pub fn keys(&self) -> impl Iterator<Item = Key> + '_ {
        self.sockets.keys().copied()
    }

    /// The UDP payload MTU to assume towards `addr`.
    pub fn mtu_for_dest(&self, addr: SocketAddr) -> u16 {
        let restrict = *self.restrict_mtu.iter().max().unwrap_or(&u16::MAX);
        Socket::mtu_for_dest(addr, restrict)
    }

    fn restrict(&mut self, mtu: u16) {
        self.restrict_mtu[self.mtu_idx] = mtu;
        self.mtu_idx = (self.mtu_idx + 1) % self.restrict_mtu.len();
    }

    /// Open a connection to `remote`; the SYN is queued.
    pub fn connect(&mut self, remote: SocketAddr, now: Instant, rng: &mut dyn Rng) -> Key {
        let mut send_id = rng.next_u32() as u16;
        // recv_id = send_id - 1 must be free for this remote.
        while self
            .sockets
            .contains_key(&(send_id.wrapping_sub(1), remote))
        {
            send_id = send_id.wrapping_add(2);
        }
        let mtu = self.mtu_for_dest(remote);
        let s = Socket::connect(self.cfg.clone(), self.clock, remote, send_id, mtu, now, rng);
        let key = (s.recv_id(), remote);
        self.sockets.insert(key, s);
        self.touched.push(key);
        key
    }

    /// Feed a datagram from `from` (any UDP payload; non-uTP is ignored).
    pub fn incoming(
        &mut self,
        from: SocketAddr,
        pkt: &[u8],
        now: Instant,
        rng: &mut dyn Rng,
    ) -> Incoming {
        if !is_utp(pkt) {
            return Incoming::Ignored;
        }
        let Some(h) = Header::parse(pkt) else {
            return Incoming::Ignored;
        };
        let key = (h.connection_id, from);
        // first test to see if it's the same socket as last time; in most
        // cases it is
        if self.last == Some(key)
            && let Some(s) = self.sockets.get_mut(&key)
        {
            let ok = s.incoming(from, pkt, now, rng);
            self.after_incoming(key);
            return if ok {
                Incoming::Handled(key)
            } else {
                Incoming::Ignored
            };
        }
        // we send the deferred ACK when the socket is drained as well, so as
        // long as the incoming packets go to the last socket we can defer
        // the ACK more. However, if we receive a packet for another socket,
        // we have to trigger the ACK in case the new socket also wants to
        // defer an ACK.
        self.flush_deferred_ack(now);
        if let Some(s) = self.sockets.get_mut(&key) {
            let ok = s.incoming(from, pkt, now, rng);
            if ok {
                self.last = Some(key);
            }
            self.after_incoming(key);
            return if ok {
                Incoming::Handled(key)
            } else {
                Incoming::Ignored
            };
        }
        if !self.incoming_enabled {
            return Incoming::Ignored;
        }
        // if not found, see if it's a SYN packet, if it is, create a new
        // connection
        if h.ty == PacketType::Syn {
            // possible SYN flood. Just ignore
            if self.sockets.len() > self.max_sockets {
                return Incoming::Ignored;
            }
            let mtu = self.mtu_for_dest(from);
            let mut s = Socket::accept(
                self.cfg.clone(),
                self.clock,
                from,
                h.connection_id,
                mtu,
                now,
            );
            if !s.incoming(from, pkt, now, rng) {
                return Incoming::Ignored;
            }
            let key = (s.recv_id(), from);
            self.sockets.insert(key, s);
            self.last = Some(key);
            self.after_incoming(key);
            self.new_connections.push(key);
            return Incoming::New(key);
        }
        // ST_RESET for an unknown connection, or any other stray packet: no
        // reset is sent back (libtorrent does not either).
        Incoming::Ignored
    }

    fn after_incoming(&mut self, key: Key) {
        if let Some(s) = self.sockets.get(&key) {
            if s.has_deferred_ack() {
                self.deferred_ack = Some(key);
            } else if self.deferred_ack == Some(key) {
                self.deferred_ack = None;
            }
        }
        if !self.touched.contains(&key) {
            self.touched.push(key);
        }
    }

    fn flush_deferred_ack(&mut self, now: Instant) {
        if let Some(k) = self.deferred_ack.take()
            && let Some(s) = self.sockets.get_mut(&k)
        {
            s.send_deferred_ack(now);
        }
    }

    /// The receive round is over: send the deferred ack. Returns the
    /// connections touched since the last call (to wake their owners).
    pub fn drained(&mut self, now: Instant) -> Vec<Key> {
        self.flush_deferred_ack(now);
        let touched = std::mem::take(&mut self.touched);
        for k in &touched {
            if let Some(s) = self.sockets.get_mut(k) {
                s.end_round();
            }
        }
        touched
    }

    /// Connections opened by SYNs since the last call.
    pub fn take_new_connections(&mut self) -> Vec<Key> {
        std::mem::take(&mut self.new_connections)
    }

    /// Drive timeouts on every connection and drop the finished ones.
    /// Returns the keys that were removed.
    pub fn tick(&mut self, now: Instant) -> Vec<Key> {
        let mut removed = Vec::new();
        let mut hints = Vec::new();
        let retired = &mut self.retired_copied;
        self.sockets.retain(|k, s| {
            if s.should_delete() {
                removed.push(*k);
                *retired += s.stats().copied_bytes;
                return false;
            }
            s.tick(now);
            if let Some(m) = s.take_restrict_mtu_hint() {
                hints.push(m);
            }
            true
        });
        for m in hints {
            self.restrict(m);
        }
        for k in &removed {
            if self.last == Some(*k) {
                self.last = None;
            }
            if self.deferred_ack == Some(*k) {
                self.deferred_ack = None;
            }
        }
        removed
    }

    /// The earliest timeout across connections.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.sockets.values().map(Socket::next_timeout).min()
    }

    /// Every pending datagram, as `(remote, packet)`.
    pub fn poll_outgoing(&mut self) -> Vec<(SocketAddr, Outgoing)> {
        let mut out = Vec::new();
        for (k, s) in &mut self.sockets {
            while let Some(o) = s.poll_outgoing() {
                out.push((k.1, o));
            }
        }
        out
    }

    /// Pending notifications per connection.
    pub fn take_notifications(&mut self) -> Vec<(Key, Notify)> {
        let mut out = Vec::new();
        for (k, s) in &mut self.sockets {
            let n = s.take_notify();
            if !n.is_empty() {
                out.push((*k, n));
            }
        }
        out
    }

    /// The owner is done with `key`: close it gracefully and free it when
    /// the FIN exchange completes.
    pub fn detach(&mut self, key: Key, now: Instant) {
        if let Some(s) = self.sockets.get_mut(&key) {
            s.detach(now);
        }
    }

    /// Abort every connection (shutdown).
    pub fn abort_all(&mut self) {
        for s in self.sockets.values_mut() {
            s.abort();
        }
        self.sockets.clear();
        self.last = None;
        self.deferred_ack = None;
    }
}

impl Manager {
    /// The clock (tests build peers sharing one).
    pub fn clock_for_test(&self) -> Clock {
        self.clock
    }
}
