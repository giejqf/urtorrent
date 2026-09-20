// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The listen port's UDP sockets (one per family) and their demultiplexer
//! (AGENTS.md 4: owned by the ring, with hooks for DHT and uTP). Consumers:
//! the BEP 15 UDP tracker (requests register a waiter keyed by `(tracker
//! address, transaction id)` and the receive loop hands replies over), the
//! DHT (every datagram that is a bencoded dictionary) and uTP (a 20-byte
//! header with version nibble 1). Anything else is dropped at `trace`.
//!
//! Datagrams arrive through one multishot `recvmsg` per socket into a
//! provided buffer ring; each wakeup drains what is queued and then tells
//! uTP the round is over (deferred acks go out once per round).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Instant;

use metainfo::InfoHash;
use tracker::udp::{self, ConnectionCache, Reply};
use tracker::{AnnounceRequest, AnnounceResponse};
use uring::{BufRing, Buffer, UdpSocket};

use super::local::{Either, Flag, select2};
use super::utp::UtpHost;

/// Provided buffers per UDP socket (datagrams are at most ~1500 bytes).
const UDP_RING_ENTRIES: u16 = 256;
const UDP_BUF_SIZE: usize = 2048;
/// Buffer group ids for the UDP rings (`RECV_RING_GROUP` is 1).
const UDP_RING_GROUP_V4: u16 = 2;
const UDP_RING_GROUP_V6: u16 = 3;
/// Datagrams handled per wakeup before yielding.
const MAX_UDP_BATCH: usize = 64;

struct Slot {
    reply: Option<Reply>,
    waker: Option<Waker>,
}

/// Waiters keyed by `(tracker address, transaction id)`.
type Waiters = HashMap<(SocketAddr, u32), Rc<RefCell<Slot>>>;

/// A datagram waiting in a socket's send queue.
struct Queued {
    to: SocketAddr,
    data: Vec<u8>,
    /// Send with don't-fragment set (uTP path-MTU probe) and report the
    /// result.
    probe: Option<Box<dyn FnOnce(uring::Result<u32>)>>,
}

/// One bound UDP socket with its send queue. Datagrams go out in order,
/// `SEND_BATCH` at a time (each batch fully completes before the next is
/// submitted): a uTP window's worth of packets is then paced by the ring's
/// round trip instead of hitting the socket buffer as one burst, which kept
/// the order and stopped receivers from dropping the tail.
struct Sock {
    socket: Rc<UdpSocket>,
    v6: bool,
    queue: RefCell<std::collections::VecDeque<Queued>>,
    kick: Rc<super::local::Notify>,
}

/// Datagrams submitted together.
const SEND_BATCH: usize = 32;

/// A consumer of datagrams that are not tracker replies: `(from, packet,
/// arrived on the v6 socket)`.
pub type DhtHook = Box<dyn Fn(SocketAddr, &[u8], bool)>;

/// Called with the key of every connection an incoming SYN opened.
pub type UtpAccept = Box<dyn Fn(utp::Key)>;

/// The demultiplexer.
pub struct UdpDemux {
    socks: Vec<Sock>,
    waiters: RefCell<Waiters>,
    cache: RefCell<ConnectionCache>,
    next_tid: Cell<u32>,
    /// KRPC (bencoded dictionary) datagrams go here.
    dht: RefCell<Option<DhtHook>>,
    /// uTP datagrams go here.
    utp: RefCell<Option<(Rc<UtpHost>, UtpAccept)>>,
}

impl UdpDemux {
    /// Bind UDP sockets on `port` for the given families. A family that
    /// fails to bind is logged and skipped (UDP trackers of that family then
    /// fail with an error instead of hanging).
    pub fn bind(
        port: u16,
        v4: Option<std::net::Ipv4Addr>,
        v6: Option<std::net::Ipv6Addr>,
        seed: u32,
    ) -> UdpDemux {
        let mut socks = Vec::new();
        let sock = |s: UdpSocket, v6: bool| Sock {
            socket: Rc::new(s),
            v6,
            queue: RefCell::new(std::collections::VecDeque::new()),
            kick: super::local::Notify::new(),
        };
        if let Some(a) = v4 {
            match UdpSocket::bind(SocketAddr::new(IpAddr::V4(a), port)) {
                Ok(s) => socks.push(sock(s, false)),
                Err(e) => tracing::warn!("udp v4 bind on {port} failed: {e}"),
            }
        }
        if let Some(a) = v6 {
            match UdpSocket::bind(SocketAddr::new(IpAddr::V6(a), port)) {
                Ok(s) => socks.push(sock(s, true)),
                Err(e) => tracing::warn!("udp v6 bind on {port} failed: {e}"),
            }
        }
        UdpDemux {
            socks,
            waiters: RefCell::new(HashMap::new()),
            cache: RefCell::new(ConnectionCache::default()),
            next_tid: Cell::new(seed | 1),
            dht: RefCell::new(None),
            utp: RefCell::new(None),
        }
    }

    /// Whether a socket exists for `ip`'s family.
    pub fn supports(&self, ip: IpAddr) -> bool {
        self.socks.iter().any(|s| s.v6 == ip.is_ipv6())
    }

    fn sock_for(&self, ip: IpAddr) -> Option<&Sock> {
        self.socks.iter().find(|s| s.v6 == ip.is_ipv6())
    }

    /// The local address of the socket serving `ip`'s family.
    pub fn local_addr_for(&self, ip: IpAddr) -> Option<SocketAddr> {
        self.sock_for(ip).map(|s| s.socket.local_addr())
    }

    fn tid(&self) -> u32 {
        // Distinct, non-sequential-looking ids are not required by the BEP;
        // a stepping counter keeps them unique within the cache lifetime.
        let t = self.next_tid.get();
        self.next_tid
            .set(t.wrapping_mul(1_664_525).wrapping_add(1_013_904_223));
        t
    }

    /// Start the receive loops (one multishot `recvmsg` per socket into its
    /// own provided buffer ring, draining every queued datagram per wakeup)
    /// and the send loops.
    pub fn spawn(self: &Rc<Self>, closing: Rc<Flag>) {
        for i in 0..self.socks.len() {
            uring::spawn(Self::send_loop(self.clone(), i, closing.clone()));
        }
        for (i, s) in self.socks.iter().enumerate() {
            let me = self.clone();
            let socket = s.socket.clone();
            let v6 = s.v6;
            let closing = closing.clone();
            let ring = match BufRing::new(
                if v6 {
                    UDP_RING_GROUP_V6
                } else {
                    UDP_RING_GROUP_V4
                },
                UDP_RING_ENTRIES,
                UDP_BUF_SIZE,
            ) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(socket = i, "udp buffer ring: {e}");
                    continue;
                }
            };
            uring::spawn(async move {
                let mut rx = socket.recv_multi(&ring);
                loop {
                    match select2(rx.next(), closing.wait()).await {
                        Either::Left(Ok((from, buf))) => {
                            let now = Instant::now();
                            me.dispatch(from, buf.as_slice(), v6, now);
                            drop(buf);
                            let mut n = 1;
                            while n < MAX_UDP_BATCH
                                && let Some((from, buf)) = rx.try_next()
                            {
                                me.dispatch(from, buf.as_slice(), v6, now);
                                n += 1;
                            }
                            me.round_over(now);
                        }
                        Either::Left(Err(e)) => {
                            tracing::warn!(socket = i, "udp recv failed: {e}");
                            uring::sleep(std::time::Duration::from_millis(100)).await;
                        }
                        Either::Right(()) => break,
                    }
                }
                drop(ring);
            });
        }
    }

    /// Install the DHT consumer.
    pub fn set_dht_hook(&self, hook: DhtHook) {
        *self.dht.borrow_mut() = Some(hook);
    }

    /// Install the uTP endpoint; `accept` is told about connections opened
    /// by incoming SYNs.
    pub fn set_utp(&self, host: Rc<UtpHost>, accept: UtpAccept) {
        *self.utp.borrow_mut() = Some((host, accept));
    }

    /// End of a receive round.
    fn round_over(&self, now: Instant) {
        let host = self.utp.borrow().as_ref().map(|(h, _)| h.clone());
        if let Some(h) = host {
            h.drained(now);
        }
    }

    /// Queue a datagram (fire and forget, in order, through the ring).
    pub fn send_raw(&self, to: SocketAddr, payload: Vec<u8>) {
        let Some(sock) = self.sock_for(to.ip()) else {
            return;
        };
        sock.queue.borrow_mut().push_back(Queued {
            to,
            data: payload,
            probe: None,
        });
        sock.kick.notify();
    }

    /// Queue a path-MTU probe: sent alone with don't-fragment set (IPv4),
    /// `on_result` gets the outcome (`EMSGSIZE` = too big for the path).
    pub fn send_probe(
        &self,
        to: SocketAddr,
        payload: Vec<u8>,
        on_result: Box<dyn FnOnce(uring::Result<u32>)>,
    ) {
        let Some(sock) = self.sock_for(to.ip()) else {
            return;
        };
        sock.queue.borrow_mut().push_back(Queued {
            to,
            data: payload,
            probe: Some(on_result),
        });
        sock.kick.notify();
    }

    /// The send loop of socket `i`.
    async fn send_loop(me: Rc<Self>, i: usize, closing: Rc<Flag>) {
        let Some(sock) = me.socks.get(i) else { return };
        let socket = sock.socket.clone();
        loop {
            if sock.queue.borrow().is_empty() {
                match select2(sock.kick.wait(), closing.wait()).await {
                    Either::Left(()) => {}
                    Either::Right(()) => break,
                }
            }
            // Plain datagrams up to the batch size, stopping at a probe.
            let mut batch = Vec::new();
            let mut probe = None;
            {
                let mut q = sock.queue.borrow_mut();
                while batch.len() < SEND_BATCH {
                    match q.front() {
                        None => break,
                        Some(f) if f.probe.is_some() => {
                            if batch.is_empty()
                                && let Some(p) = q.pop_front()
                            {
                                probe = Some(p);
                            }
                            break;
                        }
                        Some(_) => {
                            if let Some(p) = q.pop_front() {
                                batch.push(p);
                            }
                        }
                    }
                }
            }
            if !batch.is_empty() {
                let sends: Vec<_> = batch
                    .into_iter()
                    .map(|q| socket.send_to(Buffer::from_vec(q.data), q.to))
                    .collect();
                for (r, _) in super::local::join_all(sends).await {
                    if let Err(e) = r {
                        tracing::trace!(socket = i, "udp send failed: {e}");
                    }
                }
            }
            if let Some(p) = probe {
                let df = socket.set_dont_fragment(true).is_ok();
                let (r, _) = socket.send_to(Buffer::from_vec(p.data), p.to).await;
                if df {
                    let _ = socket.set_dont_fragment(false);
                }
                if let Some(cb) = p.probe {
                    cb(r);
                }
            }
        }
    }

    fn dispatch(&self, from: SocketAddr, pkt: &[u8], v6: bool, now: Instant) {
        // KRPC messages are bencoded dictionaries; tracker replies never
        // start with 'd' (their first field is a big-endian action).
        if pkt.first() == Some(&b'd') {
            if let Some(h) = self.dht.borrow().as_ref() {
                h(from, pkt, v6);
            }
            return;
        }
        // uTP: version nibble 1 in the first byte (a tracker reply's first
        // byte is the high byte of a small action, 0).
        if utp::is_utp(pkt) {
            let host = self.utp.borrow().as_ref().map(|(h, _)| h.clone());
            if let Some(h) = host
                && let Some(key) = h.incoming(from, pkt, now)
                && let Some((_, accept)) = self.utp.borrow().as_ref()
            {
                accept(key);
            }
            return;
        }
        match udp::parse_reply(pkt, v6) {
            Ok(reply) => {
                let key = (from, reply.transaction_id());
                let slot = self.waiters.borrow_mut().remove(&key);
                match slot {
                    Some(slot) => {
                        let waker = {
                            let mut s = slot.borrow_mut();
                            s.reply = Some(reply);
                            s.waker.take()
                        };
                        if let Some(w) = waker {
                            w.wake();
                        }
                    }
                    None => tracing::trace!(%from, "unmatched udp tracker reply"),
                }
            }
            Err(_) => tracing::trace!(%from, len = pkt.len(), "udp datagram ignored"),
        }
    }

    /// Send `pkt` to `to` and wait (bounded) for the reply with `tid`.
    async fn exchange(&self, to: SocketAddr, pkt: Vec<u8>, tid: u32) -> Result<Reply, String> {
        let sock = self
            .sock_for(to.ip())
            .ok_or_else(|| format!("no udp socket for {}", to.ip()))?;
        let slot = Rc::new(RefCell::new(Slot {
            reply: None,
            waker: None,
        }));
        self.waiters.borrow_mut().insert((to, tid), slot.clone());
        let (r, _) = sock.socket.send_to(Buffer::from_vec(pkt), to).await;
        if let Err(e) = r {
            self.waiters.borrow_mut().remove(&(to, tid));
            return Err(format!("udp send: {e}"));
        }
        let wait = std::future::poll_fn(|cx| {
            let mut s = slot.borrow_mut();
            match s.reply.take() {
                Some(r) => Poll::Ready(r),
                None => {
                    s.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        });
        match uring::timeout(udp::RECEIVE_TIMEOUT, wait).await {
            Ok(reply) => Ok(reply),
            Err(_) => {
                self.waiters.borrow_mut().remove(&(to, tid));
                Err("udp tracker timed out".into())
            }
        }
    }

    /// A connection id for `to`: cached, or freshly negotiated.
    async fn connection_id(&self, to: SocketAddr) -> Result<u64, String> {
        let now = Instant::now();
        if let Some(id) = self.cache.borrow().get(to.ip(), now) {
            return Ok(id);
        }
        let tid = self.tid();
        match self.exchange(to, udp::connect_request(tid), tid).await? {
            Reply::Connect { connection_id, .. } => {
                self.cache
                    .borrow_mut()
                    .insert(to.ip(), connection_id, Instant::now());
                Ok(connection_id)
            }
            Reply::Error { message, .. } => Err(format!("tracker error: {message}")),
            other => Err(format!("unexpected reply to connect: {other:?}")),
        }
    }

    /// Announce to a UDP tracker at `to`. `url_path` is the URL's path and
    /// query (BEP 41 option 2, as libtorrent sends it).
    pub async fn announce(
        &self,
        to: SocketAddr,
        req: &AnnounceRequest,
        numwant: i32,
        url_path: &str,
    ) -> Result<AnnounceResponse, String> {
        let cid = self.connection_id(to).await?;
        let tid = self.tid();
        let pkt = udp::announce_request(cid, tid, req, numwant, url_path);
        match self.exchange(to, pkt, tid).await? {
            Reply::Announce { response, .. } => Ok(response),
            Reply::Error { message, .. } => {
                self.cache.borrow_mut().forget(to.ip());
                Err(format!("tracker error: {message}"))
            }
            other => Err(format!("unexpected reply to announce: {other:?}")),
        }
    }

    /// Scrape `hashes` at `to`.
    pub async fn scrape(
        &self,
        to: SocketAddr,
        hashes: &[InfoHash],
    ) -> Result<Vec<(u32, u32, u32)>, String> {
        let cid = self.connection_id(to).await?;
        let tid = self.tid();
        let pkt = udp::scrape_request(cid, tid, hashes);
        match self.exchange(to, pkt, tid).await? {
            Reply::Scrape { entries, .. } => Ok(entries),
            Reply::Error { message, .. } => {
                self.cache.borrow_mut().forget(to.ip());
                Err(format!("tracker error: {message}"))
            }
            other => Err(format!("unexpected reply to scrape: {other:?}")),
        }
    }
}
