// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The listen port's UDP sockets (one per family) and their demultiplexer
//! (AGENTS.md 4: owned by the ring, with a hook for DHT / uTP). Consumers:
//! the BEP 15 UDP tracker (requests register a waiter keyed by `(tracker
//! address, transaction id)` and the receive loop hands replies over) and the
//! DHT (every datagram that is a bencoded dictionary). Anything else is
//! dropped at `trace`; uTP would hook in the same way.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Instant;

use metainfo::InfoHash;
use tracker::udp::{self, ConnectionCache, Reply};
use tracker::{AnnounceRequest, AnnounceResponse};
use uring::{Buffer, UdpSocket};

use super::local::{Either, Flag, select2};

struct Slot {
    reply: Option<Reply>,
    waker: Option<Waker>,
}

/// Waiters keyed by `(tracker address, transaction id)`.
type Waiters = HashMap<(SocketAddr, u32), Rc<RefCell<Slot>>>;

/// One bound UDP socket.
struct Sock {
    socket: Rc<UdpSocket>,
    v6: bool,
}

/// A consumer of datagrams that are not tracker replies: `(from, packet,
/// arrived on the v6 socket)`.
pub type DhtHook = Box<dyn Fn(SocketAddr, &[u8], bool)>;

/// The demultiplexer.
pub struct UdpDemux {
    socks: Vec<Sock>,
    waiters: RefCell<Waiters>,
    cache: RefCell<ConnectionCache>,
    next_tid: Cell<u32>,
    /// KRPC (bencoded dictionary) datagrams go here.
    dht: RefCell<Option<DhtHook>>,
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
        if let Some(a) = v4 {
            match UdpSocket::bind(SocketAddr::new(IpAddr::V4(a), port)) {
                Ok(s) => socks.push(Sock {
                    socket: Rc::new(s),
                    v6: false,
                }),
                Err(e) => tracing::warn!("udp v4 bind on {port} failed: {e}"),
            }
        }
        if let Some(a) = v6 {
            match UdpSocket::bind(SocketAddr::new(IpAddr::V6(a), port)) {
                Ok(s) => socks.push(Sock {
                    socket: Rc::new(s),
                    v6: true,
                }),
                Err(e) => tracing::warn!("udp v6 bind on {port} failed: {e}"),
            }
        }
        UdpDemux {
            socks,
            waiters: RefCell::new(HashMap::new()),
            cache: RefCell::new(ConnectionCache::default()),
            next_tid: Cell::new(seed | 1),
            dht: RefCell::new(None),
        }
    }

    /// Whether a socket exists for `ip`'s family.
    pub fn supports(&self, ip: IpAddr) -> bool {
        self.socks.iter().any(|s| s.v6 == ip.is_ipv6())
    }

    fn sock_for(&self, ip: IpAddr) -> Option<&Sock> {
        self.socks.iter().find(|s| s.v6 == ip.is_ipv6())
    }

    fn tid(&self) -> u32 {
        // Distinct, non-sequential-looking ids are not required by the BEP;
        // a stepping counter keeps them unique within the cache lifetime.
        let t = self.next_tid.get();
        self.next_tid
            .set(t.wrapping_mul(1_664_525).wrapping_add(1_013_904_223));
        t
    }

    /// Start the receive loops.
    pub fn spawn(self: &Rc<Self>, closing: Rc<Flag>) {
        for (i, s) in self.socks.iter().enumerate() {
            let me = self.clone();
            let socket = s.socket.clone();
            let v6 = s.v6;
            let closing = closing.clone();
            uring::spawn(async move {
                loop {
                    let buf = Buffer::from_vec(vec![0u8; 2048]);
                    match select2(socket.recv_from(buf), closing.wait()).await {
                        Either::Left((Ok(_), buf, Some(from))) => {
                            me.dispatch(from, buf.as_slice(), v6)
                        }
                        Either::Left((Ok(_), _, None)) => {}
                        Either::Left((Err(e), _, _)) => {
                            tracing::warn!(socket = i, "udp recv failed: {e}");
                            uring::sleep(std::time::Duration::from_millis(100)).await;
                        }
                        Either::Right(()) => break,
                    }
                }
            });
        }
    }

    /// Install the DHT consumer.
    pub fn set_dht_hook(&self, hook: DhtHook) {
        *self.dht.borrow_mut() = Some(hook);
    }

    /// Send a datagram (fire and forget, through the ring).
    pub fn send_raw(&self, to: SocketAddr, payload: Vec<u8>) {
        let Some(sock) = self.sock_for(to.ip()) else {
            return;
        };
        let socket = sock.socket.clone();
        uring::spawn(async move {
            let (r, _) = socket.send_to(Buffer::from_vec(payload), to).await;
            if let Err(e) = r {
                tracing::trace!(%to, "udp send failed: {e}");
            }
        });
    }

    fn dispatch(&self, from: SocketAddr, pkt: &[u8], v6: bool) {
        // KRPC messages are bencoded dictionaries; tracker replies never
        // start with 'd' (their first field is a big-endian action).
        if pkt.first() == Some(&b'd') {
            if let Some(h) = self.dht.borrow().as_ref() {
                h(from, pkt, v6);
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
            // Not a tracker reply and not KRPC: uTP demux hook goes here (post-0.3.0).
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
