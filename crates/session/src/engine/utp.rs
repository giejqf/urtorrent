// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! uTP (BEP 29) connections on the listen port's UDP sockets. The sans-IO
//! [`utp::Manager`] holds every connection; this module is the glue: it
//! feeds it datagrams from the UDP demultiplexer, sends what it produces,
//! ticks its timers from the session ticker, and exposes each connection
//! as a [`UtpStream`] that the peer code drives like a TCP socket
//! (`connected`, `recv`, chunks, `send_all`).
//!
//! Timestamps use `CLOCK_MONOTONIC` in microseconds, as libtorrent's do.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::task::{Poll, Waker};
use std::time::Instant;

use uring::Buffer;
use utp::{Incoming, Key, Manager, Notify, State};

use super::rng::RngRef;
use super::udp::UdpDemux;

/// Application bytes queued per connection before `send_all` waits.
const WRITE_CAP: usize = 512 * 1024;

/// The oracle's uTP settings (libtorrent defaults; qBittorrent changes none).
pub fn default_config() -> utp::Config {
    utp::Config::default()
}

#[derive(Default)]
struct Wakers {
    read: Option<Waker>,
    write: Option<Waker>,
    connect: Option<Waker>,
}

impl Wakers {
    fn wake(&mut self, n: Notify) {
        let closed = n.contains(Notify::CLOSED);
        if (n.contains(Notify::READABLE) || closed)
            && let Some(w) = self.read.take()
        {
            w.wake();
        }
        if (n.contains(Notify::WRITABLE) || closed)
            && let Some(w) = self.write.take()
        {
            w.wake();
        }
        if (n.contains(Notify::CONNECTED) || closed)
            && let Some(w) = self.connect.take()
        {
            w.wake();
        }
    }

    fn wake_all(&mut self) {
        self.wake(Notify::CLOSED);
    }
}

/// The engine's uTP endpoint.
pub struct UtpHost {
    mgr: RefCell<Manager>,
    wakers: RefCell<HashMap<Key, Wakers>>,
    udp: Rc<UdpDemux>,
    rng: Rc<super::rng::Rng>,
    me: Weak<UtpHost>,
    /// Payload bytes copied by the glue itself (partial sends under a rate
    /// limit, partial handshake reads); the sockets count their own.
    copied: Cell<u64>,
}

impl UtpHost {
    /// A host over `udp`. `incoming` allows SYNs; `max_sockets` bounds the
    /// table (SYN flood guard: libtorrent uses twice the connection limit).
    pub fn new(
        cfg: utp::Config,
        udp: Rc<UdpDemux>,
        rng: Rc<super::rng::Rng>,
        incoming: bool,
        max_sockets: usize,
    ) -> Rc<UtpHost> {
        Rc::new_cyclic(|me| UtpHost {
            mgr: RefCell::new(Manager::new(cfg, monotonic_clock(), incoming, max_sockets)),
            wakers: RefCell::new(HashMap::new()),
            udp,
            rng,
            me: me.clone(),
            copied: Cell::new(0),
        })
    }

    /// Live connections.
    pub fn connections(&self) -> usize {
        self.mgr.borrow().len()
    }

    /// Payload bytes copied in user space on the uTP data path (see
    /// [`utp::Stats::copied_bytes`]).
    pub fn copied_bytes(&self) -> u64 {
        self.copied.get() + self.mgr.borrow().copied_bytes()
    }

    /// A datagram from the UDP demultiplexer. Returns the key of a
    /// connection a SYN just opened (the caller adopts it as an incoming
    /// peer).
    pub fn incoming(&self, from: SocketAddr, pkt: &[u8], now: Instant) -> Option<Key> {
        let mut rng = RngRef(&self.rng);
        let r = self.mgr.borrow_mut().incoming(from, pkt, now, &mut rng);
        match r {
            Incoming::New(k) => Some(k),
            Incoming::Handled(_) | Incoming::Ignored => None,
        }
    }

    /// The UDP receive round is over: deferred acks go out, owners wake.
    pub fn drained(&self, now: Instant) {
        let touched = self.mgr.borrow_mut().drained(now);
        let _ = touched;
        self.flush();
    }

    /// The session ticker (100 ms): timeouts, retransmits, dead-socket
    /// reaping.
    pub fn tick(&self, now: Instant) {
        let removed = self.mgr.borrow_mut().tick(now);
        if !removed.is_empty() {
            let mut w = self.wakers.borrow_mut();
            for k in removed {
                if let Some(mut ws) = w.remove(&k) {
                    ws.wake_all();
                }
            }
        }
        self.flush();
    }

    /// Dial `remote`: the SYN leaves now, `connected` resolves later.
    pub fn connect(self: &Rc<Self>, remote: SocketAddr, now: Instant) -> UtpStream {
        let mut rng = RngRef(&self.rng);
        let key = self.mgr.borrow_mut().connect(remote, now, &mut rng);
        self.flush();
        UtpStream {
            host: self.clone(),
            key,
        }
    }

    /// Adopt a connection opened by a SYN.
    pub fn stream(self: &Rc<Self>, key: Key) -> UtpStream {
        UtpStream {
            host: self.clone(),
            key,
        }
    }

    /// Send pending datagrams and deliver notifications.
    fn flush(&self) {
        let (out, notes) = {
            let mut m = self.mgr.borrow_mut();
            (m.poll_outgoing(), m.take_notifications())
        };
        for (to, o) in out {
            if o.mtu_probe && to.is_ipv4() {
                self.send_probe(to, o.data);
            } else {
                self.udp.send_raw(to, o.data);
            }
        }
        if !notes.is_empty() {
            let mut w = self.wakers.borrow_mut();
            for (k, n) in notes {
                if let Some(ws) = w.get_mut(&k) {
                    ws.wake(n);
                }
            }
        }
    }

    /// A path-MTU probe: sent with DF (libtorrent toggles `IP_MTU_DISCOVER`
    /// around the send). `EMSGSIZE` means the kernel already knows the path
    /// is narrower: report it to the connection.
    fn send_probe(&self, to: SocketAddr, data: Vec<u8>) {
        let size = data.len() as u16;
        let host = self.me.clone();
        self.udp.send_probe(
            to,
            data,
            Box::new(move |r| {
                if r.as_ref().is_err_and(uring::Error::is_message_too_long)
                    && let Some(h) = host.upgrade()
                {
                    h.probe_rejected(to, size);
                }
            }),
        );
    }

    fn probe_rejected(&self, to: SocketAddr, size: u16) {
        let now = Instant::now();
        let mut m = self.mgr.borrow_mut();
        let keys: Vec<Key> = m.keys().filter(|k| k.1 == to).collect();
        for k in keys {
            if let Some(s) = m.get_mut(k) {
                s.probe_rejected(size, now);
            }
        }
        drop(m);
        self.flush();
    }

    fn with_wakers<R>(&self, key: Key, f: impl FnOnce(&mut Wakers) -> R) -> R {
        let mut w = self.wakers.borrow_mut();
        f(w.entry(key).or_default())
    }
}

/// `CLOCK_MONOTONIC` microseconds at `Instant::now()`, so header
/// timestamps look like libtorrent's (time since boot).
fn monotonic_clock() -> utp::Clock {
    let epoch = Instant::now();
    utp::Clock::new(epoch, uring::monotonic_micros())
}

fn closed_error(e: Option<utp::Error>) -> uring::Error {
    match e {
        Some(utp::Error::TimedOut) => uring::Error::TimedOut,
        Some(utp::Error::Reset) => io::Error::from(io::ErrorKind::ConnectionReset).into(),
        Some(utp::Error::Aborted) => io::Error::from(io::ErrorKind::ConnectionAborted).into(),
        Some(utp::Error::Eof) | None => io::Error::from(io::ErrorKind::UnexpectedEof).into(),
    }
}

/// One uTP connection as the peer code sees it. Dropping it closes the
/// connection gracefully (FIN once the write buffer drained).
pub struct UtpStream {
    host: Rc<UtpHost>,
    key: Key,
}

impl UtpStream {
    /// The remote address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.key.1
    }

    /// The UDP socket's local address for this remote's family.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.host.udp.local_addr_for(self.key.1.ip())
    }

    fn with_socket<R>(&self, f: impl FnOnce(&mut utp::Socket) -> R) -> Option<R> {
        let mut m = self.host.mgr.borrow_mut();
        m.get_mut(self.key).map(f)
    }

    /// Resolve once the SYN is acked (or the attempt failed).
    pub async fn connected(&self) -> uring::Result<()> {
        std::future::poll_fn(|cx| {
            let st = self.with_socket(|s| (s.state(), s.error()));
            match st {
                None => Poll::Ready(Err(closed_error(Some(utp::Error::Aborted)))),
                Some((State::Connected | State::FinSent, _)) => Poll::Ready(Ok(())),
                Some((State::Closed, e)) => Poll::Ready(Err(closed_error(e))),
                Some(_) => {
                    self.host
                        .with_wakers(self.key, |w| w.connect = Some(cx.waker().clone()));
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// Set the close reason carried by our FIN.
    pub fn set_close_reason(&self, code: u16) {
        self.with_socket(|s| s.set_close_reason(code));
    }

    /// A received chunk without waiting: `Some(Some(bytes))`, `Some(None)`
    /// at end of stream, `None` when nothing is queued.
    pub fn try_next(&self) -> Option<Option<Vec<u8>>> {
        let r = self.with_socket(|s| match s.read() {
            Some(c) => Some(Some(c)),
            None if s.at_eof() || s.state() == State::Closed => Some(None),
            None => None,
        });
        match r {
            None => Some(None),
            Some(x) => x,
        }
    }

    /// The next received chunk; `Ok(None)` at end of stream.
    pub async fn next(&self) -> uring::Result<Option<Vec<u8>>> {
        std::future::poll_fn(|cx| {
            let r = self.with_socket(|s| {
                if let Some(c) = s.read() {
                    return Poll::Ready(Ok(Some(c)));
                }
                if s.at_eof() {
                    return Poll::Ready(Ok(None));
                }
                if s.state() == State::Closed {
                    return Poll::Ready(match s.error() {
                        Some(utp::Error::Eof) | None => Ok(None),
                        e => Err(closed_error(e)),
                    });
                }
                Poll::Pending
            });
            match r {
                None => Poll::Ready(Ok(None)),
                Some(Poll::Pending) => {
                    self.host
                        .with_wakers(self.key, |w| w.read = Some(cx.waker().clone()));
                    Poll::Pending
                }
                Some(p) => p,
            }
        })
        .await
    }

    /// Receive into `buf` (up to its length); `Ok(0)` at end of stream.
    pub async fn recv(&self, mut buf: Buffer) -> (uring::Result<u32>, Buffer) {
        let chunk = match self.next().await {
            Ok(Some(c)) => c,
            Ok(None) => return (Ok(0), buf),
            Err(e) => return (Err(e), buf),
        };
        let n = chunk.len().min(buf.len());
        buf.as_mut_slice()[..n].copy_from_slice(&chunk[..n]);
        self.host.copied.set(self.host.copied.get() + n as u64);
        // Like the ring's `recv`: the buffer is sized to what arrived.
        buf.truncate(n);
        if n < chunk.len() {
            // Put the rest back in front for the next read.
            self.host
                .copied
                .set(self.host.copied.get() + (chunk.len() - n) as u64);
            self.with_socket(|s| s.unread(chunk[n..].to_vec()));
        }
        (Ok(n as u32), buf)
    }

    /// Queue `data` for sending, waiting while the write buffer is full.
    pub async fn send_all(&self, data: Vec<u8>) -> uring::Result<()> {
        std::future::poll_fn(|cx| {
            let r = self.with_socket(|s| {
                if s.state() == State::Closed {
                    return Poll::Ready(Err(closed_error(s.error())));
                }
                if s.state() == State::FinSent {
                    return Poll::Ready(Err(closed_error(Some(utp::Error::Eof))));
                }
                if s.write_buffer_size() >= WRITE_CAP {
                    return Poll::Pending;
                }
                Poll::Ready(Ok(()))
            });
            match r {
                None => Poll::Ready(Err(closed_error(Some(utp::Error::Aborted)))),
                Some(Poll::Pending) => {
                    self.host
                        .with_wakers(self.key, |w| w.write = Some(cx.waker().clone()));
                    Poll::Pending
                }
                Some(p) => p,
            }
        })
        .await?;
        let now = Instant::now();
        self.with_socket(|s| s.write(data, now));
        self.host.flush();
        Ok(())
    }

    /// Send bytes `[start, start + len)` of the concatenated `chunks`,
    /// copying the parts of chunks the range cuts (a rate-limited send).
    pub async fn send_range(
        &self,
        chunks: &[Buffer],
        start: usize,
        len: usize,
    ) -> uring::Result<()> {
        let mut skip = start;
        let mut left = len;
        for c in chunks {
            if left == 0 {
                break;
            }
            let s = c.as_slice();
            if skip >= s.len() {
                skip -= s.len();
                continue;
            }
            let take = (s.len() - skip).min(left);
            self.host.copied.set(self.host.copied.get() + take as u64);
            self.send_all(s[skip..skip + take].to_vec()).await?;
            left -= take;
            skip = 0;
        }
        Ok(())
    }

    /// Send whole `chunks`, moving each into the write queue (no copy).
    pub async fn send_chunks(&self, chunks: Vec<Buffer>) -> uring::Result<()> {
        for c in chunks {
            self.send_all(c.into_vec()).await?;
        }
        Ok(())
    }
}

impl Drop for UtpStream {
    fn drop(&mut self) {
        let now = Instant::now();
        self.host.mgr.borrow_mut().detach(self.key, now);
        self.host.wakers.borrow_mut().remove(&self.key);
        self.host.flush();
    }
}
