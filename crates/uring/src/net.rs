// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! TCP and UDP over io_uring. Socket creation, `setsockopt`, `bind` and
//! `listen` are one-time setup and use blocking libc calls (allowed off the
//! ring, AGENTS.md 5.3); `connect`/`accept`/`send`/`recv`/`close` go through
//! the ring. Separate v4 and v6 sockets, `IPV6_V6ONLY=1` (AGENTS.md 5.5).

use std::io;
use std::marker::PhantomData;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::rc::Rc;

use crate::bufpool::Buffer;
use crate::bufring::{BufRing, BufRingInner, RingBuf};
use crate::error::Result;
use crate::reactor::{
    self, MultiOp, accept, close_fd_detached, connect, recv, send, send_chunks, send_chunks_zc,
    send_range,
};

/// A raw sockaddr with its length, kept alive across an async `connect`.
pub(crate) struct RawSockAddr {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

impl RawSockAddr {
    fn from(addr: SocketAddr) -> RawSockAddr {
        // SAFETY: zeroed sockaddr_storage is a valid all-zero POD; we then fill
        // the family-specific prefix and report its exact length.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(v4) => {
                // SAFETY: sockaddr_storage is large enough for sockaddr_in and
                // correctly aligned; we write only the sockaddr_in prefix.
                let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                sin.sin_port = v4.port().to_be();
                sin.sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                };
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(v6) => {
                // SAFETY: as above for sockaddr_in6.
                let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = v6.port().to_be();
                sin6.sin6_addr = libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                };
                sin6.sin6_scope_id = v6.scope_id();
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        };
        RawSockAddr { storage, len }
    }

    pub(crate) fn as_ptr(&self) -> *const libc::sockaddr {
        &self.storage as *const _ as *const libc::sockaddr
    }
    pub(crate) fn as_mut_ptr(&mut self) -> *mut libc::sockaddr {
        &mut self.storage as *mut _ as *mut libc::sockaddr
    }
    pub(crate) fn len(&self) -> libc::socklen_t {
        self.len
    }
    /// Full storage size (for the kernel to fill in on receive).
    pub(crate) fn capacity(&self) -> libc::socklen_t {
        mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t
    }
    /// An empty storage for the kernel to fill.
    pub(crate) fn empty() -> RawSockAddr {
        // SAFETY: zeroed sockaddr_storage is a valid all-zero POD.
        RawSockAddr {
            storage: unsafe { mem::zeroed() },
            len: 0,
        }
    }
    /// Decode a kernel-filled storage of `len` bytes.
    pub(crate) fn to_std(&self, len: libc::socklen_t) -> Option<SocketAddr> {
        if len == 0 {
            return None;
        }
        sockaddr_to_std(&self.storage)
    }
}

fn last_os_error() -> io::Error {
    io::Error::last_os_error()
}

/// Create a non-blocking-agnostic TCP or UDP socket for `addr`'s family, with
/// `SO_REUSEADDR`, and `IPV6_V6ONLY=1` for v6 (never use v4-mapped addresses).
fn make_socket(addr: &SocketAddr, ty: libc::c_int) -> io::Result<RawFd> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: plain libc socket creation; the returned fd is checked.
    let fd = unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(last_os_error());
    }
    let one: libc::c_int = 1;
    // SAFETY: setsockopt with a valid fd and an int-sized option value.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if addr.is_ipv6() {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    Ok(fd)
}

/// `setsockopt` with a plain-old-data option value.
fn setsockopt<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a live POD value of exactly `size_of::<T>()` bytes.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            value as *const T as *const libc::c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if r < 0 { Err(last_os_error()) } else { Ok(()) }
}

fn bind_socket(fd: RawFd, addr: &SocketAddr) -> io::Result<()> {
    let raw = RawSockAddr::from(*addr);
    // SAFETY: `raw` outlives the call; ptr/len describe a valid sockaddr.
    let r = unsafe { libc::bind(fd, raw.as_ptr(), raw.len()) };
    if r < 0 { Err(last_os_error()) } else { Ok(()) }
}

fn peer_addr_of(fd: RawFd) -> io::Result<SocketAddr> {
    // SAFETY: getpeername fills `storage` up to `len`; both are valid and sized.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let r =
        unsafe { libc::getpeername(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) };
    if r < 0 {
        return Err(last_os_error());
    }
    sockaddr_to_std(&storage).ok_or_else(|| io::Error::other("unknown address family"))
}

fn local_addr_of(fd: RawFd) -> io::Result<SocketAddr> {
    // SAFETY: getsockname fills `storage` up to `len`; both are valid and sized.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let r =
        unsafe { libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) };
    if r < 0 {
        return Err(last_os_error());
    }
    sockaddr_to_std(&storage).ok_or_else(|| io::Error::other("unknown address family"))
}

fn sockaddr_to_std(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: family is AF_INET, so the storage holds a sockaddr_in.
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            // `s_addr` is stored in network byte order; its bytes are the octets
            // in order, so build the address from those bytes directly.
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            // SAFETY: family is AF_INET6, so the storage holds a sockaddr_in6.
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::new(
                IpAddr::V6(ip),
                u16::from_be(sin6.sin6_port),
            ))
        }
        _ => None,
    }
}

/// An owned socket fd that closes through the ring on drop.
struct OwnedFd {
    fd: RawFd,
    _not_send: PhantomData<Rc<()>>,
}

impl OwnedFd {
    fn new(fd: RawFd) -> OwnedFd {
        OwnedFd {
            fd,
            _not_send: PhantomData,
        }
    }
    fn raw(&self) -> RawFd {
        self.fd
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        close_fd_detached(self.fd);
    }
}

/// A TCP connection. All data transfer goes through io_uring.
pub struct TcpStream {
    fd: OwnedFd,
}

impl TcpStream {
    /// Connect to `addr` over io_uring.
    pub async fn connect(addr: SocketAddr) -> Result<TcpStream> {
        let fd = make_socket(&addr, libc::SOCK_STREAM)?;
        let owned = OwnedFd::new(fd);
        connect(fd, RawSockAddr::from(addr)).await?;
        Ok(TcpStream { fd: owned })
    }

    /// Connect, binding the local endpoint to `local` first (used to present a
    /// specific source address in the dual-stack matrix).
    pub async fn connect_from(local: IpAddr, addr: SocketAddr) -> Result<TcpStream> {
        let fd = make_socket(&addr, libc::SOCK_STREAM)?;
        let owned = OwnedFd::new(fd);
        bind_socket(fd, &SocketAddr::new(local, 0))?;
        connect(fd, RawSockAddr::from(addr)).await?;
        Ok(TcpStream { fd: owned })
    }

    fn from_fd(fd: RawFd) -> TcpStream {
        TcpStream {
            fd: OwnedFd::new(fd),
        }
    }

    /// The raw fd (for tests / diagnostics).
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.raw()
    }

    /// Local address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(local_addr_of(self.fd.raw())?)
    }

    /// Remote address.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(peer_addr_of(self.fd.raw())?)
    }

    /// Set `TCP_NODELAY` (one-time socket setup, off the ring).
    pub fn set_nodelay(&self, on: bool) -> Result<()> {
        let v: libc::c_int = i32::from(on);
        // SAFETY: setsockopt with a valid fd and an int-sized option value.
        let r = unsafe {
            libc::setsockopt(
                self.fd.raw(),
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &v as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r < 0 {
            Err(last_os_error().into())
        } else {
            Ok(())
        }
    }

    /// Send `buf`. Returns the number of bytes accepted and the buffer back
    /// (owned-buffer discipline). Fewer than `buf.len()` bytes may be sent.
    pub async fn send(&self, buf: Buffer) -> (Result<u32>, Buffer) {
        let (r, b) = send(self.fd.raw(), buf).await;
        (r.map_err(Into::into), b)
    }

    /// Send all of `buf`, resubmitting on short writes.
    pub async fn send_all(&self, buf: Buffer) -> Result<Buffer> {
        let len = buf.len();
        self.send_all_range(buf, 0, len).await
    }

    /// Send all of `buf[start..start + len]`, resubmitting on short writes,
    /// without copying: the buffer comes back untouched.
    pub async fn send_all_range(&self, buf: Buffer, start: usize, len: usize) -> Result<Buffer> {
        if start + len > buf.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let mut buf = buf;
        let mut sent = 0usize;
        while sent < len {
            let (r, b) = send_range(self.fd.raw(), buf, start + sent, len - sent).await;
            buf = b;
            match r {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => sent += n as usize,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(buf)
    }

    /// Receive into `buf` (sized to its length). Returns bytes read and the
    /// buffer (truncated to that many bytes). `Ok(0)` means the peer closed.
    pub async fn recv(&self, buf: Buffer) -> (Result<u32>, Buffer) {
        let (r, b) = recv(self.fd.raw(), buf).await;
        (r.map_err(Into::into), b)
    }

    /// Send bytes `[start, start + len)` of the concatenation of `chunks` in
    /// as few `sendmsg` operations as possible, without copying (each chunk
    /// becomes an iovec); the chunks come back untouched. This is how a
    /// batch of `piece` messages leaves: framing bytes and block buffers
    /// interleaved, one operation.
    pub async fn send_all_chunks(
        &self,
        chunks: Vec<Buffer>,
        start: usize,
        len: usize,
    ) -> Result<Vec<Buffer>> {
        let total: usize = chunks.iter().map(Buffer::len).sum();
        if start + len > total {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let mut chunks = chunks;
        let mut sent = 0usize;
        while sent < len {
            let (r, c) = send_chunks(self.fd.raw(), chunks, start + sent, len - sent).await;
            chunks = c;
            match r {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => sent += n as usize,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(chunks)
    }

    /// [`send_all_chunks`] with zero-copy sends (`IORING_OP_SENDMSG_ZC`):
    /// the kernel transmits straight from the chunks and keeps them
    /// referenced until the peer acknowledges the data, which is why they
    /// are shared (`Rc`) rather than returned. Requires the `send_zc` probe;
    /// worth it on real NICs with large payloads, not on loopback (measure).
    ///
    /// [`send_all_chunks`]: TcpStream::send_all_chunks
    pub async fn send_all_chunks_zc(
        &self,
        chunks: Rc<Vec<Buffer>>,
        start: usize,
        len: usize,
    ) -> Result<()> {
        let total: usize = chunks.iter().map(Buffer::len).sum();
        if start + len > total {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let mut sent = 0usize;
        while sent < len {
            match send_chunks_zc(self.fd.raw(), chunks.clone(), start + sent, len - sent).await {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => sent += n as usize,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Receive continuously into `ring`'s buffers (multishot `recv` with
    /// `IOSQE_BUFFER_SELECT`): one SQE serves every chunk until the peer
    /// closes or an error ends it. See [`RecvMulti`].
    pub fn recv_multi(&self, ring: &BufRing) -> RecvMulti {
        RecvMulti {
            fd: self.fd.raw(),
            ring: ring.inner().clone(),
            op: None,
        }
    }

    /// Graceful close through the ring (awaits the CQE).
    pub async fn close(self) -> Result<()> {
        let fd = self.fd.raw();
        mem::forget(self.fd); // avoid the detached close in Drop
        reactor::close(fd).await.map_err(Into::into)
    }
}

/// A multishot receive on a [`TcpStream`]. `next` yields each chunk as it
/// lands; when the ring runs out of buffers the kernel ends the multishot
/// with `ENOBUFS` and `next` re-arms it once a buffer is returned, so the
/// caller only ever sees data, end of stream, or a real socket error.
/// Dropping the `next` future (a timeout, a `select`) does not cancel the
/// receive; dropping the `RecvMulti` does.
pub struct RecvMulti {
    fd: RawFd,
    ring: Rc<BufRingInner>,
    op: Option<MultiOp>,
}

impl RecvMulti {
    /// The next received chunk; `Ok(None)` when the peer closed.
    pub async fn next(&mut self) -> Result<Option<RingBuf>> {
        loop {
            if self.op.is_none() {
                self.wait_for_buffer().await;
                let ring = self.ring.clone();
                let fd = self.fd;
                let bgid = self.ring.bgid();
                self.op = Some(MultiOp::submit(ring, move |ud| {
                    io_uring::opcode::RecvMulti::new(io_uring::types::Fd(fd), bgid)
                        .build()
                        .user_data(ud)
                }));
            }
            let Some(op) = self.op.as_mut() else { continue };
            match op.next().await {
                None => {
                    // The multishot ended (after an error we already
                    // reported, or a kernel-side stop); arm again.
                    self.op = None;
                }
                Some((res, flags)) => {
                    let bid = io_uring::cqueue::buffer_select(flags);
                    if !io_uring::cqueue::more(flags) {
                        // Last CQE of this op: drain it on the next call.
                        self.op = None;
                    }
                    if res > 0 {
                        let Some(bid) = bid else {
                            return Err(io::Error::other("recv completion without buffer").into());
                        };
                        return Ok(Some(self.ring.take(bid, res as usize)));
                    }
                    if let Some(bid) = bid {
                        self.ring.recycle_bid(bid);
                    }
                    if res == 0 {
                        return Ok(None);
                    }
                    if res == -libc::ENOBUFS {
                        self.op = None;
                        continue;
                    }
                    return Err(io::Error::from_raw_os_error(-res).into());
                }
            }
        }
    }

    /// A chunk that has already arrived, without waiting: `Some(Some(buf))`
    /// data, `Some(None)` end of stream, `None` nothing queued right now.
    /// Errors and ring exhaustion are left for the next [`next`] call.
    ///
    /// [`next`]: RecvMulti::next
    pub fn try_next(&mut self) -> Option<Option<RingBuf>> {
        let op = self.op.as_mut()?;
        let (res, flags) = op.try_next()??;
        let bid = io_uring::cqueue::buffer_select(flags);
        if !io_uring::cqueue::more(flags) {
            self.op = None;
        }
        if res > 0 {
            let bid = bid?;
            return Some(Some(self.ring.take(bid, res as usize)));
        }
        if let Some(bid) = bid {
            self.ring.recycle_bid(bid);
        }
        if res == 0 {
            return Some(None);
        }
        // An error ended the op: `next` re-arms (and a persistent socket
        // error recurs there, where it is reported).
        None
    }

    async fn wait_for_buffer(&self) {
        std::future::poll_fn(|cx| {
            if self.ring.free() > 0 {
                std::task::Poll::Ready(())
            } else {
                self.ring.wait_free(cx.waker());
                std::task::Poll::Pending
            }
        })
        .await
    }
}

/// A TCP listener. `accept` goes through the ring.
pub struct TcpListener {
    fd: OwnedFd,
    local: SocketAddr,
}

impl TcpListener {
    /// Bind and listen on `addr` (v4 or v6; v6 is v6-only).
    pub fn bind(addr: SocketAddr) -> Result<TcpListener> {
        let fd = make_socket(&addr, libc::SOCK_STREAM)?;
        let owned = OwnedFd::new(fd);
        bind_socket(fd, &addr)?;
        // SAFETY: valid listening fd; backlog is a small positive constant.
        if unsafe { libc::listen(fd, 1024) } < 0 {
            return Err(last_os_error().into());
        }
        let local = local_addr_of(fd)?;
        Ok(TcpListener { fd: owned, local })
    }

    /// The bound local address (with the real port when 0 was requested).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Accept one connection over the ring.
    pub async fn accept(&self) -> Result<TcpStream> {
        let fd = accept(self.fd.raw()).await?;
        Ok(TcpStream::from_fd(fd))
    }
}

/// A UDP socket. `recv`/`send` go through the ring (used for the UDP tracker
/// and LSD; the listen port's UDP socket is owned here per AGENTS.md 4).
pub struct UdpSocket {
    fd: OwnedFd,
    local: SocketAddr,
}

impl UdpSocket {
    /// Bind a UDP socket to `addr`.
    pub fn bind(addr: SocketAddr) -> Result<UdpSocket> {
        let fd = make_socket(&addr, libc::SOCK_DGRAM)?;
        let owned = OwnedFd::new(fd);
        bind_socket(fd, &addr)?;
        let local = local_addr_of(fd)?;
        Ok(UdpSocket { fd: owned, local })
    }

    /// Bind a multicast receiver/sender for `group` on port `port` (BEP 14
    /// LSD): `SO_REUSEADDR`, bound to the wildcard address of the group's
    /// family, joined on `iface` (a local address for IPv4, ignored for IPv6
    /// where the kernel's default interface is used), with `hops` as the
    /// TTL / hop limit and multicast loopback on. One-time setup with
    /// blocking `setsockopt` calls (AGENTS.md 5.3, non-critical); every
    /// datagram afterwards moves over the ring.
    pub fn bind_multicast(
        group: IpAddr,
        port: u16,
        iface: Option<IpAddr>,
        hops: u8,
    ) -> Result<UdpSocket> {
        let any = match group {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
        };
        let fd = make_socket(&any, libc::SOCK_DGRAM)?;
        let owned = OwnedFd::new(fd);
        bind_socket(fd, &any)?;
        let hops_i: libc::c_int = libc::c_int::from(hops);
        let one: libc::c_int = 1;
        match group {
            IpAddr::V4(g) => {
                let iface_v4 = match iface {
                    Some(IpAddr::V4(a)) => a,
                    _ => Ipv4Addr::UNSPECIFIED,
                };
                let mreq = libc::ip_mreqn {
                    imr_multiaddr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(g.octets()),
                    },
                    imr_address: libc::in_addr {
                        s_addr: u32::from_ne_bytes(iface_v4.octets()),
                    },
                    imr_ifindex: 0,
                };
                setsockopt(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &mreq)?;
                setsockopt(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, &hops_i)?;
                setsockopt(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, &one)?;
                if !iface_v4.is_unspecified() {
                    let out = libc::in_addr {
                        s_addr: u32::from_ne_bytes(iface_v4.octets()),
                    };
                    setsockopt(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &out)?;
                }
            }
            IpAddr::V6(g) => {
                let mreq = libc::ipv6_mreq {
                    ipv6mr_multiaddr: libc::in6_addr {
                        s6_addr: g.octets(),
                    },
                    ipv6mr_interface: 0,
                };
                setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &mreq)?;
                setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &hops_i)?;
                setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, &one)?;
            }
        }
        let local = local_addr_of(fd)?;
        Ok(UdpSocket { fd: owned, local })
    }

    /// The bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Connect the socket so `send`/`recv` target one peer (simplest path;
    /// `recvmsg`/`sendmsg` for unconnected multi-peer use land with the UDP
    /// tracker in M5).
    pub fn connect(&self, addr: SocketAddr) -> Result<()> {
        let raw = RawSockAddr::from(addr);
        // SAFETY: valid fd and sockaddr for the socket's family.
        let r = unsafe { libc::connect(self.fd.raw(), raw.as_ptr(), raw.len()) };
        if r < 0 {
            Err(last_os_error().into())
        } else {
            Ok(())
        }
    }

    /// Send a datagram to the connected peer.
    pub async fn send(&self, buf: Buffer) -> (Result<u32>, Buffer) {
        let (r, b) = send(self.fd.raw(), buf).await;
        (r.map_err(Into::into), b)
    }

    /// Receive one datagram from the connected peer.
    pub async fn recv(&self, buf: Buffer) -> (Result<u32>, Buffer) {
        let (r, b) = recv(self.fd.raw(), buf).await;
        (r.map_err(Into::into), b)
    }

    /// Send a datagram to `addr` (unconnected socket, `sendmsg`).
    pub async fn send_to(&self, buf: Buffer, addr: SocketAddr) -> (Result<u32>, Buffer) {
        let (r, b) = reactor::send_to(self.fd.raw(), buf, RawSockAddr::from(addr)).await;
        (r.map_err(Into::into), b)
    }

    /// Receive a datagram and its sender (`recvmsg`). The buffer is truncated
    /// to the datagram length.
    pub async fn recv_from(&self, buf: Buffer) -> (Result<u32>, Buffer, Option<SocketAddr>) {
        let (r, b, from) = reactor::recv_from(self.fd.raw(), buf).await;
        (r.map_err(Into::into), b, from)
    }
}
