// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The byte transport under a peer connection. TCP is the only variant in
//! 0.x; uTP (BEP 29) slots in here as a second variant without touching the
//! peer state machine, which only ever sees `recv` / `send_all_range`
//! (AGENTS.md 4, "must not preclude").

use std::net::{IpAddr, SocketAddr};

use uring::{BufRing, Buffer, RecvMulti, RingBuf, TcpStream};

pub use crate::api::PeerTransport as TransportKind;

/// A connected peer transport.
pub enum Transport {
    /// A TCP connection on the network ring.
    Tcp(TcpStream),
}

impl Transport {
    /// Dial `addr` over TCP, optionally from a fixed local address.
    pub async fn connect_tcp(local: Option<IpAddr>, addr: SocketAddr) -> uring::Result<Transport> {
        let s = match local {
            Some(l) => TcpStream::connect_from(l, addr).await?,
            None => TcpStream::connect(addr).await?,
        };
        Ok(Transport::Tcp(s))
    }

    /// The transport in use.
    pub fn kind(&self) -> TransportKind {
        match self {
            Transport::Tcp(_) => TransportKind::Tcp,
        }
    }

    /// Remote address.
    pub fn peer_addr(&self) -> uring::Result<SocketAddr> {
        match self {
            Transport::Tcp(s) => s.peer_addr(),
        }
    }

    /// Local address.
    pub fn local_addr(&self) -> uring::Result<SocketAddr> {
        match self {
            Transport::Tcp(s) => s.local_addr(),
        }
    }

    /// Latency-oriented setup after the handshake (`TCP_NODELAY`; a no-op
    /// for transports without the knob).
    pub fn set_nodelay(&self, on: bool) -> uring::Result<()> {
        match self {
            Transport::Tcp(s) => s.set_nodelay(on),
        }
    }

    /// Receive into `buf` (sized to its length); `Ok(0)` is end of stream.
    /// Handshakes use this; the established connection uses [`receiver`].
    ///
    /// [`receiver`]: Transport::receiver
    pub async fn recv(&self, buf: Buffer) -> (uring::Result<u32>, Buffer) {
        match self {
            Transport::Tcp(s) => s.recv(buf).await,
        }
    }

    /// The connection's inbound byte stream: chunks land in `ring`'s
    /// provided buffers with one standing multishot receive.
    pub fn receiver(&self, ring: &BufRing) -> Receiver {
        match self {
            Transport::Tcp(s) => Receiver::Tcp(s.recv_multi(ring)),
        }
    }

    /// Send all of `buf`.
    pub async fn send_all(&self, buf: Buffer) -> uring::Result<Buffer> {
        match self {
            Transport::Tcp(s) => s.send_all(buf).await,
        }
    }

    /// [`send_all_chunks`] with zero-copy sends (the chunks are shared with
    /// the kernel until acknowledged, hence the `Rc`).
    ///
    /// [`send_all_chunks`]: Transport::send_all_chunks
    pub async fn send_all_chunks_zc(
        &self,
        chunks: std::rc::Rc<Vec<Buffer>>,
        start: usize,
        len: usize,
    ) -> uring::Result<()> {
        match self {
            Transport::Tcp(s) => s.send_all_chunks_zc(chunks, start, len).await,
        }
    }

    /// Send bytes `[start, start + len)` of the concatenated `chunks` in as
    /// few operations as possible, without copying.
    pub async fn send_all_chunks(
        &self,
        chunks: Vec<Buffer>,
        start: usize,
        len: usize,
    ) -> uring::Result<Vec<Buffer>> {
        match self {
            Transport::Tcp(s) => s.send_all_chunks(chunks, start, len).await,
        }
    }
}

/// Inbound chunks of a [`Transport`].
pub enum Receiver {
    /// Multishot TCP receive.
    Tcp(RecvMulti),
}

impl Receiver {
    /// The next chunk; `Ok(None)` at end of stream.
    pub async fn next(&mut self) -> uring::Result<Option<RingBuf>> {
        match self {
            Receiver::Tcp(r) => r.next().await,
        }
    }

    /// A chunk that already arrived, without waiting (`Some(None)` = end of
    /// stream, `None` = nothing queued).
    pub fn try_next(&mut self) -> Option<Option<RingBuf>> {
        match self {
            Receiver::Tcp(r) => r.try_next(),
        }
    }
}
