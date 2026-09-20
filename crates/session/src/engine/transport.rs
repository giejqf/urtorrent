// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The byte transport under a peer connection: TCP on the network ring, or
//! uTP (BEP 29) over the listen port's UDP socket. The peer state machine
//! only ever sees `recv` / chunks / `send_all*`, so both look the same to
//! it (AGENTS.md 4, "must not preclude").

use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;

use uring::{BufRing, Buffer, RecvMulti, RingBuf, TcpStream};

pub use crate::api::PeerTransport as TransportKind;

use super::utp::UtpStream;

/// A connected peer transport.
pub enum Transport {
    /// A TCP connection on the network ring.
    Tcp(TcpStream),
    /// A uTP connection over the UDP listen socket.
    Utp(Rc<UtpStream>),
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

    /// Dial `addr` over uTP through `host`.
    pub async fn connect_utp(
        host: &Rc<super::utp::UtpHost>,
        addr: SocketAddr,
    ) -> uring::Result<Transport> {
        let s = host.connect(addr, std::time::Instant::now());
        s.connected().await?;
        Ok(Transport::Utp(Rc::new(s)))
    }

    /// The transport in use.
    pub fn kind(&self) -> TransportKind {
        match self {
            Transport::Tcp(_) => TransportKind::Tcp,
            Transport::Utp(_) => TransportKind::Utp,
        }
    }

    /// Remote address.
    pub fn peer_addr(&self) -> uring::Result<SocketAddr> {
        match self {
            Transport::Tcp(s) => s.peer_addr(),
            Transport::Utp(s) => Ok(s.peer_addr()),
        }
    }

    /// Local address.
    pub fn local_addr(&self) -> uring::Result<SocketAddr> {
        match self {
            Transport::Tcp(s) => s.local_addr(),
            Transport::Utp(s) => s
                .local_addr()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotConnected).into()),
        }
    }

    /// Latency-oriented setup after the handshake (`TCP_NODELAY`; a no-op
    /// for transports without the knob).
    pub fn set_nodelay(&self, on: bool) -> uring::Result<()> {
        match self {
            Transport::Tcp(s) => s.set_nodelay(on),
            Transport::Utp(_) => Ok(()),
        }
    }

    /// The close reason to tell the peer (uTP carries it in the FIN,
    /// libtorrent's `close_reason_t` codes; TCP has no channel for it).
    pub fn set_close_reason(&self, code: u16) {
        if let Transport::Utp(s) = self {
            s.set_close_reason(code);
        }
    }

    /// Receive into `buf` (sized to its length); `Ok(0)` is end of stream.
    /// Handshakes use this; the established connection uses [`receiver`].
    ///
    /// [`receiver`]: Transport::receiver
    pub async fn recv(&self, buf: Buffer) -> (uring::Result<u32>, Buffer) {
        match self {
            Transport::Tcp(s) => s.recv(buf).await,
            Transport::Utp(s) => s.recv(buf).await,
        }
    }

    /// The connection's inbound byte stream: TCP chunks land in `ring`'s
    /// provided buffers with one standing multishot receive; uTP chunks are
    /// the reassembled payloads.
    pub fn receiver(&self, ring: &BufRing) -> Receiver {
        match self {
            Transport::Tcp(s) => Receiver::Tcp(s.recv_multi(ring)),
            Transport::Utp(s) => Receiver::Utp(s.clone()),
        }
    }

    /// Send all of `buf`.
    pub async fn send_all(&self, buf: Buffer) -> uring::Result<Buffer> {
        match self {
            Transport::Tcp(s) => s.send_all(buf).await,
            Transport::Utp(s) => {
                s.send_all(buf.as_slice().to_vec()).await?;
                Ok(buf)
            }
        }
    }

    /// [`send_all_chunks`] with zero-copy sends (the chunks are shared with
    /// the kernel until acknowledged, hence the `Rc`).
    ///
    /// [`send_all_chunks`]: Transport::send_all_chunks
    pub async fn send_all_chunks_zc(
        &self,
        chunks: Rc<Vec<Buffer>>,
        start: usize,
        len: usize,
    ) -> uring::Result<()> {
        match self {
            Transport::Tcp(s) => s.send_all_chunks_zc(chunks, start, len).await,
            Transport::Utp(s) => s.send_range(&chunks, start, len).await,
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
            Transport::Utp(s) => {
                s.send_range(&chunks, start, len).await?;
                Ok(chunks)
            }
        }
    }
}

/// A received chunk: a provided ring buffer (TCP) or an owned payload (uTP).
pub enum Chunk {
    /// Bytes in the session's provided buffer ring.
    Ring(RingBuf),
    /// Reassembled uTP payload.
    Owned(Vec<u8>),
}

impl Chunk {
    /// The bytes.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Chunk::Ring(r) => r.as_slice(),
            Chunk::Owned(v) => v,
        }
    }

    /// The bytes, mutably (ciphers decrypt in place).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Chunk::Ring(r) => r.as_mut_slice(),
            Chunk::Owned(v) => v,
        }
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        match self {
            Chunk::Ring(r) => r.len(),
            Chunk::Owned(v) => v.len(),
        }
    }

    /// Whether the chunk is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Inbound chunks of a [`Transport`].
pub enum Receiver {
    /// Multishot TCP receive.
    Tcp(RecvMulti),
    /// uTP payloads.
    Utp(Rc<UtpStream>),
}

impl Receiver {
    /// The next chunk; `Ok(None)` at end of stream.
    pub async fn next(&mut self) -> uring::Result<Option<Chunk>> {
        match self {
            Receiver::Tcp(r) => Ok(r.next().await?.map(Chunk::Ring)),
            Receiver::Utp(s) => Ok(s.next().await?.map(Chunk::Owned)),
        }
    }

    /// A chunk that already arrived, without waiting (`Some(None)` = end of
    /// stream, `None` = nothing queued).
    pub fn try_next(&mut self) -> Option<Option<Chunk>> {
        match self {
            Receiver::Tcp(r) => r.try_next().map(|o| o.map(Chunk::Ring)),
            Receiver::Utp(s) => s.try_next().map(|o| o.map(Chunk::Owned)),
        }
    }
}
