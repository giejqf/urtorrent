// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! A std `TcpStream` with an optional MSE RC4 layer and a plaintext prefix
//! (bytes the handshake already decrypted), so the tap-peer's framing code
//! works unchanged over encrypted connections.

use std::io::{self, Read, Write};
use std::net::TcpStream;

pub struct CipherStream {
    inner: TcpStream,
    enc: Option<mse::Rc4Stream>,
    dec: Option<mse::Rc4Stream>,
    pre: Vec<u8>,
}

impl CipherStream {
    pub fn plain(inner: TcpStream) -> CipherStream {
        CipherStream {
            inner,
            enc: None,
            dec: None,
            pre: Vec::new(),
        }
    }

    /// Install the streams negotiated by an MSE handshake; `pre` is plaintext
    /// already produced by it (e.g. the peer's BitTorrent handshake).
    pub fn install(
        &mut self,
        enc: Option<mse::Rc4Stream>,
        dec: Option<mse::Rc4Stream>,
        pre: Vec<u8>,
    ) {
        self.enc = enc;
        self.dec = dec;
        let mut p = pre;
        p.extend_from_slice(&self.pre);
        self.pre = p;
    }

    pub fn inner(&self) -> &TcpStream {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut TcpStream {
        &mut self.inner
    }

    /// Raw (unciphered) read, for the handshake phase.
    pub fn read_raw(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    /// Raw write, for the handshake phase.
    pub fn write_raw(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf)
    }
}

impl Read for CipherStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pre.is_empty() {
            let n = buf.len().min(self.pre.len());
            buf[..n].copy_from_slice(&self.pre[..n]);
            self.pre.drain(..n);
            return Ok(n);
        }
        let n = self.inner.read(buf)?;
        if let Some(d) = self.dec.as_mut() {
            d.apply(&mut buf[..n]);
        }
        Ok(n)
    }
}

impl Write for CipherStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.enc.as_mut() {
            Some(e) => {
                let mut copy = buf.to_vec();
                e.apply(&mut copy);
                self.inner.write_all(&copy)?;
                Ok(buf.len())
            }
            None => self.inner.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
