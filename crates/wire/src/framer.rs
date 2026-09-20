// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Length-prefixed message framing with a hard size bound.

use crate::Error;

/// Maximum frame body we accept (a `piece` with a [`crate::MAX_BLOCK`]
/// payload or a bitfield for a very large torrent both fit comfortably;
/// anything larger is a hostile or broken peer).
pub const MAX_FRAME: usize = 1 << 20;

/// Accumulates bytes and yields complete `<len:u32 BE><body>` frames.
#[derive(Debug, Default)]
pub struct Framer {
    buf: Vec<u8>,
    pos: usize,
}

impl Framer {
    /// An empty framer.
    pub fn new() -> Framer {
        Framer::default()
    }

    /// Append received bytes. Fails if the buffered-but-unframed data would
    /// exceed the bound (which can only happen with an oversized frame).
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.pos > 0 && self.pos >= self.buf.len() / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        if self.buf.len() - self.pos + bytes.len() > MAX_FRAME + 4 {
            return Err(Error::TooLarge);
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// The next complete frame body, if one is buffered. A zero-length frame
    /// (keep-alive) is returned as an empty slice.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, Error> {
        let avail = &self.buf[self.pos..];
        if avail.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([avail[0], avail[1], avail[2], avail[3]]) as usize;
        if len > MAX_FRAME {
            return Err(Error::TooLarge);
        }
        if avail.len() < 4 + len {
            return Ok(None);
        }
        let start = self.pos + 4;
        self.pos = start + len;
        Ok(Some(&self.buf[start..start + len]))
    }

    /// Bytes buffered but not yet framed.
    pub fn pending(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Discard `n` buffered bytes (used to strip the handshake).
    pub fn consume(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_across_pushes() {
        let mut f = Framer::new();
        f.push(&[0, 0, 0]).unwrap();
        assert_eq!(f.next_frame().unwrap(), None);
        f.push(&[2, 0x01]).unwrap();
        assert_eq!(f.next_frame().unwrap(), None);
        f.push(&[0x02, 0, 0, 0, 0]).unwrap();
        assert_eq!(f.next_frame().unwrap(), Some(&[1u8, 2][..]));
        assert_eq!(f.next_frame().unwrap(), Some(&[][..]));
        assert_eq!(f.next_frame().unwrap(), None);
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut f = Framer::new();
        f.push(&(MAX_FRAME as u32 + 1).to_be_bytes()).unwrap();
        assert_eq!(f.next_frame(), Err(Error::TooLarge));
        let mut g = Framer::new();
        assert_eq!(g.push(&vec![0u8; MAX_FRAME + 5]), Err(Error::TooLarge));
    }

    #[test]
    fn compaction_keeps_data() {
        let mut f = Framer::new();
        for i in 0..1000u32 {
            let mut frame = vec![0, 0, 0, 4];
            frame.extend_from_slice(&i.to_be_bytes());
            f.push(&frame).unwrap();
            let got = f.next_frame().unwrap().unwrap().to_vec();
            assert_eq!(got, i.to_be_bytes());
        }
        assert!(f.buf.len() < 64);
    }
}
