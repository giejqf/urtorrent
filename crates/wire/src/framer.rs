// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Length-prefixed message framing with a hard size bound.
//!
//! Frames that lie entirely within the bytes just received are handed to
//! the caller straight from that slice; only a frame cut by the chunk
//! boundary is buffered, and only the part of the next chunk that completes
//! it is copied. The bytes copied are counted (`copied`) so the data path's
//! copy budget can be gated in tests.

use crate::Error;

/// Maximum frame body we accept (a `piece` with a [`crate::MAX_BLOCK`]
/// payload or a bitfield for a very large torrent both fit comfortably;
/// anything larger is a hostile or broken peer).
pub const MAX_FRAME: usize = 1 << 20;

/// A complete frame as the framer hands it out.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// The body, borrowed from the chunk it arrived in.
    Borrowed(&'a [u8]),
    /// A frame assembled across chunks: the framer's buffer, length prefix
    /// included (the body starts at byte 4), handed over so a `piece` can
    /// keep it as its block.
    Owned(Vec<u8>),
}

impl Frame<'_> {
    /// The frame body.
    pub fn body(&self) -> &[u8] {
        match self {
            Frame::Borrowed(b) => b,
            Frame::Owned(v) => &v[4..],
        }
    }
}

/// Accumulates the incomplete tail of a chunk and yields complete
/// `<len:u32 BE><body>` frames.
#[derive(Debug, Default)]
pub struct Framer {
    /// The partial frame carried over from earlier chunks (length prefix
    /// included), empty between frames.
    buf: Vec<u8>,
    /// Bytes copied into `buf` so far.
    copied: u64,
}

impl Framer {
    /// An empty framer.
    pub fn new() -> Framer {
        Framer::default()
    }

    /// Bytes copied into the carry-over buffer so far (frames that lay
    /// within one chunk cost nothing here).
    pub fn copied(&self) -> u64 {
        self.copied
    }

    /// Feed a chunk; `f` sees every complete frame body in order, most of
    /// them borrowed from `chunk` itself. A zero-length frame (keep-alive)
    /// is an empty slice. Fails if a frame exceeds the bound or `f` fails.
    pub fn feed<F>(&mut self, chunk: &[u8], mut f: F) -> Result<(), Error>
    where
        F: FnMut(Frame<'_>) -> Result<(), Error>,
    {
        let mut rest = chunk;
        // Finish a frame started in an earlier chunk.
        if !self.buf.is_empty() {
            let need = match self.pending_len()? {
                Some(n) => n + 4 - self.buf.len(),
                // Not even the length prefix yet: take what completes it.
                None => 4 - self.buf.len(),
            };
            let take = need.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            self.copied += take as u64;
            rest = &rest[take..];
            let Some(len) = self.pending_len()? else {
                return Ok(());
            };
            if self.buf.len() < 4 + len {
                if len > MAX_FRAME {
                    return Err(Error::TooLarge);
                }
                // The prefix just completed; take the body's share.
                let take = (4 + len - self.buf.len()).min(rest.len());
                self.buf.extend_from_slice(&rest[..take]);
                self.copied += take as u64;
                rest = &rest[take..];
                if self.buf.len() < 4 + len {
                    return Ok(());
                }
            }
            let mut frame = std::mem::take(&mut self.buf);
            frame.truncate(4 + len);
            f(Frame::Owned(frame))?;
        }
        // Whole frames straight from the chunk.
        while rest.len() >= 4 {
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if len > MAX_FRAME {
                return Err(Error::TooLarge);
            }
            if rest.len() < 4 + len {
                break;
            }
            f(Frame::Borrowed(&rest[4..4 + len]))?;
            rest = &rest[4 + len..];
        }
        // Carry the tail over.
        if !rest.is_empty() {
            self.buf.extend_from_slice(rest);
            self.copied += rest.len() as u64;
        }
        Ok(())
    }

    /// The frame length the carry-over buffer announces, once its prefix is
    /// complete.
    fn pending_len(&self) -> Result<Option<usize>, Error> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_FRAME {
            return Err(Error::TooLarge);
        }
        Ok(Some(len))
    }

    /// Bytes carried over but not yet framed.
    pub fn pending(&self) -> &[u8] {
        &self.buf
    }

    /// Discard `n` carried-over bytes (used to strip the handshake).
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.buf.len());
        self.buf.drain(..n);
    }

    /// Stash raw bytes without framing them (the handshake phase, where the
    /// caller parses the fixed-size prefix itself).
    pub fn stash(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.buf.len() + bytes.len() > MAX_FRAME + 4 {
            return Err(Error::TooLarge);
        }
        self.buf.extend_from_slice(bytes);
        self.copied += bytes.len() as u64;
        Ok(())
    }

    /// Frame whatever is stashed (after the handshake was stripped): the
    /// carry-over is re-fed as if it had just arrived.
    pub fn drain_stashed<F>(&mut self, f: F) -> Result<(), Error>
    where
        F: FnMut(Frame<'_>) -> Result<(), Error>,
    {
        let stashed = std::mem::take(&mut self.buf);
        let before = self.copied;
        let r = self.feed(&stashed, f);
        // Re-feeding is bookkeeping: the bytes were counted when stashed.
        self.copied = before;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(f: &mut Framer, chunk: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        f.feed(chunk, |b| {
            out.push(b.body().to_vec());
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn frames_across_chunks() {
        let mut f = Framer::new();
        assert!(collect(&mut f, &[0, 0, 0]).is_empty());
        assert!(collect(&mut f, &[2, 0x01]).is_empty());
        assert_eq!(
            collect(&mut f, &[0x02, 0, 0, 0, 0]),
            vec![vec![1u8, 2], vec![]]
        );
        assert!(collect(&mut f, &[]).is_empty());
        assert!(f.pending().is_empty());
    }

    #[test]
    fn whole_frames_are_not_copied() {
        let mut f = Framer::new();
        let mut chunk = Vec::new();
        for i in 0..10u8 {
            chunk.extend_from_slice(&[0, 0, 0, 3, i, i, i]);
        }
        let got = collect(&mut f, &chunk);
        assert_eq!(got.len(), 10);
        assert_eq!(f.copied(), 0);
        // A frame cut in two costs exactly its bytes.
        let big = vec![0u8; 100];
        let mut msg = vec![0, 0, 0, 100];
        msg.extend_from_slice(&big);
        assert!(collect(&mut f, &msg[..60]).is_empty());
        let mut owned = false;
        f.feed(&msg[60..], |fr| {
            owned = matches!(fr, Frame::Owned(_));
            assert_eq!(fr.body(), &big[..]);
            Ok(())
        })
        .unwrap();
        assert!(owned, "a frame cut across chunks is handed over owned");
        assert_eq!(f.copied(), 104);
        // Prefix split across chunks.
        assert!(collect(&mut f, &[0, 0]).is_empty());
        assert!(collect(&mut f, &[0]).is_empty());
        assert_eq!(collect(&mut f, &[1, 9]), vec![vec![9u8]]);
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut f = Framer::new();
        assert_eq!(
            f.feed(&(MAX_FRAME as u32 + 1).to_be_bytes(), |_| Ok(())),
            Err(Error::TooLarge)
        );
        let mut g = Framer::new();
        let mut split = Framer::new();
        assert!(split.feed(&[0x00, 0x10], |_| Ok(())).is_ok());
        assert_eq!(split.feed(&[0x00, 0x01], |_| Ok(())), Err(Error::TooLarge));
        assert_eq!(g.stash(&vec![0u8; MAX_FRAME + 5]), Err(Error::TooLarge));
    }

    #[test]
    fn stash_and_drain_for_the_handshake() {
        let mut f = Framer::new();
        f.stash(&[1, 2, 3]).unwrap();
        f.stash(&[0, 0, 0, 1, 7]).unwrap();
        assert_eq!(f.pending(), &[1, 2, 3, 0, 0, 0, 1, 7]);
        f.consume(3);
        let mut out = Vec::new();
        f.drain_stashed(|b| {
            out.push(b.body().to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(out, vec![vec![7u8]]);
        assert!(f.pending().is_empty());
    }

    #[test]
    fn many_small_frames_stay_bounded() {
        let mut f = Framer::new();
        for i in 0..1000u32 {
            let mut frame = vec![0, 0, 0, 4];
            frame.extend_from_slice(&i.to_be_bytes());
            let got = collect(&mut f, &frame);
            assert_eq!(got, vec![i.to_be_bytes().to_vec()]);
        }
        assert!(f.buf.capacity() < 64 || f.buf.is_empty());
    }
}
