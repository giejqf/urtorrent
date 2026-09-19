// SPDX-License-Identifier: Apache-2.0
//! Minimal torrent fixture builder for storage tests (independent of testkit).
#![allow(clippy::unwrap_used, dead_code, missing_docs)]

use sha1::{Digest, Sha1};

fn benc_int(out: &mut Vec<u8>, i: i64) {
    out.push(b'i');
    out.extend_from_slice(i.to_string().as_bytes());
    out.push(b'e');
}
fn benc_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(b.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(b);
}

/// (torrent_bytes, content) where content is the concatenated stream.
pub struct Fixture {
    pub torrent: Vec<u8>,
    pub content: Vec<u8>,
    pub piece_length: u32,
}

/// Deterministic pseudo-random content.
pub fn gen_content(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_add(0x9e3779b97f4a7c15);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xff) as u8
        })
        .collect()
}

fn pieces_hashes(content: &[u8], piece_length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in content.chunks(piece_length) {
        let mut h = Sha1::new();
        h.update(chunk);
        out.extend_from_slice(&h.finalize());
    }
    out
}

/// A single-file torrent.
pub fn single(name: &str, len: usize, piece_length: u32, seed: u64) -> Fixture {
    let content = gen_content(len, seed);
    let pieces = pieces_hashes(&content, piece_length as usize);
    let mut info = Vec::new();
    info.push(b'd');
    benc_bytes(&mut info, b"length");
    benc_int(&mut info, len as i64);
    benc_bytes(&mut info, b"name");
    benc_bytes(&mut info, name.as_bytes());
    benc_bytes(&mut info, b"piece length");
    benc_int(&mut info, i64::from(piece_length));
    benc_bytes(&mut info, b"pieces");
    benc_bytes(&mut info, &pieces);
    info.push(b'e');
    let mut torrent = Vec::new();
    torrent.push(b'd');
    benc_bytes(&mut torrent, b"info");
    torrent.extend_from_slice(&info);
    torrent.push(b'e');
    Fixture {
        torrent,
        content,
        piece_length,
    }
}

/// A multi-file torrent. `files` = (path components joined by '/', length).
pub fn multi(name: &str, files: &[(&str, usize)], piece_length: u32, seed: u64) -> Fixture {
    let total: usize = files.iter().map(|(_, l)| *l).sum();
    let content = gen_content(total, seed);
    let pieces = pieces_hashes(&content, piece_length as usize);
    let mut info = Vec::new();
    info.push(b'd');
    benc_bytes(&mut info, b"files");
    info.push(b'l');
    for (path, len) in files {
        info.push(b'd');
        benc_bytes(&mut info, b"length");
        benc_int(&mut info, *len as i64);
        benc_bytes(&mut info, b"path");
        info.push(b'l');
        for comp in path.split('/') {
            benc_bytes(&mut info, comp.as_bytes());
        }
        info.push(b'e');
        info.push(b'e');
    }
    info.push(b'e');
    benc_bytes(&mut info, b"name");
    benc_bytes(&mut info, name.as_bytes());
    benc_bytes(&mut info, b"piece length");
    benc_int(&mut info, i64::from(piece_length));
    benc_bytes(&mut info, b"pieces");
    benc_bytes(&mut info, &pieces);
    info.push(b'e');
    let mut torrent = Vec::new();
    torrent.push(b'd');
    benc_bytes(&mut torrent, b"info");
    torrent.extend_from_slice(&info);
    torrent.push(b'e');
    Fixture {
        torrent,
        content,
        piece_length,
    }
}
