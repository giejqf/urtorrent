// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Pure functions over a torrent's layout that both the disk-side
//! [`crate::Storage`] and the engine-side [`crate::DiskStore`] mirror use.

use metainfo::{Bitfield, Info};

/// Piece priorities derived from per-file priorities (one per `info.files`
/// entry): the highest priority of any non-padding file the piece touches
/// (libtorrent), 0 for a piece made only of skipped / padding bytes.
pub fn piece_priorities(info: &Info, prios: &[u8]) -> Vec<u8> {
    (0..info.piece_count())
        .map(|i| {
            info.piece_location(i)
                .map(|loc| {
                    loc.slices
                        .iter()
                        .filter(|s| !s.padding)
                        .map(|s| prios.get(s.file_index).copied().unwrap_or(0))
                        .max()
                        .unwrap_or(0)
                })
                .unwrap_or(0)
        })
        .collect()
}

/// Bytes of file `index` covered by verified pieces.
pub fn file_done(info: &Info, have: &Bitfield, index: usize) -> u64 {
    let Some(f) = info.files.get(index) else {
        return 0;
    };
    if f.length == 0 {
        return 0;
    }
    let piece_len = u64::from(info.piece_length);
    let first = (f.offset / piece_len) as usize;
    let last = ((f.offset + f.length - 1) / piece_len) as usize;
    let mut done = 0u64;
    for piece in first..=last {
        if !have.get(piece) {
            continue;
        }
        let ps = piece as u64 * piece_len;
        let pe = (ps + piece_len).min(info.total_length);
        let s = ps.max(f.offset);
        let e = pe.min(f.offset + f.length);
        if e > s {
            done += e - s;
        }
    }
    done
}
