// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Piece↔file span mapping. A piece is a contiguous range of the torrent's
//! logical byte stream; that range can straddle several files (and padding
//! files). The storage layer reads/writes a piece by touching each [`FileSlice`].

use crate::Info;

/// A contiguous slice of one file that a piece (or block) covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSlice {
    /// Index into [`Info::files`].
    pub file_index: usize,
    /// Byte offset within that file.
    pub file_offset: u64,
    /// Number of bytes.
    pub length: u64,
    /// Whether the file is a padding file (BEP 47): its bytes are synthetic
    /// zeros for hashing and are not written to disk as user content.
    pub padding: bool,
}

/// Where a piece lives on disk: the file slices it spans, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceLocation {
    /// The piece index.
    pub index: usize,
    /// Byte offset of the piece within the whole torrent stream.
    pub torrent_offset: u64,
    /// The piece's total length.
    pub length: u64,
    /// The file slices, in stream order.
    pub slices: Vec<FileSlice>,
}

/// Compute the file slices covering piece `index`.
pub fn piece_location(info: &Info, index: usize) -> Option<PieceLocation> {
    let piece_len = u64::from(info.piece_length);
    let start = (index as u64).checked_mul(piece_len)?;
    if start >= info.total_length && !(info.total_length == 0 && index == 0) {
        return None;
    }
    let this_len = (info.total_length - start).min(piece_len);
    let end = start + this_len;
    let slices = slices_for_range(info, start, end);
    Some(PieceLocation {
        index,
        torrent_offset: start,
        length: this_len,
        slices,
    })
}

/// The file slices covering the torrent byte range `[start, end)`.
pub fn slices_for_range(info: &Info, start: u64, end: u64) -> Vec<FileSlice> {
    let mut slices = Vec::new();
    if start >= end {
        return slices;
    }
    for (i, f) in info.files.iter().enumerate() {
        let f_start = f.offset;
        let f_end = f.offset + f.length;
        if f_end <= start {
            continue;
        }
        if f_start >= end {
            break;
        }
        let s = start.max(f_start);
        let e = end.min(f_end);
        if e > s {
            slices.push(FileSlice {
                file_index: i,
                file_offset: s - f_start,
                length: e - s,
                padding: f.is_padding(),
            });
        }
    }
    slices
}

impl Info {
    /// The file slices covering `[offset, offset+length)` of the torrent
    /// stream (used for block reads/writes that need not align to pieces).
    pub fn slices_for(&self, offset: u64, length: u64) -> Vec<FileSlice> {
        slices_for_range(self, offset, offset.saturating_add(length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{File, FileAttr, Info, SafePath};

    fn info(files: &[(u64, bool)], piece_length: u32) -> Info {
        let mut list = Vec::new();
        let mut offset = 0;
        for (i, &(len, pad)) in files.iter().enumerate() {
            list.push(File {
                path: SafePath::from_components(&[format!("f{i}").as_bytes()], i).unwrap(),
                length: len,
                offset,
                attr: FileAttr {
                    padding: pad,
                    ..Default::default()
                },
            });
            offset += len;
        }
        let total = offset;
        let n = total.div_ceil(u64::from(piece_length)) as usize;
        Info {
            info_hash: [0; 20],
            name: "t".into(),
            piece_length,
            piece_hashes: vec![[0; 20]; n],
            total_length: total,
            files: list,
            single_file: false,
            private: false,
            has_v2: false,
        }
    }

    #[test]
    fn piece_spanning_multiple_files() {
        // files: 1000, 70000; piece 16384.
        let info = info(&[(1000, false), (70_000, false)], 16384);
        // piece 0 covers [0,16384): 1000 of file0, 15384 of file1.
        let p0 = info.piece_location(0).unwrap();
        assert_eq!(p0.slices.len(), 2);
        assert_eq!(
            p0.slices[0],
            FileSlice {
                file_index: 0,
                file_offset: 0,
                length: 1000,
                padding: false
            }
        );
        assert_eq!(
            p0.slices[1],
            FileSlice {
                file_index: 1,
                file_offset: 0,
                length: 15384,
                padding: false
            }
        );
        // last piece is short.
        let last = info.piece_count() - 1;
        assert_eq!(
            info.piece_location(last).unwrap().length,
            5464 // 71000 - 4*16384
        );
    }

    #[test]
    fn padding_slice_marked() {
        let info = info(&[(1000, false), (15384, true), (16384, false)], 16384);
        let p0 = info.piece_location(0).unwrap();
        assert!(p0.slices.iter().any(|s| s.padding));
        // piece 0 is exactly file0 + pad => aligns file2 to piece 1.
        assert_eq!(
            info.piece_location(1).unwrap().slices,
            vec![FileSlice {
                file_index: 2,
                file_offset: 0,
                length: 16384,
                padding: false
            }]
        );
    }

    #[test]
    fn out_of_range_piece() {
        let info = info(&[(100, false)], 16384);
        assert!(info.piece_location(1).is_none());
        assert_eq!(info.piece_location(0).unwrap().length, 100);
    }

    #[test]
    fn block_slices() {
        let info = info(&[(1000, false), (70_000, false)], 16384);
        let s = info.slices_for(500, 1000);
        assert_eq!(s.len(), 2);
        assert_eq!(
            s[0],
            FileSlice {
                file_index: 0,
                file_offset: 500,
                length: 500,
                padding: false
            }
        );
        assert_eq!(
            s[1],
            FileSlice {
                file_index: 1,
                file_offset: 0,
                length: 500,
                padding: false
            }
        );
    }
}
