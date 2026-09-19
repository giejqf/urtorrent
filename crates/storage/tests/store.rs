// SPDX-License-Identifier: Apache-2.0
//! Storage integration tests over the real uring runtime: write, verify,
//! recheck-after-corruption, upload reads, multi-file spans, and resume.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fixture;

use std::path::PathBuf;
use std::rc::Rc;

use metainfo::Torrent;
use storage::{HashPool, ResumeData, Storage};
use uring::{Buffer, Runtime};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "urt-storage-{tag}-{}-{}",
        std::process::id(),
        fastrand()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn fastrand() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
}

async fn write_all(store: &Storage, content: &[u8], piece_length: u32) {
    let pl = piece_length as usize;
    let pieces = content.len().div_ceil(pl);
    for p in 0..pieces {
        let start = p * pl;
        let end = (start + pl).min(content.len());
        // Write in 16 KiB blocks to exercise the block path.
        let mut off = 0u32;
        while (start + off as usize) < end {
            let bstart = start + off as usize;
            let bend = (bstart + 16384).min(end);
            let buf = Buffer::from_vec(content[bstart..bend].to_vec());
            store.write_block(p, off, buf).await.unwrap();
            off += (bend - bstart) as u32;
        }
    }
}

#[test]
fn single_file_write_verify_upload() {
    let fx = fixture::single("data.bin", 200_000, 32768, 1);
    let torrent = Torrent::parse(&fx.torrent).unwrap();
    let info = Rc::new(torrent.info);
    let root = tmpdir("single");
    let pool = Rc::new(HashPool::new(2));
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on({
        let info = info.clone();
        let content = fx.content.clone();
        let root = root.clone();
        async move {
            let store = Storage::new(info.clone(), root, pool);
            store.create_files().unwrap();
            write_all(&store, &content, fx.piece_length).await;
            // Every piece verifies.
            for p in 0..info.piece_count() {
                assert!(store.verify_piece(p).await.unwrap(), "piece {p}");
            }
            assert!(store.have().is_complete());
            // Upload read returns exact bytes.
            let blk = store.read_block(0, 100, 4096).await.unwrap();
            assert_eq!(blk.as_slice(), &content[100..4196]);
            store.sync_all().await.unwrap();
        }
    });
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn recheck_detects_corruption() {
    let fx = fixture::single("d.bin", 100_000, 16384, 2);
    let torrent = Torrent::parse(&fx.torrent).unwrap();
    let info = Rc::new(torrent.info);
    let root = tmpdir("recheck");
    let pool = Rc::new(HashPool::new(2));
    let rt = Runtime::with_defaults().unwrap();
    let n = info.piece_count();
    rt.block_on({
        let info = info.clone();
        let content = fx.content.clone();
        let root = root.clone();
        async move {
            let store = Storage::new(info.clone(), root, pool);
            store.create_files().unwrap();
            write_all(&store, &content, fx.piece_length).await;
            let have = store.check_all().await.unwrap();
            assert!(have.is_complete());
        }
    });
    // Corrupt the file on disk (flip bytes inside piece 2).
    let path = root.join("d.bin");
    let mut data = std::fs::read(&path).unwrap();
    data[16384 * 2 + 10] ^= 0xff;
    std::fs::write(&path, &data).unwrap();
    let pool2 = Rc::new(HashPool::new(2));
    rt.block_on({
        let info = info.clone();
        let root = root.clone();
        async move {
            let store = Storage::new(info, root, pool2);
            let have = store.check_all().await.unwrap();
            assert!(!have.get(2), "corrupted piece 2 must not verify");
            assert_eq!(have.count(), n - 1);
        }
    });
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn multi_file_spans_and_write_verify() {
    // Files chosen so pieces straddle file boundaries.
    let fx = fixture::multi(
        "bundle",
        &[("a.txt", 1000), ("dir/b.bin", 70_000), ("c", 5)],
        16384,
        3,
    );
    let torrent = Torrent::parse(&fx.torrent).unwrap();
    let info = Rc::new(torrent.info);
    assert!(!info.single_file);
    let root = tmpdir("multi");
    let pool = Rc::new(HashPool::new(2));
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on({
        let info = info.clone();
        let content = fx.content.clone();
        let root = root.clone();
        async move {
            let store = Storage::new(info.clone(), root.clone(), pool);
            store.create_files().unwrap();
            // A piece 0 block spans a.txt (1000) into dir/b.bin.
            let slices = store.block_slices(0, 0, 16384).unwrap();
            assert!(slices.len() >= 2, "piece 0 should span >=2 files");
            write_all(&store, &content, fx.piece_length).await;
            for p in 0..info.piece_count() {
                assert!(store.verify_piece(p).await.unwrap(), "piece {p}");
            }
            // Files exist on disk at the mapped paths.
            assert!(root.join("bundle/a.txt").exists());
            assert!(root.join("bundle/dir/b.bin").exists());
        }
    });
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn write_and_maybe_verify_reports_completion() {
    let fx = fixture::single("w.bin", 40_000, 16384, 4);
    let torrent = Torrent::parse(&fx.torrent).unwrap();
    let info = Rc::new(torrent.info);
    let root = tmpdir("wmv");
    let pool = Rc::new(HashPool::new(1));
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on({
        let info = info.clone();
        let content = fx.content.clone();
        async move {
            let store = Storage::new(info.clone(), root.clone(), pool);
            store.create_files().unwrap();
            // Piece 0 is 16384: write first block -> incomplete (None).
            let b0 = Buffer::from_vec(content[0..16384].to_vec());
            // write only half of piece 0
            let half = Buffer::from_vec(content[0..8192].to_vec());
            assert_eq!(
                store.write_and_maybe_verify(0, 0, half).await.unwrap(),
                None
            );
            // complete piece 0
            let rest = Buffer::from_vec(content[8192..16384].to_vec());
            assert_eq!(
                store.write_and_maybe_verify(0, 8192, rest).await.unwrap(),
                Some(true)
            );
            let _ = b0;
            std::fs::remove_dir_all(&root).ok();
        }
    });
}

#[test]
fn resume_roundtrip_and_recheck_on_mismatch() {
    let fx = fixture::single("r.bin", 80_000, 16384, 5);
    let torrent = Torrent::parse(&fx.torrent).unwrap();
    let info = Rc::new(torrent.info);
    let root = tmpdir("resume");
    let resume_path = root.join("r.resume");
    let pool = Rc::new(HashPool::new(2));
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on({
        let info = info.clone();
        let content = fx.content.clone();
        let root = root.clone();
        let resume_path = resume_path.clone();
        async move {
            let store = Storage::new(info.clone(), root, pool);
            store.create_files().unwrap();
            write_all(&store, &content, fx.piece_length).await;
            store.check_all().await.unwrap();
            store.sync_all().await.unwrap();
            let mut rd = ResumeData::empty(
                info.info_hash,
                info.piece_length,
                info.total_length,
                info.piece_count(),
            );
            rd.have = store.have();
            rd.downloaded = info.total_length;
            rd.save(&resume_path).unwrap();
        }
    });
    // Reload: matches metainfo, bitfield complete.
    let rd = ResumeData::load(&resume_path).unwrap().unwrap();
    assert!(rd.matches(&info));
    assert!(rd.have.is_complete());
    assert_eq!(rd.downloaded, info.total_length);
    // A different torrent's resume must not match (forces recheck).
    let other = fixture::single("r.bin", 80_000, 16384, 999);
    let other_info = Torrent::parse(&other.torrent).unwrap().info;
    assert!(!rd.matches(&other_info));
    std::fs::remove_dir_all(&root).ok();
}
