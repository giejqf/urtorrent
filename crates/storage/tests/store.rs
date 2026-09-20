// SPDX-License-Identifier: Apache-2.0
//! Storage integration tests over the real uring runtime: write, verify,
//! recheck-after-corruption, upload reads, multi-file spans, and resume.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fixture;

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

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
    let info = Arc::new(torrent.info);
    let root = tmpdir("single");
    let pool = Rc::new(HashPool::new(2));
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on({
        let info = info.clone();
        let content = fx.content.clone();
        let root = root.clone();
        async move {
            let store = Storage::new(info.clone(), root, pool);
            store.create_files().await.unwrap();
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
    let info = Arc::new(torrent.info);
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
            store.create_files().await.unwrap();
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
    let info = Arc::new(torrent.info);
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
            store.create_files().await.unwrap();
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
    let info = Arc::new(torrent.info);
    let root = tmpdir("wmv");
    let pool = Rc::new(HashPool::new(1));
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on({
        let info = info.clone();
        let content = fx.content.clone();
        async move {
            let store = Storage::new(info.clone(), root.clone(), pool);
            store.create_files().await.unwrap();
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
    let info = Arc::new(torrent.info);
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
            store.create_files().await.unwrap();
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

/// Selective download: a skipped middle file is never created; the bytes of
/// pieces straddling it land in the parts file; raising its priority exports
/// them into the real file, and a move relocates everything.
#[test]
fn file_priorities_parts_file_and_move() {
    // 16 KiB pieces: a (20000) | b (30000) | c (14000): pieces 1 and 3
    // straddle b's boundaries, piece 2 is inside b.
    let fx = fixture::multi(
        "sel",
        &[("a.bin", 20_000), ("b.bin", 30_000), ("c.bin", 14_000)],
        16384,
        9,
    );
    let torrent = Torrent::parse(&fx.torrent).unwrap();
    let info = Arc::new(torrent.info);
    let root = tmpdir("prio");
    let root2 = tmpdir("prio-moved");
    let pool = Rc::new(HashPool::new(2));
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on({
        let info = info.clone();
        let content = fx.content.clone();
        let root = root.clone();
        let root2 = root2.clone();
        async move {
            let store = Storage::new(info.clone(), root.clone(), pool);
            store.init_priorities(&[4, 0, 4]);
            assert_eq!(store.piece_priorities(), vec![4, 4, 0, 4]);
            store.create_files().await.unwrap();
            assert!(root.join("sel/a.bin").exists());
            assert!(
                !root.join("sel/b.bin").exists(),
                "skipped file must not be created"
            );
            assert!(root.join("sel/c.bin").exists());
            // Download the wanted pieces (0, 1, 3); piece 2 is skipped.
            let pl = 16384usize;
            for p in [0usize, 1, 3] {
                let start = p * pl;
                let end = (start + pl).min(content.len());
                let buf = Buffer::from_vec(content[start..end].to_vec());
                store.write_block(p, 0, buf).await.unwrap();
                assert!(store.verify_piece(p).await.unwrap(), "piece {p}");
            }
            assert!(!root.join("sel/b.bin").exists());
            assert!(
                store.parts_path().exists(),
                "straddling bytes go to the parts file"
            );
            // a and c are complete; b holds only the straddling parts.
            assert_eq!(store.file_done(0), 20_000);
            assert_eq!(store.file_done(2), 14_000);
            let b_done = store.file_done(1);
            assert!(
                b_done > 0 && b_done < 30_000,
                "b partially covered: {b_done}"
            );
            // Uploading from a straddling piece reads through the parts file.
            let blk = store.read_block(1, 0, 16384).await.unwrap();
            assert_eq!(blk.as_slice(), &content[16384..32768]);

            // Want b after all: its parts are exported into the real file...
            store.set_file_priorities(&[4, 4, 4]).await.unwrap();
            assert_eq!(store.piece_priorities(), vec![4, 4, 4, 4]);
            assert!(root.join("sel/b.bin").exists());
            let b_disk = std::fs::read(root.join("sel/b.bin")).unwrap();
            // ... up to piece 1's end (the file is sparse beyond).
            let b_start = 20_000;
            let p1_end = 32_768;
            assert_eq!(&b_disk[..p1_end - b_start], &content[b_start..p1_end]);
            // Piece 3's slice of b also came across.
            let p3_start = 3 * pl;
            let b_end = 50_000;
            assert_eq!(
                &b_disk[p3_start - b_start..b_end - b_start],
                &content[p3_start..b_end]
            );
            // Finish piece 2 into the real file and the torrent is complete.
            let buf = Buffer::from_vec(content[2 * pl..3 * pl].to_vec());
            store.write_block(2, 0, buf).await.unwrap();
            assert!(store.verify_piece(2).await.unwrap());
            assert_eq!(
                std::fs::read(root.join("sel/b.bin")).unwrap(),
                &content[b_start..b_end]
            );

            // Move storage: files follow, data still verifies.
            store.move_to(root2.clone()).await.unwrap();
            assert!(!root.join("sel/a.bin").exists());
            assert!(root2.join("sel/a.bin").exists());
            assert_eq!(store.root(), root2);
            let have = store.check_all().await.unwrap();
            assert_eq!(have.count(), 4);
        }
    });
    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&root2).ok();
}
