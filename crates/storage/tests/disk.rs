// SPDX-License-Identifier: Apache-2.0
//! The disk ring driven from a second ring (as the engine does): jobs run on
//! the `urt-disk` thread and resolve on the caller's runtime through the
//! notifier + bridge.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fixture;

use std::future::Future;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use metainfo::Torrent;
use storage::DiskRing;
use uring::{Notifier, Runtime};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("urt-disk-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run `fut` on `rt` while draining the disk ring's completions whenever the
/// notifier fires (the engine's command loop in miniature).
fn drive<F: Future + 'static>(
    rt: &Runtime,
    notifier: Rc<Notifier>,
    ring: Rc<DiskRing>,
    fut: F,
) -> F::Output
where
    F::Output: 'static,
{
    rt.block_on(async move {
        let task = uring::spawn(fut);
        let done = Rc::new(std::cell::Cell::new(false));
        let done2 = done.clone();
        let waiter = uring::spawn(async move {
            let v = task.await;
            done2.set(true);
            v
        });
        loop {
            if done.get() {
                break;
            }
            match uring::timeout(std::time::Duration::from_millis(20), notifier.wait()).await {
                Ok(_) | Err(_) => {}
            }
            ring.drain();
        }
        waiter.await
    })
}

#[test]
fn disk_ring_end_to_end() {
    let fx = fixture::multi(
        "ring",
        &[("a.bin", 40_000), ("b.bin", 30_000), ("c.bin", 20_000)],
        16384,
        5,
    );
    let torrent = Torrent::parse(&fx.torrent).unwrap();
    let info = Arc::new(torrent.info);
    let root = tmpdir("a");
    let root2 = tmpdir("b");
    let rt = Runtime::with_defaults().unwrap();
    let notifier = Rc::new(Notifier::new().unwrap());
    let ring = Rc::new(DiskRing::start(1, notifier.handle()).unwrap());
    let content = fx.content.clone();
    let pl = 16384usize;
    let pieces = info.piece_count();
    let (ring2, root_c, root2_c, info_c) =
        (ring.clone(), root.clone(), root2.clone(), info.clone());
    drive(&rt, notifier.clone(), ring.clone(), async move {
        // Skip b: its straddling bytes go to the parts file.
        let store = ring2.open(info_c.clone(), root_c.clone(), Some(vec![4, 0, 4]));
        assert_eq!(
            store.piece_priorities(),
            storage::layout::piece_priorities(&info_c, &[4, 0, 4])
        );
        store.create_files().await.unwrap();
        assert!(!root_c.join("ring/b.bin").exists());
        for p in 0..pieces {
            if store.piece_priorities()[p] == 0 {
                continue;
            }
            let start = p * pl;
            let end = (start + pl).min(content.len());
            store
                .write_block(p, 0, content[start..end].to_vec())
                .await
                .unwrap();
            assert!(store.verify_piece(p).await.unwrap(), "piece {p}");
            assert!(store.has_piece(p));
        }
        assert_eq!(store.file_done(0), 40_000);
        // Upload read of a straddling piece goes through the parts file.
        let blk = store.read_block(2, 0, 16384).await.unwrap();
        assert_eq!(&blk[..], &content[2 * pl..3 * pl]);
        // Want everything, finish, move, recheck.
        store.set_file_priorities(&[4, 4, 4]).await.unwrap();
        assert_eq!(store.file_priorities(), vec![4, 4, 4]);
        for p in 0..pieces {
            if store.has_piece(p) {
                continue;
            }
            let start = p * pl;
            let end = (start + pl).min(content.len());
            store
                .write_block(p, 0, content[start..end].to_vec())
                .await
                .unwrap();
            assert!(store.verify_piece(p).await.unwrap(), "piece {p}");
        }
        assert_eq!(store.have().count(), pieces);
        store.sync_all().await.unwrap();
        store.move_to(root2_c.clone()).await.unwrap();
        assert_eq!(store.root(), root2_c);
        assert!(root2_c.join("ring/b.bin").exists());
        let have = store.check_all().await.unwrap();
        assert_eq!(have.count(), pieces);
        assert_eq!(
            std::fs::read(root2_c.join("ring/b.bin")).unwrap(),
            &content[40_000..70_000]
        );
        // A wrong verify after corruption is reported truthfully.
        std::fs::write(root2_c.join("ring/a.bin"), vec![0u8; 40_000]).unwrap();
        assert!(!store.verify_piece(0).await.unwrap());
        assert!(!store.has_piece(0));
    });
    drop(ring);
    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&root2).ok();
}
