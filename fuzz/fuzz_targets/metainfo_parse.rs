// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;

// Parsing a .torrent from hostile bytes must never panic; paths must stay safe.
fuzz_target!(|data: &[u8]| {
    if let Ok(t) = metainfo::Torrent::parse(data) {
        for f in &t.info.files {
            for c in f.path.components() {
                assert!(c != "." && c != ".." && !c.contains('/') && !c.contains('\0'));
            }
        }
        let _ = t.info.piece_location(0);
    }
});
