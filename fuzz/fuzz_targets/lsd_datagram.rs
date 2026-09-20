// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 14 `BT-SEARCH` datagram parser.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(s) = tracker::lsd::parse(data) {
        assert!(s.port != 0);
        assert!(s.info_hashes.len() <= tracker::lsd::MAX_HASHES);
    }
});
