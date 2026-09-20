// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! HTTP tracker announce response parser.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tracker::AnnounceResponse::parse(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = tracker::Url::parse(s);
    }
});
