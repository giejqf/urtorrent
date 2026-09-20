// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! HTTP/1.x response framing (chunked, content-length, until-close) and gzip.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut p = tracker::http::ResponseParser::new();
    for chunk in data.chunks(13) {
        if p.push(chunk).is_err() {
            break;
        }
    }
    let _ = p.finish();
    let _ = tracker::http::gunzip(data);
});
