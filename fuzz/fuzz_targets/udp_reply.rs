// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 15 reply parser.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tracker::udp::parse_reply(data, false);
    let _ = tracker::udp::parse_reply(data, true);
});
