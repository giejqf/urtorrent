// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! LTEP extended handshake: parse never panics; parse -> encode -> parse is stable.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(hs) = wire::ExtHandshake::parse(data) {
        let bytes = hs.encode();
        let again = wire::ExtHandshake::parse(&bytes).expect("re-parse");
        assert_eq!(again.v, hs.v);
        assert_eq!(again.p, hs.p);
        assert_eq!(again.reqq, hs.reqq);
        assert_eq!(again.yourip, hs.yourip);
        assert_eq!(again.metadata_size, hs.metadata_size);
    }
});
