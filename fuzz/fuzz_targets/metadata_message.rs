// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 9 `ut_metadata` payload parser (and a round-trip of accepted messages).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = wire::ext::Metadata::parse(data) {
        let again = wire::ext::Metadata::parse(&m.encode(Some(1000))).expect("re-parse");
        assert_eq!(again, m);
    }
    let _ = wire::ext::parse_upload_only(data);
});
