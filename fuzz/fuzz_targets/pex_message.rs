// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 11 `ut_pex` payload parser (and encode/parse round-trip of what it
//! accepted).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = wire::ext::Pex::parse(data) {
        let again = wire::ext::Pex::parse(&p.encode()).expect("re-parse");
        assert_eq!(again.added.len(), p.added.len());
        assert_eq!(again.dropped.len(), p.dropped.len());
    }
});
