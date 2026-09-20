// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Peer-wire message codec: decode never panics; decode -> encode is identity.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = wire::Message::decode(data) {
        let bytes = m.to_bytes();
        assert_eq!(&bytes[4..], data);
    }
    let _ = wire::Handshake::parse(data);
});
