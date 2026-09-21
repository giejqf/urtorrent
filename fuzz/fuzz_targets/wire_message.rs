// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Peer-wire message codec: decode never panics; decode -> encode is identity.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let borrowed = wire::Message::decode(data);
    if let Ok(m) = &borrowed {
        let bytes = m.to_bytes();
        assert_eq!(&bytes[4..], data);
    }
    // The owned decoder (a whole frame, length prefix included) agrees with
    // the borrowed one.
    let mut frame = (data.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(data);
    let owned = wire::Message::decode_owned(frame);
    match (borrowed, owned) {
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Err(_), Err(_)) => {}
        (a, b) => panic!("decode {a:?} vs decode_owned {b:?}"),
    }
    let _ = wire::Handshake::parse(data);
});
