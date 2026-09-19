// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;

// Decoding must never panic on arbitrary bytes.
fuzz_target!(|data: &[u8]| {
    let _ = bencode::from_bytes(data);
    let mut d = bencode::Decoder::new(data);
    let _ = d.decode_value();
});
