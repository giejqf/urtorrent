// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;

// Anything that decodes must re-encode canonically and decode again identically.
fuzz_target!(|data: &[u8]| {
    if let Ok(v) = bencode::from_bytes(data) {
        let enc = bencode::to_bytes(&v);
        let v2 = bencode::from_bytes(&enc).expect("re-decode of canonical output");
        let enc2 = bencode::to_bytes(&v2);
        assert_eq!(enc, enc2, "encoding is not a fixed point");
    }
});
