// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;

// Resume data is persisted by us, but decoding must still never panic.
fuzz_target!(|data: &[u8]| {
    let _ = storage::ResumeData::decode(data);
});
