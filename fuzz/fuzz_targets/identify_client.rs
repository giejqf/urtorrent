// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 20 peer-id client identification: any 20 bytes name a client or
//! nothing, never panic, and the name is short.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut id = [0u8; 20];
    let n = data.len().min(20);
    id[..n].copy_from_slice(&data[..n]);
    if let Some(name) = wire::identify::client_name(&id) {
        assert!(!name.is_empty() && name.len() < 96, "{name}");
    }
});
