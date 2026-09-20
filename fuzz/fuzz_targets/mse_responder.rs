// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! MSE responder fed arbitrary bytes (a hostile initiator): must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

struct R(u64);
impl profile::Rng for R {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.0 >> 33) as u32
    }
}

fuzz_target!(|data: &[u8]| {
    let mut rng = R(7);
    let mut resp = mse::Responder::new([9u8; 20], 3, true);
    let torrents = [[1u8; 20], [2u8; 20]];
    for chunk in data.chunks(97) {
        if resp.receive(chunk, &torrents, &mut rng).is_err() {
            break;
        }
        let _ = resp.take_outbound();
    }
    let mut init = mse::Initiator::new([1u8; 20], [3u8; 20], vec![0; 68], 3, &mut rng);
    let _ = init.take_outbound();
    for chunk in data.chunks(101) {
        if init.receive(chunk, &mut rng).is_err() {
            break;
        }
    }
});
