// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Follows libtorrent-rasterbar's dos_blocker.cpp (BSD-3-Clause), Copyright
// (c) Arvid Norberg and contributors; see NOTICE.

//! Per-address flood protection: an address sending more than 50 packets in
//! a 10-second window is ignored for 5 minutes. Only a handful of addresses
//! are tracked (the least active slot is recycled).

use std::net::IpAddr;
use std::time::{Duration, Instant};

const SLOTS: usize = 20;
/// Packets per second before blocking (libtorrent `dht_block_ratelimit`).
const RATE_LIMIT: u32 = 5;
/// How long a blocked address stays blocked (`dht_block_timeout`).
const BLOCK_FOR: Duration = Duration::from_secs(5 * 60);
const WINDOW: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
struct Entry {
    src: Option<IpAddr>,
    count: u32,
    limit: Option<Instant>,
}

/// The blocker.
#[derive(Debug, Clone)]
pub struct DosBlocker {
    slots: Vec<Entry>,
}

impl Default for DosBlocker {
    fn default() -> Self {
        DosBlocker {
            slots: vec![
                Entry {
                    src: None,
                    count: 0,
                    limit: None,
                };
                SLOTS
            ],
        }
    }
}

impl DosBlocker {
    /// Record a packet from `addr`; `false` means drop it.
    pub fn incoming(&mut self, addr: IpAddr, now: Instant) -> bool {
        let mut min = 0usize;
        let mut matched = None;
        for (i, e) in self.slots.iter().enumerate() {
            if e.src == Some(addr) {
                matched = Some(i);
                break;
            }
            let m = &self.slots[min];
            if e.count < m.count || (e.count == m.count && e.limit < m.limit) {
                min = i;
            }
        }
        match matched {
            Some(i) => {
                let e = &mut self.slots[i];
                e.count += 1;
                if e.count >= RATE_LIMIT * 10 {
                    if e.limit.is_some_and(|l| now < l) {
                        if e.count == RATE_LIMIT * 10 {
                            e.limit = Some(now + BLOCK_FOR);
                        }
                        return false;
                    }
                    e.count = 0;
                    e.limit = Some(now + WINDOW);
                }
                true
            }
            None => {
                let e = &mut self.slots[min];
                e.count = 1;
                e.limit = Some(now + WINDOW);
                e.src = Some(addr);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floods_get_blocked_then_expire() {
        let mut b = DosBlocker::default();
        let t0 = Instant::now();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        for _ in 0..49 {
            assert!(b.incoming(ip, t0 + Duration::from_millis(10)));
        }
        // The 50th within the window trips the block.
        assert!(!b.incoming(ip, t0 + Duration::from_millis(20)));
        assert!(!b.incoming(ip, t0 + Duration::from_secs(60)));
        assert!(b.incoming(ip, t0 + BLOCK_FOR + Duration::from_secs(1)));
        // Slow senders are fine.
        let other: IpAddr = "10.0.0.10".parse().unwrap();
        for i in 0..200u64 {
            assert!(b.incoming(other, t0 + Duration::from_secs(i)));
        }
    }
}
