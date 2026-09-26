// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Token-bucket rate limiting, shared by every peer of a session (or of a
//! torrent). Pure bookkeeping plus a local notify: buckets refill lazily from
//! the clock when tokens are taken, and a starved waiter sleeps for the time
//! its minimal grant takes to accrue (so nothing has to walk every limiter on
//! a timer); `set_rate` wakes waiters. Peers `acquire` before sending or
//! posting a receive.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

use super::local::Notify;

/// Smallest grant, so a waiter always makes progress once tokens exist.
const MIN_GRANT: u64 = 1024;

struct Bucket {
    /// Bytes per second; 0 = unlimited.
    rate: u64,
    tokens: u64,
    last: Instant,
}

impl Bucket {
    fn refill(&mut self, now: Instant) {
        if self.rate == 0 {
            return;
        }
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        let add = (self.rate as u128 * elapsed.as_nanos() / 1_000_000_000) as u64;
        // Burst capacity: one second of rate (libtorrent-like).
        self.tokens = (self.tokens + add).min(self.rate);
    }
}

/// A shared limiter.
pub struct Limiter {
    bucket: RefCell<Bucket>,
    ready: Rc<Notify>,
}

impl Limiter {
    /// A limiter at `rate` bytes/s (0 = unlimited).
    pub fn new(rate: u64, now: Instant) -> Rc<Limiter> {
        Rc::new(Limiter {
            bucket: RefCell::new(Bucket {
                rate,
                tokens: rate,
                last: now,
            }),
            ready: Notify::new(),
        })
    }

    /// Change the rate (0 = unlimited). Waiters are woken.
    pub fn set_rate(&self, rate: u64, now: Instant) {
        let mut b = self.bucket.borrow_mut();
        b.rate = rate;
        b.tokens = b.tokens.min(rate.max(1));
        b.last = now;
        drop(b);
        self.ready.notify();
    }

    /// The configured rate.
    pub fn rate(&self) -> u64 {
        self.bucket.borrow().rate
    }

    /// Whether the limiter is unlimited.
    pub fn is_unlimited(&self) -> bool {
        self.rate() == 0
    }

    /// Try to take up to `want` tokens now; returns how many were granted
    /// (0 if none available). Unlimited limiters grant everything.
    pub fn try_take(&self, want: u64, now: Instant) -> u64 {
        let mut b = self.bucket.borrow_mut();
        if b.rate == 0 {
            return want;
        }
        b.refill(now);
        let min = MIN_GRANT.min(b.rate).min(want.max(1));
        if b.tokens < min {
            return 0;
        }
        let grant = want.min(b.tokens);
        b.tokens -= grant;
        grant
    }

    /// Wait until at least a minimal grant is available, then take up to
    /// `want`. Returns the grant (> 0).
    pub async fn acquire(&self, want: u64) -> u64 {
        loop {
            let now = Instant::now();
            let got = self.try_take(want, now);
            if got > 0 {
                return got;
            }
            // Time for the minimal grant to accrue at the current rate (the
            // rate may change meanwhile: `set_rate` notifies).
            let wait = {
                let b = self.bucket.borrow();
                let need = MIN_GRANT.min(b.rate).saturating_sub(b.tokens).max(1);
                let nanos = (need as u128 * 1_000_000_000 / b.rate.max(1) as u128) as u64;
                std::time::Duration::from_nanos(nanos.clamp(1_000_000, 1_000_000_000))
            };
            super::local::select2(self.ready.wait(), uring::sleep(wait)).await;
        }
    }

    /// Give back unused tokens (e.g. a short send).
    pub fn refund(&self, n: u64) {
        let mut b = self.bucket.borrow_mut();
        if b.rate != 0 {
            b.tokens = (b.tokens + n).min(b.rate);
        }
    }
}

/// Take a grant from the session limiter, then narrow it through the
/// torrent's; unused session tokens go back.
pub async fn acquire_pair(session: &Limiter, torrent: &Limiter, want: u64) -> u64 {
    let g1 = session.acquire(want).await;
    let g2 = torrent.acquire(g1).await;
    if g2 < g1 {
        session.refund(g1 - g2);
    }
    g2
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unlimited_grants_everything() {
        let l = Limiter::new(0, Instant::now());
        assert_eq!(l.try_take(1 << 30, Instant::now()), 1 << 30);
    }

    #[test]
    fn bucket_refills_with_time_and_caps_burst() {
        let t0 = Instant::now();
        let l = Limiter::new(10_000, t0);
        // Full bucket at start: one second of rate.
        assert_eq!(l.try_take(20_000, t0), 10_000);
        assert_eq!(l.try_take(1, t0), 0);
        // 100 ms later: 1000 tokens, under the minimum grant; 200 ms: 2000.
        let t1 = t0 + Duration::from_millis(100);
        assert_eq!(l.try_take(5000, t1), 0);
        let t1 = t0 + Duration::from_millis(200);
        assert_eq!(l.try_take(5000, t1), 2000);
        // Far later: capped at the rate.
        let t2 = t1 + Duration::from_secs(60);
        assert_eq!(l.try_take(u64::MAX, t2), 10_000);
        l.refund(3000);
        assert_eq!(l.try_take(u64::MAX, t2), 3000);
    }

    #[test]
    fn min_grant_prevents_starvation_dribble() {
        let t0 = Instant::now();
        let l = Limiter::new(100_000, t0);
        l.try_take(u64::MAX, t0);
        // 1 ms later: 100 tokens, below MIN_GRANT -> nothing yet.
        assert_eq!(l.try_take(16384, t0 + Duration::from_millis(1)), 0);
        assert_eq!(l.try_take(16384, t0 + Duration::from_millis(20)), 2000);
    }
}
