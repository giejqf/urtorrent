// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
//
// Ported from libtorrent's `timestamp_history` (src/timestamp_history.cpp)
// and `sliding_average` (include/libtorrent/sliding_average.hpp), Copyright
// (c) 2010-2020 Arvid Norberg; BSD-3-Clause. See NOTICE.

//! Delay base tracking (LEDBAT's base delay over the last 20 minutes) and
//! the RTT estimator.

use crate::header::compare_less_wrap;

const TIME_MASK: u32 = 0xffff_ffff;
const HISTORY_SIZE: usize = 20;

/// Minimum one-way delay observed per minute over the last 20 minutes; the
/// base delay is the minimum of the history.
#[derive(Clone, Debug)]
pub struct TimestampHistory {
    history: [u32; HISTORY_SIZE],
    base: u32,
    /// `None` until the first sample.
    num_samples: Option<u16>,
    index: usize,
}

impl Default for TimestampHistory {
    fn default() -> Self {
        TimestampHistory {
            history: [0; HISTORY_SIZE],
            base: 0,
            num_samples: None,
            index: 0,
        }
    }
}

impl TimestampHistory {
    /// Whether a sample has been added.
    pub fn initialized(&self) -> bool {
        self.num_samples.is_some()
    }

    /// The current base delay (only meaningful once initialized).
    pub fn base(&self) -> u32 {
        self.base
    }

    /// Add a raw delay sample; returns the delay relative to the base.
    /// `step` moves the history on to the next minute slot.
    pub fn add_sample(&mut self, sample: u32, step: bool) -> u32 {
        if !self.initialized() {
            self.history.fill(sample);
            self.base = sample;
            self.num_samples = Some(0);
        }
        let mut n = self.num_samples.unwrap_or(0);
        // don't let the counter wrap
        if n < 0xfffe {
            n += 1;
        }
        // if sample is less than base, update the base and update the
        // history entry (because it will be less than that too)
        if compare_less_wrap(sample, self.base, TIME_MASK) {
            self.base = sample;
            self.history[self.index] = sample;
        } else if compare_less_wrap(sample, self.history[self.index], TIME_MASK) {
            self.history[self.index] = sample;
        }
        let ret = sample.wrapping_sub(self.base);
        // don't step base delay history unless we have at least 120
        // samples. Anything less would suggest that the connection is
        // essentially idle and the samples are probably not very reliable
        if step && n > 120 {
            n = 0;
            self.index = (self.index + 1) % HISTORY_SIZE;
            self.history[self.index] = sample;
            self.base = sample;
            for &h in &self.history {
                if compare_less_wrap(h, self.base, TIME_MASK) {
                    self.base = h;
                }
            }
        }
        self.num_samples = Some(n);
        ret
    }

    /// Shift the base by `change` (clock drift compensation).
    pub fn adjust_base(&mut self, change: i32) {
        self.base = self.base.wrapping_add(change as u32);
        // make sure this adjustment sticks by updating all history slots
        for h in &mut self.history {
            if compare_less_wrap(*h, self.base, TIME_MASK) {
                *h = self.base;
            }
        }
    }
}

/// An exponential moving average with mean deviation, in 1/64 fixed point
/// (`sliding_average<int, INVERTED_GAIN>`).
#[derive(Clone, Debug, Default)]
pub struct SlidingAverage<const INVERTED_GAIN: i64> {
    mean: i64,
    average_deviation: i64,
    num_samples: i64,
}

impl<const INVERTED_GAIN: i64> SlidingAverage<INVERTED_GAIN> {
    /// Add a sample.
    pub fn add_sample(&mut self, s: i64) {
        let s = s * 64;
        let deviation = if self.num_samples > 0 {
            (self.mean - s).abs()
        } else {
            0
        };
        if self.num_samples < INVERTED_GAIN {
            self.num_samples += 1;
        }
        self.mean += (s - self.mean) / self.num_samples;
        if self.num_samples > 1 {
            self.average_deviation += (deviation - self.average_deviation) / (self.num_samples - 1);
        }
    }

    /// The mean (0 before any sample).
    pub fn mean(&self) -> i64 {
        if self.num_samples > 0 {
            (self.mean + 32) / 64
        } else {
            0
        }
    }

    /// The mean absolute deviation (0 before two samples).
    pub fn avg_deviation(&self) -> i64 {
        if self.num_samples > 1 {
            (self.average_deviation + 32) / 64
        } else {
            0
        }
    }

    /// Samples seen (saturating at the inverted gain).
    pub fn num_samples(&self) -> i64 {
        self.num_samples
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn base_is_the_minimum() {
        let mut h = TimestampHistory::default();
        assert!(!h.initialized());
        assert_eq!(h.add_sample(1000, false), 0);
        assert_eq!(h.add_sample(1500, false), 500);
        assert_eq!(h.add_sample(900, false), 0);
        assert_eq!(h.base(), 900);
        h.adjust_base(100);
        assert_eq!(h.base(), 1000);
        assert_eq!(h.add_sample(1200, false), 200);
    }

    #[test]
    fn sliding_average_converges() {
        let mut a: SlidingAverage<16> = SlidingAverage::default();
        assert_eq!(a.mean(), 0);
        for _ in 0..50 {
            a.add_sample(100);
        }
        assert_eq!(a.mean(), 100);
        assert_eq!(a.avg_deviation(), 0);
        a.add_sample(200);
        assert!(a.mean() > 100 && a.mean() < 200);
        assert!(a.avg_deviation() > 0);
    }
}
