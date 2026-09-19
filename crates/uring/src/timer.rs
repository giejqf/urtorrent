// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Timers on the ring. The engine's timeouts and backoff are driven by
//! io_uring `timeout` SQEs (AGENTS.md 5.3: "the timers that drive them"), not
//! by a separate clock source.

use std::future::Future;
use std::time::Duration;

use io_uring::types::Timespec;

use crate::error::{Error, Result};
use crate::reactor::timeout as ring_timeout;

/// Sleep for `dur` using an io_uring timeout.
pub async fn sleep(dur: Duration) {
    let ts = Timespec::new().sec(dur.as_secs()).nsec(dur.subsec_nanos());
    // A normal timeout elapses with -ETIME; any result means "the time passed".
    let _ = ring_timeout(ts).await;
}

/// Race `future` against `dur`. Returns `Ok(output)` if the future finishes
/// first, or `Err(Error::TimedOut)` if the deadline elapses. When the future
/// wins, the timeout op is cancelled by its `Op` future being dropped.
pub async fn timeout<F: Future>(dur: Duration, future: F) -> Result<F::Output> {
    let mut future = std::pin::pin!(future);
    let mut timer = std::pin::pin!(sleep(dur));
    std::future::poll_fn(move |cx| {
        if let std::task::Poll::Ready(v) = future.as_mut().poll(cx) {
            return std::task::Poll::Ready(Ok(v));
        }
        match timer.as_mut().poll(cx) {
            std::task::Poll::Ready(()) => std::task::Poll::Ready(Err(Error::TimedOut)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}
