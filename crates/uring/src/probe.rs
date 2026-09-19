// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Feature probing via `IORING_REGISTER_PROBE` (AGENTS.md 5.3). At startup the
//! kernel is asked which opcodes it supports; the baseline set the critical
//! path needs is required, and its absence is a hard error with a clear message
//! (no degraded mode).

use io_uring::opcode;
use io_uring::{IoUring, register::Probe};

use crate::error::{Error, Result};

/// Which io_uring opcodes the running kernel supports, split into the baseline
/// urtorrent requires and the optional fast paths it can use when present.
#[derive(Debug, Clone, Default)]
pub struct Features {
    /// Baseline opcodes present (all required).
    pub nop: bool,
    /// `connect`.
    pub connect: bool,
    /// `accept`.
    pub accept: bool,
    /// `send`.
    pub send: bool,
    /// `recv`.
    pub recv: bool,
    /// `read`.
    pub read: bool,
    /// `write`.
    pub write: bool,
    /// `close`.
    pub close: bool,
    /// `fsync`.
    pub fsync: bool,
    /// `fallocate`.
    pub fallocate: bool,
    /// `timeout`.
    pub timeout: bool,
    /// `async_cancel`.
    pub async_cancel: bool,
    // --- optional fast paths (probed, used when available) ---
    /// Multishot `accept` (kernel 5.19+).
    pub accept_multi: bool,
    /// Zero-copy `send` (kernel 6.0+).
    pub send_zc: bool,
    /// Multishot `recv` with provided buffers.
    pub recv_multi: bool,
    /// `recvmsg` (for UDP tracker / LSD demux).
    pub recvmsg: bool,
    /// `sendmsg`.
    pub sendmsg: bool,
    /// `ftruncate` (6.9+).
    pub ftruncate: bool,
}

impl Features {
    /// The names of any missing baseline opcodes.
    pub fn missing_baseline(&self) -> Vec<&'static str> {
        let mut m = Vec::new();
        for (present, name) in [
            (self.nop, "nop"),
            (self.connect, "connect"),
            (self.accept, "accept"),
            (self.send, "send"),
            (self.recv, "recv"),
            (self.read, "read"),
            (self.write, "write"),
            (self.close, "close"),
            (self.fsync, "fsync"),
            (self.fallocate, "fallocate"),
            (self.timeout, "timeout"),
            (self.async_cancel, "async_cancel"),
        ] {
            if !present {
                m.push(name);
            }
        }
        m
    }

    /// Error if any baseline opcode is missing.
    pub fn require_baseline(&self) -> Result<()> {
        let missing = self.missing_baseline();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Error::Unavailable(format!(
                "kernel io_uring lacks required opcodes: {} (baseline is Linux 6.1 LTS)",
                missing.join(", ")
            )))
        }
    }

    /// A one-line human summary (used by `uring-probe` / `xtask doctor`).
    pub fn summary(&self) -> String {
        let baseline = if self.missing_baseline().is_empty() {
            "baseline OK"
        } else {
            "BASELINE INCOMPLETE"
        };
        let mut fast = Vec::new();
        for (present, name) in [
            (self.accept_multi, "accept_multi"),
            (self.recv_multi, "recv_multi"),
            (self.send_zc, "send_zc"),
            (self.recvmsg, "recvmsg"),
            (self.sendmsg, "sendmsg"),
            (self.ftruncate, "ftruncate"),
        ] {
            if present {
                fast.push(name);
            }
        }
        format!("{baseline}; fast paths: [{}]", fast.join(", "))
    }
}

/// Probe the running kernel's io_uring opcode support. Creates a tiny throwaway
/// ring; failing to create one is itself an [`Error::Unavailable`].
pub fn probe() -> Result<Features> {
    let ring = IoUring::new(8).map_err(|e| Error::Unavailable(format!("io_uring_setup failed: {e} (kernel too old, or io_uring disabled by seccomp / kernel.io_uring_disabled)")))?;
    let mut probe = Probe::new();
    ring.submitter()
        .register_probe(&mut probe)
        .map_err(|e| Error::Unavailable(format!("IORING_REGISTER_PROBE failed: {e}")))?;
    let s = |code: u8| probe.is_supported(code);
    Ok(Features {
        nop: s(opcode::Nop::CODE),
        connect: s(opcode::Connect::CODE),
        accept: s(opcode::Accept::CODE),
        send: s(opcode::Send::CODE),
        recv: s(opcode::Recv::CODE),
        read: s(opcode::Read::CODE),
        write: s(opcode::Write::CODE),
        close: s(opcode::Close::CODE),
        fsync: s(opcode::Fsync::CODE),
        fallocate: s(opcode::Fallocate::CODE),
        timeout: s(opcode::Timeout::CODE),
        async_cancel: s(opcode::AsyncCancel::CODE),
        accept_multi: s(opcode::AcceptMulti::CODE),
        send_zc: s(opcode::SendZc::CODE),
        recv_multi: s(opcode::RecvMulti::CODE),
        recvmsg: s(opcode::RecvMsg::CODE),
        sendmsg: s(opcode::SendMsg::CODE),
        ftruncate: s(opcode::Ftruncate::CODE),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_present_on_ci_kernel() {
        // The CI/dev kernel is 6.1+; the baseline must be complete.
        let f = probe().expect("io_uring available");
        assert!(
            f.missing_baseline().is_empty(),
            "missing: {:?}",
            f.missing_baseline()
        );
        f.require_baseline().unwrap();
    }
}
