// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Packet capture on the lab bridge (via `tcpdump`), for differential runs.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::lab::Proc;

/// A running `tcpdump` writing a pcap file.
pub struct Pcap {
    proc: Option<Proc>,
    pub path: PathBuf,
}

impl Pcap {
    /// Start capturing `interface` into `path`. Returns `Ok(None)` when tcpdump
    /// is not installed (captures are informational, never a gate).
    pub fn start(interface: &str, path: &Path, filter: &str) -> Result<Option<Pcap>> {
        if Command::new("which")
            .arg("tcpdump")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            tracing::warn!("tcpdump not installed; skipping pcap");
            return Ok(None);
        }
        let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let mut cmd = Command::new("sudo");
        cmd.args([
            "-n", "tcpdump", "-i", interface, "-U", "-s", "0", "-Z", &user, "-w",
        ])
        .arg(path);
        if !filter.is_empty() {
            cmd.arg(filter);
        }
        let dir = path.parent().unwrap_or(Path::new("."));
        let proc = Proc::spawn("tcpdump", cmd, dir).context("starting tcpdump")?;
        // Give tcpdump a moment to attach before traffic starts.
        std::thread::sleep(Duration::from_millis(500));
        Ok(Some(Pcap {
            proc: Some(proc),
            path: path.to_path_buf(),
        }))
    }

    pub fn stop(&mut self) {
        if let Some(mut p) = self.proc.take() {
            let _ = p.terminate(Duration::from_secs(5));
        }
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        self.stop();
    }
}
