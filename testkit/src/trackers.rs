// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Third-party trackers used as independent implementations: `opentracker`.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::lab::{Proc, wait_tcp};

/// A running opentracker bound to lab bridge addresses (host namespace).
pub struct OpenTracker {
    _proc: Proc,
    pub addrs: Vec<SocketAddr>,
}

impl OpenTracker {
    pub fn available() -> bool {
        Command::new("which")
            .arg("opentracker")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Start opentracker listening (HTTP and UDP) on every `addrs`. Debian's
    /// build runs in closed (whitelist) mode, so the info-hashes to serve must
    /// be given up front.
    pub fn start(
        addrs: &[SocketAddr],
        whitelist: &[[u8; 20]],
        log_dir: &Path,
    ) -> Result<OpenTracker> {
        if !Self::available() {
            bail!("opentracker is not installed");
        }
        std::fs::create_dir_all(log_dir)?;
        let wl = log_dir.join("opentracker-whitelist.txt");
        let mut s = String::new();
        for h in whitelist {
            s.push_str(&crate::bencode::hex(h));
            s.push('\n');
        }
        std::fs::write(&wl, s)?;
        let mut cmd = Command::new("opentracker");
        cmd.current_dir(log_dir);
        for a in addrs {
            let ip = match a.ip() {
                IpAddr::V4(v) => v.to_string(),
                IpAddr::V6(v) => v.to_string(),
            };
            cmd.args([
                "-i",
                &ip,
                "-p",
                &a.port().to_string(),
                "-P",
                &a.port().to_string(),
            ]);
        }
        cmd.arg("-w").arg(&wl);
        let mut proc = Proc::spawn("opentracker", cmd, log_dir).context("starting opentracker")?;
        for a in addrs {
            wait_tcp(*a, Duration::from_secs(10))
                .with_context(|| format!("opentracker did not listen on {a}"))?;
        }
        // opentracker keeps running after a failed bind; make sure the ports
        // we are talking to are *ours* (a system-wide opentracker service on
        // *:6969 would otherwise silently take over).
        std::thread::sleep(Duration::from_millis(200));
        let err = proc.stderr_log();
        if err.contains("Address already in use") || !proc.is_running() {
            bail!("opentracker could not bind {:?}: {}", addrs, err.trim());
        }
        Ok(OpenTracker {
            _proc: proc,
            addrs: addrs.to_vec(),
        })
    }

    pub fn http_url(&self, idx: usize) -> String {
        let a = self.addrs[idx];
        match a.ip() {
            IpAddr::V4(v) => format!("http://{v}:{}/announce", a.port()),
            IpAddr::V6(v) => format!("http://[{v}]:{}/announce", a.port()),
        }
    }
    pub fn udp_url(&self, idx: usize) -> String {
        let a = self.addrs[idx];
        match a.ip() {
            IpAddr::V4(v) => format!("udp://{v}:{}/announce", a.port()),
            IpAddr::V6(v) => format!("udp://[{v}]:{}/announce", a.port()),
        }
    }
}
