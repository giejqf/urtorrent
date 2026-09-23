// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Third-party trackers used as independent implementations: `opentracker`.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::lab::{Proc, wait_tcp};

/// A running opentracker bound to lab bridge addresses (host namespace): one
/// process, or one per family where the distribution splits the builds.
pub struct OpenTracker {
    _procs: Vec<Proc>,
    pub addrs: Vec<SocketAddr>,
}

/// Debian and Ubuntu before the 2025 upstream snapshot build opentracker once
/// per family: `opentracker` refuses IPv6 addresses ("V4 Tracker is V4
/// only!") and the separate `opentracker-ipv6` package refuses IPv4 ones.
/// Newer builds serve both families from `opentracker` alone.
const V6_BUILD: &str = "opentracker-ipv6";

fn on_path(bin: &str) -> bool {
    Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

impl OpenTracker {
    pub fn available() -> bool {
        on_path("opentracker")
    }

    /// Start opentracker listening (HTTP and UDP) on every `addrs`. Debian's
    /// build runs in closed (whitelist) mode, so the info-hashes to serve must
    /// be given up front. Where the IPv6 build is a separate binary
    /// (`opentracker-ipv6`), each family gets its own process.
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
        let groups: Vec<(&str, Vec<SocketAddr>)> = if on_path(V6_BUILD) {
            let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) =
                addrs.iter().partition(|a| a.is_ipv6());
            [("opentracker", v4), (V6_BUILD, v6)]
                .into_iter()
                .filter(|(_, a)| !a.is_empty())
                .collect()
        } else {
            vec![("opentracker", addrs.to_vec())]
        };
        let mut procs = Vec::new();
        for (bin, addrs) in groups {
            procs.push(Self::spawn(bin, &addrs, &wl, log_dir)?);
        }
        Ok(OpenTracker {
            _procs: procs,
            addrs: addrs.to_vec(),
        })
    }

    fn spawn(bin: &str, addrs: &[SocketAddr], wl: &Path, log_dir: &Path) -> Result<Proc> {
        let mut cmd = Command::new(bin);
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
        cmd.arg("-w").arg(wl);
        let mut proc = Proc::spawn(bin, cmd, log_dir).with_context(|| format!("starting {bin}"))?;
        for a in addrs {
            if let Err(e) = wait_tcp(*a, Duration::from_secs(10)) {
                let err = proc.stderr_log();
                let hint = if err.contains("V4 Tracker is V4 only") {
                    format!(" (this opentracker is IPv4-only: install {V6_BUILD})")
                } else {
                    String::new()
                };
                bail!("{bin} did not listen on {a}: {e}: {}{hint}", err.trim());
            }
        }
        // opentracker keeps running after a failed bind; make sure the ports
        // we are talking to are *ours* (a system-wide opentracker service on
        // *:6969 would otherwise silently take over).
        std::thread::sleep(Duration::from_millis(200));
        let err = proc.stderr_log();
        if err.contains("Address already in use") || !proc.is_running() {
            bail!("{bin} could not bind {:?}: {}", addrs, err.trim());
        }
        Ok(proc)
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
