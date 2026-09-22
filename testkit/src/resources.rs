// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Resource sampling for the benchmarks: peak RSS and CPU time of a process
//! (and its threads), read from `/proc`. A sampler thread polls while the
//! work runs; the process's own `VmHWM` gives the true peak between polls.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// What a run cost.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Usage {
    /// Peak resident set size, bytes (`VmHWM`, the kernel's own high-water
    /// mark: exact, not a sample).
    pub peak_rss: u64,
    /// Resident set size at the last sample, bytes.
    pub last_rss: u64,
    /// Peak anonymous resident memory seen, bytes (`RssAnon`): what the
    /// process allocated, without file-backed pages. libtorrent 2.0 maps
    /// the torrent's files, so its `VmRSS` counts page cache this does
    /// not.
    pub peak_anon: u64,
    /// Peak file-backed resident memory seen, bytes (`RssFile`).
    pub peak_file: u64,
    /// User CPU time, seconds.
    pub user: f64,
    /// System CPU time, seconds.
    pub sys: f64,
    /// Samples taken (0 = the process was gone before the first one).
    pub samples: u64,
}

impl Usage {
    /// User + system CPU, seconds.
    pub fn cpu(&self) -> f64 {
        self.user + self.sys
    }

    /// Peak RSS in MiB.
    pub fn peak_mib(&self) -> f64 {
        self.peak_rss as f64 / (1024.0 * 1024.0)
    }

    /// Peak anonymous RSS in MiB.
    pub fn anon_mib(&self) -> f64 {
        self.peak_anon as f64 / (1024.0 * 1024.0)
    }

    /// Peak file-backed RSS in MiB.
    pub fn file_mib(&self) -> f64 {
        self.peak_file as f64 / (1024.0 * 1024.0)
    }
}

/// Clock ticks per second. `getconf CLK_TCK` is 100 on every Linux the
/// project supports; `/proc/self/stat` is in those units. (The testkit
/// forbids `unsafe`, so this is read rather than `sysconf`ed.)
fn clk_tck() -> f64 {
    std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(100.0)
}

/// `(utime, stime)` in seconds from `/proc/<pid>/stat`.
pub fn cpu_of(pid: u32) -> Option<(f64, f64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the (possibly parenthesised, space-containing) comm.
    let rest = stat.rsplit_once(") ")?.1;
    let f: Vec<&str> = rest.split_whitespace().collect();
    // stat(5): field 14 (utime) is index 11 after the state field here.
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    let tck = clk_tck();
    Some((utime as f64 / tck, stime as f64 / tck))
}

/// `(VmRSS, VmHWM, RssAnon, RssFile)` in bytes from `/proc/<pid>/status`.
pub fn rss_of(pid: u32) -> Option<(u64, u64, u64, u64)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let kb = |key: &str| -> Option<u64> {
        let line = status.lines().find(|l| l.starts_with(key))?;
        line.split_whitespace().nth(1)?.parse::<u64>().ok()
    };
    Some((
        kb("VmRSS:")? * 1024,
        kb("VmHWM:")? * 1024,
        kb("RssAnon:").unwrap_or(0) * 1024,
        kb("RssFile:").unwrap_or(0) * 1024,
    ))
}

/// Polls a process while it works; the last reading before it exits wins.
pub struct Sampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    peak_anon: Arc<AtomicU64>,
    peak_file: Arc<AtomicU64>,
    last: Arc<AtomicU64>,
    user_us: Arc<AtomicU64>,
    sys_us: Arc<AtomicU64>,
    samples: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Sampler {
    /// Start sampling `pid` every 50 ms.
    pub fn start(pid: u32) -> Sampler {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(0));
        let peak_anon = Arc::new(AtomicU64::new(0));
        let peak_file = Arc::new(AtomicU64::new(0));
        let last = Arc::new(AtomicU64::new(0));
        let user_us = Arc::new(AtomicU64::new(0));
        let sys_us = Arc::new(AtomicU64::new(0));
        let samples = Arc::new(AtomicU64::new(0));
        let handle = {
            let (stop, peak, peak_anon, peak_file, last, user_us, sys_us, samples) = (
                stop.clone(),
                peak.clone(),
                peak_anon.clone(),
                peak_file.clone(),
                last.clone(),
                user_us.clone(),
                sys_us.clone(),
                samples.clone(),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let mut alive = false;
                    if let Some((rss, hwm, anon, file)) = rss_of(pid) {
                        alive = true;
                        last.store(rss, Ordering::Relaxed);
                        peak.fetch_max(hwm, Ordering::Relaxed);
                        peak_anon.fetch_max(anon, Ordering::Relaxed);
                        peak_file.fetch_max(file, Ordering::Relaxed);
                    }
                    if let Some((u, s)) = cpu_of(pid) {
                        alive = true;
                        user_us.store((u * 1e6) as u64, Ordering::Relaxed);
                        sys_us.store((s * 1e6) as u64, Ordering::Relaxed);
                    }
                    if alive {
                        samples.fetch_add(1, Ordering::Relaxed);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            })
        };
        Sampler {
            stop,
            peak,
            peak_anon,
            peak_file,
            last,
            user_us,
            sys_us,
            samples,
            handle: Some(handle),
        }
    }

    /// Reading so far, without stopping.
    pub fn read(&self) -> Usage {
        Usage {
            peak_rss: self.peak.load(Ordering::Relaxed),
            last_rss: self.last.load(Ordering::Relaxed),
            peak_anon: self.peak_anon.load(Ordering::Relaxed),
            peak_file: self.peak_file.load(Ordering::Relaxed),
            user: self.user_us.load(Ordering::Relaxed) as f64 / 1e6,
            sys: self.sys_us.load(Ordering::Relaxed) as f64 / 1e6,
            samples: self.samples.load(Ordering::Relaxed),
        }
    }

    /// Stop sampling and take the final reading.
    pub fn finish(mut self) -> Usage {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.read()
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
