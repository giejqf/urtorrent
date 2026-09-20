// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Driver for `urt-client`, the library under test as a lab actor. Mirrors
//! the oracle driver: launch inside a namespace, observe through a status
//! file, steer through a control file, stop gracefully.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::lab::{Actor, Proc};

/// Configuration for one client launch.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub profile: String,
    pub listen_port: u16,
    pub sequential: bool,
    pub resume: bool,
    pub exit_when_complete: bool,
    /// Bytes per second, 0 = unlimited.
    pub upload_limit: u64,
    pub download_limit: u64,
    /// `disabled` / `enabled` / `forced`.
    pub encryption: String,
    /// Extra environment (e.g. `RUST_LOG`).
    pub env: Vec<(String, String)>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            profile: "qbt".into(),
            listen_port: 6881,
            sequential: false,
            resume: true,
            exit_when_complete: false,
            upload_limit: 0,
            download_limit: 0,
            encryption: "enabled".into(),
            env: vec![("RUST_LOG".into(), "debug".into())],
        }
    }
}

impl ClientConfig {
    pub fn profile(mut self, p: &str) -> Self {
        self.profile = p.into();
        self
    }
    pub fn upload_limit(mut self, bytes_per_sec: u64) -> Self {
        self.upload_limit = bytes_per_sec;
        self
    }
    pub fn download_limit(mut self, bytes_per_sec: u64) -> Self {
        self.download_limit = bytes_per_sec;
        self
    }
    pub fn encryption(mut self, mode: &str) -> Self {
        self.encryption = mode.into();
        self
    }
    pub fn env(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }
}

/// A status snapshot written by the client.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct ClientStatus {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub pieces_have: usize,
    #[serde(default)]
    pub pieces_total: usize,
    #[serde(default)]
    pub total_size: u64,
    #[serde(default)]
    pub downloaded: u64,
    #[serde(default)]
    pub uploaded: u64,
    #[serde(default)]
    pub left: u64,
    #[serde(default)]
    pub corrupt: u64,
    #[serde(default)]
    pub redundant: u64,
    #[serde(default)]
    pub download_rate: u64,
    #[serde(default)]
    pub upload_rate: u64,
    #[serde(default)]
    pub peers: usize,
    #[serde(default)]
    pub seeds: usize,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub trackers: Vec<ClientTracker>,
    #[serde(default)]
    pub peer_list: Vec<ClientPeer>,
    /// Every peer that completed a handshake since start (latest counters).
    #[serde(default)]
    pub peers_seen: Vec<ClientPeer>,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub exited: bool,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct ClientTracker {
    pub url: String,
    #[serde(default)]
    pub working: bool,
    #[serde(default)]
    pub fails: u32,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct ClientPeer {
    pub addr: String,
    #[serde(default)]
    pub client: Option<String>,
    #[serde(default)]
    pub incoming: bool,
    #[serde(default)]
    pub downloaded: u64,
    #[serde(default)]
    pub uploaded: u64,
    #[serde(default)]
    pub is_seed: bool,
    #[serde(default)]
    pub peer_id: Option<String>,
    #[serde(default)]
    pub encrypted: bool,
}

/// A running client.
pub struct UrtClient {
    pub actor: Actor,
    pub config: ClientConfig,
    pub save_path: PathBuf,
    pub resume_dir: PathBuf,
    status_path: PathBuf,
    control_path: PathBuf,
    proc: Option<Proc>,
}

/// Path of the `urt-client` binary: built alongside the `testkit` binary.
pub fn client_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("current exe")?;
    let dir = exe.parent().context("exe dir")?;
    for cand in [dir.join("urt-client"), dir.join("../urt-client")] {
        if cand.exists() {
            return Ok(cand);
        }
    }
    bail!(
        "urt-client binary not found next to {} (run `cargo build -p testkit --bins`)",
        exe.display()
    )
}

impl UrtClient {
    /// Launch the client inside `actor` with `torrent` (a `.torrent` file).
    pub fn launch(actor: &Actor, config: ClientConfig, torrent: &Path) -> Result<UrtClient> {
        let bin = client_binary()?;
        let save_path = actor.log_dir.join("data");
        let resume_dir = actor.log_dir.join("resume");
        let status_path = actor.log_dir.join("status.json");
        let control_path = actor.log_dir.join("control");
        std::fs::create_dir_all(&save_path)?;
        std::fs::create_dir_all(&resume_dir)?;
        let _ = std::fs::remove_file(&status_path);
        let _ = std::fs::remove_file(&control_path);
        let mut cmd = actor.command_with_env(&bin, &config.env);
        cmd.arg("--torrent")
            .arg(torrent)
            .arg("--save")
            .arg(&save_path)
            .arg("--status")
            .arg(&status_path)
            .arg("--control")
            .arg(&control_path)
            .arg("--listen-port")
            .arg(config.listen_port.to_string())
            .arg("--profile")
            .arg(&config.profile);
        if config.resume {
            cmd.arg("--resume").arg(&resume_dir);
        }
        if config.sequential {
            cmd.arg("--sequential");
        }
        if config.exit_when_complete {
            cmd.arg("--exit-when-complete");
        }
        cmd.arg("--encryption").arg(&config.encryption);
        if config.upload_limit > 0 {
            cmd.arg("--upload-limit")
                .arg(config.upload_limit.to_string());
        }
        if config.download_limit > 0 {
            cmd.arg("--download-limit")
                .arg(config.download_limit.to_string());
        }
        // Bind only the families the actor has (v6-only namespaces have no
        // IPv4 address to announce anyway).
        if actor.v4.is_none() {
            cmd.arg("--no-v4");
        }
        if actor.v6.is_none() {
            cmd.arg("--no-v6");
        }
        let proc = Proc::spawn(&format!("urt-{}", actor.name), cmd, &actor.log_dir)?;
        let c = UrtClient {
            actor: actor.clone(),
            config,
            save_path,
            resume_dir,
            status_path,
            control_path,
            proc: Some(proc),
        };
        // Wait for the first status snapshot (engine up, torrent added).
        c.wait_for(Duration::from_secs(20), "client to start", |_| true)?;
        Ok(c)
    }

    /// The latest status snapshot, if written yet.
    pub fn status(&self) -> Option<ClientStatus> {
        let s = std::fs::read_to_string(&self.status_path).ok()?;
        serde_json::from_str(&s).ok()
    }

    /// Poll until `pred` holds or `timeout` elapses.
    pub fn wait_for<F: Fn(&ClientStatus) -> bool>(
        &self,
        timeout: Duration,
        what: &str,
        pred: F,
    ) -> Result<ClientStatus> {
        let start = Instant::now();
        loop {
            if let Some(st) = self.status() {
                if let Some(e) = &st.error {
                    bail!("client reported an error while waiting for {what}: {e}");
                }
                if pred(&st) {
                    return Ok(st);
                }
            }
            if start.elapsed() > timeout {
                let st = self.status();
                bail!(
                    "timed out waiting for {what}; last status: {st:?}\nstderr tail:\n{}",
                    self.stderr_tail(40)
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Send a control command (`shutdown`, `pause`, `resume`, `reannounce`,
    /// `save-resume`, `recheck`).
    pub fn command(&self, cmd: &str) -> Result<()> {
        let tmp = self.control_path.with_extension("tmp");
        std::fs::write(&tmp, cmd)?;
        std::fs::rename(&tmp, &self.control_path)?;
        Ok(())
    }

    /// Graceful shutdown: `stopped` announces, resume data, exit.
    pub fn shutdown(&mut self) -> Result<()> {
        self.command("shutdown")?;
        if let Some(mut p) = self.proc.take() {
            let start = Instant::now();
            while p.is_running() && start.elapsed() < Duration::from_secs(20) {
                std::thread::sleep(Duration::from_millis(50));
            }
            if p.is_running() {
                bail!(
                    "client did not exit after shutdown\nstderr tail:\n{}",
                    self.stderr_tail(40)
                );
            }
        }
        Ok(())
    }

    /// Simulate a crash.
    pub fn kill9(&mut self) -> Result<()> {
        if let Some(mut p) = self.proc.take() {
            p.kill9()?;
        }
        Ok(())
    }

    /// Start again in the same namespace with the same save / resume dirs
    /// (after `kill9` or `shutdown`).
    pub fn relaunch(&mut self, torrent: &Path) -> Result<()> {
        let fresh = UrtClient::launch(&self.actor, self.config.clone(), torrent)?;
        self.proc = fresh.proc;
        Ok(())
    }

    pub fn stderr_tail(&self, n: usize) -> String {
        let text = self
            .proc
            .as_ref()
            .map(|p| p.stderr_log())
            .unwrap_or_else(|| {
                std::fs::read_to_string(
                    self.actor
                        .log_dir
                        .join(format!("urt-{}.stderr.log", self.actor.name)),
                )
                .unwrap_or_default()
            });
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }
}
