// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! `transmission-daemon` as an independent peer implementation, driven over
//! its RPC (`/transmission/rpc`, session-id handshake). Only what the
//! scenarios need: add a torrent, poll its progress, list peers, stop.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::lab::{Actor, Proc, wait_tcp};

/// Transmission settings for one launch.
#[derive(Clone, Debug)]
pub struct TransmissionConfig {
    pub peer_port: u16,
    pub rpc_port: u16,
    /// `tolerated` (plaintext preferred), `preferred`, `required`.
    pub encryption: &'static str,
}

impl Default for TransmissionConfig {
    fn default() -> Self {
        TransmissionConfig {
            peer_port: 51413,
            rpc_port: 9091,
            encryption: "tolerated",
        }
    }
}

/// A running daemon.
pub struct Transmission {
    pub actor: Actor,
    pub config: TransmissionConfig,
    pub download_dir: PathBuf,
    rpc: String,
    session_id: std::cell::RefCell<String>,
    agent: ureq::Agent,
    proc: Option<Proc>,
}

/// Whether `transmission-daemon` is installed.
pub fn available() -> bool {
    std::process::Command::new("transmission-daemon")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

impl Transmission {
    /// Launch inside `actor`.
    pub fn launch(actor: &Actor, config: TransmissionConfig) -> Result<Transmission> {
        if !available() {
            bail!("transmission-daemon is not installed (apt install transmission-daemon)");
        }
        let conf_dir = actor.log_dir.join("transmission");
        let download_dir = actor.log_dir.join("data");
        std::fs::create_dir_all(&conf_dir)?;
        std::fs::create_dir_all(&download_dir)?;
        // Settings the flags cannot express go through settings.json.
        std::fs::write(
            conf_dir.join("settings.json"),
            json!({
                "pex-enabled": false,
                "dht-enabled": false,
                "lpd-enabled": false,
                // 4.1 derives utp/tcp from `preferred_transports` (note the
                // underscore: the canonical key as the daemon saves it), whose
                // default ([utp, tcp]) overrides the legacy `utp-enabled` flag.
                // uTP is out of scope for 0.1.0, so leave only TCP.
                "utp-enabled": false,
                "preferred_transports": ["tcp"],
                "port-forwarding-enabled": false,
                "rpc-whitelist-enabled": false,
                "rpc-host-whitelist-enabled": false,
                "rpc-authentication-required": false,
                "peer-port-random-on-start": false,
                "speed-limit-down-enabled": false,
                "speed-limit-up-enabled": false,
                "start-added-torrents": true,
                "umask": 18,
                "cache-size-mb": 4,
                "download-queue-enabled": false,
                "seed-queue-enabled": false,
            })
            .to_string(),
        )?;
        let mut cmd = actor.command(std::path::Path::new("transmission-daemon"));
        cmd.arg("-f")
            .arg("-g")
            .arg(&conf_dir)
            .arg("-w")
            .arg(&download_dir)
            .arg("-p")
            .arg(config.rpc_port.to_string())
            .arg("-P")
            .arg(config.peer_port.to_string())
            .arg("-T")
            .arg("-M")
            .arg("-O")
            .arg("-Y")
            .arg("-a")
            .arg("*")
            .arg("--log-level")
            .arg("debug")
            .arg("-e")
            .arg(actor.log_dir.join("transmission.log"));
        match config.encryption {
            "required" => cmd.arg("-er"),
            "preferred" => cmd.arg("-ep"),
            _ => cmd.arg("-et"),
        };
        if let Some(v4) = actor.v4 {
            cmd.arg("-i").arg(v4.to_string());
        }
        if let Some(v6) = actor.v6 {
            cmd.arg("-I").arg(v6.to_string());
        }
        // RPC listens on every address; the lab is isolated anyway.
        cmd.arg("-r").arg(if actor.v4.is_some() {
            "0.0.0.0".to_string()
        } else {
            "::".to_string()
        });
        let proc = Proc::spawn(&format!("transmission-{}", actor.name), cmd, &actor.log_dir)?;
        let rpc_addr: SocketAddr = actor.sock(config.rpc_port);
        if let Err(e) = wait_tcp(rpc_addr, Duration::from_secs(30)) {
            let out = proc.stdout_log();
            if out.contains("Permission denied") {
                bail!(
                    "transmission-daemon cannot access the lab run directory (AppArmor). \
                     Run `cargo xtask doctor` for the local override to add. Log: {}",
                    out.lines().next().unwrap_or("")
                );
            }
            return Err(e).context("transmission RPC did not come up");
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build()
            .into();
        let t = Transmission {
            actor: actor.clone(),
            config,
            download_dir,
            rpc: format!("http://{rpc_addr}/transmission/rpc"),
            session_id: std::cell::RefCell::new(String::new()),
            agent,
            proc: Some(proc),
        };
        // Handshake for the session id and confirm the daemon answers.
        let start = Instant::now();
        loop {
            match t.call("session-get", json!({})) {
                Ok(v) => {
                    tracing::info!(
                        actor = %actor.name,
                        version = %v["version"].as_str().unwrap_or("?"),
                        "transmission up"
                    );
                    break;
                }
                Err(e) if start.elapsed() < Duration::from_secs(30) => {
                    tracing::debug!("transmission rpc not ready: {e}");
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => return Err(e).context("transmission RPC never became ready"),
            }
        }
        Ok(t)
    }

    /// One RPC call; retries once on the 409 session-id handshake.
    pub fn call(&self, method: &str, arguments: Value) -> Result<Value> {
        let body = json!({ "method": method, "arguments": arguments }).to_string();
        for _ in 0..2 {
            let sid = self.session_id.borrow().clone();
            let resp = self
                .agent
                .post(&self.rpc)
                .header("X-Transmission-Session-Id", &sid)
                .send(body.as_bytes())
                .with_context(|| format!("rpc {method}"))?;
            let status = resp.status().as_u16();
            if status == 409 {
                if let Some(v) = resp.headers().get("X-Transmission-Session-Id") {
                    *self.session_id.borrow_mut() = v.to_str().unwrap_or("").to_string();
                    continue;
                }
                bail!("409 without session id");
            }
            let text = resp.into_body().read_to_string().unwrap_or_default();
            if status >= 400 {
                bail!("rpc {method} -> {status}: {text}");
            }
            let v: Value = serde_json::from_str(&text).context("rpc json")?;
            if v["result"] != "success" {
                bail!("rpc {method} failed: {}", v["result"]);
            }
            return Ok(v["arguments"].clone());
        }
        bail!("rpc {method}: session id handshake failed")
    }

    /// Add a torrent from its bytes; returns the transmission id.
    pub fn add_torrent(&self, torrent: &[u8]) -> Result<i64> {
        let b64 = base64(torrent);
        let v = self.call(
            "torrent-add",
            json!({ "metainfo": b64, "download-dir": self.download_dir.to_string_lossy() }),
        )?;
        let t = v
            .get("torrent-added")
            .or_else(|| v.get("torrent-duplicate"))
            .context("torrent-add: no torrent in reply")?;
        t["id"].as_i64().context("torrent id")
    }

    /// `torrent-get` for one torrent.
    pub fn torrent(&self, id: i64) -> Result<Value> {
        let v = self.call(
            "torrent-get",
            json!({
                "ids": [id],
                "fields": ["id", "status", "percentDone", "downloadedEver", "uploadedEver",
                           "leftUntilDone", "peersConnected", "error", "errorString",
                           "trackerStats", "peers"]
            }),
        )?;
        v["torrents"]
            .as_array()
            .and_then(|a| a.first().cloned())
            .context("torrent not found")
    }

    /// Poll until `pred` holds.
    pub fn wait_for<F: Fn(&Value) -> bool>(
        &self,
        id: i64,
        timeout: Duration,
        what: &str,
        pred: F,
    ) -> Result<Value> {
        let start = Instant::now();
        loop {
            let t = self.torrent(id)?;
            if t["error"].as_i64().unwrap_or(0) != 0 {
                bail!(
                    "transmission error while waiting for {what}: {}",
                    t["errorString"]
                );
            }
            if pred(&t) {
                return Ok(t);
            }
            if start.elapsed() > timeout {
                bail!("timed out waiting for {what}; last: {t}");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Stop the daemon gracefully (SIGTERM: it sends `stopped`).
    pub fn shutdown(&mut self) -> Result<()> {
        if let Some(mut p) = self.proc.take() {
            p.terminate(Duration::from_secs(20))?;
        }
        Ok(())
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.actor.log_dir.join("transmission.log")).unwrap_or_default()
    }
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
