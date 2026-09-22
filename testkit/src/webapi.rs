// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! qBittorrent WebAPI (`/api/v2/...`) client, just enough to drive the oracle.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::Value;

/// A WebAPI client for one oracle instance.
#[derive(Clone)]
pub struct WebApi {
    base: String,
    agent: ureq::Agent,
}

/// Subset of `torrents/info`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TorrentInfo {
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub progress: f64,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub total_size: i64,
    #[serde(default)]
    pub completed: i64,
    #[serde(default)]
    pub downloaded: i64,
    #[serde(default)]
    pub uploaded: i64,
    #[serde(default)]
    pub dlspeed: i64,
    #[serde(default)]
    pub upspeed: i64,
    #[serde(default)]
    pub num_seeds: i64,
    #[serde(default)]
    pub num_leechs: i64,
    #[serde(default)]
    pub num_complete: i64,
    #[serde(default)]
    pub num_incomplete: i64,
    #[serde(default)]
    pub save_path: String,
    #[serde(default)]
    pub tracker: String,
    #[serde(default)]
    pub trackers_count: i64,
}

impl TorrentInfo {
    /// All data present (not while (re)checking).
    pub fn is_complete(&self) -> bool {
        !self.state.starts_with("checking")
            && (self.progress >= 1.0
                || matches!(
                    self.state.as_str(),
                    "uploading" | "stalledUP" | "queuedUP" | "forcedUP" | "stoppedUP" | "pausedUP"
                ))
    }
    /// Actively seeding (accepting peers).
    pub fn is_seeding(&self) -> bool {
        matches!(self.state.as_str(), "uploading" | "stalledUP" | "forcedUP")
    }
}

/// Subset of `torrents/trackers`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TrackerInfo {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub status: i64,
    #[serde(default)]
    pub tier: i64,
    #[serde(default)]
    pub msg: String,
    #[serde(default)]
    pub num_peers: i64,
    #[serde(default)]
    pub num_seeds: i64,
    #[serde(default)]
    pub num_leeches: i64,
}

/// Subset of `sync/torrentPeers` entries.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PeerInfo {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: i64,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub peer_id_client: String,
    #[serde(default)]
    pub connection: String,
    #[serde(default)]
    pub flags: String,
    #[serde(default)]
    pub progress: f64,
    #[serde(default)]
    pub downloaded: i64,
    #[serde(default)]
    pub uploaded: i64,
}

/// Options for `torrents/add`.
#[derive(Clone, Debug, Default)]
pub struct AddTorrent {
    pub torrent: Option<Vec<u8>>,
    pub magnet: Option<String>,
    pub save_path: Option<String>,
    pub stopped: bool,
    pub skip_checking: bool,
    pub sequential: bool,
    pub tags: Option<String>,
}

impl AddTorrent {
    pub fn file(bytes: &[u8]) -> AddTorrent {
        AddTorrent {
            torrent: Some(bytes.to_vec()),
            ..Default::default()
        }
    }
    pub fn magnet(uri: &str) -> AddTorrent {
        AddTorrent {
            magnet: Some(uri.to_string()),
            ..Default::default()
        }
    }
    pub fn save_path(mut self, p: &str) -> Self {
        self.save_path = Some(p.to_string());
        self
    }
    pub fn stopped(mut self, v: bool) -> Self {
        self.stopped = v;
        self
    }
    pub fn skip_checking(mut self, v: bool) -> Self {
        self.skip_checking = v;
        self
    }
}

impl WebApi {
    pub fn new(addr: SocketAddr) -> WebApi {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build()
            .into();
        WebApi {
            base: format!("http://{addr}/api/v2"),
            agent,
        }
    }

    fn check(&self, path: &str, resp: ureq::http::Response<ureq::Body>) -> Result<String> {
        let status = resp.status().as_u16();
        let body = resp.into_body().read_to_string().unwrap_or_default();
        if status >= 400 {
            bail!("WebAPI {path} -> {status}: {body}");
        }
        Ok(body)
    }

    pub fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<String> {
        let mut url = format!("{}/{path}", self.base);
        if !query.is_empty() {
            url.push('?');
            url.push_str(
                &query
                    .iter()
                    .map(|(k, v)| format!("{k}={}", crate::http::percent_encode(v.as_bytes())))
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        // Transport hiccups (an interrupted syscall while the oracle is
        // busy with hundreds of torrents) are retried: they say nothing
        // about the thing under test.
        let mut last = None;
        for attempt in 0..3 {
            match self.agent.get(&url).call() {
                Ok(resp) => return self.check(path, resp),
                Err(e) => {
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(50 * (attempt + 1)));
                }
            }
        }
        Err(last.map_or_else(
            || anyhow!("GET {url}: no response"),
            |e| anyhow!("GET {url}: {e}"),
        ))
    }

    pub fn post_form(&self, path: &str, form: &[(&str, &str)]) -> Result<String> {
        let url = format!("{}/{path}", self.base);
        let resp = self
            .agent
            .post(&url)
            .send_form(form.iter().copied())
            .with_context(|| format!("POST {url}"))?;
        self.check(path, resp)
    }

    pub fn post_multipart(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        files: &[(&str, &str, &[u8])],
    ) -> Result<String> {
        let boundary = format!("----urtorrent{}", std::process::id());
        let mut body = Vec::new();
        for (k, v) in fields {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
                )
                .as_bytes(),
            );
        }
        for (name, filename, data) in files {
            body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: application/x-bittorrent\r\n\r\n").as_bytes());
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let url = format!("{}/{path}", self.base);
        let resp = self
            .agent
            .post(&url)
            .content_type(format!("multipart/form-data; boundary={boundary}"))
            .send(&body[..])
            .with_context(|| format!("POST multipart {url}"))?;
        self.check(path, resp)
    }

    pub fn version(&self) -> Result<String> {
        self.get("app/version", &[])
    }

    pub fn build_info(&self) -> Result<Value> {
        Ok(serde_json::from_str(&self.get("app/buildInfo", &[])?)?)
    }

    pub fn preferences(&self) -> Result<Value> {
        Ok(serde_json::from_str(&self.get("app/preferences", &[])?)?)
    }

    pub fn set_preferences(&self, prefs: &Value) -> Result<()> {
        self.post_form("app/setPreferences", &[("json", &prefs.to_string())])?;
        Ok(())
    }

    pub fn shutdown(&self) -> Result<()> {
        self.post_form("app/shutdown", &[])?;
        Ok(())
    }

    /// Add a torrent. Returns once the torrent shows up in `torrents/info`.
    pub fn add_torrent(&self, add: &AddTorrent, info_hash_hex: &str) -> Result<TorrentInfo> {
        let mut fields: Vec<(String, String)> = Vec::new();
        if let Some(p) = &add.save_path {
            fields.push(("savepath".into(), p.clone()));
        }
        fields.push(("stopped".into(), add.stopped.to_string()));
        fields.push(("paused".into(), add.stopped.to_string()));
        fields.push(("skip_checking".into(), add.skip_checking.to_string()));
        fields.push(("sequentialDownload".into(), add.sequential.to_string()));
        if let Some(t) = &add.tags {
            fields.push(("tags".into(), t.clone()));
        }
        if let Some(m) = &add.magnet {
            fields.push(("urls".into(), m.clone()));
        }
        let f: Vec<(&str, &str)> = fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let files: Vec<(&str, &str, &[u8])> = match &add.torrent {
            Some(t) => vec![("torrents", "fixture.torrent", t.as_slice())],
            None => Vec::new(),
        };
        let r = self.post_multipart("torrents/add", &f, &files)?;
        // qBt <= 5.1 answers "Ok."; 5.2+ answers a JSON summary.
        let ok = r.trim() == "Ok."
            || serde_json::from_str::<Value>(&r)
                .ok()
                .and_then(|v| v.get("success_count").and_then(Value::as_i64))
                .is_some_and(|n| n >= 1);
        if !ok {
            bail!("torrents/add returned {r:?}");
        }
        let start = Instant::now();
        loop {
            if let Some(t) = self.torrent(info_hash_hex)? {
                return Ok(t);
            }
            if start.elapsed() > Duration::from_secs(15) {
                bail!("torrent {info_hash_hex} did not appear after add");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn torrents(&self) -> Result<Vec<TorrentInfo>> {
        Ok(serde_json::from_str(&self.get("torrents/info", &[])?)?)
    }

    pub fn torrent(&self, hash: &str) -> Result<Option<TorrentInfo>> {
        let v: Vec<TorrentInfo> =
            serde_json::from_str(&self.get("torrents/info", &[("hashes", hash)])?)?;
        Ok(v.into_iter().find(|t| t.hash.eq_ignore_ascii_case(hash)))
    }

    pub fn properties(&self, hash: &str) -> Result<Value> {
        Ok(serde_json::from_str(
            &self.get("torrents/properties", &[("hash", hash)])?,
        )?)
    }

    pub fn trackers(&self, hash: &str) -> Result<Vec<TrackerInfo>> {
        Ok(serde_json::from_str(
            &self.get("torrents/trackers", &[("hash", hash)])?,
        )?)
    }

    pub fn files(&self, hash: &str) -> Result<Value> {
        Ok(serde_json::from_str(
            &self.get("torrents/files", &[("hash", hash)])?,
        )?)
    }

    pub fn peers(&self, hash: &str) -> Result<Vec<PeerInfo>> {
        let v: Value =
            serde_json::from_str(&self.get("sync/torrentPeers", &[("hash", hash), ("rid", "0")])?)?;
        let mut out = Vec::new();
        if let Some(m) = v.get("peers").and_then(Value::as_object) {
            for p in m.values() {
                out.push(serde_json::from_value(p.clone()).unwrap_or_default());
            }
        }
        Ok(out)
    }

    pub fn stop(&self, hash: &str) -> Result<()> {
        self.post_form("torrents/stop", &[("hashes", hash)])?;
        Ok(())
    }
    pub fn start(&self, hash: &str) -> Result<()> {
        self.post_form("torrents/start", &[("hashes", hash)])?;
        Ok(())
    }
    pub fn recheck(&self, hash: &str) -> Result<()> {
        self.post_form("torrents/recheck", &[("hashes", hash)])?;
        Ok(())
    }
    pub fn reannounce(&self, hash: &str) -> Result<()> {
        self.post_form("torrents/reannounce", &[("hashes", hash)])?;
        Ok(())
    }
    pub fn delete(&self, hash: &str, delete_files: bool) -> Result<()> {
        self.post_form(
            "torrents/delete",
            &[("hashes", hash), ("deleteFiles", &delete_files.to_string())],
        )?;
        Ok(())
    }
    pub fn set_file_priority(&self, hash: &str, ids: &[usize], prio: u8) -> Result<()> {
        let id = ids
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join("|");
        self.post_form(
            "torrents/filePrio",
            &[("hash", hash), ("id", &id), ("priority", &prio.to_string())],
        )?;
        Ok(())
    }
    pub fn add_peers(&self, hash: &str, peers: &[SocketAddr]) -> Result<()> {
        let p = peers
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("|");
        self.post_form("torrents/addPeers", &[("hashes", hash), ("peers", &p)])?;
        Ok(())
    }
    pub fn set_location(&self, hash: &str, location: &str) -> Result<()> {
        self.post_form(
            "torrents/setLocation",
            &[("hashes", hash), ("location", location)],
        )?;
        Ok(())
    }
    pub fn transfer_info(&self) -> Result<Value> {
        Ok(serde_json::from_str(&self.get("transfer/info", &[])?)?)
    }
    pub fn main_log(&self) -> Result<Vec<String>> {
        let v: Vec<Value> = serde_json::from_str(&self.get(
            "log/main",
            &[
                ("normal", "true"),
                ("info", "true"),
                ("warning", "true"),
                ("critical", "true"),
            ],
        )?)?;
        Ok(v.iter()
            .map(|e| {
                e.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            })
            .collect())
    }
    pub fn peer_log(&self) -> Result<Vec<String>> {
        let v: Vec<Value> = serde_json::from_str(&self.get("log/peers", &[])?)?;
        Ok(v.iter()
            .map(|e| {
                format!(
                    "{} {}",
                    e.get("ip").and_then(Value::as_str).unwrap_or(""),
                    e.get("reason").and_then(Value::as_str).unwrap_or("")
                )
            })
            .collect())
    }

    /// Poll `torrents/info` until `pred` holds or `timeout` passes.
    pub fn wait_for<F: Fn(&TorrentInfo) -> bool>(
        &self,
        hash: &str,
        timeout: Duration,
        what: &str,
        pred: F,
    ) -> Result<TorrentInfo> {
        let start = Instant::now();
        let mut last = None;
        loop {
            if let Some(t) = self.torrent(hash)? {
                if pred(&t) {
                    return Ok(t);
                }
                last = Some(t);
            }
            if start.elapsed() > timeout {
                return Err(anyhow!(
                    "timed out waiting for {what} on {hash}; last state: {last:?}"
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}
