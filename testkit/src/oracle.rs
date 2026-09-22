// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The pinned qBittorrent oracle: binary acquisition (checksum-pinned via
//! `testkit/oracle.lock`), per-test profile generation, launch inside a lab
//! namespace, and a WebAPI client to drive it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::lab::{Actor, Proc, wait_tcp};
use crate::webapi::WebApi;

/// Which libtorrent line the oracle build links.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LtLine {
    Lt2,
    Lt1,
}

impl LtLine {
    pub fn name(self) -> &'static str {
        match self {
            LtLine::Lt2 => "lt2",
            LtLine::Lt1 => "lt1",
        }
    }
}

#[derive(Debug, Deserialize)]
struct LockFile {
    oracle: LockOracle,
}

#[derive(Debug, Deserialize)]
struct LockOracle {
    qbittorrent: String,
    binary: Vec<LockBinary>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LockBinary {
    pub libtorrent: String,
    pub primary: bool,
    pub tag: String,
    pub url: String,
    pub sha256: String,
}

/// The parsed lock file.
#[derive(Debug, Clone)]
pub struct OracleLock {
    pub qbittorrent: String,
    pub binaries: Vec<LockBinary>,
}

pub fn lock_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("oracle.lock")
}

impl OracleLock {
    pub fn load() -> Result<OracleLock> {
        let p = lock_path();
        let s = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        let lf: LockFile = toml::from_str(&s).context("parsing oracle.lock")?;
        Ok(OracleLock {
            qbittorrent: lf.oracle.qbittorrent,
            binaries: lf.oracle.binary,
        })
    }

    pub fn binary(&self, line: LtLine) -> Result<&LockBinary> {
        let want_major = match line {
            LtLine::Lt2 => "2.",
            LtLine::Lt1 => "1.",
        };
        self.binaries
            .iter()
            .find(|b| b.libtorrent.starts_with(want_major))
            .with_context(|| format!("no {line:?} binary in oracle.lock"))
    }
}

/// Where oracle binaries are cached.
pub fn cache_dir() -> PathBuf {
    if let Ok(p) = std::env::var("URT_ORACLE_CACHE") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    Path::new(&home).join(".cache/urtorrent/oracle")
}

fn sha256_file(p: &Path) -> Result<String> {
    let data = std::fs::read(p)?;
    let mut h = Sha256::new();
    h.update(&data);
    Ok(crate::bencode::hex(&h.finalize()))
}

/// Ensure the pinned binary for `line` is present and verified; return its path.
pub fn ensure_binary(line: LtLine) -> Result<PathBuf> {
    let lock = OracleLock::load()?;
    let b = lock.binary(line)?;
    let dir = cache_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "qbittorrent-nox-{}",
        b.tag.trim_start_matches("release-")
    ));
    if path.exists() && sha256_file(&path)? == b.sha256 {
        return Ok(path);
    }
    tracing::info!(url = %b.url, "downloading oracle binary");
    let tmp = path.with_extension("part");
    let st = std::process::Command::new("curl")
        .args(["-sSL", "--fail", "-o"])
        .arg(&tmp)
        .arg(&b.url)
        .status()
        .context("running curl")?;
    if !st.success() {
        bail!("curl failed downloading {}", b.url);
    }
    let got = sha256_file(&tmp)?;
    if got != b.sha256 {
        let _ = std::fs::remove_file(&tmp);
        bail!(
            "oracle binary checksum mismatch for {}: got {got}, lock says {}",
            b.tag,
            b.sha256
        );
    }
    std::fs::rename(&tmp, &path)?;
    let mut perm = std::fs::metadata(&path)?.permissions();
    use std::os::unix::fs::PermissionsExt;
    perm.set_mode(0o755);
    std::fs::set_permissions(&path, perm)?;
    Ok(path)
}

/// libtorrent `settings_pack::enc_policy` as exposed by qBittorrent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encryption {
    /// Prefer encryption, allow plaintext (qBt "Allow encryption", value 0).
    Prefer = 0,
    /// Require encryption (qBt value 1).
    Force = 1,
    /// Disable encryption (qBt value 2).
    Disable = 2,
}

/// qBittorrent `BTProtocol`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtProtocol {
    Both = 0,
    Tcp = 1,
    Utp = 2,
}

/// Oracle settings for one launch. Defaults are the primary-capture profile
/// from AGENTS.md 7.3: DHT and uTP off, everything else at qBittorrent defaults.
#[derive(Clone, Debug)]
pub struct OracleConfig {
    pub line: LtLine,
    pub listen_port: u16,
    pub webui_port: u16,
    pub dht: bool,
    pub pex: bool,
    pub lsd: bool,
    pub upnp: bool,
    pub encryption: Encryption,
    pub protocol: BtProtocol,
    pub max_connections: i64,
    pub announce_to_all_tiers: bool,
    pub announce_to_all_trackers: bool,
    pub anonymous_mode: bool,
    pub validate_https: bool,
    pub queueing: bool,
    /// Extra environment for the process (e.g. `SSL_CERT_FILE` for the test CA).
    pub env: Vec<(String, String)>,
    /// Extra raw `[BitTorrent]` settings appended to the config file.
    pub extra_session_settings: Vec<(String, String)>,
    /// Interface the session should bind to (qBt "network interface"); `eth0` in the lab.
    pub interface: Option<String>,
}

impl OracleConfig {
    pub fn primary() -> OracleConfig {
        OracleConfig {
            line: LtLine::Lt2,
            listen_port: 6881,
            webui_port: 8080,
            dht: false,
            pex: true,
            lsd: true,
            upnp: false,
            encryption: Encryption::Prefer,
            protocol: BtProtocol::Tcp,
            max_connections: 500,
            announce_to_all_tiers: true,
            announce_to_all_trackers: false,
            anonymous_mode: false,
            validate_https: true,
            queueing: false,
            env: Vec::new(),
            extra_session_settings: Vec::new(),
            interface: None,
        }
    }

    /// qBittorrent's out-of-the-box settings (DHT and uTP on): documents the
    /// capability-gap quirks.
    pub fn defaults() -> OracleConfig {
        OracleConfig {
            dht: true,
            protocol: BtProtocol::Both,
            ..OracleConfig::primary()
        }
    }

    pub fn line(mut self, line: LtLine) -> Self {
        self.line = line;
        self
    }
    pub fn encryption(mut self, e: Encryption) -> Self {
        self.encryption = e;
        self
    }
    pub fn env(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.to_string(), v.to_string()));
        self
    }
    pub fn pex(mut self, on: bool) -> Self {
        self.pex = on;
        self
    }
    pub fn lsd(mut self, on: bool) -> Self {
        self.lsd = on;
        self
    }
    pub fn dht(mut self, on: bool) -> Self {
        self.dht = on;
        self
    }
    pub fn protocol(mut self, p: BtProtocol) -> Self {
        self.protocol = p;
        self
    }

    fn conf(&self, save_path: &Path, whitelist: &[String]) -> String {
        let b = |v: bool| if v { "true" } else { "false" };
        let mut s = String::new();
        s.push_str("[BitTorrent]\n");
        let proto = match self.protocol {
            BtProtocol::Both => "Both",
            BtProtocol::Tcp => "TCP",
            BtProtocol::Utp => "UTP",
        };
        s.push_str(&format!("Session\\BTProtocol={proto}\n"));
        s.push_str(&format!("Session\\DHTEnabled={}\n", b(self.dht)));
        s.push_str(&format!("Session\\PeXEnabled={}\n", b(self.pex)));
        s.push_str(&format!("Session\\LSDEnabled={}\n", b(self.lsd)));
        s.push_str(&format!("Session\\Encryption={}\n", self.encryption as i32));
        s.push_str(&format!("Session\\Port={}\n", self.listen_port));
        s.push_str(&format!(
            "Session\\MaxConnections={}\n",
            self.max_connections
        ));
        s.push_str(&format!(
            "Session\\QueueingSystemEnabled={}\n",
            b(self.queueing)
        ));
        s.push_str(&format!(
            "Session\\AnnounceToAllTiers={}\n",
            b(self.announce_to_all_tiers)
        ));
        s.push_str(&format!(
            "Session\\AnnounceToAllTrackers={}\n",
            b(self.announce_to_all_trackers)
        ));
        s.push_str(&format!(
            "Session\\AnonymousModeEnabled={}\n",
            b(self.anonymous_mode)
        ));
        s.push_str(&format!(
            "Session\\ValidateHTTPSTrackerCertificate={}\n",
            b(self.validate_https)
        ));
        s.push_str(&format!(
            "Session\\DefaultSavePath={}\n",
            save_path.display()
        ));
        s.push_str("Session\\TempPathEnabled=false\n");
        s.push_str("Session\\SSL\\Enabled=false\n");
        s.push_str("Session\\AddTorrentStopped=false\n");
        s.push_str("Session\\ResolvePeerCountries=false\n");
        if let Some(i) = &self.interface {
            s.push_str(&format!(
                "Session\\Interface={i}\nSession\\InterfaceName={i}\n"
            ));
        }
        for (k, v) in &self.extra_session_settings {
            s.push_str(&format!("Session\\{k}={v}\n"));
        }
        s.push_str("\n[LegalNotice]\nAccepted=true\n\n");
        s.push_str("[Network]\nPortForwardingEnabled=");
        s.push_str(b(self.upnp));
        s.push_str("\nProxy\\HostnameLookupEnabled=false\n\n");
        s.push_str("[Preferences]\n");
        s.push_str("Connection\\ResolvePeerCountries=false\n");
        s.push_str("General\\Locale=en\n");
        s.push_str(&format!("WebUI\\Port={}\n", self.webui_port));
        s.push_str("WebUI\\Username=admin\n");
        s.push_str("WebUI\\LocalHostAuth=false\n");
        s.push_str("WebUI\\AuthSubnetWhitelistEnabled=true\n");
        s.push_str(&format!(
            "WebUI\\AuthSubnetWhitelist={}\n",
            whitelist.join(", ")
        ));
        s.push_str("WebUI\\CSRFProtection=false\n");
        s.push_str("WebUI\\HostHeaderValidation=false\n");
        s.push_str("WebUI\\ClickjackingProtection=false\n");
        s
    }
}

/// A running oracle instance.
pub struct Oracle {
    pub actor: Actor,
    pub config: OracleConfig,
    pub profile_dir: PathBuf,
    pub save_path: PathBuf,
    pub api: WebApi,
    proc: Option<Proc>,
}

impl Oracle {
    /// The `qbittorrent-nox` process's pid (for resource sampling).
    pub fn pid(&self) -> Option<u32> {
        self.proc.as_ref().and_then(crate::lab::Proc::leaf_pid)
    }

    /// Launch the oracle inside `actor`. `whitelist` are the subnets allowed to
    /// use the WebAPI without a password (the lab subnets).
    pub fn launch(actor: &Actor, config: OracleConfig, whitelist: &[String]) -> Result<Oracle> {
        let bin = ensure_binary(config.line)?;
        let profile_dir = actor.log_dir.join("profile");
        let save_path = actor.log_dir.join("data");
        std::fs::create_dir_all(profile_dir.join("qBittorrent/config"))?;
        std::fs::create_dir_all(&save_path)?;
        std::fs::write(
            profile_dir.join("qBittorrent/config/qBittorrent.conf"),
            config.conf(&save_path, whitelist),
        )?;
        let mut cmd = actor.command_with_env(&bin, &config.env);
        cmd.arg(format!("--profile={}", profile_dir.display()))
            .arg(format!("--webui-port={}", config.webui_port));
        let proc = Proc::spawn(&format!("oracle-{}", actor.name), cmd, &actor.log_dir)?;
        let api_addr = actor.sock(config.webui_port);
        wait_tcp(api_addr, Duration::from_secs(30)).context("oracle WebUI did not come up")?;
        let api = WebApi::new(api_addr);
        // The WebUI answers before the session is ready; poll a real endpoint.
        let start = Instant::now();
        loop {
            match api.version() {
                Ok(v) => {
                    tracing::info!(actor = %actor.name, version = %v, "oracle up");
                    break;
                }
                Err(e) if start.elapsed() < Duration::from_secs(30) => {
                    tracing::debug!("oracle api not ready: {e}");
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => return Err(e).context("oracle WebAPI never became ready"),
            }
        }
        let o = Oracle {
            actor: actor.clone(),
            config,
            profile_dir,
            save_path,
            api,
            proc: Some(proc),
        };
        o.verify_pin()?;
        o.apply_preferences()?;
        Ok(o)
    }

    fn verify_pin(&self) -> Result<()> {
        let lock = OracleLock::load()?;
        let want = lock.binary(self.config.line)?;
        let v = self.api.version()?;
        if v.trim_start_matches('v') != lock.qbittorrent {
            bail!(
                "oracle reports qBittorrent {v}, lock pins {}",
                lock.qbittorrent
            );
        }
        let bi = self.api.build_info()?;
        let lt = bi.get("libtorrent").and_then(|v| v.as_str()).unwrap_or("");
        if !lt.starts_with(&want.libtorrent) {
            bail!(
                "oracle reports libtorrent {lt}, lock pins {}",
                want.libtorrent
            );
        }
        Ok(())
    }

    fn apply_preferences(&self) -> Result<()> {
        let c = &self.config;
        let prefs = serde_json::json!({
            "listen_port": c.listen_port,
            "random_port": false,
            "dht": c.dht,
            "pex": c.pex,
            "lsd": c.lsd,
            "upnp": c.upnp,
            "encryption": c.encryption as i32,
            "bittorrent_protocol": c.protocol as i32,
            "max_connec": c.max_connections,
            "announce_to_all_tiers": c.announce_to_all_tiers,
            "announce_to_all_trackers": c.announce_to_all_trackers,
            "anonymous_mode": c.anonymous_mode,
            "queueing_enabled": c.queueing,
            "save_path": self.save_path.to_string_lossy(),
            "temp_path_enabled": false,
            "resolve_peer_countries": false,
            "ssl_enabled": false,
            "add_stopped_enabled": false,
        });
        self.api.set_preferences(&prefs)?;
        // libtorrent applies the listen port asynchronously; wait for it.
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            let p = self.api.preferences()?;
            if p.get("listen_port").and_then(|v| v.as_i64()) == Some(i64::from(c.listen_port)) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        bail!("oracle did not accept listen_port {}", c.listen_port)
    }

    pub fn listen_port(&self) -> u16 {
        self.config.listen_port
    }

    /// Graceful shutdown through the WebAPI (sends `stopped` to trackers).
    pub fn shutdown(&mut self) -> Result<()> {
        if let Some(mut p) = self.proc.take() {
            let _ = self.api.shutdown();
            let start = Instant::now();
            while p.is_running() && start.elapsed() < Duration::from_secs(20) {
                std::thread::sleep(Duration::from_millis(100));
            }
            p.terminate(Duration::from_secs(10))?;
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

    /// Restart after a crash or shutdown with the same profile (resume data).
    pub fn restart(&mut self, whitelist: &[String]) -> Result<()> {
        let bin = ensure_binary(self.config.line)?;
        let mut cmd = self.actor.command_with_env(&bin, &self.config.env);
        cmd.arg(format!("--profile={}", self.profile_dir.display()))
            .arg(format!("--webui-port={}", self.config.webui_port));
        let _ = whitelist;
        let proc = Proc::spawn(
            &format!("oracle-{}-restart", self.actor.name),
            cmd,
            &self.actor.log_dir,
        )?;
        wait_tcp(
            self.actor.sock(self.config.webui_port),
            Duration::from_secs(30),
        )?;
        let start = Instant::now();
        while self.api.version().is_err() && start.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(200));
        }
        self.proc = Some(proc);
        Ok(())
    }

    pub fn main_log(&self) -> String {
        self.proc.as_ref().map(Proc::stderr_log).unwrap_or_default()
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
