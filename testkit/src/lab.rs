// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The isolated network lab: a host bridge carrying a private IPv4 and IPv6
//! subnet, and one network namespace per actor attached to it with a veth pair.
//! Actors have no default route, so nothing in the lab can reach the public
//! internet (AGENTS.md rule 3). The harness itself runs in the host namespace
//! and reaches actors through the bridge address.
//!
//! Requires passwordless `sudo` for `ip` and `nsenter`; `xtask doctor` checks.

use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Address-family shape of an actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Shape {
    V4,
    V6,
    Dual,
}

impl Shape {
    pub fn all() -> [Shape; 3] {
        [Shape::V4, Shape::V6, Shape::Dual]
    }
    pub fn name(self) -> &'static str {
        match self {
            Shape::V4 => "v4",
            Shape::V6 => "v6",
            Shape::Dual => "dual",
        }
    }
    pub fn parse(s: &str) -> Option<Shape> {
        match s {
            "v4" => Some(Shape::V4),
            "v6" => Some(Shape::V6),
            "dual" => Some(Shape::Dual),
            _ => None,
        }
    }
    pub fn has_v4(self) -> bool {
        matches!(self, Shape::V4 | Shape::Dual)
    }
    pub fn has_v6(self) -> bool {
        matches!(self, Shape::V6 | Shape::Dual)
    }
}

const BRIDGE_PREFIX: &str = "urt";

fn sudo() -> Command {
    let mut c = Command::new("sudo");
    c.arg("-n");
    c
}

fn run(cmd: &mut Command) -> Result<String> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("spawning {cmd:?}"))?;
    if !out.status.success() {
        bail!(
            "{cmd:?} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn ip(args: &[&str]) -> Result<String> {
    let mut c = sudo();
    c.arg("ip").args(args);
    run(&mut c)
}

/// Check that the privileged operations the lab needs are available.
pub fn preflight() -> Result<()> {
    run(sudo().arg("true"))
        .context("passwordless sudo is required for the netns lab (sudo -n true failed)")?;
    ip(&["-V"]).context("iproute2 not usable via sudo")?;
    run(sudo().arg("nsenter").arg("--version"))
        .context("nsenter (util-linux) not usable via sudo")?;
    Ok(())
}

/// A lab: one bridge, N actor namespaces.
pub struct Lab {
    id: u8,
    bridge: String,
    next_host: u8,
    actors: Vec<String>,
    keep: bool,
    /// Where actor logs, profiles and captures go.
    pub run_dir: PathBuf,
}

impl Lab {
    /// Create a new lab with a fresh id. `run_dir` receives logs and captures.
    pub fn create(run_dir: &Path) -> Result<Lab> {
        preflight()?;
        fs::create_dir_all(run_dir)?;
        let existing = ip(&["-o", "link", "show", "type", "bridge"])?;
        let taken: Vec<u8> = existing
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(str::trim)
            .filter_map(|n| n.strip_prefix(BRIDGE_PREFIX))
            .filter_map(|n| n.parse().ok())
            .collect();
        let mut id = (std::process::id() % 200 + 20) as u8;
        for _ in 0..240 {
            if !taken.contains(&id) {
                break;
            }
            id = id.wrapping_add(1).max(20);
        }
        let bridge = format!("{BRIDGE_PREFIX}{id}");
        ip(&["link", "add", &bridge, "type", "bridge"])?;
        let lab = Lab {
            id,
            bridge: bridge.clone(),
            next_host: 10,
            actors: Vec::new(),
            keep: false,
            run_dir: run_dir.to_path_buf(),
        };
        let res = (|| -> Result<()> {
            ip(&["link", "set", &bridge, "up"])?;
            ip(&[
                "addr",
                "add",
                &format!("{}/24", lab.host_v4()),
                "dev",
                &bridge,
            ])?;
            ip(&[
                "-6",
                "addr",
                "add",
                &format!("{}/64", lab.host_v6()),
                "dev",
                &bridge,
                "nodad",
            ])?;
            // Never forward lab traffic anywhere.
            run(sudo().args([
                "sysctl",
                "-q",
                &format!("net.ipv4.conf.{bridge}.forwarding=0"),
                &format!("net.ipv6.conf.{bridge}.forwarding=0"),
            ]))?;
            // Multicast snooping off so LSD floods to every actor like a dumb switch.
            let _ = ip(&[
                "link",
                "set",
                &bridge,
                "type",
                "bridge",
                "mcast_snooping",
                "0",
            ]);
            // Host firewalls (ufw, docker) commonly default INPUT to drop: let
            // lab traffic reach the harness (tap-tracker, tap-peer, opentracker).
            firewall_allow(&bridge, true);
            Ok(())
        })();
        if let Err(e) = res {
            let _ = ip(&["link", "del", &bridge]);
            return Err(e);
        }
        tracing::info!(id, %bridge, "lab created");
        Ok(lab)
    }

    pub fn id(&self) -> u8 {
        self.id
    }
    pub fn bridge(&self) -> &str {
        &self.bridge
    }
    /// The harness's own IPv4 address on the lab bridge.
    pub fn host_v4(&self) -> Ipv4Addr {
        Ipv4Addr::new(10, 77, self.id, 1)
    }
    /// The harness's own IPv6 address on the lab bridge.
    pub fn host_v6(&self) -> Ipv6Addr {
        Ipv6Addr::new(0xfd77, u16::from(self.id), 0, 0, 0, 0, 0, 1)
    }
    pub fn host_addr(&self, shape: Shape) -> IpAddr {
        if shape.has_v4() {
            IpAddr::V4(self.host_v4())
        } else {
            IpAddr::V6(self.host_v6())
        }
    }
    pub fn v4_subnet(&self) -> String {
        format!("10.77.{}.0/24", self.id)
    }
    pub fn v6_subnet(&self) -> String {
        format!("fd77:{:x}::/64", self.id)
    }

    /// Keep the lab (and its namespaces) around after drop, for debugging.
    pub fn keep(&mut self) {
        self.keep = true;
    }

    /// Add an extra host-side address `10.77.<id>.<n>` / `fd77:<id>::<n>` on
    /// the bridge, so that several harness-side actors (tap-tracker, tap-peers)
    /// can present distinct IPs to the clients under test.
    pub fn host_alias(&self, n: u8) -> Result<(Ipv4Addr, Ipv6Addr)> {
        if !(2..10).contains(&n) {
            bail!("host alias index must be 2..9");
        }
        let v4 = Ipv4Addr::new(10, 77, self.id, n);
        let v6 = Ipv6Addr::new(0xfd77, u16::from(self.id), 0, 0, 0, 0, 0, u16::from(n));
        let _ = ip(&["addr", "add", &format!("{v4}/24"), "dev", &self.bridge]);
        let _ = ip(&[
            "-6",
            "addr",
            "add",
            &format!("{v6}/64"),
            "dev",
            &self.bridge,
            "nodad",
        ]);
        Ok((v4, v6))
    }

    /// Create an actor namespace attached to the bridge.
    pub fn actor(&mut self, name: &str) -> Result<Actor> {
        self.actor_with_shape(name, Shape::Dual)
    }

    pub fn actor_with_shape(&mut self, name: &str, shape: Shape) -> Result<Actor> {
        let idx = self.next_host;
        if idx == 250 {
            bail!("too many actors in lab");
        }
        self.next_host += 1;
        let ns = format!("{}-{name}", self.bridge);
        let veth = format!("{}n{idx}", self.bridge);
        ip(&["netns", "add", &ns])?;
        self.actors.push(ns.clone());
        ip(&[
            "link", "add", &veth, "type", "veth", "peer", "name", "eth0", "netns", &ns,
        ])?;
        ip(&["link", "set", &veth, "master", &self.bridge, "up"])?;
        ip(&["-n", &ns, "link", "set", "lo", "up"])?;
        let v4 = shape.has_v4().then(|| Ipv4Addr::new(10, 77, self.id, idx));
        let v6 = shape
            .has_v6()
            .then(|| Ipv6Addr::new(0xfd77, u16::from(self.id), 0, 0, 0, 0, 0, u16::from(idx)));
        if let Some(a) = v4 {
            ip(&["-n", &ns, "addr", "add", &format!("{a}/24"), "dev", "eth0"])?;
        } else {
            // v6-only: make sure nothing can even bind v4 on the lab interface.
            let _ = ip(&[
                "netns",
                "exec",
                &ns,
                "sysctl",
                "-q",
                "net.ipv6.conf.eth0.disable_ipv6=0",
            ]);
        }
        if let Some(a) = v6 {
            ip(&[
                "-n",
                &ns,
                "-6",
                "addr",
                "add",
                &format!("{a}/64"),
                "dev",
                "eth0",
                "nodad",
            ])?;
        } else {
            ip(&[
                "netns",
                "exec",
                &ns,
                "sysctl",
                "-q",
                "net.ipv6.conf.eth0.disable_ipv6=1",
                "net.ipv6.conf.lo.disable_ipv6=1",
                "net.ipv6.conf.all.disable_ipv6=1",
            ])?;
        }
        ip(&["-n", &ns, "link", "set", "eth0", "up"])?;
        // Wait until the interface is fully up (carrier on both ends of the veth).
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            let st = ip(&["-n", &ns, "-o", "link", "show", "eth0"]).unwrap_or_default();
            if st.contains("LOWER_UP") {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        tracing::info!(%ns, ?v4, ?v6, "actor created");
        Ok(Actor {
            name: name.to_string(),
            ns,
            shape,
            v4,
            v6,
            log_dir: self.run_dir.join(name),
        })
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        if self.keep {
            tracing::warn!(bridge = %self.bridge, "keeping lab; run `testkit lab clean` to remove");
            return;
        }
        for ns in &self.actors {
            let _ = ip(&["netns", "del", ns]);
        }
        firewall_allow(&self.bridge, false);
        let _ = ip(&["link", "del", &self.bridge]);
    }
}

/// Insert (or delete) an INPUT accept rule for traffic arriving on `bridge`,
/// for both address families. Best effort: hosts without iptables are fine.
fn firewall_allow(bridge: &str, add: bool) {
    for tool in ["iptables", "ip6tables"] {
        if Command::new("which")
            .arg(tool)
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            continue;
        }
        let op = if add { "-I" } else { "-D" };
        let mut c = sudo();
        c.args([tool, "-w", "5", op, "INPUT", "-i", bridge, "-j", "ACCEPT"]);
        if let Err(e) = run(&mut c) {
            tracing::debug!("{tool} {op} rule for {bridge}: {e}");
        }
    }
}

/// Remove every lab bridge and namespace on this machine (stale runs).
pub fn clean_all() -> Result<Vec<String>> {
    let mut removed = Vec::new();
    let nss = ip(&["netns", "list"]).unwrap_or_default();
    for l in nss.lines() {
        let name = l.split_whitespace().next().unwrap_or("");
        if name.starts_with(BRIDGE_PREFIX) && name.contains('-') {
            let _ = ip(&["netns", "del", name]);
            removed.push(name.to_string());
        }
    }
    let links = ip(&["-o", "link", "show", "type", "bridge"]).unwrap_or_default();
    for l in links.lines() {
        let name = l.split(':').nth(1).map(str::trim).unwrap_or("");
        if let Some(rest) = name.strip_prefix(BRIDGE_PREFIX)
            && rest.parse::<u8>().is_ok()
        {
            firewall_allow(name, false);
            let _ = ip(&["link", "del", name]);
            removed.push(name.to_string());
        }
    }
    // Stale firewall rules from crashed runs.
    for tool in ["iptables", "ip6tables"] {
        let mut c = sudo();
        c.args([tool, "-w", "5", "-S", "INPUT"]);
        let Ok(rules) = run(&mut c) else { continue };
        for r in rules.lines() {
            if let Some(rest) = r.strip_prefix("-A INPUT -i ") {
                let dev = rest.split_whitespace().next().unwrap_or("");
                if dev.starts_with(BRIDGE_PREFIX)
                    && dev[BRIDGE_PREFIX.len()..].parse::<u8>().is_ok()
                {
                    firewall_allow(dev, false);
                    removed.push(format!("{tool} rule {dev}"));
                }
            }
        }
    }
    Ok(removed)
}

/// One namespace in the lab.
#[derive(Clone, Debug)]
pub struct Actor {
    pub name: String,
    ns: String,
    pub shape: Shape,
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
    pub log_dir: PathBuf,
}

impl Actor {
    pub fn netns(&self) -> &str {
        &self.ns
    }

    /// The actor's preferred address (v4 when it has one).
    pub fn addr(&self) -> IpAddr {
        match (self.v4, self.v6) {
            (Some(a), _) => IpAddr::V4(a),
            (None, Some(a)) => IpAddr::V6(a),
            (None, None) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    pub fn sock(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.addr(), port)
    }

    pub fn addrs(&self) -> Vec<IpAddr> {
        self.v4
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.v6.map(IpAddr::V6))
            .collect()
    }

    /// A command that runs `program` inside this namespace as the current user.
    pub fn command(&self, program: &Path) -> Command {
        self.command_with_env(program, &[])
    }

    /// Like [`Actor::command`] with extra environment variables for the program.
    pub fn command_with_env(&self, program: &Path, extra_env: &[(String, String)]) -> Command {
        let uid = users::uid();
        let gid = users::gid();
        let mut c = sudo();
        c.arg("nsenter")
            .arg(format!("--net=/run/netns/{}", self.ns))
            .arg("-S")
            .arg(uid.to_string())
            .arg("-G")
            .arg(gid.to_string())
            .arg("--");
        c.arg("env")
            .arg("-i")
            .arg(format!(
                "HOME={}",
                std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
            ))
            .arg("PATH=/usr/local/bin:/usr/bin:/bin")
            .arg(format!(
                "USER={}",
                std::env::var("USER").unwrap_or_default()
            ));
        for (k, v) in extra_env {
            c.arg(format!("{k}={v}"));
        }
        c.arg(program);
        c
    }

    /// Run a short command in the namespace and return stdout.
    pub fn exec(&self, program: &str, args: &[&str]) -> Result<String> {
        let mut c = self.command(Path::new(program));
        c.args(args);
        run(&mut c)
    }
}

mod users {
    pub fn uid() -> u32 {
        read_status("Uid")
    }
    pub fn gid() -> u32 {
        read_status("Gid")
    }
    fn read_status(key: &str) -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with(key))
                    .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
            })
            .unwrap_or(0)
    }
}

/// A process launched into a namespace through `sudo nsenter`. Tracks the leaf
/// pid (the actual program, running as the unprivileged user) so that it can
/// be signalled directly - including `kill -9` scenarios.
pub struct Proc {
    pub name: String,
    child: Child,
    leaf: Option<u32>,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
}

impl Proc {
    /// Spawn `cmd`, redirecting stdout/stderr to files under `log_dir`.
    pub fn spawn(name: &str, mut cmd: Command, log_dir: &Path) -> Result<Proc> {
        fs::create_dir_all(log_dir)?;
        let stdout_path = log_dir.join(format!("{name}.stdout.log"));
        let stderr_path = log_dir.join(format!("{name}.stderr.log"));
        let out = fs::File::create(&stdout_path)?;
        let err = fs::File::create(&stderr_path)?;
        cmd.stdin(Stdio::null()).stdout(out).stderr(err);
        let child = cmd
            .spawn()
            .with_context(|| format!("spawning {name}: {cmd:?}"))?;
        let mut p = Proc {
            name: name.to_string(),
            child,
            leaf: None,
            stdout_path,
            stderr_path,
        };
        p.leaf = p.find_leaf(Duration::from_secs(5));
        tracing::debug!(name, sudo_pid = p.child.id(), leaf = ?p.leaf, "spawned");
        Ok(p)
    }

    /// Spawn with stdin/stdout piped (for control protocols over stdio).
    pub fn spawn_piped(name: &str, mut cmd: Command, log_dir: &Path) -> Result<Proc> {
        fs::create_dir_all(log_dir)?;
        let stdout_path = log_dir.join(format!("{name}.stdout.log"));
        let stderr_path = log_dir.join(format!("{name}.stderr.log"));
        let err = fs::File::create(&stderr_path)?;
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(err);
        let child = cmd
            .spawn()
            .with_context(|| format!("spawning {name}: {cmd:?}"))?;
        let mut p = Proc {
            name: name.to_string(),
            child,
            leaf: None,
            stdout_path,
            stderr_path,
        };
        p.leaf = p.find_leaf(Duration::from_secs(5));
        Ok(p)
    }

    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Pid of the actual program (not the sudo wrapper).
    pub fn leaf_pid(&self) -> Option<u32> {
        self.leaf
    }

    fn find_leaf(&self, timeout: Duration) -> Option<u32> {
        let start = Instant::now();
        let root = self.child.id();
        while start.elapsed() < timeout {
            // Follow the single-child chain below sudo, skipping wrappers.
            let mut pid = root;
            let mut found = None;
            for _ in 0..8 {
                let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                let comm = comm.trim();
                let uid = proc_uid(pid);
                if uid == Some(users::uid()) && !matches!(comm, "sudo" | "nsenter" | "env") {
                    found = Some(pid);
                    break;
                }
                let kids = children(pid);
                match kids.first() {
                    Some(&k) => pid = k,
                    None => break,
                }
            }
            if found.is_some() {
                return found;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    fn signal(&self, sig: &str) -> Result<()> {
        let Some(pid) = self.leaf else {
            bail!("no leaf pid for {}", self.name)
        };
        run(Command::new("kill").arg(sig).arg(pid.to_string()))?;
        Ok(())
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// SIGTERM the program and wait up to `timeout` for the wrapper to exit.
    pub fn terminate(&mut self, timeout: Duration) -> Result<()> {
        if !self.is_running() {
            return Ok(());
        }
        let _ = self.signal("-TERM");
        let start = Instant::now();
        while start.elapsed() < timeout {
            if !self.is_running() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        tracing::warn!(name = %self.name, "did not exit after SIGTERM; killing");
        self.kill9()
    }

    /// SIGKILL the program (simulates a crash) and reap the wrapper.
    pub fn kill9(&mut self) -> Result<()> {
        if let Some(pid) = self.leaf {
            let _ = run(Command::new("kill").arg("-KILL").arg(pid.to_string()));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        Ok(())
    }

    pub fn stdout_log(&self) -> String {
        fs::read_to_string(&self.stdout_path).unwrap_or_default()
    }
    pub fn stderr_log(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.terminate(Duration::from_secs(10));
    }
}

fn children(pid: u32) -> Vec<u32> {
    fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect()
}

fn proc_uid(pid: u32) -> Option<u32> {
    let s = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Wait until a TCP port answers.
pub fn wait_tcp(addr: SocketAddr, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Ok(_) => return Ok(()),
            Err(e) => {
                if start.elapsed() > timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{addr} not answering: {e}"),
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}
