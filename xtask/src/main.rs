// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! `cargo xtask <command>`: developer commands (AGENTS.md section 9).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    missing_docs
)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};

/// Library crates (the graph that must stay free of epoll/kqueue/IOCP reactors
/// and of tokio's runtime features). Extended as milestones land.
const LIB_CRATES: &[&str] = &[
    "bencode",
    "metainfo",
    "wire",
    "mse",
    "tracker",
    "picker",
    "profile",
    "uring",
    "storage",
    "session",
    "urtorrent",
];

/// tokio features that may never be enabled anywhere under the library crates.
const BANNED_TOKIO_FEATURES: &[&str] = &[
    "rt",
    "rt-multi-thread",
    "net",
    "fs",
    "io-util",
    "time",
    "process",
    "signal",
    "io-std",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// AGENTS.md 5.3 enforcement #4: run a data-path exercise under strace and fail
/// if the library issues any epoll/kqueue-style reactor syscall, or any
/// off-ring socket/file data syscall. Socket and torrent-file fds are tracked
/// from `socket()`/`openat()` so that startup noise (ld.so, stdio) is ignored.
fn syscalls() -> Result<()> {
    if !have("strace") {
        bail!("strace is required for `xtask syscalls` (apt install strace)");
    }
    // Build and locate the self-contained uring data-path probe.
    run(
        cargo().args(["build", "-q", "-p", "uring", "--bin", "syscall-probe"]),
        "build syscall-probe",
    )?;
    let probe = root().join("target/debug/syscall-probe");
    if !probe.exists() {
        bail!("syscall-probe binary not found at {}", probe.display());
    }
    let trace = std::env::temp_dir().join(format!("urt-syscalls-{}.txt", std::process::id()));
    let status = Command::new("strace")
        .args(["-f", "-y", "-e", "trace=%net,%desc,epoll_create,epoll_create1,epoll_ctl,epoll_wait,epoll_pwait,poll,ppoll,select,pselect6,io_uring_enter,io_uring_setup,io_uring_register", "-o"])
        .arg(&trace)
        .arg(&probe)
        .status()
        .context("running strace")?;
    if !status.success() {
        bail!("syscall-probe failed under strace (exit {status})");
    }
    let text = std::fs::read_to_string(&trace).context("reading strace output")?;
    let report = analyze_syscalls(&text);
    let _ = std::fs::remove_file(&trace);

    println!("io_uring_enter calls: {}", report.io_uring_enter);
    if report.io_uring_enter == 0 {
        bail!("no io_uring_enter observed: the data path did not use io_uring");
    }
    if report.violations.is_empty() {
        println!(
            "syscalls: OK — no epoll/poll/select or off-ring socket/file data syscalls on the data path"
        );
        Ok(())
    } else {
        for v in &report.violations {
            println!("  VIOLATION {v}");
        }
        bail!(
            "{} banned data-path syscall(s) detected (AGENTS.md rule 4)",
            report.violations.len()
        )
    }
}

/// `poll([{fd=0..2, events=0}, ...], n, 0)`: only stdio fds, no events.
fn is_stdio_probe(args: &str) -> bool {
    let fds: Vec<&str> = args.split("fd=").skip(1).collect();
    !fds.is_empty()
        && fds.iter().all(|f| {
            let fd = f
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>();
            matches!(fd.as_str(), "0" | "1" | "2")
        })
        && !args.contains("events=POLL")
}

struct SyscallReport {
    io_uring_enter: usize,
    violations: Vec<String>,
}

/// Parse strace `-y` output (which annotates fds like `3<socket:[...]>` or
/// `5</tmp/...>`). Flags: any epoll_*/select/pselect6 (global); any socket data
/// op (recv*/send*/connect/accept*) — all of ours are on-ring; and any
/// read/write/pread/pwrite/poll/ppoll whose fd is annotated as a socket or a
/// file under a temp/data path (a torrent file), since those must go through
/// the ring.
fn analyze_syscalls(text: &str) -> SyscallReport {
    // Reactor syscalls that must never appear at all.
    const GLOBAL_BAN: &[&str] = &[
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "epoll_pwait",
        "select",
        "pselect6",
    ];
    // Socket data / connection ops that are always on-ring for us.
    const SOCKET_BAN: &[&str] = &[
        "connect", "accept", "accept4", "recvfrom", "sendto", "recvmsg", "sendmsg", "recvmmsg",
        "sendmmsg", "recv", "send",
    ];
    // Ambiguous ops: banned only when their fd is a socket or a torrent file.
    const FD_SENSITIVE: &[&str] = &[
        "read", "write", "pread64", "pwrite64", "readv", "writev", "poll", "ppoll",
    ];

    let mut io_uring_enter = 0usize;
    let mut violations = Vec::new();
    for line in text.lines() {
        // Lines look like: "1234 syscall(args...) = ret" (with -f pid prefix).
        let Some(rest) = line.split_once(' ').map(|x| x.1) else {
            continue;
        };
        let rest = rest.trim_start();
        let name = rest.split(['(', ' ']).next().unwrap_or("");
        if name == "io_uring_enter" {
            io_uring_enter += 1;
            continue;
        }
        if GLOBAL_BAN.contains(&name) {
            violations.push(format!("{name}: {}", line.trim()));
            continue;
        }
        if SOCKET_BAN.contains(&name) {
            violations.push(format!("{name}: {}", line.trim()));
            continue;
        }
        if FD_SENSITIVE.contains(&name) {
            // With -y, the first arg's fd carries an annotation in <...>.
            let args = rest.split_once('(').map(|x| x.1).unwrap_or("");
            // Rust's runtime start-up probes fds 0-2 with `poll(events=0)` to
            // detect closed stdio; when stdin happens to be a socket (CI
            // harnesses) that is not a data-path poll.
            if name == "poll" && is_stdio_probe(args) {
                continue;
            }
            let first = args.split(',').next().unwrap_or("");
            let is_socket =
                first.contains("socket:") || first.contains("TCP:") || first.contains("UDP:");
            let is_torrent_file = (first.contains("/tmp/") || first.contains("urt-"))
                && !first.contains("urt-syscalls-");
            if is_socket || is_torrent_file {
                violations.push(format!("{name} on {}: {}", first.trim(), line.trim()));
            }
        }
    }
    SyscallReport {
        io_uring_enter,
        violations,
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: cargo xtask <command>

  check              fmt, clippy -D warnings, unit + property tests, doc build, dependency policy
  doctor             kernel, io_uring, seccomp/sysctl, memlock, sudo/netns, Docker, oracle binaries
  it [scenario ...]  integration scenarios (netns lab)      [--shape v4|v6|dual] [--keep]
  diff [scenario ..] differential run + discriminator       [--shape ...]
  capture [scen ...] regenerate golden captures from the pinned oracle
  fuzz <target> [secs]
  syscalls           assert no non-uring data-path syscalls during a transfer"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return usage();
    };
    let rest = &args[1..];
    let r = match cmd.as_str() {
        "check" => check(rest),
        "doctor" => doctor(),
        "it" => testkit(&["it"], rest),
        "capture" => testkit(&["capture"], rest),
        "diff" => testkit(&["diff"], rest),
        "fuzz" => fuzz(rest),
        "syscalls" => syscalls(),
        _ => return usage(),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn cargo() -> Command {
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    eprintln!("==> {what}");
    let st = cmd.status().with_context(|| format!("running {what}"))?;
    if !st.success() {
        bail!("{what} failed ({st})");
    }
    Ok(())
}

fn existing_lib_crates() -> Vec<&'static str> {
    LIB_CRATES
        .iter()
        .copied()
        .filter(|c| root().join("crates").join(c).join("Cargo.toml").exists())
        .collect()
}

fn check(args: &[String]) -> Result<()> {
    let quick = args.iter().any(|a| a == "--quick");
    run(
        cargo().args(["fmt", "--all", "--check"]),
        "cargo fmt --check",
    )?;
    run(
        cargo().args([
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ]),
        "cargo clippy",
    )?;
    if !quick {
        run(cargo().args(["test", "--workspace"]), "cargo test")?;
        run(
            cargo()
                .args(["doc", "--workspace", "--no-deps"])
                .env("RUSTDOCFLAGS", "-D warnings"),
            "cargo doc",
        )?;
    }
    dependency_policy()?;
    eprintln!("check: OK");
    Ok(())
}

/// AGENTS.md 5.3 enforcement #2: cargo-deny bans and the tokio feature audit.
fn dependency_policy() -> Result<()> {
    let libs = existing_lib_crates();
    if libs.is_empty() {
        eprintln!("==> dependency policy: no library crates yet, skipping");
        return Ok(());
    }
    if root().join("deny.toml").exists() {
        if Command::new("cargo")
            .arg("deny")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            run(
                cargo().args(["deny", "check", "bans", "licenses", "sources"]),
                "cargo deny",
            )?;
        } else {
            eprintln!("warning: cargo-deny not installed; skipping bans check (CI runs it)");
        }
    }
    // tokio feature audit: `cargo tree -e features` under each library crate.
    for c in libs {
        let out = cargo()
            .args([
                "tree",
                "-p",
                c,
                "-e",
                "features",
                "--prefix",
                "none",
                "--no-dedupe",
            ])
            .output()
            .context("cargo tree")?;
        if !out.status.success() {
            bail!(
                "cargo tree -p {c} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut bad = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            // lines look like: `tokio feature "rt"` or `tokio v1.x`
            if let Some(rest) = line.strip_prefix("tokio feature \"") {
                let feat = rest.trim_end_matches('"');
                if BANNED_TOKIO_FEATURES.contains(&feat) {
                    bad.push(feat.to_string());
                }
            }
        }
        if !bad.is_empty() {
            bail!(
                "tokio runtime features enabled under library crate `{c}`: {bad:?} (AGENTS.md rule 4)"
            );
        }
        for reactor in ["mio ", "polling ", "async-io ", "async-std "] {
            if text.lines().any(|l| l.trim().starts_with(reactor)) {
                bail!(
                    "`{}` appears in the dependency tree of `{c}` (AGENTS.md rule 4)",
                    reactor.trim()
                );
            }
        }
    }
    eprintln!("==> dependency policy: OK");
    Ok(())
}

fn testkit(sub: &[&str], args: &[String]) -> Result<()> {
    // The lab launches `urt-client` (the library under test) next to the
    // testkit binary; build every testkit binary first.
    run(
        cargo().args(["build", "-q", "-p", "testkit", "--bins"]),
        "build testkit binaries",
    )?;
    let mut c = cargo();
    c.args(["run", "-q", "-p", "testkit", "--bin", "testkit", "--"])
        .args(sub)
        .args(args);
    run(&mut c, &format!("testkit {}", sub.join(" ")))
}

fn fuzz(args: &[String]) -> Result<()> {
    let Some(target) = args.first() else {
        bail!("usage: cargo xtask fuzz <target> [secs]")
    };
    let secs = args.get(1).map(String::as_str).unwrap_or("60");
    if !root().join("fuzz").exists() {
        bail!("no fuzz/ directory yet (arrives with the first parser crate)");
    }
    // cargo-fuzz defaults to a musl target that lacks a prebuilt sanitizer
    // runtime here; pin the gnu host triple.
    let host = "x86_64-unknown-linux-gnu";
    // Go through the rustup proxy (not `$CARGO`, which is the stable
    // toolchain's own binary and does not understand `+nightly`).
    let mut c = Command::new("cargo");
    c.current_dir(root());
    c.args([
        "+nightly",
        "fuzz",
        "run",
        "--fuzz-dir",
        "fuzz",
        "--target",
        host,
        target,
        "--",
        &format!("-max_total_time={secs}"),
    ]);
    run(&mut c, &format!("cargo fuzz run {target} for {secs}s"))
}

// ---------------------------------------------------------------- doctor

struct Report {
    problems: usize,
}

impl Report {
    fn ok(&self, what: &str, detail: &str) {
        println!("  ok    {what}: {detail}");
    }
    fn warn(&self, what: &str, detail: &str) {
        println!("  warn  {what}: {detail}");
    }
    fn fail(&mut self, what: &str, detail: &str) {
        self.problems += 1;
        println!("  FAIL  {what}: {detail}");
    }
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn have(bin: &str) -> bool {
    Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn doctor() -> Result<()> {
    println!("urtorrent doctor");
    let mut r = Report { problems: 0 };

    // Kernel version
    let rel = read("/proc/sys/kernel/osrelease");
    let mut parts = rel
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().unwrap_or(0));
    let (maj, min) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    if (maj, min) >= (6, 1) {
        r.ok("kernel", &format!("{rel} (baseline 6.1)"));
    } else {
        r.fail("kernel", &format!("{rel} is older than the 6.1 baseline"));
    }

    // io_uring sysctl
    match read("/proc/sys/kernel/io_uring_disabled").as_str() {
        "" | "0" => r.ok("io_uring_disabled", "0 (enabled)"),
        "1" => r.warn(
            "io_uring_disabled",
            "1: only processes in the io_uring group may use io_uring (kernel.io_uring_group)",
        ),
        v => r.fail(
            "io_uring_disabled",
            &format!("{v}: io_uring is disabled by sysctl kernel.io_uring_disabled; set it to 0"),
        ),
    }
    if let Some(probe) = uring_probe() {
        match probe {
            Ok(s) => r.ok("io_uring probe", &s),
            Err(e) => r.fail("io_uring probe", &e),
        }
    }

    // memlock (older kernels need it for registered buffers)
    let out = Command::new("sh")
        .args(["-c", "ulimit -l"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if out == "unlimited" || out.parse::<u64>().map(|k| k >= 8192).unwrap_or(false) {
        r.ok("memlock", &format!("ulimit -l = {out} KiB"));
    } else {
        r.warn(
            "memlock",
            &format!(
                "ulimit -l = {out}; kernels >= 5.12 do not need it for io_uring, older ones do"
            ),
        );
    }

    // Lab prerequisites
    match Command::new("sudo").args(["-n", "true"]).status() {
        Ok(s) if s.success() => r.ok("sudo", "passwordless sudo available (needed for netns lab)"),
        _ => r.fail(
            "sudo",
            "passwordless sudo is required by `xtask it` (ip netns, nsenter, tcpdump)",
        ),
    }
    for (bin, why, hard) in [
        ("ip", "iproute2 for the netns lab", true),
        (
            "nsenter",
            "util-linux, to run actors inside namespaces",
            true,
        ),
        (
            "opentracker",
            "independent tracker implementation (apt install opentracker)",
            true,
        ),
        (
            "transmission-daemon",
            "independent peer implementation (apt install transmission-daemon)",
            false,
        ),
        (
            "tcpdump",
            "pcap capture for differential runs (informational)",
            false,
        ),
        ("strace", "`xtask syscalls` enforcement", false),
        ("curl", "oracle binary download", true),
    ] {
        if have(bin) {
            r.ok(bin, why);
        } else if hard {
            r.fail(bin, &format!("missing: {why}"));
        } else {
            r.warn(bin, &format!("missing: {why}"));
        }
    }
    // Ubuntu confines transmission-daemon with AppArmor to /var/lib; the lab
    // runs it from testkit/runs, which needs a local override.
    if have("transmission-daemon") && std::path::Path::new("/etc/apparmor.d/transmission").exists()
    {
        let local = read("/etc/apparmor.d/local/transmission-daemon");
        let runs = root().join("testkit/runs");
        if local.contains(&runs.to_string_lossy().to_string()) {
            r.ok(
                "transmission apparmor",
                "local override allows testkit/runs",
            );
        } else {
            r.warn(
                "transmission apparmor",
                &format!(
                    "profile confines transmission-daemon to /var/lib; add to /etc/apparmor.d/local/transmission-daemon:\n           owner {0}/** rw,\n           owner {0}/ r,\n           owner {0}/*/ r,\n           owner {0}/*/*/ r,\n         then `sudo apparmor_parser -r /etc/apparmor.d/transmission`",
                    runs.display()
                ),
            );
        }
    }
    if read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1" {
        r.warn(
            "userns",
            "apparmor_restrict_unprivileged_userns=1: unprivileged user namespaces are restricted; the lab uses sudo instead",
        );
    }

    // Docker (alternative integration environment)
    if have("docker") {
        match Command::new("docker").arg("info").output() {
            Ok(o) if o.status.success() => {
                r.ok("docker", "available");
                let seccomp = root().join("testkit/docker/seccomp-io_uring.json");
                if seccomp.exists() {
                    r.ok("docker seccomp", &format!("profile at {} (Docker's default profile blocks io_uring_*; run our container with --security-opt seccomp=<profile>)", seccomp.display()));
                } else {
                    r.warn("docker seccomp", "testkit/docker/seccomp-io_uring.json missing; Docker's default seccomp profile blocks io_uring_setup/enter/register");
                }
            }
            _ => r.warn(
                "docker",
                "installed but the daemon is not reachable (optional)",
            ),
        }
    } else {
        r.warn(
            "docker",
            "not installed (optional; the netns lab is the primary environment)",
        );
    }

    // Oracle binaries
    let lock = root().join("testkit/oracle.lock");
    if lock.exists() {
        let txt = std::fs::read_to_string(&lock).unwrap_or_default();
        let tags: Vec<&str> = txt
            .lines()
            .filter_map(|l| l.trim().strip_prefix("tag = \""))
            .map(|t| t.trim_end_matches('"'))
            .collect();
        let cache = std::env::var("URT_ORACLE_CACHE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                Path::new(&std::env::var("HOME").unwrap_or_default())
                    .join(".cache/urtorrent/oracle")
            });
        for t in tags {
            let p = cache.join(format!(
                "qbittorrent-nox-{}",
                t.trim_start_matches("release-")
            ));
            if p.exists() {
                r.ok("oracle", &format!("{}", p.display()));
            } else {
                r.warn(
                    "oracle",
                    &format!("{} not downloaded yet (testkit oracle ensure)", p.display()),
                );
            }
        }
    } else {
        r.fail("oracle.lock", "testkit/oracle.lock missing");
    }

    // Toolchain extras
    for (bin, why) in [
        ("cargo-deny", "dependency bans (cargo install cargo-deny)"),
        ("cargo-fuzz", "fuzzing (cargo install cargo-fuzz + nightly)"),
        ("cargo-semver-checks", "semver CI check"),
    ] {
        if have(bin) {
            r.ok(bin, why);
        } else {
            r.warn(bin, &format!("missing: {why}"));
        }
    }

    println!();
    if r.problems == 0 {
        println!("doctor: no blocking problems");
        Ok(())
    } else {
        bail!("doctor: {} blocking problem(s)", r.problems)
    }
}

/// Probe io_uring through the library's own reactor once it exists; until
/// then, return None.
fn uring_probe() -> Option<Result<String, String>> {
    let bin = root().join("target/debug/uring-probe");
    if !bin.exists() {
        return None;
    }
    match Command::new(bin).output() {
        Ok(o) if o.status.success() => {
            Some(Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()))
        }
        Ok(o) => Some(Err(String::from_utf8_lossy(&o.stderr).trim().to_string())),
        Err(e) => Some(Err(e.to_string())),
    }
}
