// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Soak / perf exercise for `cargo xtask soak` (AGENTS.md 7.1 layer 7), two
//! engines on loopback in one process:
//!
//! - `transfer --size N`: a single-file torrent of `N` bytes seeded from a
//!   sparse (all-zero) file, leeched by a second engine; reports wall time,
//!   throughput, peak RSS and open fds before / after.
//! - `many --torrents N`: `N` one-piece torrents seeded by A and leeched by
//!   B; reports add rate, completion time, fds / RSS with everything loaded
//!   and after removing it all (leak check).
//!
//! Exit status is non-zero when a transfer fails to complete, data does not
//! verify, or fds leak after removal.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::io::{Read, Seek, SeekFrom};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use urtorrent::{AddTorrent, Session, TorrentState};

fn block_on<F: Future>(fut: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park_timeout(Duration::from_millis(5)),
        }
    }
}

fn bstr(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(s.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(s);
}

/// A single-file torrent whose content is all zeros (so the seeder's file can
/// be sparse); `salt` makes the info-hash unique.
fn zero_torrent(name: &str, size: u64, piece_len: u32, salt: u64) -> Vec<u8> {
    let pieces_n = size.div_ceil(u64::from(piece_len));
    let full = <sha1::Sha1 as sha1::Digest>::digest(vec![0u8; piece_len as usize]);
    let last_len = (size - (pieces_n - 1) * u64::from(piece_len)) as usize;
    let last = <sha1::Sha1 as sha1::Digest>::digest(vec![0u8; last_len]);
    let mut pieces = Vec::with_capacity(pieces_n as usize * 20);
    for i in 0..pieces_n {
        if i + 1 == pieces_n {
            pieces.extend_from_slice(&last);
        } else {
            pieces.extend_from_slice(&full);
        }
    }
    let mut info = Vec::new();
    info.push(b'd');
    bstr(&mut info, b"length");
    info.extend_from_slice(format!("i{size}e").as_bytes());
    bstr(&mut info, b"name");
    bstr(&mut info, name.as_bytes());
    bstr(&mut info, b"piece length");
    info.extend_from_slice(format!("i{piece_len}e").as_bytes());
    bstr(&mut info, b"pieces");
    bstr(&mut info, &pieces);
    bstr(&mut info, b"salt");
    info.extend_from_slice(format!("i{salt}e").as_bytes());
    info.push(b'e');
    let mut t = Vec::new();
    t.push(b'd');
    bstr(&mut t, b"info");
    t.extend_from_slice(&info);
    t.push(b'e');
    t
}

static DISK_THREAD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
static ZERO_COPY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn session(ip: Ipv4Addr, max_peers: usize) -> Result<Session> {
    Ok(block_on(
        Session::builder()
            .listen_port(0)
            .listen_v4(Some(ip))
            .listen_v6(None)
            .lsd(false)
            .dht(false)
            .max_peers_per_torrent(max_peers)
            .hash_threads(2)
            .disk_thread(DISK_THREAD.load(std::sync::atomic::Ordering::Relaxed))
            .zero_copy_send(ZERO_COPY.load(std::sync::atomic::Ordering::Relaxed))
            .build(),
    )?)
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(0)
}

fn rss_kib() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let get = |key: &str| {
        status
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    (get("VmRSS:"), get("VmHWM:"))
}

/// Process CPU time so far: `(user, system)` from `/proc/self/stat`.
fn cpu_time() -> (Duration, Duration) {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // Fields after the parenthesised command name; utime/stime are the 14th
    // and 15th fields overall (1-based), i.e. index 11 and 12 after ")".
    let tail = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
    let f: Vec<&str> = tail.split_whitespace().collect();
    let ticks = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let hz = 100u64; // CLK_TCK on every Linux we run on
    let d = |t: u64| Duration::from_millis(t * 1000 / hz);
    (d(ticks(11)), d(ticks(12)))
}

fn report(tag: &str) {
    let (rss, hwm) = rss_kib();
    let (user, sys) = cpu_time();
    println!(
        "  [{tag}] fds={} rss={} MiB peak={} MiB cpu user={:.1}s sys={:.1}s",
        open_fds(),
        rss / 1024,
        hwm / 1024,
        user.as_secs_f64(),
        sys.as_secs_f64(),
    );
}

fn wait_state(s: &Session, id: urtorrent::TorrentId, want: TorrentState, secs: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let st = block_on(s.status(id))?;
        if st.state == want {
            return Ok(());
        }
        if st.state == TorrentState::Error {
            bail!("torrent error: {:?}", st.error);
        }
        if Instant::now() > deadline {
            bail!("timed out waiting for {want:?}: {st:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn transfer(dir: &Path, size: u64, piece: Option<u32>) -> Result<()> {
    let piece_len: u32 = piece.unwrap_or(if size >= 4 << 30 { 4 << 20 } else { 1 << 20 });
    println!(
        "transfer: {} MiB, {} KiB pieces ({} pieces)",
        size / (1024 * 1024),
        piece_len / 1024,
        size.div_ceil(u64::from(piece_len))
    );
    let a_dir = dir.join("a");
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&a_dir)?;
    std::fs::create_dir_all(&b_dir)?;
    let torrent = zero_torrent("soak.bin", size, piece_len, 1);
    // Sparse seed file: correct content (zeros), no disk use.
    std::fs::File::create(a_dir.join("soak.bin"))?.set_len(size)?;
    report("start");
    let a = session(Ipv4Addr::LOCALHOST, 50)?;
    let t0 = Instant::now();
    let a_id = block_on(a.add_torrent(AddTorrent::metainfo(torrent.clone(), &a_dir)))?;
    wait_state(&a, a_id, TorrentState::Seeding, 3600)?;
    let check = t0.elapsed();
    println!(
        "  seeder check: {:.1}s ({:.0} MiB/s hashing)",
        check.as_secs_f64(),
        size as f64 / (1024.0 * 1024.0) / check.as_secs_f64().max(0.001)
    );
    let b = session(Ipv4Addr::new(127, 0, 0, 2), 50)?;
    let b_id = block_on(b.add_torrent(AddTorrent::metainfo(torrent, &b_dir)))?;
    block_on(b.add_peer(
        b_id,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), a.listen_port()),
    ))?;
    let t1 = Instant::now();
    let mut last = Instant::now();
    loop {
        let st = block_on(b.status(b_id))?;
        if st.complete {
            break;
        }
        if st.state == TorrentState::Error {
            bail!("leecher error: {:?}", st.error);
        }
        if last.elapsed() > Duration::from_secs(10) {
            last = Instant::now();
            println!(
                "  {:5.1}% {:>6.1} MiB/s peers={} corrupt={}",
                st.progress() * 100.0,
                st.download_rate as f64 / (1024.0 * 1024.0),
                st.peers,
                st.corrupt
            );
        }
        ensure!(
            t1.elapsed() < Duration::from_secs(4 * 3600),
            "transfer took too long"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let dt = t1.elapsed();
    let st = block_on(b.status(b_id))?;
    println!(
        "  transfer: {:.1}s, {:.0} MiB/s, downloaded={} corrupt={} redundant={}",
        dt.as_secs_f64(),
        size as f64 / (1024.0 * 1024.0) / dt.as_secs_f64().max(0.001),
        st.downloaded,
        st.corrupt,
        st.redundant
    );
    ensure!(
        st.downloaded == size,
        "downloaded {} != {}",
        st.downloaded,
        size
    );
    ensure!(st.corrupt == 0);
    // Spot-check the leecher's file: size and a few sampled ranges of zeros.
    let mut f = std::fs::File::open(b_dir.join("soak.bin"))?;
    ensure!(f.metadata()?.len() == size, "leecher file size");
    let mut buf = vec![0u8; 65536];
    for k in 0..16u64 {
        let off = (size / 17) * k;
        f.seek(SeekFrom::Start(off))?;
        let n = f.read(&mut buf)?;
        ensure!(buf[..n].iter().all(|b| *b == 0), "non-zero data at {off}");
    }
    report("complete");
    block_on(b.shutdown())?;
    block_on(a.shutdown())?;
    report("shutdown");
    std::fs::remove_dir_all(dir).ok();
    Ok(())
}

fn many(dir: &Path, n: usize) -> Result<()> {
    println!("many: {n} torrents");
    let a_dir = dir.join("a");
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&a_dir)?;
    std::fs::create_dir_all(&b_dir)?;
    let size = 32 * 1024u64;
    let fds0 = open_fds();
    report("start");
    let a = session(Ipv4Addr::LOCALHOST, 50)?;
    let b = session(Ipv4Addr::new(127, 0, 0, 2), 50)?;
    let a_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), a.listen_port());
    let mut torrents = Vec::with_capacity(n);
    let t0 = Instant::now();
    for i in 0..n {
        let name = format!("t{i}.bin");
        let t = zero_torrent(&name, size, 16384, i as u64 + 100);
        std::fs::File::create(a_dir.join(&name))?.set_len(size)?;
        let a_id = block_on(a.add_torrent(AddTorrent::metainfo(t.clone(), &a_dir)))?;
        let b_id = block_on(b.add_torrent(AddTorrent::metainfo(t, &b_dir)))?;
        torrents.push((a_id, b_id));
    }
    println!(
        "  added {n} torrents to two engines in {:.1}s",
        t0.elapsed().as_secs_f64()
    );
    for (a_id, _) in &torrents {
        wait_state(&a, *a_id, TorrentState::Seeding, 600)?;
    }
    println!("  all seeding after {:.1}s", t0.elapsed().as_secs_f64());
    let t1 = Instant::now();
    for (_, b_id) in &torrents {
        block_on(b.add_peer(*b_id, a_addr))?;
    }
    let deadline = Instant::now() + Duration::from_secs(1800);
    loop {
        let statuses = block_on(b.statuses())?;
        let done = statuses.iter().filter(|s| s.complete).count();
        if done == n {
            break;
        }
        if let Some(e) = statuses.iter().find(|s| s.state == TorrentState::Error) {
            bail!("torrent error: {:?}", e.error);
        }
        ensure!(Instant::now() < deadline, "only {done}/{n} completed");
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("  all {n} downloaded in {:.1}s", t1.elapsed().as_secs_f64());
    report("loaded");
    let stats = block_on(b.stats())?;
    ensure!(
        stats.downloaded == size * n as u64,
        "session downloaded {}",
        stats.downloaded
    );
    for (a_id, b_id) in &torrents {
        block_on(a.remove_torrent(*a_id))?;
        block_on(b.remove_torrent(*b_id))?;
    }
    std::thread::sleep(Duration::from_millis(500));
    report("removed");
    let fds_after = open_fds();
    block_on(b.shutdown())?;
    block_on(a.shutdown())?;
    report("shutdown");
    let fds_end = open_fds();
    ensure!(
        fds_end <= fds0 + 4,
        "fd leak: {fds0} before, {fds_end} after shutdown"
    );
    ensure!(
        fds_after < fds0 + 64,
        "fds still held after removing every torrent: {fds_after} (baseline {fds0})"
    );
    std::fs::remove_dir_all(dir).ok();
    Ok(())
}

fn main() -> Result<()> {
    testkit::init_tracing_with("warn");
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "all".into());
    let mut size: u64 = 2 << 30;
    let mut piece: Option<u32> = None;
    let mut torrents: usize = 500;
    let mut dir: Option<PathBuf> = None;
    while let Some(k) = args.next() {
        if k == "--inline-disk" {
            DISK_THREAD.store(false, std::sync::atomic::Ordering::Relaxed);
            continue;
        }
        if k == "--zero-copy" {
            ZERO_COPY.store(true, std::sync::atomic::Ordering::Relaxed);
            continue;
        }
        let v = args.next().with_context(|| format!("{k} needs a value"))?;
        match k.as_str() {
            "--size" => size = parse_size(&v)?,
            "--piece" => piece = Some(u32::try_from(parse_size(&v)?)?),
            "--torrents" => torrents = v.parse()?,
            "--dir" => dir = Some(PathBuf::from(v)),
            other => bail!("unknown argument {other}"),
        }
    }
    // Not `temp_dir()`: /tmp is often a small tmpfs and the transfer writes
    // the whole torrent.
    let dir =
        dir.unwrap_or_else(|| PathBuf::from("target").join(format!("soak-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&dir);
    match mode.as_str() {
        "transfer" => transfer(&dir.join("transfer"), size, piece)?,
        "many" => many(&dir.join("many"), torrents)?,
        "all" => {
            many(&dir.join("many"), torrents)?;
            transfer(&dir.join("transfer"), size, piece)?;
        }
        other => bail!("unknown mode {other} (transfer | many | all)"),
    }
    let _ = std::fs::remove_dir_all(&dir);
    println!("soak: OK");
    Ok(())
}

fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('G') | Some('g') => (&s[..s.len() - 1], 1u64 << 30),
        Some('M') | Some('m') => (&s[..s.len() - 1], 1u64 << 20),
        Some('K') | Some('k') => (&s[..s.len() - 1], 1u64 << 10),
        _ => (s, 1),
    };
    Ok(num.parse::<u64>()? * mult)
}
