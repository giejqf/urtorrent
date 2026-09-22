// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Resource benchmarks against the oracle (qBittorrent 5.2.3 /
//! libtorrent 2.0.14): the same work, once with our client and once with
//! the oracle, measuring peak RSS and CPU time of the client process.
//!
//! Fairness rules, because the numbers are meaningless otherwise: the two
//! runs use the same fixture, the same counterpart (a common oracle peer),
//! the same transport and encryption settings, fresh namespaces, and are
//! run one after another (never at the same time) on an otherwise idle
//! lab. What differs is only the client under measurement.
//!
//! Peak RSS is `VmHWM` (the kernel's own high-water mark, not a sample);
//! CPU is `utime + stime` of the process, threads included, from
//! `/proc/<pid>/stat`. The oracle is a WebUI-carrying application and ours
//! is a test client: the CPU figures compare the work of moving the data,
//! the RSS figures include whatever each process is built from, which is
//! noted with the results.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};

use crate::client::ClientConfig;
use crate::fixtures::{Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::{BtProtocol, Encryption, OracleConfig};
use crate::resources::{Sampler, Usage};
use crate::scenario::{Ctx, ScenarioDef, Tag};
use crate::webapi::AddTorrent;

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "bench_leech",
            shapes: &[Shape::V4],
            tags: &[Tag::Bench],
            run: bench_leech,
        },
        ScenarioDef {
            name: "bench_seed",
            shapes: &[Shape::V4],
            tags: &[Tag::Bench],
            run: bench_seed,
        },
        ScenarioDef {
            name: "bench_many",
            shapes: &[Shape::V4],
            tags: &[Tag::Bench],
            run: bench_many,
        },
    ]
}

/// Payload of the transfer benchmarks.
const SIZE: u64 = 256 << 20;
/// Piece length of the transfer benchmarks.
const PIECE: u32 = 1 << 20;
/// Torrents of the many-torrents benchmark.
const MANY: usize = 300;
/// Payload of each of those.
const MANY_SIZE: u64 = 512 << 10;

/// Settings shared by every oracle in the benchmarks: no discovery, TCP,
/// no encryption — the same shape our client runs in.
fn plain_oracle() -> OracleConfig {
    OracleConfig {
        dht: false,
        pex: false,
        lsd: false,
        encryption: Encryption::Disable,
        protocol: BtProtocol::Tcp,
        ..OracleConfig::primary()
    }
}

/// The matching settings for our client.
fn plain_client() -> ClientConfig {
    ClientConfig::default()
        .lsd(false)
        .pex(false)
        .protocol("tcp")
        .encryption("disabled")
}

fn note_usage(ctx: &mut Ctx, what: &str, u: Usage, secs: f64, bytes: u64) {
    let mib = bytes as f64 / (1024.0 * 1024.0);
    ctx.note(format!(
        "{what}: peak RSS {:.1} MiB (anon {:.1}, file {:.1}), \
         CPU {:.2}s (user {:.2} + sys {:.2}), wall {secs:.1}s, {:.0} MiB/s, \
         {:.3} CPU-s per GiB, {} samples",
        u.peak_mib(),
        u.anon_mib(),
        u.file_mib(),
        u.cpu(),
        u.user,
        u.sys,
        mib / secs.max(0.001),
        u.cpu() / (mib / 1024.0).max(0.000_001),
        u.samples,
    ));
}

/// Leeching: a common oracle seeder, measured client downloads from it.
fn bench_leech(ctx: &mut Ctx) -> Result<()> {
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("bench.bin")
            .with_size(SIZE)
            .with_piece_length(PIECE)
            .with_tracker("http://127.0.0.1:1/announce"),
    ));
    let h = fx.info_hash_hex();
    let torrent_path = ctx.file("bench.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;

    // The seeder both runs share.
    let seeder = ctx.oracle("seeder", plain_oracle())?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(300), "seeder ready", |t| {
            t.is_seeding()
        })?;
    let seeder_addr = SocketAddr::new(seeder.actor.addr(), seeder.listen_port());

    // Us.
    let mut ours = ctx.client("urt", plain_client().add_peer(seeder_addr), &torrent_path)?;
    let pid = ours.pid().context_pid("urt")?;
    let sampler = Sampler::start(pid);
    let started = Instant::now();
    ours.wait_for(Duration::from_secs(600), "our download", |s| s.complete)?;
    let our_secs = started.elapsed().as_secs_f64();
    let our_usage = sampler.finish();
    ours.shutdown()?;
    note_usage(ctx, "leech urtorrent", our_usage, our_secs, SIZE);

    // The oracle, from the same seeder.
    let leecher = ctx.oracle("leecher", plain_oracle())?;
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    let pid = leecher.pid().context_pid("leecher")?;
    let sampler = Sampler::start(pid);
    let started = Instant::now();
    leecher.api.add_peers(&h, &[seeder_addr])?;
    leecher
        .api
        .wait_for(&h, Duration::from_secs(600), "oracle download", |t| {
            t.is_seeding()
        })?;
    let their_secs = started.elapsed().as_secs_f64();
    let their_usage = sampler.finish();
    note_usage(ctx, "leech libtorrent", their_usage, their_secs, SIZE);

    fx.verify_data(&ours.save_path)?
        .map_err(|e| anyhow::anyhow!("our data mismatch: {e}"))?;
    ensure!(
        our_usage.samples > 0 && their_usage.samples > 0,
        "no samples"
    );
    Ok(())
}

/// Seeding: a common oracle leecher, measured client serves it.
fn bench_seed(ctx: &mut Ctx) -> Result<()> {
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("bench.bin")
            .with_size(SIZE)
            .with_piece_length(PIECE)
            .with_tracker("http://127.0.0.1:1/announce"),
    ));
    let h = fx.info_hash_hex();
    let torrent_path = ctx.file("bench.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;

    // Us, seeding: the data is in place before the client starts, so it
    // checks it once and seeds (the same thing the oracle does below).
    let actor = ctx.actor("urt")?;
    fx.write_data(&actor.log_dir.join("data"))?;
    let mut ours = crate::client::UrtClient::launch(&actor, plain_client(), &torrent_path)?;
    ours.wait_for(Duration::from_secs(300), "our seed ready", |s| s.complete)?;
    let our_addr = SocketAddr::new(ours.actor.addr(), ours.listen_port());
    let leecher = ctx.oracle("leecher", plain_oracle())?;
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    let pid = ours.pid().context_pid("urt")?;
    let sampler = Sampler::start(pid);
    let started = Instant::now();
    leecher.api.add_peers(&h, &[our_addr])?;
    leecher
        .api
        .wait_for(&h, Duration::from_secs(600), "leech from us", |t| {
            t.is_seeding()
        })?;
    let our_secs = started.elapsed().as_secs_f64();
    let our_usage = sampler.finish();
    ours.shutdown()?;
    note_usage(ctx, "seed urtorrent", our_usage, our_secs, SIZE);

    // The oracle seeding to a fresh oracle leecher.
    let seeder = ctx.oracle("seeder", plain_oracle())?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(300), "their seed ready", |t| {
            t.is_seeding()
        })?;
    let leecher2 = ctx.oracle("leecher2", plain_oracle())?;
    leecher2.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher2.save_path.to_string_lossy()),
        &h,
    )?;
    let pid = seeder.pid().context_pid("seeder")?;
    let sampler = Sampler::start(pid);
    let started = Instant::now();
    leecher2.api.add_peers(
        &h,
        &[SocketAddr::new(seeder.actor.addr(), seeder.listen_port())],
    )?;
    leecher2
        .api
        .wait_for(&h, Duration::from_secs(600), "leech from them", |t| {
            t.is_seeding()
        })?;
    let their_secs = started.elapsed().as_secs_f64();
    let their_usage = sampler.finish();
    note_usage(ctx, "seed libtorrent", their_usage, their_secs, SIZE);
    ensure!(
        our_usage.samples > 0 && their_usage.samples > 0,
        "no samples"
    );
    Ok(())
}

/// Many torrents, idle: what a loaded session costs in memory.
fn bench_many(ctx: &mut Ctx) -> Result<()> {
    let mut torrents = Vec::new();
    let dir = ctx.file("many");
    std::fs::create_dir_all(&dir)?;
    for i in 0..MANY {
        let fx = Fixture::generate(
            FixtureSpec::small(&format!("m{i}.bin"))
                .with_size(MANY_SIZE)
                .with_piece_length(64 << 10)
                .with_tracker("http://127.0.0.1:1/announce"),
        );
        let path = dir.join(format!("m{i}.torrent"));
        std::fs::write(&path, &fx.torrent)?;
        torrents.push((fx, path));
    }

    // Us: one client, every torrent added through the control file. The
    // data is in place before it starts, so each torrent checks once and
    // seeds — the same work the oracle does below.
    let (first_fx, first_path) = &torrents[0];
    let actor = ctx.actor("urt")?;
    let data_dir = actor.log_dir.join("data");
    std::fs::create_dir_all(&data_dir)?;
    for (fx, _) in &torrents {
        fx.write_data(&data_dir)?;
    }
    let started = Instant::now();
    let mut ours =
        crate::client::UrtClient::launch(&actor, plain_client().add_dir(&dir), first_path)?;
    let pid = ours.pid().context_pid("urt")?;
    let sampler = Sampler::start(pid);
    let st = ours.wait_for(Duration::from_secs(900), "all ours seeding", |s| {
        s.torrents >= MANY && s.all_seeding
    })?;
    let our_secs = started.elapsed().as_secs_f64();
    let our_usage = sampler.finish();
    ensure!(st.torrents == MANY, "{} torrents", st.torrents);
    ours.shutdown()?;
    let _ = first_fx;
    note_usage(
        ctx,
        "many urtorrent",
        our_usage,
        our_secs,
        MANY_SIZE * MANY as u64,
    );
    ctx.note(format!(
        "many urtorrent: {:.0} KiB per torrent (anon)",
        our_usage.peak_anon as f64 / MANY as f64 / 1024.0
    ));

    // The oracle, same torrents, same data.
    let oracle = ctx.oracle("oracle", plain_oracle())?;
    for (fx, _) in &torrents {
        fx.write_data(&oracle.save_path)?;
    }
    let pid = oracle.pid().context_pid("oracle")?;
    let sampler = Sampler::start(pid);
    let started = Instant::now();
    for (fx, _) in &torrents {
        oracle.api.add_torrent(
            &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
            &fx.info_hash_hex(),
        )?;
    }
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        let list = oracle.api.torrents()?;
        let seeding = list.iter().filter(|t| t.is_seeding()).count();
        if seeding >= MANY {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "only {seeding}/{MANY} seeding on the oracle"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let their_secs = started.elapsed().as_secs_f64();
    let their_usage = sampler.finish();
    note_usage(
        ctx,
        "many libtorrent",
        their_usage,
        their_secs,
        MANY_SIZE * MANY as u64,
    );
    ctx.note(format!(
        "many libtorrent: {:.0} KiB per torrent (anon)",
        their_usage.peak_anon as f64 / MANY as f64 / 1024.0
    ));
    Ok(())
}

/// `Option<u32>` to a pid with a message.
trait PidContext {
    fn context_pid(self, what: &str) -> Result<u32>;
}

impl PidContext for Option<u32> {
    fn context_pid(self, what: &str) -> Result<u32> {
        self.ok_or_else(|| anyhow::anyhow!("no pid for {what}"))
    }
}
