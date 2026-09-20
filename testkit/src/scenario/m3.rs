// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! M3 scenarios: seeding, and the robustness matrix around it. We seed to the
//! oracle and to Transmission; pause/resume; survive `kill -9` without ever
//! claiming pieces we do not have; recheck corrupted data; ban a peer that
//! serves bad hashes; honour rate limits; and never let counters go backwards.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use sha1::{Digest, Sha1};

use super::{Ctx, ScenarioDef, Tag};
use crate::client::{ClientConfig, UrtClient};
use crate::fixtures::{FileSpec, Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::OracleConfig;
use crate::tap::peer::{Misbehaviour, Role, TapPeer, TapPeerConfig};
use crate::tap::tracker::{TapEvent, TapTracker, TapTrackerConfig};
use crate::transmission::{Transmission, TransmissionConfig};
use crate::webapi::AddTorrent;

const ALL: &[Shape] = &[Shape::V4, Shape::V6, Shape::Dual];

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "seed_to_oracle",
            shapes: ALL,
            tags: &[Tag::It],
            run: seed_to_oracle,
        },
        ScenarioDef {
            name: "seed_to_transmission",
            shapes: ALL,
            tags: &[Tag::It],
            run: seed_to_transmission,
        },
        ScenarioDef {
            name: "pause_resume",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: pause_resume,
        },
        ScenarioDef {
            name: "kill9_resume",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: kill9_resume,
        },
        ScenarioDef {
            name: "recheck_corrupted",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: recheck_corrupted,
        },
        ScenarioDef {
            name: "hash_fail_ban",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: hash_fail_ban,
        },
        ScenarioDef {
            name: "rate_limits",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: rate_limits,
        },
        ScenarioDef {
            name: "file_priorities",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: file_priorities,
        },
        ScenarioDef {
            name: "move_storage",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: move_storage,
        },
    ]
}

fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

fn tap_tracker(ctx: &Ctx) -> Result<TapTracker> {
    let http: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7070))
        .collect();
    TapTracker::start(TapTrackerConfig {
        http,
        interval: 30,
        min_interval: Some(10),
        ..Default::default()
    })
}

fn fixture(name: &str, size: u64, tracker: &TapTracker) -> Arc<Fixture> {
    Arc::new(Fixture::generate(
        FixtureSpec::small(name)
            .with_size(size)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ))
}

fn announces_from<'a>(events: &'a [TapEvent], ips: &[IpAddr]) -> Vec<&'a TapEvent> {
    events
        .iter()
        .filter(|e| e.kind == "announce" && ips.contains(&e.from.ip()))
        .collect()
}

fn query<'a>(e: &'a TapEvent, key: &str) -> Option<&'a str> {
    e.http
        .as_ref()?
        .query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Launch our client as a seeder: data in place, rechecked on add.
fn launch_seeder(ctx: &mut Ctx, fx: &Fixture, config: ClientConfig) -> Result<UrtClient> {
    let torrent_path = ctx.file("seed.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let actor = ctx.actor("urt")?;
    let save = actor.log_dir.join("data");
    std::fs::create_dir_all(&save)?;
    fx.write_data(&save)?;
    let client = UrtClient::launch(&actor, config, &torrent_path)?;
    let st = client.wait_for(Duration::from_secs(60), "seeder to finish checking", |s| {
        s.complete && s.state == "Seeding"
    })?;
    ensure!(st.downloaded == 0, "a rechecked seed downloaded nothing");
    Ok(client)
}

/// We seed (qbt profile); the oracle leeches from us.
fn seed_to_oracle(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = fixture("seed.bin", 4 << 20, &tracker);
    let h = fx.info_hash_hex();
    let mut client = launch_seeder(ctx, &fx, ClientConfig::default())?;
    let our_ips = client.actor.addrs();
    let leecher = ctx.oracle("leecher", OracleConfig::primary())?;
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    let t = leecher
        .api
        .wait_for(&h, Duration::from_secs(120), "oracle to complete", |t| {
            t.is_complete()
        })
        .inspect_err(|_| {
            tracing::error!("client log tail:\n{}", client.stderr_tail(60));
            tracing::error!(
                "oracle log:\n{}",
                leecher.api.main_log().unwrap_or_default().join("\n")
            );
        })?;
    ctx.note(format!("oracle complete: state={}", t.state));
    fx.verify_data(&leecher.save_path)?
        .map_err(|e| anyhow::anyhow!("oracle data mismatch: {e}"))?;
    let st = client.wait_for(Duration::from_secs(10), "upload counter", |s| {
        s.uploaded >= fx.total_len
    })?;
    ctx.note(format!(
        "we uploaded {} (payload {}), peers seen {:?}",
        st.uploaded,
        fx.total_len,
        st.peers_seen
            .iter()
            .map(|p| format!("{} {:?} up={}", p.addr, p.client, p.uploaded))
            .collect::<Vec<_>>()
    ));
    // Truthful: exactly the payload (the oracle requests each block once) —
    // allow end-game duplicates the oracle may have asked for.
    ensure!(
        st.uploaded >= fx.total_len && st.uploaded <= fx.total_len + 4 * 64 * 1024,
        "uploaded {} vs payload {}",
        st.uploaded,
        fx.total_len
    );
    ensure!(st.downloaded == 0 && st.corrupt == 0);
    ensure!(
        st.peers_seen.iter().any(|p| p
            .client
            .as_deref()
            .is_some_and(|c| c.starts_with("qBittorrent"))),
        "no qBittorrent peer seen"
    );
    client.shutdown()?;
    let events = tracker.events();
    let ours = announces_from(&events, &our_ips);
    let seq: Vec<Option<&str>> = ours.iter().map(|e| query(e, "event")).collect();
    ctx.note(format!("our announce sequence: {seq:?}"));
    ensure!(seq.first() == Some(&Some("started")));
    ensure!(
        !seq.contains(&Some("completed")),
        "a seed never announces completed"
    );
    ensure!(seq.last() == Some(&Some("stopped")));
    ensure!(ours.iter().all(|e| query(e, "left") == Some("0")));
    let last = ours.last().unwrap();
    ensure!(
        query(last, "uploaded") == Some(st.uploaded.to_string().as_str()),
        "stopped announce carries the real upload count"
    );
    let p = ctx.file("tap-tracker.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker.jsonl", &p);
    Ok(())
}

/// We seed; Transmission (an independent implementation) leeches from us.
fn seed_to_transmission(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = fixture("seed-tr.bin", 4 << 20, &tracker);
    let mut client = launch_seeder(ctx, &fx, ClientConfig::default())?;
    let actor = ctx.actor("transmission")?;
    let mut tr = Transmission::launch(&actor, TransmissionConfig::default())?;
    let id = tr.add_torrent(&fx.torrent)?;
    let t = tr
        .wait_for(
            id,
            Duration::from_secs(120),
            "transmission to complete",
            |t| t["percentDone"].as_f64().unwrap_or(0.0) >= 1.0,
        )
        .inspect_err(|_| {
            tracing::error!("client log tail:\n{}", client.stderr_tail(60));
            let log = tr.log();
            let tail: Vec<&str> = log.lines().rev().take(60).collect();
            tracing::error!("transmission log tail:\n{}", tail.join("\n"));
            for e in tracker.events() {
                if let Some(h) = &e.http {
                    tracing::error!(
                        "tracker saw {} {} -> {:?}",
                        e.from,
                        h.request_line,
                        crate::tap::tracker::decode_response(&e.response_hex)
                    );
                }
            }
        })?;
    ctx.note(format!(
        "transmission complete: downloaded={} peers={}",
        t["downloadedEver"], t["peersConnected"]
    ));
    fx.verify_data(&tr.download_dir)?
        .map_err(|e| anyhow::anyhow!("transmission data mismatch: {e}"))?;
    let st = client.wait_for(Duration::from_secs(10), "upload counter", |s| {
        s.uploaded >= fx.total_len
    })?;
    ensure!(
        st.peers_seen.iter().any(|p| p
            .client
            .as_deref()
            .is_some_and(|c| c.starts_with("Transmission"))),
        "no Transmission peer seen: {:?}",
        st.peers_seen
    );
    tr.shutdown()?;
    client.shutdown()?;
    Ok(())
}

/// Pause mid-download (stopped announce, peers dropped), resume, finish.
fn pause_resume(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = fixture("pause.bin", 8 << 20, &tracker);
    let h = fx.info_hash_hex();
    let seeder = ctx.oracle("seeder", OracleConfig::primary())?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder checked", |t| {
            t.is_seeding()
        })?;
    let torrent_path = ctx.file("pause.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    // Throttle so there is a "middle" to pause in.
    let mut client = ctx.client(
        "urt",
        ClientConfig::default().download_limit(1 << 20),
        &torrent_path,
    )?;
    let our_ips = client.actor.addrs();
    let st = client.wait_for(Duration::from_secs(60), "some progress", |s| {
        s.pieces_have >= 8 && !s.complete
    })?;
    client.command("pause")?;
    let paused = client.wait_for(Duration::from_secs(20), "paused", |s| s.state == "Paused")?;
    ensure!(paused.peers == 0, "peers still connected while paused");
    ensure!(
        paused.pieces_have >= st.pieces_have,
        "pieces went backwards"
    );
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| announces_from(ev, &our_ips)
            .iter()
            .any(|e| query(e, "event") == Some("stopped"))),
        "no stopped announce on pause"
    );
    std::thread::sleep(Duration::from_secs(2));
    let still = client.status().unwrap();
    ensure!(still.pieces_have == paused.pieces_have && still.downloaded == paused.downloaded);
    client.command("resume")?;
    let done = client.wait_for(Duration::from_secs(120), "complete after resume", |s| {
        s.complete
    })?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch: {e}"))?;
    ensure!(
        done.downloaded == fx.total_len,
        "downloaded {} != {}",
        done.downloaded,
        fx.total_len
    );
    client.shutdown()?;
    let events = tracker.events();
    let seq: Vec<Option<&str>> = announces_from(&events, &our_ips)
        .iter()
        .map(|e| query(e, "event"))
        .collect();
    ctx.note(format!("announce sequence: {seq:?}"));
    ensure!(
        seq.iter().filter(|e| **e == Some("started")).count() == 2
            && seq.iter().filter(|e| **e == Some("stopped")).count() == 2
            && seq.iter().filter(|e| **e == Some("completed")).count() == 1,
        "expected started/stopped/started/completed/stopped: {seq:?}"
    );
    Ok(())
}

/// `kill -9` mid-download, restart with the same dirs: the client must never
/// claim pieces it does not have, and must finish with correct data.
fn kill9_resume(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = fixture("kill9.bin", 8 << 20, &tracker);
    let h = fx.info_hash_hex();
    let seeder = ctx.oracle("seeder", OracleConfig::primary())?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder checked", |t| {
            t.is_seeding()
        })?;
    let torrent_path = ctx.file("kill9.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default().download_limit(1 << 20),
        &torrent_path,
    )?;
    client.wait_for(Duration::from_secs(60), "some progress", |s| {
        s.pieces_have >= 8 && !s.complete
    })?;
    // Persist what we have so far, then die abruptly a moment later.
    client.command("save-resume")?;
    std::thread::sleep(Duration::from_millis(700));
    let before = client.status().unwrap();
    client.kill9()?;
    ctx.note(format!(
        "killed at pieces_have={} downloaded={}",
        before.pieces_have, before.downloaded
    ));
    // Resume file: only verified, fsynced pieces; never more than we had.
    let resume_files: Vec<_> = std::fs::read_dir(&client.resume_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "resume"))
        .collect();
    ensure!(resume_files.len() == 1, "expected one resume file");
    // Decode the resume file with the harness's own bencode (never trust the
    // code under test to read its own claims).
    let rd = crate::bencode::decode(&std::fs::read(resume_files[0].path())?)
        .map_err(|e| anyhow::anyhow!("resume bencode: {e:?}"))?;
    let have_bytes = rd
        .get("have")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("resume: no have bitfield"))?
        .to_vec();
    let resume_downloaded = rd.get("downloaded").and_then(|v| v.as_int()).unwrap_or(0);
    let claimed: Vec<usize> = (0..fx.piece_count())
        .filter(|&i| {
            have_bytes
                .get(i / 8)
                .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
        })
        .collect();
    ensure!(
        claimed.len() <= before.pieces_have,
        "resume claims more than we had"
    );
    let on_disk = std::fs::read(fx.content_path(&client.save_path))?;
    for &i in &claimed {
        let start = i * 64 * 1024;
        let end = (start + 64 * 1024).min(on_disk.len());
        ensure!(
            end <= on_disk.len() && sha1(&on_disk[start..end]) == fx.piece_hashes[i],
            "resume claims piece {i} but disk data does not verify"
        );
    }
    client.relaunch(&torrent_path)?;
    let after = client.wait_for(Duration::from_secs(20), "restart", |s| {
        s.state != "Checking"
    })?;
    ensure!(
        after.pieces_have >= claimed.len(),
        "lost verified pieces on restart"
    );
    ensure!(
        after.pieces_have <= before.pieces_have + 2,
        "claimed pieces it cannot have"
    );
    let done = client.wait_for(Duration::from_secs(120), "complete after crash", |s| {
        s.complete
    })?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch after kill -9: {e}"))?;
    ctx.note(format!(
        "after crash: resumed with {} pieces, finished with downloaded={} (resume carried {})",
        after.pieces_have, done.downloaded, resume_downloaded
    ));
    client.shutdown()?;
    Ok(())
}

/// Corrupt data on disk, force a recheck: the have-set shrinks to what
/// verifies, then the torrent repairs itself from the oracle.
fn recheck_corrupted(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = fixture("recheck.bin", 4 << 20, &tracker);
    let h = fx.info_hash_hex();
    let seeder = ctx.oracle("seeder", OracleConfig::primary())?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder checked", |t| {
            t.is_seeding()
        })?;
    let torrent_path = ctx.file("recheck.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client("urt", ClientConfig::default(), &torrent_path)?;
    let done = client.wait_for(Duration::from_secs(120), "complete", |s| s.complete)?;
    // Corrupt three pieces' worth of bytes in the middle.
    fx.corrupt(&client.save_path, 10 * 64 * 1024 + 7, 3 * 64 * 1024)?;
    let checked_before = done.events.iter().filter(|e| e.contains("Checked")).count();
    client.command("recheck")?;
    // The recheck and the repair can both finish between two status
    // snapshots, so read the result from the event log: a second `Checked`
    // with fewer pieces, then completion again.
    let repaired = client.wait_for(Duration::from_secs(120), "recheck + repair", |s| {
        s.events.iter().filter(|e| e.contains("Checked")).count() > checked_before
            && s.complete
            && s.pieces_have == fx.piece_count()
    })?;
    let checked: Vec<usize> = repaired
        .events
        .iter()
        .filter_map(|e| {
            e.strip_prefix("Checked { id: TorrentId(1), pieces_have: ")
                .and_then(|r| r.trim_end_matches(" }").parse().ok())
        })
        .collect();
    let found = *checked.last().unwrap_or(&0);
    ctx.note(format!(
        "after recheck: {found} of {} pieces (checks: {checked:?})",
        fx.piece_count()
    ));
    ensure!(
        found + 4 >= fx.piece_count() && found + 3 <= fx.piece_count(),
        "recheck found {found} pieces, expected 3-4 missing of {}",
        fx.piece_count()
    );
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch after repair: {e}"))?;
    ensure!(
        repaired.downloaded > done.downloaded,
        "repair re-downloaded the damaged pieces"
    );
    client.shutdown()?;
    Ok(())
}

/// A tap-peer serving corrupted blocks gets blamed and banned; the download
/// still completes from the oracle.
fn hash_fail_ban(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = fixture("ban.bin", 4 << 20, &tracker);
    let h = fx.info_hash_hex();
    let bad_addr = SocketAddr::new(ctx.host_alias(2)?, 6890);
    let bad = TapPeer::start(
        TapPeerConfig::new(fx.info_hash, Role::Seeder)
            .listen(vec![bad_addr])
            .fixture(fx.clone())
            .misbehave(Misbehaviour::CorruptPieces)
            .linger(Duration::from_secs(60)),
    )?;
    tracker.inject_peer(fx.info_hash, bad_addr, 0);
    let seeder = ctx.oracle("seeder", OracleConfig::primary())?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder checked", |t| {
            t.is_seeding()
        })?;
    let torrent_path = ctx.file("ban.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client("urt", ClientConfig::default(), &torrent_path)?;
    let done = client.wait_for(Duration::from_secs(120), "complete despite bad peer", |s| {
        s.complete
    })?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch: {e}"))?;
    ctx.note(format!(
        "corrupt={} redundant={} downloaded={} payload={}",
        done.corrupt, done.redundant, done.downloaded, fx.total_len
    ));
    ensure!(
        done.corrupt > 0,
        "the bad peer's blocks must show up as corrupt"
    );
    ensure!(
        done.downloaded == fx.total_len + done.corrupt + done.redundant
            || done.downloaded >= fx.total_len,
        "accounting: downloaded {} payload {} corrupt {} redundant {}",
        done.downloaded,
        fx.total_len,
        done.corrupt,
        done.redundant
    );
    let banned = done
        .events
        .iter()
        .filter(|e| e.contains("HashFailed"))
        .count();
    ctx.note(format!("hash failures: {banned}"));
    ensure!(banned >= 1, "no HashFailed event");
    let disconnects: Vec<&String> = done
        .events
        .iter()
        .filter(|e| e.contains("PeerDisconnected") && e.contains("banned"))
        .collect();
    ensure!(
        !disconnects.is_empty(),
        "the bad peer was never banned: {:?}",
        done.events
    );
    // The bad peer saw us come and go; it recorded our requests.
    ensure!(
        bad.captures().iter().any(|c| c.handshake.is_some()),
        "bad peer never got a connection"
    );
    client.shutdown()?;
    Ok(())
}

/// Upload and download limits are honoured within tolerance, and counters
/// sampled during the transfer never decrease.
fn rate_limits(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = fixture("rate.bin", 4 << 20, &tracker);
    let h = fx.info_hash_hex();
    // Us seeding with a 1 MiB/s upload cap; the oracle leeches.
    let mut seeder = launch_seeder(ctx, &fx, ClientConfig::default().upload_limit(1 << 20))?;
    let leecher = ctx.oracle("leecher", OracleConfig::primary())?;
    let t0 = Instant::now();
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    let mut last_up = 0u64;
    let mut samples = 0;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let t = leecher.api.torrent(&h)?.unwrap_or_default();
        if let Some(st) = seeder.status() {
            ensure!(st.uploaded >= last_up, "uploaded went backwards");
            last_up = st.uploaded;
            samples += 1;
        }
        if t.is_complete() {
            break;
        }
        ensure!(Instant::now() < deadline, "oracle did not complete");
        std::thread::sleep(Duration::from_millis(100));
    }
    let elapsed = t0.elapsed();
    ctx.note(format!(
        "4 MiB at 1 MiB/s took {elapsed:?} ({samples} samples)"
    ));
    ensure!(
        elapsed >= Duration::from_millis(2500),
        "upload limit not honoured: {elapsed:?}"
    );
    ensure!(
        elapsed <= Duration::from_secs(30),
        "far too slow: {elapsed:?}"
    );
    seeder.shutdown()?;
    Ok(())
}

/// Selective download from the oracle: the middle file is skipped, so it is
/// never created and the pieces straddling it park their skipped bytes in
/// the parts file; then it is wanted after all and the torrent completes.
fn file_priorities(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("sel")
            .with_files(vec![
                FileSpec::new("a.bin", 700_000),
                FileSpec::new("sub/b.bin", 1_300_000),
                FileSpec::new("c.bin", 500_000),
            ])
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    let h = fx.info_hash_hex();
    let seeder = ctx.oracle("seeder", OracleConfig::primary())?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder checked", |t| {
            t.is_seeding()
        })?;
    let torrent_path = ctx.file("sel.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default()
            .profile("qbt")
            .file_priorities(vec![4, 0, 4]),
        &torrent_path,
    )?;
    let st = client.wait_for(Duration::from_secs(120), "wanted files to complete", |s| {
        s.complete
    })?;
    ctx.note(format!(
        "selective: pieces {}/{} wanted {}/{} left {} files {:?}",
        st.pieces_have,
        st.pieces_total,
        st.total_wanted_done,
        st.total_wanted,
        st.left,
        st.files
            .iter()
            .map(|f| format!("{} p{} {}/{}", f.path, f.priority, f.done, f.size))
            .collect::<Vec<_>>()
    ));
    ensure!(
        st.pieces_have < st.pieces_total,
        "skipped pieces were downloaded"
    );
    ensure!(st.left > 0, "left must stay truthful for skipped data");
    ensure!(st.total_wanted_done == st.total_wanted);
    ensure!(st.files.len() == 3 && st.files[1].priority == 0);
    ensure!(st.files[0].done == 700_000 && st.files[2].done == 500_000);
    let b_path = client.save_path.join("sel/sub/b.bin");
    ensure!(!b_path.exists(), "skipped file must not be created");
    ensure!(
        client.save_path.join(".sel.parts").exists(),
        "straddling bytes belong in the parts file"
    );
    let a = std::fs::read(client.save_path.join("sel/a.bin"))?;
    ensure!(a == fx.data_range(0, 700_000), "a.bin content");
    let c = std::fs::read(client.save_path.join("sel/c.bin"))?;
    ensure!(c == fx.data_range(2_000_000, 500_000), "c.bin content");
    // `completed` is only for full seeds (libtorrent): none so far.
    let our_ips = client.actor.addrs();
    let events = tracker.events();
    let ours = announces_from(&events, &our_ips);
    ensure!(
        !ours.iter().any(|e| query(e, "event") == Some("completed")),
        "a finished selective download is not `completed`"
    );

    // Want everything.
    client.command("prio 4,4,4")?;
    let st = client.wait_for(Duration::from_secs(120), "full download", |s| {
        s.complete && s.pieces_have == s.pieces_total
    })?;
    ensure!(st.left == 0 && st.corrupt == 0);
    ensure!(
        st.downloaded == fx.total_len,
        "downloaded {} vs {}",
        st.downloaded,
        fx.total_len
    );
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    client.wait_for(Duration::from_secs(20), "completed announce", |_| {
        let events = tracker.events();
        announces_from(&events, &our_ips)
            .iter()
            .any(|e| query(e, "event") == Some("completed"))
    })?;
    client.shutdown()?;
    let p = ctx.file("tap-tracker.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker.jsonl", &p);
    Ok(())
}

/// Move storage while downloading from the oracle (rate-limited so the move
/// happens mid-transfer): the download continues in the new directory and
/// the data verifies there.
fn move_storage(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("mv")
            .with_files(vec![
                FileSpec::new("one.bin", 2_500_000),
                FileSpec::new("d/two.bin", 1_500_000),
            ])
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    let h = fx.info_hash_hex();
    let seeder = ctx.oracle("seeder", OracleConfig::primary())?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder checked", |t| {
            t.is_seeding()
        })?;
    let torrent_path = ctx.file("mv.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default()
            .profile("qbt")
            .download_limit(512 * 1024),
        &torrent_path,
    )?;
    client.wait_for(Duration::from_secs(60), "some pieces", |s| {
        s.pieces_have >= 8
    })?;
    let new_dir = client.actor.log_dir.join("moved");
    client.command(&format!("move {}", new_dir.display()))?;
    let st = client.wait_for(Duration::from_secs(30), "storage moved", |s| {
        s.save_path == new_dir.to_string_lossy()
            && s.events.iter().any(|e| e.starts_with("StorageMoved"))
    })?;
    ctx.note(format!(
        "moved at {}/{} pieces; old dir has one.bin: {}",
        st.pieces_have,
        st.pieces_total,
        client.save_path.join("mv/one.bin").exists()
    ));
    ensure!(
        !client.save_path.join("mv/one.bin").exists(),
        "old location must be empty"
    );
    let st = client.wait_for(Duration::from_secs(120), "download to complete", |s| {
        s.complete
    })?;
    ensure!(st.corrupt == 0 && st.downloaded == fx.total_len);
    fx.verify_data(&new_dir)?
        .map_err(|e| anyhow::anyhow!("moved data mismatch: {e}"))?;
    client.command("recheck")?;
    std::thread::sleep(Duration::from_millis(500));
    let st = client.wait_for(Duration::from_secs(60), "recheck after move", |s| {
        s.state == "Seeding" && s.pieces_have == s.pieces_total
    })?;
    ensure!(st.complete);
    client.shutdown()?;
    Ok(())
}
