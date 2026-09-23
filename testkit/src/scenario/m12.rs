// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! 0.12.0 (what the daemon needs) scenarios. Capture first: what the oracle
//! does with a torrent whose files vanished between two runs, and with a
//! magnet added with qBittorrent's "stop condition: metadata received".

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use serde_json::json;

use super::{Ctx, ScenarioDef, Tag};
use crate::fixtures::{Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::{Encryption, OracleConfig};
use crate::tap::peer::{Role, TapEncryption, TapPeer, TapPeerConfig};
use crate::tap::tracker::{TapEvent, TapTracker, TapTrackerConfig};
use crate::webapi::{AddTorrent, WebApi};

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "capture_missing_files",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_missing_files,
        },
        ScenarioDef {
            name: "capture_magnet_hold",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_magnet_hold,
        },
    ]
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

/// `event` and `left` of each announce after `since_ms`.
fn announce_summary(events: &[TapEvent], since_ms: u64) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter(|e| e.kind == "announce" && e.ts_ms >= since_ms)
        .map(|e| {
            let line = e
                .http
                .as_ref()
                .map(|h| h.request_line.clone())
                .unwrap_or_default();
            let param = |k: &str| {
                line.split(['?', '&', ' '])
                    .find_map(|kv| kv.strip_prefix(&format!("{k}=")).map(str::to_string))
            };
            json!({ "event": param("event"), "left": param("left") })
        })
        .collect()
}

/// Poll the oracle's state for `d`, recording each distinct state.
fn states_for(api: &WebApi, hash: &str, d: Duration) -> Result<Vec<String>> {
    let mut seen: Vec<String> = Vec::new();
    let start = Instant::now();
    while start.elapsed() < d {
        if let Some(t) = api.torrent(hash)?
            && seen.last() != Some(&t.state)
        {
            seen.push(t.state.clone());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(seen)
}

/// A seeding torrent's file is deleted while the oracle is down. What state
/// does it come back in, what does it tell the tracker, and what do "start"
/// and "recheck" do, with the file still missing and once it is back?
fn capture_missing_files(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("missing.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    let h = fx.info_hash_hex();
    let mut oracle = ctx.oracle(
        "oracle",
        OracleConfig::primary().encryption(Encryption::Disable),
    )?;
    fx.write_data(&oracle.save_path)?;
    oracle.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    oracle
        .api
        .wait_for(&h, Duration::from_secs(60), "oracle seeding", |t| {
            t.is_seeding()
        })?;
    oracle.shutdown()?;
    let data = oracle.save_path.join("missing.bin");
    std::fs::remove_file(&data)?;
    let wl = ctx.whitelist();
    let since = tracker.events().last().map_or(0, |e| e.ts_ms + 1);
    oracle.restart(&wl)?;
    let after_restart = states_for(&oracle.api, &h, Duration::from_secs(15))?;
    let t = oracle.api.torrent(&h)?.unwrap_or_default();
    ctx.note(format!(
        "after restart: states={after_restart:?} progress={} completed={}",
        t.progress, t.completed
    ));
    let files_after_restart = data.exists();
    let announces_after_restart = announce_summary(&tracker.events(), since);

    // "Start" with the file still missing.
    let since = tracker.events().last().map_or(0, |e| e.ts_ms + 1);
    oracle.api.start(&h)?;
    let after_start = states_for(&oracle.api, &h, Duration::from_secs(8))?;
    let announces_after_start = announce_summary(&tracker.events(), since);
    let files_after_start = data.exists();
    ctx.note(format!("after start: {after_start:?}"));

    // "Recheck" with the file still missing.
    oracle.api.recheck(&h)?;
    let after_recheck_missing = states_for(&oracle.api, &h, Duration::from_secs(8))?;
    let t = oracle.api.torrent(&h)?.unwrap_or_default();
    let progress_after_recheck_missing = t.progress;
    let files_after_recheck_missing = data.exists();
    ctx.note(format!(
        "after recheck (missing): {after_recheck_missing:?} progress={}",
        t.progress
    ));

    // The file is back: recheck again.
    oracle.api.stop(&h)?;
    std::thread::sleep(Duration::from_secs(1));
    fx.write_data(&oracle.save_path)?;
    oracle.api.recheck(&h)?;
    oracle.api.start(&h)?;
    let after_recheck_back = states_for(&oracle.api, &h, Duration::from_secs(10))?;
    ctx.note(format!("after recheck (back): {after_recheck_back:?}"));
    let log: Vec<String> = oracle
        .api
        .main_log()
        .unwrap_or_default()
        .into_iter()
        .filter(|l| l.contains("missing.bin") || l.to_lowercase().contains("error"))
        .collect();
    for l in &log {
        ctx.note(format!("log: {l}"));
    }
    let summary = json!({
        "after_restart": { "states": after_restart, "file_exists": files_after_restart,
                            "announces": announces_after_restart },
        "after_start": { "states": after_start, "file_exists": files_after_start,
                          "announces": announces_after_start },
        "after_recheck_missing": { "states": after_recheck_missing,
                                    "progress": progress_after_recheck_missing,
                                    "file_exists": files_after_recheck_missing },
        "after_recheck_back": { "states": after_recheck_back },
        "log": log,
    });
    let p = ctx.file("missing-files.json");
    std::fs::write(&p, serde_json::to_string_pretty(&summary)?)?;
    ctx.artifact("missing-files.json", &p);
    let tp = ctx.file("tap-tracker-missing.jsonl");
    tracker.save_jsonl(&tp)?;
    ctx.artifact("tap-tracker-missing.jsonl", &tp);
    Ok(())
}

/// A magnet added with "stop condition: metadata received": what reaches the
/// wire and the disk once the metadata is in, and what starting it does.
fn capture_magnet_hold(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("hold.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    let seed_ip = ctx.host_alias(2)?;
    let peer_addr = SocketAddr::new(seed_ip, 6890);
    tracker.inject_peer(fx.info_hash, peer_addr, 0);
    let tap_seed = TapPeer::start(
        TapPeerConfig::new(fx.info_hash, Role::Seeder)
            .listen(vec![peer_addr])
            .fixture(fx.clone())
            .encryption(TapEncryption::Disabled)
            .linger(Duration::from_secs(8)),
    )?;
    let oracle = ctx.oracle(
        "oracle",
        OracleConfig::primary().encryption(Encryption::Disable),
    )?;
    let h = fx.info_hash_hex();
    let magnet = format!(
        "magnet:?xt=urn:btih:{h}&dn=hold.bin&tr={}",
        crate::http::percent_encode(tracker.http_url(0).as_bytes())
    );
    oracle.api.add_torrent(
        &AddTorrent::magnet(&magnet)
            .save_path(&oracle.save_path.to_string_lossy())
            .stop_condition("MetadataReceived"),
        &h,
    )?;
    let t = oracle.api.wait_for(
        &h,
        Duration::from_secs(60),
        "metadata, then the stop",
        |t| t.total_size > 0 && t.state.starts_with("stopped"),
    )?;
    let held_state = t.state.clone();
    let held_progress = t.progress;
    // Watch the held torrent for a while.
    let held_states = states_for(&oracle.api, &h, Duration::from_secs(8))?;
    let file_while_held = oracle.save_path.join("hold.bin").exists();
    let caps_held = tap_seed.captures();
    let pieces_while_held: usize = caps_held
        .iter()
        .flat_map(|c| c.events.iter())
        .filter(|e| e.dir == "send" && e.kind == "piece")
        .count();
    let held_announces = announce_summary(&tracker.events(), 0);
    ctx.note(format!(
        "held: state={held_state} states={held_states:?} progress={held_progress} file={file_while_held} pieces_sent={pieces_while_held} announces={held_announces:?}"
    ));
    for c in &caps_held {
        let kinds: Vec<String> = c
            .events
            .iter()
            .map(|e| {
                if e.kind == "extended" {
                    format!("{}:extended[{}]", e.dir, e.detail["ext_id"])
                } else {
                    format!("{}:{}", e.dir, e.kind)
                }
            })
            .collect();
        ctx.note(format!(
            "held conn {} from {}: closed={:?} reason={:?} events={kinds:?}",
            c.id, c.remote, c.closed_ms, c.close_reason
        ));
    }
    // Start it: it must download.
    oracle.api.start(&h)?;
    oracle
        .api
        .wait_for(&h, Duration::from_secs(120), "download after start", |t| {
            t.is_complete()
        })?;
    fx.verify_data(&oracle.save_path)?
        .map_err(|e| anyhow::anyhow!("oracle data mismatch: {e}"))?;
    ensure!(
        !caps_held.is_empty(),
        "the oracle never connected to the tap seed"
    );
    let summary = json!({
        "held": {
            "state": held_state,
            "states": held_states,
            "progress": held_progress,
            "file_exists": file_while_held,
            "piece_messages_received": pieces_while_held,
            "connections": caps_held.iter().map(|c| json!({
                "closed": c.closed_ms.is_some(),
                "close_reason": c.close_reason,
                "events": c.events.iter().map(|e| if e.kind == "extended" {
                    format!("{}:extended[{}]", e.dir, e.detail["ext_id"])
                } else {
                    format!("{}:{}", e.dir, e.kind)
                }).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "announces": held_announces,
        },
        "after_start_announces": announce_summary(&tracker.events(), 0),
    });
    let p = ctx.file("magnet-hold.json");
    std::fs::write(&p, serde_json::to_string_pretty(&summary)?)?;
    ctx.artifact("magnet-hold.json", &p);
    let pp = ctx.file("tap-peer-hold.jsonl");
    tap_seed.save_jsonl(&pp)?;
    ctx.artifact("tap-peer-hold.jsonl", &pp);
    let tp = ctx.file("tap-tracker-hold.jsonl");
    tracker.save_jsonl(&tp)?;
    ctx.artifact("tap-tracker-hold.jsonl", &tp);
    Ok(())
}
