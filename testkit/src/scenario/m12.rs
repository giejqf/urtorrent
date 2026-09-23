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
use crate::client::ClientConfig;
use crate::fixtures::{FileSpec, Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::{Encryption, OracleConfig};
use crate::tap::peer::{PeerEvent, Role, TapEncryption, TapPeer, TapPeerConfig};
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
        ScenarioDef {
            name: "magnet_hold",
            shapes: &[Shape::V4],
            tags: &[Tag::It, Tag::Diff],
            run: magnet_hold,
        },
        ScenarioDef {
            name: "capture_partial_seed",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_partial_seed,
        },
        ScenarioDef {
            name: "partial_seed_shape",
            shapes: &[Shape::V4],
            tags: &[Tag::It, Tag::Diff],
            run: partial_seed_shape,
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

/// Our client under the qbt profile, a magnet added with
/// `hold_after_metadata`: what the tracker and the seed see must match the
/// oracle's "stop condition: metadata received" (`capture_magnet_hold`):
/// the same announces (`started` with the placeholder `left` before the
/// metadata, then `stopped`), the metadata fetched and no piece requested,
/// the connection dropped, nothing on disk. Resumed, it downloads.
fn magnet_hold(ctx: &mut Ctx) -> Result<()> {
    let golden = crate::scenario::golden_file("capture_magnet_hold", Shape::V4, "magnet-hold.json")
        .ok_or_else(|| {
            anyhow::anyhow!("no golden; run `cargo xtask capture capture_magnet_hold`")
        })?;
    let golden: serde_json::Value = serde_json::from_slice(&std::fs::read(golden)?)?;
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
    let h = fx.info_hash_hex();
    let magnet = format!(
        "magnet:?xt=urn:btih:{h}&dn=hold.bin&tr={}",
        crate::http::percent_encode(tracker.http_url(0).as_bytes())
    );
    let actor = ctx.actor("urt")?;
    let mut client = crate::client::UrtClient::launch_magnet(
        &actor,
        ClientConfig::default()
            .profile("qbt")
            .encryption("disabled")
            .lsd(false)
            .hold(true),
        &magnet,
    )?;
    client.wait_for(Duration::from_secs(60), "the hold", |s| s.state == "Held")?;
    // Let the stop play out (stopped announce, the peer dropped).
    ensure!(
        tap_seed.wait_for(Duration::from_secs(10), |c| c
            .iter()
            .any(|c| c.closed_ms.is_some())),
        "the seed's connection was not dropped"
    );
    std::thread::sleep(Duration::from_secs(2));
    let caps = tap_seed.captures();
    let pieces_sent: usize = caps
        .iter()
        .flat_map(|c| c.events.iter())
        .filter(|e| e.dir == "send" && e.kind == "piece")
        .count();
    let requests: usize = caps
        .iter()
        .flat_map(|c| c.events.iter())
        .filter(|e| e.dir == "recv" && e.kind == "request")
        .count();
    let ours = announce_summary(&tracker.events(), 0);
    let theirs = golden["held"]["announces"].clone();
    ctx.note(format!("held: ours={ours:?} oracle={theirs}"));
    ensure!(
        serde_json::Value::Array(ours.clone()) == theirs,
        "held announces differ: ours {ours:?}, oracle {theirs}"
    );
    ensure!(
        pieces_sent == 0 && requests == 0,
        "a held torrent requested {requests} blocks"
    );
    ensure!(
        !client.save_path.join("hold.bin").exists(),
        "a held torrent created its file"
    );
    ensure!(
        client.status().is_some_and(|s| s.state == "Held"),
        "no longer held"
    );
    // Start it: it must download.
    client.command("resume")?;
    client.wait_for(Duration::from_secs(60), "download after resume", |s| {
        s.state == "Seeding"
    })?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch: {e}"))?;
    let after: Vec<Option<String>> = announce_summary(&tracker.events(), 0)
        .iter()
        .map(|a| a["event"].as_str().map(str::to_string))
        .collect();
    let oracle_after: Vec<Option<String>> = golden["after_start_announces"]
        .as_array()
        .map(|v| {
            v.iter()
                .map(|a| a["event"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    ctx.note(format!(
        "after resume: ours={after:?} oracle={oracle_after:?}"
    ));
    ensure!(
        after.starts_with(&oracle_after),
        "announces after resume differ: ours {after:?}, oracle {oracle_after:?}"
    );
    client.shutdown()?;
    Ok(())
}

/// The selective fixture of the partial-seed scenarios: the middle file is
/// skipped, so pieces 10 and 30 straddle it and 11-29 lie inside it.
fn partial_fixture(tracker: &TapTracker) -> Arc<Fixture> {
    Arc::new(Fixture::generate(
        FixtureSpec::small("sel")
            .with_files(vec![
                FileSpec::new("a.bin", 700_000),
                FileSpec::new("sub/b.bin", 1_300_000),
                FileSpec::new("c.bin", 500_000),
            ])
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ))
}

/// A silent tap peer that advertises BEP 21 `upload_only` (libtorrent sends
/// the message only to peers that list it in their `m` map).
fn upload_only_tap(fx: &Fixture) -> Result<TapPeer> {
    let mut m = crate::bencode::Value::dict();
    m.insert("ut_pex", crate::bencode::Value::Int(1));
    m.insert("ut_metadata", crate::bencode::Value::Int(2));
    m.insert("upload_only", crate::bencode::Value::Int(3));
    let mut ext = crate::bencode::Value::dict();
    ext.insert("m", m);
    ext.insert("v", crate::bencode::Value::str("tap-peer 0.1"));
    ext.insert("reqq", crate::bencode::Value::Int(250));
    TapPeer::start(
        TapPeerConfig::new(fx.info_hash, Role::Silent)
            .ext_handshake(Some(ext))
            .encryption(TapEncryption::Disabled)
            .linger(Duration::from_secs(30)),
    )
}

fn connect_retry(tap: &TapPeer, target: SocketAddr, attempts: usize) -> bool {
    for _ in 0..attempts {
        tap.connect_async(target);
        if tap.wait_for(Duration::from_secs(3), |c| {
            c.iter().any(|c| c.handshake.is_some())
        }) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// A received message as the shape comparison sees it: its kind, the
/// extension id for extension messages, and the payload of a non-bencoded
/// one (BEP 21 `upload_only` is one raw byte).
fn shape_of(e: &PeerEvent) -> serde_json::Value {
    if e.kind == "extended" {
        let raw = if e.detail["decoded"].is_null() {
            e.detail["raw_hex"].clone()
        } else {
            serde_json::Value::Null
        };
        json!({ "kind": "extended", "ext_id": e.detail["ext_id"], "raw": raw })
    } else {
        json!({ "kind": e.kind })
    }
}

/// What a partial seed shows a peer that connects to it, then what it sends
/// when its selection widens: the bitfield, the extension handshake's
/// `upload_only`, and the messages after the change.
fn observe_partial_seed(
    tap: &TapPeer,
    target: SocketAddr,
    widen: &dyn Fn() -> Result<()>,
) -> Result<serde_json::Value> {
    ensure!(connect_retry(tap, target, 10), "the tap could not connect");
    ensure!(
        tap.wait_for(Duration::from_secs(10), |c| c
            .iter()
            .any(|c| c.ext_handshake().is_some())),
        "no extension handshake"
    );
    std::thread::sleep(Duration::from_secs(2));
    let before = tap.captures();
    let conn = before
        .iter()
        .find(|c| c.ext_handshake().is_some())
        .ok_or_else(|| anyhow::anyhow!("no connection"))?;
    let recv: Vec<&PeerEvent> = conn.events.iter().filter(|e| e.dir == "recv").collect();
    let bitfield = recv
        .iter()
        .find(|e| e.kind == "bitfield")
        .map(|e| e.detail.clone());
    let ext = conn.ext_handshake().cloned().unwrap_or_default();
    let seen = recv.len();
    widen()?;
    std::thread::sleep(Duration::from_secs(4));
    let after_caps = tap.captures();
    let after: Vec<serde_json::Value> = after_caps
        .iter()
        .find(|c| c.id == conn.id)
        .map(|c| {
            c.events
                .iter()
                .filter(|e| e.dir == "recv")
                .skip(seen)
                .filter(|e| e.kind != "keep_alive")
                .map(shape_of)
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({
        "first": recv.iter().map(|e| shape_of(e)).collect::<Vec<_>>(),
        "bitfield": bitfield,
        "ext_keys": ext.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()),
        "upload_only": ext.get("upload_only").cloned(),
        "after_widen": after,
    }))
}

/// The oracle as a partial seed: it downloaded a selection (the middle file
/// skipped) and its seeder is gone. A tap peer records what it advertises,
/// and what it sends when the middle file is selected after all.
fn capture_partial_seed(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = partial_fixture(&tracker);
    let h = fx.info_hash_hex();
    let mut seeder = ctx.oracle(
        "seeder",
        OracleConfig::primary().encryption(Encryption::Disable),
    )?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder", |t| t.is_seeding())?;
    let partial = ctx.oracle(
        "partial",
        OracleConfig::primary().encryption(Encryption::Disable),
    )?;
    partial.api.add_torrent(
        &AddTorrent::file(&fx.torrent)
            .save_path(&partial.save_path.to_string_lossy())
            .stopped(true),
        &h,
    )?;
    partial.api.set_file_priority(&h, &[1], 0)?;
    partial.api.start(&h)?;
    let t = partial
        .api
        .wait_for(&h, Duration::from_secs(120), "the selection", |t| {
            t.is_complete()
        })?;
    ctx.note(format!(
        "oracle partial: state={} progress={}",
        t.state, t.progress
    ));
    seeder.shutdown()?;
    let tap = upload_only_tap(&fx)?;
    let target = SocketAddr::new(partial.actor.addr(), partial.listen_port());
    let api = partial.api.clone();
    let hh = h.clone();
    let summary = observe_partial_seed(&tap, target, &move || api.set_file_priority(&hh, &[1], 1))?;
    ctx.note(format!("oracle partial seed: {summary}"));
    let p = ctx.file("partial-seed.json");
    std::fs::write(&p, serde_json::to_string_pretty(&summary)?)?;
    ctx.artifact("partial-seed.json", &p);
    let tp = ctx.file("tap-peer-partial.jsonl");
    tap.save_jsonl(&tp)?;
    ctx.artifact("tap-peer-partial.jsonl", &tp);
    Ok(())
}

/// Our client (qbt profile) as a partial seed, against the oracle's
/// (`capture_partial_seed`): the same bitfield, the same `upload_only` in
/// the extension handshake and the same messages when the selection widens.
/// Then an oracle that wants the same selection downloads it from us, its
/// only source.
fn partial_seed_shape(ctx: &mut Ctx) -> Result<()> {
    let golden =
        crate::scenario::golden_file("capture_partial_seed", Shape::V4, "partial-seed.json")
            .ok_or_else(|| {
                anyhow::anyhow!("no golden; run `cargo xtask capture capture_partial_seed`")
            })?;
    let golden: serde_json::Value = serde_json::from_slice(&std::fs::read(golden)?)?;
    let tracker = tap_tracker(ctx)?;
    let fx = partial_fixture(&tracker);
    let h = fx.info_hash_hex();
    let mut seeder = ctx.oracle(
        "seeder",
        OracleConfig::primary().encryption(Encryption::Disable),
    )?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder", |t| t.is_seeding())?;
    let torrent_path = ctx.file("sel.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default()
            .profile("qbt")
            .encryption("disabled")
            .lsd(false)
            .file_priorities(vec![4, 0, 4]),
        &torrent_path,
    )?;
    client.wait_for(Duration::from_secs(120), "the selection", |s| s.complete)?;
    seeder.shutdown()?;
    let tap = upload_only_tap(&fx)?;
    let target = SocketAddr::new(client.actor.addr(), client.listen_port());
    let ours = {
        let c = &client;
        observe_partial_seed(&tap, target, &|| c.command("prio 4,4,4"))?
    };
    ctx.note(format!("ours: {ours}"));
    ctx.note(format!("oracle: {golden}"));
    for key in ["bitfield", "upload_only", "after_widen"] {
        ensure!(
            ours[key] == golden[key],
            "{key} differs: ours {}, oracle {}",
            ours[key],
            golden[key]
        );
    }
    // Back to the selection, and an oracle downloads it from us alone.
    client.command("prio 4,0,4")?;
    let leecher = ctx.oracle(
        "leecher",
        OracleConfig::primary().encryption(Encryption::Disable),
    )?;
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent)
            .save_path(&leecher.save_path.to_string_lossy())
            .stopped(true),
        &h,
    )?;
    leecher.api.set_file_priority(&h, &[1], 0)?;
    leecher.api.start(&h)?;
    leecher.api.add_peers(&h, &[target])?;
    leecher.api.wait_for(
        &h,
        Duration::from_secs(120),
        "the oracle's selection",
        |t| t.is_complete(),
    )?;
    let a = std::fs::read(leecher.save_path.join("sel/a.bin"))?;
    ensure!(
        a == fx.data_range(0, 700_000),
        "a.bin from our partial seed"
    );
    let c = std::fs::read(leecher.save_path.join("sel/c.bin"))?;
    ensure!(
        c == fx.data_range(2_000_000, 500_000),
        "c.bin from our partial seed"
    );
    client.shutdown()?;
    Ok(())
}
