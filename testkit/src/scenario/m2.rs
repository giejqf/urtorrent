// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! M2 scenarios: the library leeches from the oracle. The oracle seeds a
//! fixture through tap-tracker; `urt-client` (qbt profile) downloads it. We
//! assert the bytes on disk, the truthful counters, and the announce sequence
//! the tracker saw (`started` -> `completed` exactly once -> `stopped`).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};

use super::{Ctx, ScenarioDef, Tag};
use crate::client::ClientConfig;
use crate::fixtures::{Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::OracleConfig;
use crate::tap::tracker::{TapEvent, TapTracker, TapTrackerConfig};
use crate::webapi::AddTorrent;

const ALL: &[Shape] = &[Shape::V4, Shape::V6, Shape::Dual];

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![ScenarioDef {
        name: "leech_from_oracle",
        shapes: ALL,
        tags: &[Tag::It],
        run: leech_from_oracle,
    }]
}

/// Announces from `ips` (under the qbt profile our peer id is
/// indistinguishable from the oracle's by design, so the source address is
/// what tells the two apart).
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

/// Oracle seeds, we leech (qbt profile), tap-tracker records both sides.
fn leech_from_oracle(ctx: &mut Ctx) -> Result<()> {
    let http: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7070))
        .collect();
    let tracker = TapTracker::start(TapTrackerConfig {
        http,
        interval: 30,
        min_interval: Some(10),
        ..Default::default()
    })?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("leech.bin")
            .with_size(4 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    let h = fx.info_hash_hex();

    // Seeder: the oracle at primary settings (encryption "allow": it accepts
    // our plaintext connection and connects out in plaintext, quirks Q3).
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
    ensure!(
        tracker.wait_for(Duration::from_secs(30), |ev| ev
            .iter()
            .any(|e| e.kind == "announce")),
        "seeder never announced"
    );

    // Leecher: us.
    let torrent_path = ctx.file("leech.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client("urt", ClientConfig::default().profile("qbt"), &torrent_path)?;
    let our_ips = client.actor.addrs();
    let seeder_ips = seeder.actor.addrs();
    let st = client.wait_for(Duration::from_secs(120), "download to complete", |s| {
        s.complete
    })?;
    ctx.note(format!(
        "complete: downloaded={} left={} corrupt={} redundant={} peers={} rate={}",
        st.downloaded, st.left, st.corrupt, st.redundant, st.peers, st.total_size
    ));
    // Ground truth: the bytes on disk.
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    // Truthful accounting (AGENTS.md rule 1): every received byte is counted
    // once; the useful ones add up to the torrent (a second connection to
    // the same seeder in end-game can bring a few duplicate blocks).
    ensure!(
        st.downloaded - st.redundant - st.corrupt == fx.total_len,
        "downloaded {} - redundant {} - corrupt {} != {}",
        st.downloaded,
        st.redundant,
        st.corrupt,
        fx.total_len
    );
    ensure!(st.left == 0, "left {} != 0", st.left);
    ensure!(st.corrupt == 0, "corrupt {}", st.corrupt);
    ensure!(st.pieces_have == fx.piece_count());
    ensure!(
        st.peers_seen.iter().any(|p| p
            .client
            .as_deref()
            .is_some_and(|c| c.starts_with("qBittorrent"))),
        "no qBittorrent peer seen: {:?}",
        st.peers_seen
    );
    ensure!(
        st.peers_seen.iter().map(|p| p.downloaded).sum::<u64>() == st.downloaded,
        "per-peer downloaded does not add up: {:?} vs {}",
        st.peers_seen,
        st.downloaded
    );

    // `completed` must reach the tracker, exactly once.
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| announces_from(ev, &our_ips)
            .iter()
            .any(|e| query(e, "event") == Some("completed"))),
        "no completed announce from us"
    );
    // The oracle's side must agree that it uploaded to us.
    let oracle_peers = seeder.api.peers(&h)?;
    ctx.note(format!(
        "seeder saw peers: {:?}",
        oracle_peers
            .iter()
            .map(|p| format!("{}:{} {}", p.ip, p.port, p.client))
            .collect::<Vec<_>>()
    ));

    // Graceful stop: exactly one `stopped`.
    client.shutdown()?;
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| announces_from(ev, &our_ips)
            .iter()
            .any(|e| query(e, "event") == Some("stopped"))),
        "no stopped announce after shutdown"
    );
    let events = tracker.events();
    let ours = announces_from(&events, &our_ips);
    ensure!(!ours.is_empty(), "tracker saw no announce from us");
    ensure!(
        ours.iter()
            .all(|e| query(e, "peer_id").is_some_and(|p| p.starts_with("-qB5230-"))),
        "peer id is not the profile's"
    );
    let seq: Vec<Option<&str>> = ours.iter().map(|e| query(e, "event")).collect();
    ctx.note(format!("our announce sequence: {seq:?}"));
    ensure!(
        seq.first() == Some(&Some("started")),
        "first announce is not started: {seq:?}"
    );
    ensure!(
        seq.iter().filter(|e| **e == Some("completed")).count() == 1,
        "completed not exactly once: {seq:?}"
    );
    ensure!(
        seq.iter().filter(|e| **e == Some("stopped")).count() == 1
            && seq.last() == Some(&Some("stopped")),
        "stopped not exactly once at the end: {seq:?}"
    );
    // Counters on the wire are truthful too.
    let started = ours[0];
    ensure!(query(started, "left") == Some(fx.total_len.to_string().as_str()));
    ensure!(query(started, "downloaded") == Some("0"));
    let completed = ours
        .iter()
        .find(|e| query(e, "event") == Some("completed"))
        .unwrap();
    ensure!(query(completed, "left") == Some("0"));
    ensure!(query(completed, "downloaded") == Some(fx.total_len.to_string().as_str()));
    // The identity is the profile's; the parameter order is the oracle's.
    let seeder_announce = *announces_from(&events, &seeder_ips)
        .first()
        .ok_or_else(|| anyhow::anyhow!("no seeder announce"))?;
    let keys = |e: &TapEvent| -> Vec<String> {
        e.http
            .as_ref()
            .unwrap()
            .query
            .iter()
            .map(|(k, _)| k.clone())
            .collect()
    };
    ensure!(
        keys(started) == keys(seeder_announce),
        "parameter order differs from the oracle: {:?} vs {:?}",
        keys(started),
        keys(seeder_announce)
    );
    let hdrs = |e: &TapEvent| -> Vec<String> {
        e.http
            .as_ref()
            .unwrap()
            .headers
            .iter()
            .map(|(k, _)| k.clone())
            .collect()
    };
    ensure!(
        hdrs(started) == hdrs(seeder_announce),
        "header order differs from the oracle: {:?} vs {:?}",
        hdrs(started),
        hdrs(seeder_announce)
    );
    let path = ctx.file("tap-tracker.jsonl");
    tracker.save_jsonl(&path)?;
    ctx.artifact("tap-tracker.jsonl", &path);
    Ok(())
}
