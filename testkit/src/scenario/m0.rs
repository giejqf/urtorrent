// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! M0 scenarios: the oracle can be observed. Two oracle instances transfer a
//! torrent through opentracker; tap-tracker and tap-peer record the oracle's
//! HTTP announces and peer-wire behaviour (the first golden captures).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail, ensure};

use super::{Ctx, ScenarioDef, Tag};
use crate::capture::Pcap;
use crate::fixtures::{Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::{Encryption, OracleConfig};
use crate::tap::peer::{Role, TapPeer, TapPeerConfig};
use crate::tap::tracker::{TapTracker, TapTrackerConfig, announces_by_hash};
use crate::trackers::OpenTracker;
use crate::webapi::AddTorrent;

const ALL: &[Shape] = &[Shape::V4, Shape::V6, Shape::Dual];

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "oracle_transfer",
            shapes: ALL,
            tags: &[Tag::It],
            run: oracle_transfer,
        },
        ScenarioDef {
            name: "capture_tracker_http",
            shapes: ALL,
            tags: &[Tag::It, Tag::Capture],
            run: capture_tracker_http,
        },
        ScenarioDef {
            name: "capture_peer_plain",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It, Tag::Capture],
            run: capture_peer_plain,
        },
        ScenarioDef {
            name: "capture_peer_encrypted",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_peer_encrypted,
        },
        ScenarioDef {
            name: "capture_defaults",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_defaults,
        },
    ]
}

fn fixture(name: &str, tracker: &str) -> Arc<Fixture> {
    Arc::new(Fixture::generate(
        FixtureSpec::small(name)
            .with_size(2 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(tracker),
    ))
}

/// Two oracles, one opentracker, one torrent.
fn oracle_transfer(ctx: &mut Ctx) -> Result<()> {
    let tracker_addrs: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 6969))
        .collect();
    let fx = fixture("transfer.bin", "http://placeholder/announce");
    let tracker = OpenTracker::start(
        &tracker_addrs,
        &[fx.info_hash],
        &ctx.run_dir.join("opentracker"),
    )?;
    let fx = fixture("transfer.bin", &tracker.http_url(0));
    let _pcap = Pcap::start(
        ctx.lab.bridge(),
        &ctx.file("transfer.pcap"),
        "not port 8080",
    )?;

    let seeder = ctx.oracle("seeder", OracleConfig::primary())?;
    let leecher = ctx.oracle("leecher", OracleConfig::primary())?;
    fx.write_data(&seeder.save_path)?;
    let h = fx.info_hash_hex();
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder.api.wait_for(
        &h,
        Duration::from_secs(60),
        "seeder to finish checking",
        |t| t.is_seeding(),
    )?;
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    let t = leecher
        .api
        .wait_for(&h, Duration::from_secs(120), "leecher to complete", |t| {
            t.is_complete()
        })
        .inspect_err(|_| {
            tracing::error!(
                "leecher log:\n{}",
                leecher.api.main_log().unwrap_or_default().join("\n")
            );
        })?;
    ctx.note(format!(
        "leecher complete: downloaded={} state={}",
        t.downloaded, t.state
    ));
    // Ground truth that the bytes moved: the leecher's on-disk data matches
    // the fixture byte-for-byte. The oracle's per-torrent transfer *stat*
    // counters lag (and can read 0 on a fast loopback transfer that is torn
    // down immediately), so they are reported, not asserted, in this liveness
    // test. Truthful-accounting assertions (AGENTS.md rule 1) target OUR
    // library's counters and land in later milestones.
    fx.verify_data(&leecher.save_path)?
        .map_err(|e| anyhow::anyhow!("leecher data mismatch: {e}"))?;
    let s = seeder.api.torrent(&h)?;
    let l = leecher.api.torrent(&h)?;
    ctx.note(format!(
        "seeder uploaded={:?} leecher downloaded={:?}",
        s.map(|t| t.uploaded),
        l.map(|t| t.downloaded)
    ));
    let peers = leecher.api.peers(&h)?;
    ctx.note(format!(
        "leecher saw peers: {:?}",
        peers
            .iter()
            .map(|p| format!("{}:{} {}", p.ip, p.port, p.client))
            .collect::<Vec<_>>()
    ));
    Ok(())
}

/// Oracle seeder + leecher announcing to tap-tracker: records the HTTP
/// announce sequence (started / regular / completed / stopped).
fn capture_tracker_http(ctx: &mut Ctx) -> Result<()> {
    let http: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7070))
        .collect();
    let tracker = TapTracker::start(TapTrackerConfig {
        http: http.clone(),
        interval: 30,
        min_interval: Some(10),
        ..Default::default()
    })?;
    let fx = fixture("capture.bin", &tracker.http_url(0));
    let h = fx.info_hash_hex();
    let seeder = ctx.oracle("seeder", OracleConfig::primary())?;
    let mut leecher = ctx.oracle("leecher", OracleConfig::primary())?;
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
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    leecher
        .api
        .wait_for(&h, Duration::from_secs(120), "leecher complete", |t| {
            t.is_complete()
        })?;
    fx.verify_data(&leecher.save_path)?
        .map_err(|e| anyhow::anyhow!("leecher data mismatch: {e}"))?;
    // `completed` announce.
    ensure!(
        tracker.wait_for(Duration::from_secs(30), |ev| ev.iter().any(|e| e
            .http
            .as_ref()
            .is_some_and(|h| h
                .query
                .iter()
                .any(|(k, v)| k == "event" && v == "completed")))),
        "no completed announce"
    );
    // A regular (no event) announce: libtorrent clamps the tracker interval to
    // its `min_announce_interval` (5 minutes), so force one instead of waiting.
    std::thread::sleep(Duration::from_secs(2));
    leecher.api.reannounce(&h)?;
    ensure!(
        tracker.wait_for(Duration::from_secs(30), |ev| {
            ev.iter()
                .filter(|e| {
                    e.kind == "announce"
                        && e.http
                            .as_ref()
                            .is_some_and(|h| !h.query.iter().any(|(k, _)| k == "event"))
                })
                .count()
                >= 1
        }),
        "no regular announce after forced reannounce"
    );
    // Graceful shutdown: expect `stopped`.
    leecher.shutdown()?;
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| ev.iter().any(|e| e
            .http
            .as_ref()
            .is_some_and(|h| h
                .query
                .iter()
                .any(|(k, v)| k == "event" && v == "stopped")))),
        "no stopped announce after shutdown"
    );
    let events = tracker.events();
    let by_hash = announces_by_hash(&events);
    ensure!(
        by_hash.contains_key(&h),
        "announces for wrong info-hash: {:?}",
        by_hash.keys()
    );
    let path = ctx.file("tap-tracker.jsonl");
    tracker.save_jsonl(&path)?;
    ctx.artifact("tap-tracker.jsonl", &path);
    ctx.note(format!("{} tracker events captured", events.len()));
    for e in &events {
        if let Some(hv) = &e.http {
            tracing::info!(
                "{} {} from {}: {}",
                e.ts_ms,
                e.kind,
                e.from,
                hv.request_line
            );
        }
    }
    Ok(())
}

pub fn run_peer_capture(
    ctx: &mut Ctx,
    oracle_cfg: OracleConfig,
    tag: &str,
    tap_enc: crate::tap::peer::TapEncryption,
    tap_initiates_mse: bool,
) -> Result<()> {
    let http: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7070))
        .collect();
    // Distinct harness-side IPs: the oracle allows one connection per IP per torrent.
    let seed_ip = ctx.host_alias(2)?;
    let leech_ip = ctx.host_alias(3)?;
    let peer_addr = SocketAddr::new(seed_ip, 6890);
    let _pcap = Pcap::start(
        ctx.lab.bridge(),
        &ctx.file(&format!("peer-{tag}.pcap")),
        "not port 8080",
    )?;
    // Torrent A: oracle leeches from tap-peer (oracle is the connection initiator).
    let tracker = TapTracker::start(TapTrackerConfig {
        http: http.clone(),
        interval: 30,
        ..Default::default()
    })?;
    let fx_a = fixture("peer-out.bin", &tracker.http_url(0));
    tracker.inject_peer(fx_a.info_hash, peer_addr, 0);
    let tap_seed = TapPeer::start(
        TapPeerConfig::new(fx_a.info_hash, Role::Seeder)
            .listen(vec![peer_addr])
            .fixture(fx_a.clone())
            .encryption(tap_enc)
            .linger(Duration::from_secs(8)),
    )?;
    let oracle = ctx.oracle("oracle", oracle_cfg)?;
    let ha = fx_a.info_hash_hex();
    oracle.api.add_torrent(
        &AddTorrent::file(&fx_a.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &ha,
    )?;
    oracle
        .api
        .wait_for(
            &ha,
            Duration::from_secs(120),
            "oracle to leech from tap-peer",
            |t| t.is_complete(),
        )
        .inspect_err(|_| {
            tracing::error!(
                "oracle log:\n{}",
                oracle.api.main_log().unwrap_or_default().join("\n")
            );
        })?;
    fx_a.verify_data(&oracle.save_path)?
        .map_err(|e| anyhow::anyhow!("oracle data mismatch: {e}"))?;
    ensure!(
        tap_seed.wait_for(Duration::from_secs(30), |c| c
            .iter()
            .any(|c| c.handshake.is_some() && c.closed_ms.is_some())),
        "tap-peer saw no completed plaintext connection"
    );
    let out_path = ctx.file(&format!("tap-peer-{tag}-oracle-initiator.jsonl"));
    tap_seed.save_jsonl(&out_path)?;
    ctx.artifact(&format!("tap-peer-{tag}-oracle-initiator.jsonl"), &out_path);
    for c in tap_seed.captures() {
        ctx.note(format!(
            "in-conn {} from {}: plaintext={} mse={:?} hs={:?} recv={:?} close={}",
            c.id,
            c.remote,
            !c.not_plaintext,
            c.mse,
            c.handshake.as_ref().map(|h| &h.reserved_bits),
            c.recv_kinds().iter().take(12).collect::<Vec<_>>(),
            c.close_reason
        ));
    }

    // Torrent B: oracle seeds, tap-peer connects in as a leecher (oracle responds).
    let fx_b = Arc::new(Fixture::generate(
        FixtureSpec::small("peer-in.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0))
            .with_seed(7),
    ));
    let hb = fx_b.info_hash_hex();
    fx_b.write_data(&oracle.save_path)?;
    oracle.api.add_torrent(
        &AddTorrent::file(&fx_b.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &hb,
    )?;
    oracle
        .api
        .wait_for(&hb, Duration::from_secs(60), "oracle checked B", |t| {
            t.is_seeding()
        })?;
    let tap_leech = TapPeer::start(
        TapPeerConfig::new(fx_b.info_hash, Role::Leecher)
            .fixture(fx_b.clone())
            .encryption(tap_enc)
            .initiate_mse(tap_initiates_mse)
            .linger(Duration::from_secs(3))
            .bind_addr(leech_ip),
    )?;
    // libtorrent refuses incoming peers for a short moment after a torrent
    // starts (even once it reports seeding); retry until it answers.
    let mut cap = tap_leech.connect(SocketAddr::new(oracle.actor.addr(), oracle.listen_port()))?;
    for _ in 0..20 {
        if cap.handshake.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
        cap = tap_leech.connect(SocketAddr::new(oracle.actor.addr(), oracle.listen_port()))?;
    }
    ctx.note(format!(
        "out-conn to oracle: mse={:?} hs={:?} pieces_ok={} recv={:?} close={}",
        cap.mse,
        cap.handshake.as_ref().map(|h| &h.reserved_bits),
        cap.pieces_ok,
        cap.recv_kinds().iter().take(12).collect::<Vec<_>>(),
        cap.close_reason
    ));
    if cap.handshake.is_none() {
        tracing::error!(
            "oracle peer log: {:?}",
            oracle.api.peer_log().unwrap_or_default()
        );
        tracing::error!(
            "oracle main log:\n{}",
            oracle.api.main_log().unwrap_or_default().join("\n")
        );
        bail!("oracle did not answer our handshake: {}", cap.close_reason);
    }
    ensure!(
        cap.pieces_ok as usize == fx_b.piece_count(),
        "tap-peer leeched {} of {} pieces",
        cap.pieces_ok,
        fx_b.piece_count()
    );
    let in_path = ctx.file(&format!("tap-peer-{tag}-oracle-responder.jsonl"));
    tap_leech.save_jsonl(&in_path)?;
    ctx.artifact(&format!("tap-peer-{tag}-oracle-responder.jsonl"), &in_path);
    let tr_path = ctx.file(&format!("tap-tracker-{tag}.jsonl"));
    tracker.save_jsonl(&tr_path)?;
    ctx.artifact(&format!("tap-tracker-{tag}.jsonl"), &tr_path);
    Ok(())
}

/// Plaintext peer-wire capture (oracle encryption disabled).
fn capture_peer_plain(ctx: &mut Ctx) -> Result<()> {
    run_peer_capture(
        ctx,
        OracleConfig::primary().encryption(Encryption::Disable),
        "plain",
        crate::tap::peer::TapEncryption::Disabled,
        false,
    )
}

/// Oracle with encryption preferred: outgoing connections try MSE first.
fn capture_peer_encrypted(ctx: &mut Ctx) -> Result<()> {
    run_peer_capture(
        ctx,
        OracleConfig::primary().encryption(Encryption::Prefer),
        "prefer-enc",
        crate::tap::peer::TapEncryption::Disabled,
        false,
    )
}

/// Oracle at qBittorrent defaults (DHT + uTP on): documents capability-gap
/// quirks (reserved bits, LTEP entries, PORT messages).
fn capture_defaults(ctx: &mut Ctx) -> Result<()> {
    let http: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7070))
        .collect();
    let peer_addr = SocketAddr::new(ctx.host_alias(2)?, 6890);
    let tracker = TapTracker::start(TapTrackerConfig {
        http,
        interval: 30,
        ..Default::default()
    })?;
    let fx = fixture("defaults.bin", &tracker.http_url(0));
    tracker.inject_peer(fx.info_hash, peer_addr, 0);
    let tap = TapPeer::start(
        TapPeerConfig::new(fx.info_hash, Role::Seeder)
            .listen(vec![peer_addr])
            .fixture(fx.clone())
            .linger(Duration::from_secs(8)),
    )?;
    let oracle = ctx.oracle(
        "oracle",
        OracleConfig::defaults().encryption(Encryption::Disable),
    )?;
    let h = fx.info_hash_hex();
    oracle.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    oracle.api.wait_for(
        &h,
        Duration::from_secs(120),
        "oracle leech (defaults)",
        |t| t.is_complete(),
    )?;
    ensure!(
        tap.wait_for(Duration::from_secs(30), |c| c
            .iter()
            .any(|c| c.handshake.is_some() && c.closed_ms.is_some())),
        "no completed connection"
    );
    let p = ctx.file("tap-peer-defaults.jsonl");
    tap.save_jsonl(&p)?;
    ctx.artifact("tap-peer-defaults.jsonl", &p);
    let t = ctx.file("tap-tracker-defaults.jsonl");
    tracker.save_jsonl(&t)?;
    ctx.artifact("tap-tracker-defaults.jsonl", &t);
    for c in tap.captures() {
        ctx.note(format!(
            "conn {} hs={:?} recv={:?}",
            c.id,
            c.handshake.as_ref().map(|h| &h.reserved_bits),
            c.recv_kinds().iter().take(10).collect::<Vec<_>>()
        ));
    }
    if tap.captures().iter().all(|c| c.handshake.is_none()) {
        bail!("no handshake captured");
    }
    Ok(())
}
