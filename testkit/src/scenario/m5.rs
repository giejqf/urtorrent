// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! M5 scenarios: reach. UDP tracker captures and conformance, scrape, tier
//! failover, PT-style trackers, encryption modes, dual-stack announces.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};

use super::{Ctx, ScenarioDef, Tag};
use crate::discriminator::Fingerprint;
use crate::fixtures::{Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::OracleConfig;
use crate::tap::tracker::{TapTracker, TapTrackerConfig};
use crate::webapi::AddTorrent;

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "capture_tracker_udp",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::Capture],
            run: capture_tracker_udp,
        },
        ScenarioDef {
            name: "capture_scrape",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_scrape,
        },
        ScenarioDef {
            name: "udp_tracker",
            shapes: &[Shape::V4, Shape::V6, Shape::Dual],
            tags: &[Tag::It],
            run: udp_tracker,
        },
        ScenarioDef {
            name: "http_scrape",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: http_scrape,
        },
    ]
}

/// Oracle seeder + leecher on a UDP tracker: connect / announce datagrams,
/// field values, connection-id reuse, and the retransmit schedule against a
/// tracker that goes silent.
fn capture_tracker_udp(ctx: &mut Ctx) -> Result<()> {
    let udp: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 6969))
        .collect();
    let tracker = TapTracker::start(TapTrackerConfig {
        udp,
        interval: 30,
        min_interval: Some(10),
        ..Default::default()
    })?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("udp.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.udp_url(0)),
    ));
    let h = fx.info_hash_hex();
    // LSD off: peers must come from the tracker under test.
    let seeder = ctx.oracle("seeder", OracleConfig::primary().lsd(false))?;
    let mut leecher = ctx.oracle("leecher", OracleConfig::primary().lsd(false))?;
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
            .any(|e| e.transport == "udp" && e.kind == "announce")),
        "seeder never announced over udp: {:?}",
        tracker
            .events()
            .iter()
            .map(|e| (&e.transport, &e.kind))
            .collect::<Vec<_>>()
    );
    // The leecher meets a silent tracker first: its `connect` must be
    // retransmitted on the BEP 15 schedule (15 s, 30 s, ...).
    tracker.set_behaviour(crate::tap::tracker::Behaviour::Silent);
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    std::thread::sleep(Duration::from_secs(50));
    tracker.set_behaviour(crate::tap::tracker::Behaviour::Normal);
    let complete = leecher
        .api
        .wait_for(&h, Duration::from_secs(240), "leecher complete", |t| {
            t.is_complete()
        });
    let p = ctx.file("tap-tracker-udp.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker-udp.jsonl", &p);
    complete?;
    let got_completed = tracker.wait_for(Duration::from_secs(60), |ev| {
        ev.iter().any(|e| {
            e.udp
                .as_ref()
                .and_then(|u| u.announce.as_ref())
                .is_some_and(|a| a.event == 1)
        })
    });
    ctx.note(format!("completed announce seen: {got_completed}"));
    // A forced re-announce once the tracker's min interval has passed: the
    // cached connection id must be reused.
    std::thread::sleep(Duration::from_secs(11));
    leecher.api.reannounce(&h)?;
    std::thread::sleep(Duration::from_secs(3));
    leecher.shutdown()?;
    std::thread::sleep(Duration::from_secs(3));
    let events = tracker.events();
    for e in &events {
        if let Some(u) = &e.udp {
            ctx.note(format!(
                "{} {} from {} action={} tid={} cid={:016x} ann={:?} ext={}",
                e.ts_ms,
                e.kind,
                e.from,
                u.action,
                u.transaction_id,
                u.connection_id,
                u.announce
                    .as_ref()
                    .map(|a| (a.event, a.num_want, a.key, a.ip, a.port, a.left)),
                u.announce
                    .as_ref()
                    .map(|a| a.extensions_hex.clone())
                    .unwrap_or_default()
            ));
        }
    }
    tracker.save_jsonl(&p)?;
    Ok(())
}

/// Does the oracle scrape, and how? A stopped torrent (qBittorrent "add
/// stopped") and a forced reannounce both go through libtorrent's tracker
/// code paths that may scrape.
fn capture_scrape(ctx: &mut Ctx) -> Result<()> {
    let http: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7070))
        .collect();
    let udp: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 6969))
        .collect();
    let tracker = TapTracker::start(TapTrackerConfig {
        http,
        udp,
        interval: 30,
        ..Default::default()
    })?;
    let oracle = ctx.oracle("oracle", OracleConfig::primary())?;
    let fx_http = Fixture::generate(
        FixtureSpec::small("scrape-http.bin")
            .with_size(256 << 10)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    );
    let fx_udp = Fixture::generate(
        FixtureSpec::small("scrape-udp.bin")
            .with_size(256 << 10)
            .with_piece_length(64 << 10)
            .with_seed(3)
            .with_tracker(&tracker.udp_url(0)),
    );
    for fx in [&fx_http, &fx_udp] {
        fx.write_data(&oracle.save_path)?;
        oracle.api.add_torrent(
            &AddTorrent::file(&fx.torrent)
                .save_path(&oracle.save_path.to_string_lossy())
                .stopped(true),
            &fx.info_hash_hex(),
        )?;
    }
    std::thread::sleep(Duration::from_secs(40));
    let events = tracker.events();
    let scrapes: Vec<_> = events.iter().filter(|e| e.kind == "scrape").collect();
    ctx.note(format!(
        "{} events, {} scrapes: {:?}",
        events.len(),
        scrapes.len(),
        scrapes
            .iter()
            .map(|e| (
                e.transport.clone(),
                e.http.as_ref().map(|h| h.request_line.clone()),
                e.udp.as_ref().map(|u| u.scrape_hashes.clone())
            ))
            .collect::<Vec<_>>()
    ));
    let p = ctx.file("tap-tracker-scrape.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker-scrape.jsonl", &p);
    Ok(())
}

/// Oracle seeds, we leech, both on a UDP tracker; the tracker's view of our
/// datagrams must match the oracle's (discriminator, UDP side).
fn udp_tracker(ctx: &mut Ctx) -> Result<()> {
    let udp: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 6969))
        .collect();
    let tracker = TapTracker::start(TapTrackerConfig {
        udp,
        interval: 30,
        min_interval: Some(10),
        ..Default::default()
    })?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("udpleech.bin")
            .with_size(2 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.udp_url(0)),
    ));
    let h = fx.info_hash_hex();
    let seeder = ctx.oracle("seeder", OracleConfig::primary().lsd(false))?;
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
            .any(|e| e.transport == "udp" && e.kind == "announce")),
        "seeder never announced over udp"
    );
    let torrent_path = ctx.file("udpleech.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        crate::client::ClientConfig::default().profile("qbt"),
        &torrent_path,
    )?;
    let our_ips = client.actor.addrs();
    let st = client.wait_for(Duration::from_secs(120), "download via udp tracker", |s| {
        s.complete
    })?;
    ensure!(st.downloaded == fx.total_len);
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch: {e}"))?;
    // Scrape both ways while we are here (the oracle never scrapes on its
    // own, so this is checked against libtorrent's packet layout instead).
    client.command("scrape")?;
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| ev
            .iter()
            .any(|e| e.kind == "scrape" && our_ips.contains(&e.from.ip()))),
        "no udp scrape from us"
    );
    client.shutdown()?;
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| ev.iter().any(|e| {
            our_ips.contains(&e.from.ip())
                && e.udp
                    .as_ref()
                    .and_then(|u| u.announce.as_ref())
                    .is_some_and(|a| a.event == 3)
        })),
        "no stopped over udp"
    );
    let events = tracker.events();
    let oracle_fp = Fingerprint {
        udp: crate::discriminator::udp_fingerprint(&events, &seeder.actor.addrs()),
        ..Default::default()
    };
    let our_fp = Fingerprint {
        udp: crate::discriminator::udp_fingerprint(&events, &our_ips),
        ..Default::default()
    };
    ensure!(our_fp.udp.is_some(), "no udp observation of us");
    let d = crate::discriminator::diff(&oracle_fp, &our_fp);
    ctx.note(format!("udp tells: {d:?}"));
    ensure!(d.is_empty(), "udp tracker tells: {d:?}");
    let scrape = events
        .iter()
        .find(|e| e.kind == "scrape" && our_ips.contains(&e.from.ip()))
        .unwrap();
    ensure!(
        scrape
            .udp
            .as_ref()
            .is_some_and(|u| u.scrape_hashes == vec![h.clone()]),
        "scrape carried the wrong hashes: {:?}",
        scrape.udp
    );
    let p = ctx.file("tap-tracker-udp.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker-udp.jsonl", &p);
    Ok(())
}

/// HTTP scrape shape (BEP 48 / libtorrent): `announce` -> `scrape` in the URL,
/// `info_hash=` only, same headers as an announce.
fn http_scrape(ctx: &mut Ctx) -> Result<()> {
    let http: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7070))
        .collect();
    let tracker = TapTracker::start(TapTrackerConfig {
        http,
        interval: 30,
        ..Default::default()
    })?;
    let fx = Fixture::generate(
        FixtureSpec::small("scrape.bin")
            .with_size(256 << 10)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    );
    let h = fx.info_hash_hex();
    let torrent_path = ctx.file("scrape.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let actor = ctx.actor("urt")?;
    fx.write_data(&actor.log_dir.join("data"))?;
    let mut client = crate::client::UrtClient::launch(
        &actor,
        crate::client::ClientConfig::default().profile("qbt"),
        &torrent_path,
    )?;
    client.wait_for(Duration::from_secs(60), "seeding", |s| s.complete)?;
    client.command("scrape")?;
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| ev
            .iter()
            .any(|e| e.kind == "scrape")),
        "no http scrape"
    );
    let events = tracker.events();
    let scrape = events.iter().find(|e| e.kind == "scrape").unwrap();
    let hv = scrape.http.as_ref().unwrap();
    ctx.note(format!("scrape: {}", hv.request_line));
    ensure!(hv.path == "/scrape", "scrape path {}", hv.path);
    ensure!(
        hv.query.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>() == vec!["info_hash"],
        "scrape params {:?}",
        hv.query
    );
    let announce = events.iter().find(|e| e.kind == "announce").unwrap();
    let hdr = |e: &crate::tap::tracker::TapEvent| -> Vec<String> {
        e.http
            .as_ref()
            .unwrap()
            .headers
            .iter()
            .map(|(k, _)| k.clone())
            .collect()
    };
    ensure!(
        hdr(scrape) == hdr(announce),
        "scrape headers differ from announce"
    );
    let decoded = crate::http::percent_decode(hv.query[0].1.as_bytes());
    ensure!(crate::bencode::hex(&decoded) == h, "scrape hash mismatch");
    let st = client.wait_for(Duration::from_secs(10), "scrape result", |s| {
        s.events.iter().any(|e| e.contains("ScrapeReply"))
    })?;
    ctx.note(format!(
        "scrape events: {:?}",
        st.events
            .iter()
            .filter(|e| e.contains("Scrape"))
            .collect::<Vec<_>>()
    ));
    client.shutdown()?;
    Ok(())
}
