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
            name: "capture_peer_forced",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_peer_forced,
        },
        ScenarioDef {
            name: "capture_peer_allow_mse",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_peer_allow_mse,
        },
        ScenarioDef {
            name: "capture_tracker_dual",
            shapes: &[Shape::Dual],
            tags: &[Tag::Capture],
            run: capture_tracker_dual,
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
        ScenarioDef {
            name: "dual_stack_announce",
            shapes: &[Shape::Dual],
            tags: &[Tag::It, Tag::Diff],
            run: dual_stack_announce,
        },
        ScenarioDef {
            name: "tracker_failover",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: tracker_failover,
        },
        ScenarioDef {
            name: "pt_tracker",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: pt_tracker,
        },
        ScenarioDef {
            name: "oracle_utp_tcp_fallback",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: oracle_utp_tcp_fallback,
        },
        ScenarioDef {
            name: "encryption_matrix",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: encryption_matrix,
        },
        ScenarioDef {
            name: "mse_shape",
            shapes: &[Shape::V4],
            tags: &[Tag::It, Tag::Diff],
            run: mse_shape,
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

/// Oracle in "force encryption" mode: its outgoing MSE handshake to a tap
/// seeder (provide, pads, IA), and its responder side to a tap initiator
/// (select, pads).
fn capture_peer_forced(ctx: &mut Ctx) -> Result<()> {
    super::m0::run_peer_capture(
        ctx,
        OracleConfig::primary().encryption(crate::oracle::Encryption::Force),
        "forced",
        crate::tap::peer::TapEncryption::Allowed { prefer_rc4: true },
        true,
    )
}

/// Oracle in "allow encryption" mode answering a tap initiator that offers
/// both methods: reveals `prefer_rc4`.
fn capture_peer_allow_mse(ctx: &mut Ctx) -> Result<()> {
    super::m0::run_peer_capture(
        ctx,
        OracleConfig::primary().encryption(crate::oracle::Encryption::Prefer),
        "allow-mse",
        crate::tap::peer::TapEncryption::Allowed { prefer_rc4: false },
        true,
    )
}

/// Every encryption mode on each side against the oracle: forced-vs-disabled
/// never connects, everything else transfers. Also checks that a "forced"
/// pairing actually negotiated RC4.
fn encryption_matrix(ctx: &mut Ctx) -> Result<()> {
    use crate::oracle::Encryption;
    let tracker = tap_tracker_http(ctx)?;
    let mut results = Vec::new();
    for (oracle_mode, ours, expect) in [
        (Encryption::Disable, "disabled", true),
        (Encryption::Disable, "enabled", true),
        (Encryption::Disable, "forced", false),
        (Encryption::Prefer, "disabled", true),
        (Encryption::Prefer, "enabled", true),
        (Encryption::Prefer, "forced", true),
        (Encryption::Force, "disabled", false),
        (Encryption::Force, "enabled", true),
        (Encryption::Force, "forced", true),
    ] {
        let fx = Arc::new(Fixture::generate(
            FixtureSpec::small(&format!("enc-{oracle_mode:?}-{ours}.bin"))
                .with_size(512 << 10)
                .with_piece_length(64 << 10)
                .with_seed(0xE0 + oracle_mode as u64 * 4 + ours.len() as u64)
                .with_tracker(&tracker.http_url(0)),
        ));
        let h = fx.info_hash_hex();
        let name = format!(
            "seeder-{}-{ours}",
            format!("{oracle_mode:?}").to_lowercase()
        );
        let seeder = ctx.oracle(
            &name,
            OracleConfig::primary().encryption(oracle_mode).lsd(false),
        )?;
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
        // Our first announce must already see the seeder (we re-announce
        // only after the 5-minute clamp).
        let hh = h.clone();
        ensure!(
            tracker.wait_for(Duration::from_secs(30), |ev| ev.iter().any(|e| {
                e.kind == "announce"
                    && e.http.as_ref().is_some_and(|hv| {
                        hv.query.iter().any(|(k, v)| {
                            k == "info_hash"
                                && crate::bencode::hex(&crate::http::percent_decode(v.as_bytes()))
                                    == hh
                        })
                    })
            })),
            "seeder never announced"
        );
        let torrent_path = ctx.file(&format!("enc-{name}.torrent"));
        std::fs::write(&torrent_path, &fx.torrent)?;
        let mut client = ctx.client(
            &format!("urt-{}-{ours}", format!("{oracle_mode:?}").to_lowercase()),
            crate::client::ClientConfig::default()
                .profile("qbt")
                .encryption(ours),
            &torrent_path,
        )?;
        let deadline =
            std::time::Instant::now() + Duration::from_secs(if expect { 60 } else { 12 });
        let mut done = None;
        while std::time::Instant::now() < deadline {
            if let Some(st) = client.status()
                && st.complete
            {
                done = Some(st);
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let ok = done.is_some();
        results.push(format!(
            "oracle {oracle_mode:?} / us {ours}: {}",
            if ok { "transferred" } else { "no transfer" }
        ));
        ensure!(
            ok == expect,
            "oracle {oracle_mode:?} vs us {ours}: expected {expect}, got {ok}"
        );
        if let Some(st) = done {
            fx.verify_data(&client.save_path)?
                .map_err(|e| anyhow::anyhow!("data mismatch: {e}"))?;
            let rc4 = matches!(oracle_mode, Encryption::Force) || ours == "forced";
            let peer = st.peers_seen.iter().find(|p| {
                p.client
                    .as_deref()
                    .is_some_and(|c| c.starts_with("qBittorrent"))
            });
            ensure!(
                peer.is_some_and(|p| p.encrypted == rc4),
                "oracle {oracle_mode:?} / us {ours}: encrypted flag {:?}, expected {rc4}",
                peer.map(|p| p.encrypted)
            );
        }
        client.shutdown()?;
        drop(seeder);
    }
    for r in results {
        ctx.note(r);
    }
    Ok(())
}

/// Our MSE handshake shape vs the oracle's (golden `capture_peer_forced`):
/// as initiator (provide, len(IA)) and as responder (select for provide=3).
fn mse_shape(ctx: &mut Ctx) -> Result<()> {
    use crate::tap::peer::{Role, TapEncryption, TapPeer, TapPeerConfig};
    let tracker = tap_tracker_http(ctx)?;
    let seed_ip = ctx.host_alias(2)?;
    let leech_ip = ctx.host_alias(3)?;
    let seed_addr = SocketAddr::new(seed_ip, 6890);
    // A: we (forced) leech from a tap seeder that allows both.
    let fx_a = Arc::new(Fixture::generate(
        FixtureSpec::small("mse-a.bin")
            .with_size(512 << 10)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    tracker.inject_peer(fx_a.info_hash, seed_addr, 0);
    let tap_seed = TapPeer::start(
        TapPeerConfig::new(fx_a.info_hash, Role::Seeder)
            .listen(vec![seed_addr])
            .fixture(fx_a.clone())
            .encryption(TapEncryption::Allowed { prefer_rc4: true })
            .linger(Duration::from_secs(30)),
    )?;
    let torrent_a = ctx.file("mse-a.torrent");
    std::fs::write(&torrent_a, &fx_a.torrent)?;
    let mut client = ctx.client(
        "urt",
        crate::client::ClientConfig::default()
            .profile("qbt")
            .encryption("forced"),
        &torrent_a,
    )?;
    client.wait_for(
        Duration::from_secs(60),
        "forced download from tap seeder",
        |s| s.complete,
    )?;
    ensure!(
        tap_seed.wait_for(Duration::from_secs(10), |c| c
            .iter()
            .any(|c| c.mse.is_some())),
        "tap seeder recorded no mse handshake"
    );
    let ours_init = tap_seed
        .captures()
        .into_iter()
        .find(|c| c.mse.is_some())
        .unwrap();
    ctx.note(format!(
        "our initiator as seen by the tap: {:?}",
        ours_init.mse
    ));
    // The oracle's initiator view from the golden capture.
    let golden = crate::scenario::golden_file(
        "capture_peer_forced",
        crate::lab::Shape::V4,
        "tap-peer-forced-oracle-initiator.jsonl",
    );
    if let Some(p) = golden {
        let caps: Vec<crate::tap::peer::PeerCapture> = std::fs::read_to_string(p)?
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        let oracle = caps.iter().find(|c| c.mse.is_some()).unwrap();
        let d = crate::discriminator::diff(
            &Fingerprint {
                mse: crate::discriminator::mse_fingerprint(oracle),
                ..Default::default()
            },
            &Fingerprint {
                mse: crate::discriminator::mse_fingerprint(&ours_init),
                ..Default::default()
            },
        );
        ctx.note(format!("mse initiator tells: {d:?}"));
        ensure!(d.is_empty(), "mse initiator tells: {d:?}");
    } else {
        ctx.note("no golden capture_peer_forced; initiator comparison skipped");
    }
    client.shutdown()?;
    // B: a tap initiator offering both connects to us (enabled) seeding:
    // our select must be RC4 (prefer_rc4), as the oracle's was.
    let fx_b = Arc::new(Fixture::generate(
        FixtureSpec::small("mse-b.bin")
            .with_size(256 << 10)
            .with_piece_length(64 << 10)
            .with_seed(11)
            .with_tracker(&tracker.http_url(0)),
    ));
    let torrent_b = ctx.file("mse-b.torrent");
    std::fs::write(&torrent_b, &fx_b.torrent)?;
    let actor = ctx.actor("urt-seed")?;
    fx_b.write_data(&actor.log_dir.join("data"))?;
    let mut seeder = crate::client::UrtClient::launch(
        &actor,
        crate::client::ClientConfig::default()
            .profile("qbt")
            .encryption("enabled"),
        &torrent_b,
    )?;
    seeder.wait_for(Duration::from_secs(60), "seeding", |s| s.complete)?;
    let tap_leech = TapPeer::start(
        TapPeerConfig::new(fx_b.info_hash, Role::Leecher)
            .fixture(fx_b.clone())
            .encryption(TapEncryption::Allowed { prefer_rc4: false })
            .initiate_mse(true)
            .linger(Duration::from_secs(3))
            .bind_addr(leech_ip),
    )?;
    let cap = tap_leech.connect(SocketAddr::new(actor.addr(), 6881))?;
    ctx.note(format!(
        "our responder as seen by the tap: {:?} pieces_ok={}",
        cap.mse, cap.pieces_ok
    ));
    let m = cap
        .mse
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no mse handshake with our seeder: {}", cap.close_reason))?;
    ensure!(
        m.crypto_field == Some(2),
        "we selected {:?}, the oracle selects RC4 for provide=3",
        m.crypto_field
    );
    ensure!(
        cap.pieces_ok as usize == fx_b.piece_count(),
        "leeched {} pieces over rc4",
        cap.pieces_ok
    );
    seeder.shutdown()?;
    Ok(())
}

fn query<'a>(e: &'a crate::tap::tracker::TapEvent, key: &str) -> Option<&'a str> {
    e.http
        .as_ref()?
        .query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn tap_tracker_http(ctx: &Ctx) -> Result<TapTracker> {
    let http: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7070))
        .collect();
    TapTracker::start(TapTrackerConfig {
        http,
        interval: 30,
        ..Default::default()
    })
}

/// Dual-stack announce semantics: a tracker *hostname* resolving to both
/// families. Does the oracle announce once per listen socket (v4 and v6)?
fn capture_tracker_dual(ctx: &mut Ctx) -> Result<()> {
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
    let url = format!("http://{}:7070/announce", ctx.lab.tracker_host());
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("dual.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&url),
    ));
    let h = fx.info_hash_hex();
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
            .any(|e| e.kind == "announce")),
        "seeder never announced to {url}"
    );
    std::thread::sleep(Duration::from_secs(3));
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    leecher
        .api
        .wait_for(&h, Duration::from_secs(120), "leecher complete", |t| {
            t.is_complete()
        })?;
    std::thread::sleep(Duration::from_secs(3));
    leecher.shutdown()?;
    std::thread::sleep(Duration::from_secs(3));
    let events = tracker.events();
    for e in &events {
        if let Some(hv) = &e.http {
            ctx.note(format!(
                "{} {} -> {} : {}",
                e.ts_ms, e.from, e.to, hv.request_line
            ));
        }
    }
    let p = ctx.file("tap-tracker-dual.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker-dual.jsonl", &p);
    Ok(())
}

/// Dual-stack: a hostname tracker; we must announce once per listen socket
/// (v4 and v6), each with its own started / completed / stopped, exactly as
/// the oracle does (golden `capture_tracker_dual`).
fn dual_stack_announce(ctx: &mut Ctx) -> Result<()> {
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
    let url = format!("http://{}:7070/announce", ctx.lab.tracker_host());
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("dual.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&url),
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
            .filter(|e| e.kind == "announce")
            .count()
            >= 2),
        "seeder did not announce over both families"
    );
    let torrent_path = ctx.file("dual.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        crate::client::ClientConfig::default().profile("qbt"),
        &torrent_path,
    )?;
    let our_ips = client.actor.addrs();
    client.wait_for(Duration::from_secs(120), "download", |s| s.complete)?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch: {e}"))?;
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| ev
            .iter()
            .filter(|e| our_ips.contains(&e.from.ip()) && query(e, "event") == Some("completed"))
            .count()
            >= 2),
        "completed not announced on both families"
    );
    client.shutdown()?;
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| ev
            .iter()
            .filter(|e| our_ips.contains(&e.from.ip()) && query(e, "event") == Some("stopped"))
            .count()
            >= 2),
        "stopped not announced on both families"
    );
    let events = tracker.events();
    for family_v6 in [false, true] {
        let ours: Vec<Option<&str>> = events
            .iter()
            .filter(|e| our_ips.contains(&e.from.ip()) && e.from.ip().is_ipv6() == family_v6)
            .map(|e| query(e, "event"))
            .collect();
        ctx.note(format!(
            "our v{} announces: {ours:?}",
            if family_v6 { 6 } else { 4 }
        ));
        ensure!(
            ours == vec![Some("started"), Some("completed"), Some("stopped")],
            "v{} sequence: {ours:?}",
            if family_v6 { 6 } else { 4 }
        );
        // Same identity on both families, indistinguishable from the oracle's.
        let oracle_ips: Vec<std::net::IpAddr> = seeder
            .actor
            .addrs()
            .into_iter()
            .filter(|a| a.is_ipv6() == family_v6)
            .collect();
        let ours_ips: Vec<std::net::IpAddr> = our_ips
            .iter()
            .copied()
            .filter(|a| a.is_ipv6() == family_v6)
            .collect();
        let d = crate::discriminator::diff(
            &Fingerprint {
                tracker: crate::discriminator::tracker_fingerprint(&events, &oracle_ips),
                ..Default::default()
            },
            &Fingerprint {
                tracker: crate::discriminator::tracker_fingerprint(&events, &ours_ips),
                ..Default::default()
            },
        );
        ensure!(
            d.is_empty(),
            "tells on v{}: {d:?}",
            if family_v6 { 6 } else { 4 }
        );
    }
    // The same peer id and key on both families (one torrent).
    let ids: std::collections::HashSet<&str> = events
        .iter()
        .filter(|e| our_ips.contains(&e.from.ip()))
        .filter_map(|e| query(e, "peer_id"))
        .collect();
    ensure!(ids.len() == 1, "peer id differs across families: {ids:?}");
    let p = ctx.file("tap-tracker-dual.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker-dual.jsonl", &p);
    Ok(())
}

/// Tier failover and backoff: tier 0 is down, tier 1 works. We must announce
/// to tier 1, keep retrying tier 0 with growing gaps, and finish.
fn tracker_failover(ctx: &mut Ctx) -> Result<()> {
    let down = TapTracker::start(TapTrackerConfig {
        http: ctx
            .host_addrs()
            .into_iter()
            .map(|a| SocketAddr::new(a, 7071))
            .collect(),
        behaviour: crate::tap::tracker::Behaviour::HttpStatus(503),
        interval: 30,
        ..Default::default()
    })?;
    let up = TapTracker::start(TapTrackerConfig {
        http: ctx
            .host_addrs()
            .into_iter()
            .map(|a| SocketAddr::new(a, 7072))
            .collect(),
        interval: 30,
        ..Default::default()
    })?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("failover.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .with_trackers(vec![vec![down.http_url(0)], vec![up.http_url(0)]]),
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
        up.wait_for(Duration::from_secs(30), |ev| ev
            .iter()
            .any(|e| e.kind == "announce")),
        "seeder never reached the working tier"
    );
    let torrent_path = ctx.file("failover.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        crate::client::ClientConfig::default().profile("qbt"),
        &torrent_path,
    )?;
    let our_ips = client.actor.addrs();
    let st = client.wait_for(Duration::from_secs(120), "download via tier 1", |s| {
        s.complete
    })?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch: {e}"))?;
    let tr: Vec<String> = st
        .trackers
        .iter()
        .map(|t| {
            format!(
                "{} working={} fails={} err={:?}",
                t.url, t.working, t.fails, t.last_error
            )
        })
        .collect();
    ctx.note(format!("tracker status: {tr:?}"));
    ensure!(st.trackers.len() == 2);
    ensure!(
        !st.trackers[0].working && st.trackers[0].fails >= 1,
        "tier 0 not failed: {tr:?}"
    );
    ensure!(st.trackers[1].working, "tier 1 not working: {tr:?}");
    // Watch the retries against the down tracker: 5+12=17 s then 5+50=55 s.
    std::thread::sleep(Duration::from_secs(75));
    let attempts: Vec<u64> = down
        .events()
        .iter()
        .filter(|e| our_ips.contains(&e.from.ip()))
        .map(|e| e.ts_ms)
        .collect();
    ctx.note(format!("attempts at tier 0 (ms): {attempts:?}"));
    ensure!(
        attempts.len() >= 3,
        "expected retries with backoff, saw {attempts:?}"
    );
    let gap1 = attempts[1] - attempts[0];
    let gap2 = attempts[2] - attempts[1];
    ensure!(
        (14_000..=22_000).contains(&gap1) && (50_000..=62_000).contains(&gap2),
        "backoff gaps {gap1} ms / {gap2} ms (expected ~17 s / ~55 s)"
    );
    // Recovery: tier 0 comes back and gets our next retry as `started`.
    down.set_behaviour(crate::tap::tracker::Behaviour::Normal);
    client.shutdown()?;
    let up_events = up.events();
    let seq: Vec<Option<&str>> = up_events
        .iter()
        .filter(|e| our_ips.contains(&e.from.ip()))
        .map(|e| query(e, "event"))
        .collect();
    ctx.note(format!("tier 1 sequence: {seq:?}"));
    ensure!(
        seq.first() == Some(&Some("started")) && seq.last() == Some(&Some("stopped")),
        "tier 1 sequence: {seq:?}"
    );
    // The down tracker never got `started` (every attempt failed), so no
    // `stopped` goes there either.
    ensure!(
        !down
            .events()
            .iter()
            .any(|e| our_ips.contains(&e.from.ip()) && query(e, "event") == Some("stopped")),
        "stopped sent to a tracker that never accepted started"
    );
    Ok(())
}

/// A private-tracker-style tracker: passkey in the URL, a client whitelist
/// with the oracle's identity, a private torrent. The qbt profile is
/// accepted and downloads; the native profile is refused (the whitelist has
/// teeth).
fn pt_tracker(ctx: &mut Ctx) -> Result<()> {
    let http: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7070))
        .collect();
    let tracker = TapTracker::start(TapTrackerConfig {
        http,
        interval: 30,
        passkey: Some("s3cretpasskey0123456789abcdef".into()),
        peer_id_whitelist: Some(vec!["-qB5230-".into()]),
        ..Default::default()
    })?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("pt.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .private(true)
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
    ensure!(
        tracker.wait_for(Duration::from_secs(30), |ev| ev
            .iter()
            .any(|e| e.kind == "announce")),
        "seeder never announced"
    );
    let torrent_path = ctx.file("pt.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    // native first: refused.
    let mut native = ctx.client(
        "urt-native",
        crate::client::ClientConfig::default().profile("native"),
        &torrent_path,
    )?;
    let st = native.wait_for(Duration::from_secs(30), "native tracker error", |s| {
        s.trackers.iter().any(|t| t.last_error.is_some())
    })?;
    ctx.note(format!(
        "native profile: {:?}",
        st.trackers
            .iter()
            .map(|t| t.last_error.clone())
            .collect::<Vec<_>>()
    ));
    ensure!(
        !st.complete && st.peers == 0,
        "native profile got through a PT whitelist"
    );
    native.shutdown()?;
    // qbt: accepted, downloads.
    let mut client = ctx.client(
        "urt",
        crate::client::ClientConfig::default().profile("qbt"),
        &torrent_path,
    )?;
    let st = client.wait_for(Duration::from_secs(120), "download via PT tracker", |s| {
        s.complete
    })?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch: {e}"))?;
    ensure!(
        st.trackers.iter().all(|t| t.working),
        "tracker not working: {:?}",
        st.trackers
    );
    client.shutdown()?;
    let p = ctx.file("tap-tracker-pt.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker-pt.jsonl", &p);
    Ok(())
}

/// The oracle with uTP enabled (its default) leeches from us with uTP off:
/// libtorrent dials every new peer over uTP first, its SYN goes unanswered
/// (3 s), and it must fall back to TCP and complete.
fn oracle_utp_tcp_fallback(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker_http(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("utp.bin")
            .with_size(2 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    let h = fx.info_hash_hex();
    let torrent_path = ctx.file("utp.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let actor = ctx.actor("urt")?;
    fx.write_data(&actor.log_dir.join("data"))?;
    let mut client = crate::client::UrtClient::launch(
        &actor,
        crate::client::ClientConfig::default()
            .profile("qbt")
            .protocol("tcp"),
        &torrent_path,
    )?;
    client.wait_for(Duration::from_secs(60), "seeding", |s| s.complete)?;
    let leecher = ctx.oracle(
        "leecher",
        OracleConfig::primary()
            .protocol(crate::oracle::BtProtocol::Both)
            .lsd(false),
    )?;
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    leecher.api.wait_for(
        &h,
        Duration::from_secs(120),
        "oracle (uTP enabled) to complete",
        |t| t.is_complete(),
    )?;
    fx.verify_data(&leecher.save_path)?
        .map_err(|e| anyhow::anyhow!("oracle data mismatch: {e}"))?;
    let peers = leecher.api.peers(&h)?;
    ctx.note(format!(
        "oracle's view of us: {:?}",
        peers
            .iter()
            .map(|p| format!("{}:{} {} conn={}", p.ip, p.port, p.client, p.connection))
            .collect::<Vec<_>>()
    ));
    let st = client
        .status()
        .ok_or_else(|| anyhow::anyhow!("no client status"))?;
    ensure!(
        st.peers_seen
            .iter()
            .chain(st.peer_list.iter())
            .all(|p| p.transport != "Utp"),
        "a uTP connection with uTP disabled: {:?}",
        st.peers_seen
    );
    ensure!(
        st.utp_connections == 0,
        "utp connections: {}",
        st.utp_connections
    );
    client.shutdown()?;
    Ok(())
}
