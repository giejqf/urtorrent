// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! M4 scenarios: identity. HTTPS trackers (rustls on our side, the test CA on
//! both), the announce `key` format captured over many torrents, and the
//! identity differential: oracle, us (qbt), us (native) and Transmission all
//! observed by the same tap-tracker and tap-peer, then classified.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};

use super::{Ctx, ScenarioDef, Tag};
use crate::client::ClientConfig;
use crate::discriminator::{self, Fingerprint};
use crate::fixtures::{Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::OracleConfig;
use crate::tap::peer::{Role, TapPeer, TapPeerConfig};
use crate::tap::tracker::{TapEvent, TapTracker, TapTrackerConfig};
use crate::transmission::{Transmission, TransmissionConfig};
use crate::webapi::AddTorrent;

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "https_tracker",
            shapes: &[Shape::V4, Shape::V6, Shape::Dual],
            tags: &[Tag::It, Tag::Capture],
            run: https_tracker,
        },
        ScenarioDef {
            name: "capture_keys",
            shapes: &[Shape::V4],
            tags: &[Tag::It, Tag::Capture],
            run: capture_keys,
        },
        ScenarioDef {
            name: "diff_identity",
            shapes: &[Shape::V4],
            tags: &[Tag::It, Tag::Diff],
            run: diff_identity,
        },
    ]
}

fn query<'a>(e: &'a TapEvent, key: &str) -> Option<&'a str> {
    e.http
        .as_ref()?
        .query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Oracle seeds, we leech, both announcing over HTTPS to the tap-tracker's
/// test CA. Post-TLS request bytes are what the tracker records and compares.
fn https_tracker(ctx: &mut Ctx) -> Result<()> {
    let https: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7443))
        .collect();
    let tracker = TapTracker::start(TapTrackerConfig {
        https,
        interval: 30,
        min_interval: Some(10),
        ..Default::default()
    })?;
    let ca_path = ctx.file("test-ca.pem");
    std::fs::write(
        &ca_path,
        tracker
            .ca_pem
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("tap-tracker has no CA"))?,
    )?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("https.bin")
            .with_size(2 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.https_url(0)),
    ));
    let h = fx.info_hash_hex();
    let seeder = ctx.oracle(
        "seeder",
        OracleConfig::primary().env("SSL_CERT_FILE", &ca_path.to_string_lossy()),
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
    ensure!(
        tracker.wait_for(Duration::from_secs(30), |ev| ev
            .iter()
            .any(|e| e.kind == "announce" && e.transport == "https")),
        "oracle never announced over https: {:?}",
        tracker
            .events()
            .iter()
            .map(|e| (&e.kind, &e.transport))
            .collect::<Vec<_>>()
    );
    let torrent_path = ctx.file("https.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default()
            .profile("qbt")
            .env("SSL_CERT_FILE", &ca_path.to_string_lossy()),
        &torrent_path,
    )?;
    let our_ips = client.actor.addrs();
    let st = client.wait_for(
        Duration::from_secs(120),
        "download over an https tracker",
        |s| s.complete,
    )?;
    // In the dual shape the oracle is dialled over both families (Q25) and
    // the end game may fetch a block twice.
    ensure!(
        st.downloaded >= fx.total_len
            && st.downloaded - fx.total_len <= st.redundant
            && st.corrupt == 0,
        "downloaded {} redundant {} corrupt {} for {} bytes",
        st.downloaded,
        st.redundant,
        st.corrupt,
        fx.total_len
    );
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("data mismatch: {e}"))?;
    client.shutdown()?;
    let events = tracker.events();
    let ours: Vec<&TapEvent> = events
        .iter()
        .filter(|e| e.kind == "announce" && our_ips.contains(&e.from.ip()))
        .collect();
    ensure!(!ours.is_empty(), "no announce from us");
    ensure!(
        ours.iter().all(|e| e.transport == "https"),
        "our announces were not https"
    );
    ensure!(
        ours.iter().any(|e| query(e, "event") == Some("completed"))
            && ours.iter().any(|e| query(e, "event") == Some("stopped")),
        "missing completed/stopped over https"
    );
    // Identity over HTTPS is the same as over HTTP (TLS itself is excluded).
    let oracle_ips = seeder.actor.addrs();
    let oracle_fp = Fingerprint {
        tracker: discriminator::tracker_fingerprint(&events, &oracle_ips),
        ..Default::default()
    };
    let our_fp = Fingerprint {
        tracker: discriminator::tracker_fingerprint(&events, &our_ips),
        ..Default::default()
    };
    let d = discriminator::diff(&oracle_fp, &our_fp);
    ensure!(d.is_empty(), "https announce tells: {d:?}");
    let p = ctx.file("tap-tracker-https.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker-https.jsonl", &p);
    ctx.note(format!(
        "{} https announces, ours {}",
        events.len(),
        ours.len()
    ));
    Ok(())
}

/// Many torrents in one oracle: is `key` per torrent or per session, and is
/// it zero-padded to 8 hex digits?
fn capture_keys(ctx: &mut Ctx) -> Result<()> {
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
    let oracle = ctx.oracle("oracle", OracleConfig::primary())?;
    let n = 40;
    let mut hashes = Vec::new();
    for i in 0..n {
        let fx = Fixture::generate(
            FixtureSpec::small(&format!("keys-{i}.bin"))
                .with_size(64 << 10)
                .with_piece_length(16 << 10)
                .with_seed(1000 + i as u64)
                .with_tracker(&tracker.http_url(0)),
        );
        fx.write_data(&oracle.save_path)?;
        let h = fx.info_hash_hex();
        oracle.api.add_torrent(
            &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
            &h,
        )?;
        hashes.push(h);
    }
    ensure!(
        tracker.wait_for(Duration::from_secs(90), |ev| {
            let mut seen = std::collections::HashSet::new();
            for e in ev.iter().filter(|e| e.kind == "announce") {
                if let Some(ih) = query(e, "info_hash") {
                    seen.insert(ih.to_string());
                }
            }
            seen.len() >= n
        }),
        "not every torrent announced"
    );
    let events = tracker.events();
    let mut keys: Vec<(String, String)> = events
        .iter()
        .filter(|e| e.kind == "announce")
        .filter_map(|e| {
            Some((
                query(e, "info_hash")?.to_string(),
                query(e, "key")?.to_string(),
            ))
        })
        .collect();
    keys.sort();
    keys.dedup();
    let distinct: std::collections::HashSet<&String> = keys.iter().map(|(_, k)| k).collect();
    let lengths: std::collections::HashSet<usize> = keys.iter().map(|(_, k)| k.len()).collect();
    let leading_zero = keys.iter().filter(|(_, k)| k.starts_with('0')).count();
    let upper = keys.iter().all(|(_, k)| {
        k.chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
    });
    ctx.note(format!(
        "{} torrents, {} distinct keys, key lengths {:?}, {} with a leading zero, all upper-hex: {}",
        n,
        distinct.len(),
        lengths,
        leading_zero,
        upper
    ));
    ensure!(distinct.len() > 1, "keys are per session, not per torrent");
    ensure!(
        lengths == std::collections::HashSet::from([8]),
        "keys are not all 8 chars: {lengths:?}"
    );
    ensure!(upper, "keys are not upper-case hex");
    if leading_zero == 0 {
        ctx.note("no key started with 0 in this run; zero padding still unproven (p ≈ 8%)");
    }
    let p = ctx.file("tap-tracker-keys.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker-keys.jsonl", &p);
    Ok(())
}

/// The differential: four leechers download the same torrent from a tap-peer
/// seeder through the tap-tracker, one after another. The discriminator must
/// not separate the oracle from us under the qbt profile, and must separate
/// it from Transmission and from our native profile.
fn diff_identity(ctx: &mut Ctx) -> Result<()> {
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
    let seed_addr = SocketAddr::new(ctx.host_alias(2)?, 6890);
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("diff.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    tracker.inject_peer(fx.info_hash, seed_addr, 0);
    let tap = TapPeer::start(
        TapPeerConfig::new(fx.info_hash, Role::Seeder)
            .listen(vec![seed_addr])
            .fixture(fx.clone())
            .linger(Duration::from_secs(600)),
    )?;
    let h = fx.info_hash_hex();
    let torrent_path = ctx.file("diff.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;

    let fingerprint = |events: &[TapEvent], ips: &[IpAddr]| -> Fingerprint {
        let peer = tap
            .captures()
            .into_iter()
            .filter(|c| ips.contains(&c.remote.ip()) && c.handshake.is_some())
            .find_map(|c| discriminator::peer_fingerprint(&c));
        let tracker = discriminator::tracker_fingerprint(events, ips);
        let handshake_id_is_announce_id = match (&tracker, &peer) {
            (Some(t), Some(p)) => Some(discriminator::handshake_id_is_announce_id(t, p)),
            _ => None,
        };
        Fingerprint {
            tracker,
            peer,
            handshake_id_is_announce_id,
            ..Default::default()
        }
    };

    // 1. The oracle at its default encryption setting ("allow"), like the
    // goldens: it still connects out in plaintext to an unknown peer (Q3), so
    // the tap-peer sees the handshake. (With encryption *disabled* the oracle
    // drops `supportcrypto=1` from its announces — Q8.)
    let mut oracle = ctx.oracle("oracle", OracleConfig::primary())?;
    oracle.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    oracle
        .api
        .wait_for(&h, Duration::from_secs(120), "oracle to leech", |t| {
            t.is_complete()
        })?;
    oracle.shutdown()?;
    let oracle_ips = oracle.actor.addrs();
    ensure!(
        tracker.wait_for(Duration::from_secs(20), |ev| ev.iter().any(|e| oracle_ips
            .contains(&e.from.ip())
            && query(e, "event") == Some("stopped"))),
        "oracle sent no stopped"
    );
    let oracle_fp = fingerprint(&tracker.events(), &oracle_ips);

    // 2. Us, qbt profile.
    let mut us_qbt = ctx.client(
        "urt-qbt",
        ClientConfig::default().profile("qbt"),
        &torrent_path,
    )?;
    us_qbt.wait_for(Duration::from_secs(120), "qbt-profile download", |s| {
        s.complete
    })?;
    us_qbt.shutdown()?;
    let qbt_ips = us_qbt.actor.addrs();
    let us_qbt_fp = fingerprint(&tracker.events(), &qbt_ips);

    // 3. Us, native profile.
    let mut us_native = ctx.client(
        "urt-native",
        ClientConfig::default().profile("native"),
        &torrent_path,
    )?;
    us_native.wait_for(Duration::from_secs(120), "native-profile download", |s| {
        s.complete
    })?;
    us_native.shutdown()?;
    let native_ips = us_native.actor.addrs();
    let us_native_fp = fingerprint(&tracker.events(), &native_ips);

    // 4. Transmission.
    let actor = ctx.actor("transmission")?;
    let mut tr = Transmission::launch(&actor, TransmissionConfig::default())?;
    let id = tr.add_torrent(&fx.torrent)?;
    tr.wait_for(id, Duration::from_secs(120), "transmission download", |t| {
        t["percentDone"].as_f64().unwrap_or(0.0) >= 1.0
    })?;
    tr.shutdown()?;
    let tr_ips = actor.addrs();
    let tr_fp = fingerprint(&tracker.events(), &tr_ips);

    // The verdicts.
    let golden = discriminator::golden_oracle()?;
    let stable = discriminator::diff(&golden, &oracle_fp);
    ctx.note(format!("live oracle vs golden oracle: {stable:?}"));
    let d_qbt = discriminator::diff(&oracle_fp, &us_qbt_fp);
    let d_native = discriminator::diff(&oracle_fp, &us_native_fp);
    let d_tr = discriminator::diff(&oracle_fp, &tr_fp);
    ctx.note(format!("oracle vs us(qbt): {d_qbt:?}"));
    ctx.note(format!("oracle vs us(native): {d_native:?}"));
    ctx.note(format!("oracle vs transmission: {d_tr:?}"));
    ctx.note(format!(
        "classify: us(qbt)={:?} us(native)={:?} transmission={:?}",
        discriminator::classify(&us_qbt_fp),
        discriminator::classify(&us_native_fp),
        discriminator::classify(&tr_fp)
    ));
    let p = ctx.file("tap-tracker-diff.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker-diff.jsonl", &p);
    let p = ctx.file("tap-peer-diff.jsonl");
    tap.save_jsonl(&p)?;
    ctx.artifact("tap-peer-diff.jsonl", &p);
    ensure!(
        stable.is_empty(),
        "the live oracle differs from its golden: {stable:?}"
    );
    ensure!(
        us_qbt_fp.tracker.is_some() && us_qbt_fp.peer.is_some(),
        "incomplete observation of us: {us_qbt_fp:?}"
    );
    ensure!(
        d_qbt.is_empty(),
        "L1/L2 tells under the qbt profile: {d_qbt:?}"
    );
    ensure!(
        !d_native.is_empty(),
        "the discriminator has no teeth: native profile passes"
    );
    ensure!(
        !d_tr.is_empty(),
        "the discriminator has no teeth: Transmission passes"
    );
    Ok(())
}
