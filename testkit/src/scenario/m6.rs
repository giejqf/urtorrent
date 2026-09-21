// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! M6 scenarios: extensions. PEX, `ut_metadata` / magnets, `upload_only`,
//! LSD, web seeds, and the private-torrent guarantee (rule 2) checked on the
//! wire.

use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};

use super::{Ctx, ScenarioDef, Tag};
use crate::capture::Pcap;
use crate::client::{ClientConfig, UrtClient};
use crate::discriminator::{self, Fingerprint};
use crate::fixtures::{Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::{Encryption, OracleConfig};
use crate::tap::peer::{PeerCapture, Role, TapEncryption, TapPeer, TapPeerConfig};
use crate::tap::tracker::{TapTracker, TapTrackerConfig};
use crate::tap::webseed::TapWebSeed;
use crate::webapi::AddTorrent;

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "capture_pex",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_pex,
        },
        ScenarioDef {
            name: "capture_peer_private",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_peer_private,
        },
        ScenarioDef {
            name: "capture_magnet_private",
            shapes: &[Shape::V4],
            tags: &[Tag::It, Tag::Capture],
            run: capture_magnet_private,
        },
        ScenarioDef {
            name: "magnet_private_shape",
            shapes: &[Shape::V4],
            tags: &[Tag::It, Tag::Diff],
            run: magnet_private_shape,
        },
        ScenarioDef {
            name: "capture_magnet",
            shapes: &[Shape::V4],
            tags: &[Tag::Capture],
            run: capture_magnet,
        },
        ScenarioDef {
            name: "pex_discovery",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It, Tag::Diff],
            run: pex_discovery,
        },
        ScenarioDef {
            name: "magnet_via_ut_metadata",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It],
            run: magnet_via_ut_metadata,
        },
        ScenarioDef {
            name: "lsd_discovery",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It],
            run: lsd_discovery,
        },
        ScenarioDef {
            name: "web_seed_only",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It, Tag::Diff],
            run: web_seed_only,
        },
        ScenarioDef {
            name: "private_no_pex_lsd",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It],
            run: private_no_pex_lsd,
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

/// Connect a tap to `target`, retrying: libtorrent refuses incoming peers for
/// a short moment after a torrent starts.
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

/// A silent tap leecher listening on `ip:port` that advertises its listen
/// port (`p`), so libtorrent will exchange it.
fn silent_with_port(fx: &Arc<Fixture>, ip: IpAddr, port: u16) -> Result<TapPeer> {
    let mut ext = TapPeerConfig::new(fx.info_hash, Role::Silent)
        .ext_handshake
        .unwrap();
    ext.insert("p", crate::bencode::Value::Int(i64::from(port)));
    TapPeer::start(
        TapPeerConfig::new(fx.info_hash, Role::Silent)
            .fixture(fx.clone())
            .encryption(TapEncryption::Disabled)
            .listen(vec![SocketAddr::new(ip, port)])
            .ext_handshake(Some(ext))
            .bind_addr(ip)
            .linger(Duration::from_secs(600)),
    )
}

/// The oracle seeds; two silent tap leechers connect a few seconds apart and
/// stay. The oracle's `ut_pex` messages to each (timing, contents, flags) are
/// the spec for our PEX.
fn capture_pex(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("pex.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    let h = fx.info_hash_hex();
    let oracle = ctx.oracle(
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
    std::thread::sleep(Duration::from_secs(1));
    let a_ip = ctx.host_alias(2)?;
    let b_ip = ctx.host_alias(3)?;
    let tap_a = silent_with_port(&fx, a_ip, 6891)?;
    let tap_b = silent_with_port(&fx, b_ip, 6892)?;
    let target = SocketAddr::new(oracle.actor.addr(), oracle.listen_port());
    tap_a.connect_async(target);
    std::thread::sleep(Duration::from_secs(4));
    tap_b.connect_async(target);
    // Long enough for the first PEX to each and one 60 s delta.
    std::thread::sleep(Duration::from_secs(70));
    tap_b.stop();
    std::thread::sleep(Duration::from_secs(5));
    tap_a.stop();
    for (name, tap) in [("A", &tap_a), ("B", &tap_b)] {
        for c in tap.captures() {
            let ext: Vec<String> = c
                .events
                .iter()
                .filter(|e| e.kind == "extended")
                .map(|e| {
                    format!(
                        "{} ext_id={} {}",
                        e.ts_ms, e.detail["ext_id"], e.detail["decoded"]
                    )
                })
                .collect();
            ctx.note(format!(
                "tap {name} conn {} ({}): hs={:?} close={} extended messages:\n  {}",
                c.id,
                c.remote,
                c.handshake.as_ref().map(|h| &h.reserved_bits),
                c.close_reason,
                ext.join("\n  ")
            ));
        }
        let p = ctx.file(&format!("tap-peer-pex-{name}.jsonl"));
        tap.save_jsonl(&p)?;
        ctx.artifact(&format!("tap-peer-pex-{name}.jsonl"), &p);
    }
    Ok(())
}

/// Private torrents (BEP 27): the oracle's LTEP `m` map and first messages.
fn capture_peer_private(ctx: &mut Ctx) -> Result<()> {
    super::m0::run_peer_capture_with(
        ctx,
        OracleConfig::primary().encryption(Encryption::Disable),
        "private",
        TapEncryption::Disabled,
        false,
        true,
    )
}

/// The oracle adds a magnet link and fetches the metadata from a tap seeder
/// that serves `ut_metadata`: what libtorrent sends before and after it
/// knows the metadata is the spec for our magnet mode.
/// A *private* torrent added by magnet link: libtorrent registers `ut_pex`
/// and `ut_metadata` before it can know the torrent is private, so what does
/// its LTEP `m` look like once the metadata is in? Captured from a tap peer
/// that connects afterwards (docs/quirks.md Q11).
fn capture_magnet_private(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("pmagnet.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .private(true)
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
        "magnet:?xt=urn:btih:{h}&dn=pmagnet.bin&tr={}",
        crate::http::percent_encode(tracker.http_url(0).as_bytes())
    );
    oracle.api.add_torrent(
        &AddTorrent::magnet(&magnet).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    oracle.api.wait_for(
        &h,
        Duration::from_secs(120),
        "oracle to fetch the private metadata and download",
        |t| t.is_complete(),
    )?;
    // A fresh tap peer connects now that the oracle knows the torrent is
    // private: its `m` is the observation.
    let probe = TapPeer::start(
        TapPeerConfig::new(fx.info_hash, Role::Silent)
            .fixture(fx.clone())
            .encryption(TapEncryption::Disabled)
            .bind_addr(ctx.host_alias(3)?)
            .linger(Duration::from_secs(5)),
    )?;
    ensure!(
        connect_retry(&probe, SocketAddr::new(oracle.actor.addr(), 6881), 10),
        "probe could not connect to the oracle"
    );
    ensure!(
        probe.wait_for(Duration::from_secs(10), |c| c
            .iter()
            .any(|c| c.ext_handshake().is_some())),
        "no LTEP handshake from the oracle"
    );
    for c in probe.captures() {
        ctx.note(format!(
            "oracle LTEP handshake after metadata (private, via magnet): {:?}",
            c.ext_handshake()
        ));
    }
    for c in tap_seed.captures() {
        ctx.note(format!(
            "oracle LTEP handshake before metadata: {:?}",
            c.ext_handshake()
        ));
    }
    let p = ctx.file("tap-peer-pmagnet-probe.jsonl");
    probe.save_jsonl(&p)?;
    ctx.artifact("tap-peer-pmagnet-probe.jsonl", &p);
    let p = ctx.file("tap-peer-pmagnet-seed.jsonl");
    tap_seed.save_jsonl(&p)?;
    ctx.artifact("tap-peer-pmagnet-seed.jsonl", &p);
    Ok(())
}

/// Differential for the private-magnet case (Q11): our LTEP `m` before
/// and after the metadata must match the oracle's captured in
/// `capture_magnet_private`.
fn magnet_private_shape(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("pmagnet.bin")
            .with_size(1 << 20)
            .with_piece_length(64 << 10)
            .private(true)
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
        "magnet:?xt=urn:btih:{h}&dn=pmagnet.bin&tr={}",
        crate::http::percent_encode(tracker.http_url(0).as_bytes())
    );
    let actor = ctx.actor("urt")?;
    let mut client = UrtClient::launch_magnet(
        &actor,
        ClientConfig::default()
            .profile("qbt")
            .encryption("disabled"),
        &magnet,
    )?;
    let st = client.wait_for(Duration::from_secs(120), "our download via magnet", |s| {
        s.complete
    })?;
    ensure!(st.private, "the torrent did not come out private");
    let probe = TapPeer::start(
        TapPeerConfig::new(fx.info_hash, Role::Silent)
            .fixture(fx.clone())
            .encryption(TapEncryption::Disabled)
            .bind_addr(ctx.host_alias(3)?)
            .linger(Duration::from_secs(5)),
    )?;
    let port = st.listen_port;
    ensure!(
        connect_retry(&probe, SocketAddr::new(client.actor.addr(), port), 10),
        "probe could not connect to us"
    );
    ensure!(
        probe.wait_for(Duration::from_secs(10), |c| c
            .iter()
            .any(|c| c.ext_handshake().is_some())),
        "no LTEP handshake from us"
    );
    let m_keys = |v: Option<&serde_json::Value>| -> Vec<String> {
        v.and_then(|d| d.get("m"))
            .and_then(|m| m.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    };
    let ours_after = probe
        .captures()
        .iter()
        .find_map(|c| c.ext_handshake().map(|v| m_keys(Some(v))))
        .unwrap_or_default();
    let ours_before: Vec<Vec<String>> = tap_seed
        .captures()
        .iter()
        .filter_map(|c| c.ext_handshake().map(|v| m_keys(Some(v))))
        .collect();
    client.shutdown()?;
    let load = |name: &str| -> Result<Vec<Vec<String>>> {
        let Some(p) = crate::scenario::golden_file("capture_magnet_private", Shape::V4, name)
        else {
            anyhow::bail!("no golden {name}; run `cargo xtask capture capture_magnet_private`");
        };
        let caps: Vec<crate::tap::peer::PeerCapture> = std::fs::read_to_string(p)?
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        Ok(caps
            .iter()
            .filter_map(|c| c.ext_handshake().map(|v| m_keys(Some(v))))
            .collect())
    };
    let oracle_after = load("tap-peer-pmagnet-probe.jsonl")?
        .into_iter()
        .next()
        .unwrap_or_default();
    let oracle_before = load("tap-peer-pmagnet-seed.jsonl")?;
    ctx.note(format!(
        "m after metadata: oracle {oracle_after:?} us {ours_after:?}; before: oracle {oracle_before:?} us {ours_before:?}"
    ));
    ensure!(
        ours_after == oracle_after,
        "L2 ltep m after private metadata: oracle {oracle_after:?} vs us {ours_after:?}"
    );
    // The first connection to the seeder (metadata unknown) advertises the
    // full map on both sides.
    let full_oracle = oracle_before
        .iter()
        .find(|k| k.iter().any(|x| x == "ut_metadata"))
        .cloned();
    let full_ours = ours_before
        .iter()
        .find(|k| k.iter().any(|x| x == "ut_metadata"))
        .cloned();
    ensure!(
        full_ours == full_oracle,
        "L2 ltep m before metadata: oracle {full_oracle:?} vs us {full_ours:?}"
    );
    Ok(())
}

fn capture_magnet(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("magnet.bin")
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
        "magnet:?xt=urn:btih:{h}&dn=magnet.bin&tr={}",
        crate::http::percent_encode(tracker.http_url(0).as_bytes())
    );
    oracle.api.add_torrent(
        &AddTorrent::magnet(&magnet).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    oracle
        .api
        .wait_for(
            &h,
            Duration::from_secs(120),
            "oracle to fetch and download",
            |t| t.is_complete(),
        )
        .inspect_err(|_| {
            tracing::error!(
                "oracle log:\n{}",
                oracle.api.main_log().unwrap_or_default().join("\n")
            );
        })?;
    fx.verify_data(&oracle.save_path)?
        .map_err(|e| anyhow::anyhow!("oracle data mismatch: {e}"))?;
    ensure!(
        tap_seed.wait_for(Duration::from_secs(30), |c| c
            .iter()
            .any(|c| c.handshake.is_some() && c.closed_ms.is_some())),
        "tap seeder saw no completed connection"
    );
    for c in tap_seed.captures() {
        let kinds: Vec<String> = c
            .events
            .iter()
            .take(24)
            .map(|e| {
                if e.kind == "extended" {
                    format!("{}:extended[{}]", e.dir, e.detail["ext_id"])
                } else {
                    format!("{}:{}", e.dir, e.kind)
                }
            })
            .collect();
        ctx.note(format!(
            "conn {} from {}: ext={:?} first={:?}",
            c.id,
            c.remote,
            c.ext_handshake(),
            kinds
        ));
    }
    let p = ctx.file("tap-peer-magnet-oracle.jsonl");
    tap_seed.save_jsonl(&p)?;
    ctx.artifact("tap-peer-magnet-oracle.jsonl", &p);
    let tp = ctx.file("tap-tracker-magnet.jsonl");
    tracker.save_jsonl(&tp)?;
    ctx.artifact("tap-tracker-magnet.jsonl", &tp);
    Ok(())
}

/// The oracle seeds to us and to a silent tap peer B (which advertises its
/// listen port). The oracle's PEX tells us about B; we connect to it, and B
/// records the PEX message *we* send. Assertions: we learned B through PEX,
/// and our message has the oracle's shape (discriminator).
fn pex_discovery(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("pex.bin")
            .with_size(6 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    let h = fx.info_hash_hex();
    let oracle = ctx.oracle(
        "oracle",
        OracleConfig::primary()
            .encryption(Encryption::Disable)
            .lsd(false),
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
    let b_ip = ctx.host_alias(3)?;
    let tap_b = silent_with_port(&fx, b_ip, 6892)?;
    ensure!(
        connect_retry(
            &tap_b,
            SocketAddr::new(oracle.actor.addr(), oracle.listen_port()),
            10
        ),
        "tap B could not connect to the oracle"
    );
    // Us, download-limited so the oracle keeps both peers long enough for its
    // first PEX (sent once it has more than one peer).
    let torrent_path = ctx.file("pex.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default()
            .profile("qbt")
            .lsd(false)
            .download_limit(512 * 1024),
        &torrent_path,
    )?;
    let st = client.wait_for(Duration::from_secs(60), "PEX from the oracle", |s| {
        s.events.iter().any(|e| e.starts_with("PexPeers"))
    })?;
    let pex_events: Vec<&String> = st
        .events
        .iter()
        .filter(|e| e.starts_with("PexPeers"))
        .collect();
    ctx.note(format!("pex events: {pex_events:?}"));
    ensure!(
        pex_events
            .iter()
            .any(|e| e.contains("added: 1") || e.contains("added: 2")),
        "the oracle's PEX brought no new peer: {pex_events:?}"
    );
    // We dial B (learned through PEX) and B records what we send.
    ensure!(
        tap_b.wait_for(Duration::from_secs(30), |c| c
            .iter()
            .any(|c| c.direction == "in" && c.handshake.is_some())),
        "we never connected to the PEX-learned peer"
    );
    let st = client.wait_for(Duration::from_secs(30), "B in our peer list via PEX", |s| {
        s.peer_list
            .iter()
            .chain(s.peers_seen.iter())
            .any(|p| p.source == "Pex")
    })?;
    ctx.note(format!(
        "our peers: {:?}",
        st.peer_list
            .iter()
            .map(|p| format!("{} {} {:?}", p.addr, p.source, p.client))
            .collect::<Vec<_>>()
    ));
    // Our first PEX message to B arrives within ~a second of connecting (we
    // have two peers). Wait for it, then compare with the oracle's shape.
    ensure!(
        tap_b.wait_for(Duration::from_secs(20), |c| c
            .iter()
            .any(|c| c.direction == "in"
                && c.recv().any(|e| e.kind == "extended"
                    && e.detail.get("ext_id").and_then(|v| v.as_u64()) == Some(1)))),
        "we sent B no ut_pex message"
    );
    let caps = tap_b.captures();
    let ours: Vec<&PeerCapture> = caps
        .iter()
        .filter(|c| c.direction == "in" && c.handshake.is_some())
        .collect();
    let our_fp = Fingerprint {
        peer: ours.iter().find_map(|c| discriminator::peer_fingerprint(c)),
        pex: ours
            .iter()
            .find_map(|c| discriminator::pex_fingerprint(c, 1)),
        ..Default::default()
    };
    ctx.note(format!("our pex fingerprint: {:?}", our_fp.pex));
    ensure!(our_fp.pex.is_some(), "no PEX fingerprint");
    let pex = our_fp.pex.clone().unwrap();
    ensure!(
        pex.keys
            == [
                "added", "added.f", "added6", "added6.f", "dropped", "dropped6"
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        "pex keys {:?}",
        pex.keys
    );
    ensure!(pex.flags_consistent);
    ensure!(
        pex.includes_recipient_ip,
        "libtorrent includes the recipient"
    );
    ensure!(
        pex.flag_bits & 0x10 == 0,
        "0x10 is never set by libtorrent 2.0"
    );
    // The oracle entry is a seed that advertises ut_holepunch: 0x02 | 0x08.
    ensure!(
        pex.flag_bits & 0x0a == 0x0a,
        "expected seed+holepunch flags for the oracle entry, got {:#x}",
        pex.flag_bits
    );
    let oracle_fp = discriminator::golden_oracle()?;
    if oracle_fp.pex.is_some() {
        let tells = discriminator::diff(
            &Fingerprint {
                pex: oracle_fp.pex.clone(),
                ..Default::default()
            },
            &Fingerprint {
                pex: our_fp.pex.clone(),
                ..Default::default()
            },
        );
        ctx.note(format!("pex tells vs oracle golden: {tells:?}"));
        ensure!(
            tells.is_empty(),
            "PEX shape differs from the oracle: {tells:?}"
        );
    } else {
        ctx.note("no capture_pex golden yet; PEX shape compared to libtorrent rules only");
    }
    let p = ctx.file("tap-peer-pex-B.jsonl");
    tap_b.save_jsonl(&p)?;
    ctx.artifact("tap-peer-pex-B.jsonl", &p);
    client.wait_for(Duration::from_secs(120), "download to complete", |s| {
        s.complete
    })?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    client.shutdown()?;
    tap_b.stop();
    Ok(())
}

/// Both directions of BEP 9: we add a magnet and fetch the metadata from the
/// oracle seeder; then the oracle adds a magnet for a torrent we seed.
fn magnet_via_ut_metadata(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker(ctx)?;
    // Part A: the oracle seeds, we start from a magnet.
    let fx_a = Arc::new(Fixture::generate(
        FixtureSpec::small("magnet-a.bin")
            .with_size(3 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0)),
    ));
    let ha = fx_a.info_hash_hex();
    let oracle = ctx.oracle("oracle", OracleConfig::primary())?;
    fx_a.write_data(&oracle.save_path)?;
    oracle.api.add_torrent(
        &AddTorrent::file(&fx_a.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &ha,
    )?;
    oracle
        .api
        .wait_for(&ha, Duration::from_secs(60), "oracle seeding A", |t| {
            t.is_seeding()
        })?;
    let magnet = format!(
        "magnet:?xt=urn:btih:{ha}&dn=magnet-a.bin&tr={}",
        crate::http::percent_encode(tracker.http_url(0).as_bytes())
    );
    let actor = ctx.actor("urt")?;
    let mut client =
        UrtClient::launch_magnet(&actor, ClientConfig::default().profile("qbt"), &magnet)?;
    let st = client.wait_for(Duration::from_secs(60), "metadata from the oracle", |s| {
        s.has_metadata
    })?;
    ctx.note(format!(
        "metadata received: name={} pieces={} size={} events={:?}",
        st.name,
        st.pieces_total,
        st.total_size,
        st.events
            .iter()
            .filter(|e| e.starts_with("MetadataReceived") || e.starts_with("Checked"))
            .collect::<Vec<_>>()
    ));
    ensure!(st.name == "magnet-a.bin");
    ensure!(st.pieces_total == fx_a.piece_count());
    ensure!(st.total_size == fx_a.total_len);
    let st = client.wait_for(Duration::from_secs(120), "download A to complete", |s| {
        s.complete
    })?;
    fx_a.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    ensure!(st.downloaded == fx_a.total_len && st.corrupt == 0);
    // The announces before the metadata carried libtorrent's 16 KiB `left`
    // placeholder (Q12), the ones after it the real size.
    let events = tracker.events();
    let ours: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "announce" && client.actor.addrs().contains(&e.from.ip()))
        .collect();
    let lefts: Vec<Option<&str>> = ours.iter().map(|e| query(e, "left")).collect();
    ctx.note(format!("our announce left values: {lefts:?}"));
    ensure!(
        lefts.first() == Some(&Some("16384")),
        "first announce left: {lefts:?}"
    );
    client.shutdown()?;

    // Part B: we seed a second torrent; the oracle starts from a magnet.
    let fx_b = Arc::new(Fixture::generate(
        FixtureSpec::small("magnet-b.bin")
            .with_size(2 << 20)
            .with_piece_length(64 << 10)
            .with_tracker(&tracker.http_url(0))
            .with_seed(11),
    ));
    let hb = fx_b.info_hash_hex();
    let torrent_path = ctx.file("magnet-b.torrent");
    std::fs::write(&torrent_path, &fx_b.torrent)?;
    let actor_b = ctx.actor("urt-seed")?;
    let save = actor_b.log_dir.join("data");
    std::fs::create_dir_all(&save)?;
    fx_b.write_data(&save)?;
    let mut seeder = UrtClient::launch(
        &actor_b,
        ClientConfig::default().profile("qbt"),
        &torrent_path,
    )?;
    seeder.wait_for(Duration::from_secs(60), "our seeder checked", |s| {
        s.complete && s.state == "Seeding"
    })?;
    let magnet_b = format!(
        "magnet:?xt=urn:btih:{hb}&dn=magnet-b.bin&tr={}",
        crate::http::percent_encode(tracker.http_url(0).as_bytes())
    );
    oracle.api.add_torrent(
        &AddTorrent::magnet(&magnet_b).save_path(&oracle.save_path.to_string_lossy()),
        &hb,
    )?;
    let t = oracle
        .api
        .wait_for(
            &hb,
            Duration::from_secs(120),
            "oracle to fetch B and download",
            |t| t.is_complete(),
        )
        .inspect_err(|_| {
            tracing::error!("seeder log tail:\n{}", seeder.stderr_tail(60));
            tracing::error!(
                "oracle log:\n{}",
                oracle.api.main_log().unwrap_or_default().join("\n")
            );
        })?;
    ctx.note(format!(
        "oracle B complete: state={} name={}",
        t.state, t.name
    ));
    fx_b.verify_data(&oracle.save_path)?
        .map_err(|e| anyhow::anyhow!("oracle data mismatch: {e}"))?;
    let st = seeder.wait_for(Duration::from_secs(10), "upload counter", |s| {
        s.uploaded >= fx_b.total_len
    })?;
    ensure!(st.downloaded == 0 && st.corrupt == 0);
    seeder.shutdown()?;
    let p = ctx.file("tap-tracker.jsonl");
    tracker.save_jsonl(&p)?;
    ctx.artifact("tap-tracker.jsonl", &p);
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

/// No tracker at all: the oracle seeds with LSD on, we find it (and it finds
/// us) over multicast on the lab bridge. The pcap holds both sides' `BT-SEARCH`
/// datagrams; ours must match the oracle's after normalising port, cookie and
/// info-hash.
fn lsd_discovery(ctx: &mut Ctx) -> Result<()> {
    let pcap_path = ctx.file("lsd.pcap");
    let pcap = Pcap::start(ctx.lab.bridge(), &pcap_path, "udp port 6771")?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("lsd.bin")
            .with_size(2 << 20)
            .with_piece_length(64 << 10),
    ));
    let h = fx.info_hash_hex();
    let oracle = ctx.oracle("oracle", OracleConfig::primary().lsd(true))?;
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
    let torrent_path = ctx.file("lsd.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default().profile("qbt").lsd(true),
        &torrent_path,
    )?;
    let st = client.wait_for(Duration::from_secs(90), "an LSD peer", |s| {
        s.events.iter().any(|e| e.starts_with("LsdPeer"))
            || s.peer_list.iter().any(|p| p.source == "Lsd")
    })?;
    ctx.note(format!(
        "lsd events: {:?}",
        st.events
            .iter()
            .filter(|e| e.starts_with("LsdPeer"))
            .collect::<Vec<_>>()
    ));
    let st = client.wait_for(Duration::from_secs(120), "download to complete", |s| {
        s.complete
    })?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    ensure!(
        st.peers_seen
            .iter()
            .any(|p| p.source == "Lsd" || p.source == "Incoming"),
        "no peer learned through LSD: {:?}",
        st.peers_seen
    );
    client.shutdown()?;
    let mut pcap = pcap;
    if let Some(p) = pcap.as_mut() {
        p.stop();
        std::thread::sleep(Duration::from_millis(300));
        let packets = lsd_packets(&pcap_path)?;
        let oracle_ips = oracle.actor.addrs();
        let our_ips = client.actor.addrs();
        let theirs: Vec<&(IpAddr, String)> = packets
            .iter()
            .filter(|(ip, _)| oracle_ips.contains(ip))
            .collect();
        let ours: Vec<&(IpAddr, String)> = packets
            .iter()
            .filter(|(ip, _)| our_ips.contains(ip))
            .collect();
        ctx.note(format!(
            "lsd datagrams: oracle {} ours {}\n  oracle: {:?}\n  ours:   {:?}",
            theirs.len(),
            ours.len(),
            theirs.first().map(|(_, t)| t),
            ours.first().map(|(_, t)| t)
        ));
        ensure!(!theirs.is_empty(), "the oracle sent no LSD announce (pcap)");
        ensure!(!ours.is_empty(), "we sent no LSD announce (pcap)");
        let norm = |t: &str| {
            t.lines()
                .map(|l| {
                    if let Some(rest) = l.strip_prefix("Port: ") {
                        let _ = rest;
                        "Port: <port>".to_string()
                    } else if l.starts_with("Infohash: ") {
                        "Infohash: <hash>".to_string()
                    } else if l.starts_with("cookie: ") {
                        "cookie: <hex>".to_string()
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        let o = norm(&theirs[0].1);
        let u = norm(&ours[0].1);
        ensure!(
            o == u,
            "LSD datagram differs from the oracle's:\n{o:?}\nvs\n{u:?}"
        );
        // The info-hash is lowercase hex in both.
        ensure!(
            ours[0].1.contains(&format!("Infohash: {h}")),
            "our Infohash header is not the lowercase hex: {}",
            ours[0].1
        );
        ensure!(theirs[0].1.contains(&format!("Infohash: {h}")));
        ctx.artifact("lsd.pcap", &pcap_path);
    } else {
        ctx.note("tcpdump unavailable: LSD datagram comparison skipped");
    }
    Ok(())
}

/// Extract `(source ip, payload text)` of every UDP datagram to port 6771 in
/// a pcap via `tcpdump -A`.
fn lsd_packets(path: &std::path::Path) -> Result<Vec<(IpAddr, String)>> {
    let out = Command::new("tcpdump")
        .args(["-r"])
        .arg(path)
        .args(["-nn", "-A", "-l", "udp and dst port 6771"])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut packets = Vec::new();
    let mut cur: Option<(IpAddr, String)> = None;
    for line in text.lines() {
        // Header lines look like "12:00:00.000 IP 10.77.1.2.6771 > 239.192.152.143.6771: UDP, length 137"
        if line.contains(" > ") && (line.contains(" IP ") || line.contains(" IP6 ")) {
            if let Some(c) = cur.take() {
                packets.push(c);
            }
            let src = line.split_whitespace().nth(2).unwrap_or("").to_string();
            // Strip the trailing ".port".
            let ip_str = match src.rsplit_once('.') {
                Some((ip, _)) => ip.to_string(),
                None => src.clone(),
            };
            let ip: IpAddr = ip_str
                .parse()
                .or_else(|_| ip_str.trim_matches(|c| c == '[' || c == ']').parse())
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            cur = Some((ip, String::new()));
        } else if let Some((_, text)) = cur.as_mut() {
            // `-A` prints the payload as text with `.` for non-printables; the
            // BT-SEARCH lines are ASCII, so keep from `BT-SEARCH` on.
            if let Some(idx) = line.find("BT-SEARCH") {
                text.push_str(&line[idx..]);
                text.push('\n');
            } else if !text.is_empty() {
                text.push_str(line);
                text.push('\n');
            }
        }
    }
    if let Some(c) = cur.take() {
        packets.push(c);
    }
    Ok(packets
        .into_iter()
        .filter(|(_, t)| t.contains("BT-SEARCH"))
        .collect())
}

/// A torrent whose only source is a web seed (BEP 19): we complete from the
/// tap web seed, and the oracle does too; the HTTP requests both make are
/// compared (informational L3 for now, hard-checked: Range format).
fn web_seed_only(ctx: &mut Ctx) -> Result<()> {
    let addrs: Vec<SocketAddr> = ctx
        .host_addrs()
        .into_iter()
        .map(|a| SocketAddr::new(a, 7090))
        .collect();
    let fx0 = Fixture::generate(
        FixtureSpec::small("web.bin")
            .with_size(2 << 20)
            .with_piece_length(64 << 10),
    );
    // The url-list must be in the torrent: build the server first with a
    // placeholder fixture layout (same name/size), then the real torrent.
    let server = TapWebSeed::start(addrs, Arc::new(fx0), "/seed/")?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("web.bin")
            .with_size(2 << 20)
            .with_piece_length(64 << 10)
            .with_url_list(vec![server.url(0)]),
    ));
    let h = fx.info_hash_hex();
    let torrent_path = ctx.file("web.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default().profile("qbt").lsd(false),
        &torrent_path,
    )?;
    let st = client.wait_for(
        Duration::from_secs(120),
        "download from the web seed",
        |s| s.complete,
    )?;
    ensure!(st.web_seeds == 1);
    ensure!(
        st.downloaded == fx.total_len && st.corrupt == 0,
        "downloaded {} corrupt {}",
        st.downloaded,
        st.corrupt
    );
    ensure!(
        st.peers == 0 && st.peers_seen.is_empty(),
        "no peers were involved"
    );
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    client.shutdown()?;
    let ours = server.requests();
    ensure!(!ours.is_empty(), "the web seed saw no request from us");
    ensure!(
        ours.iter().all(|r| r.status == 206),
        "non-206 answers: {:?}",
        ours.iter().map(|r| r.status).collect::<Vec<_>>()
    );

    // The oracle, same torrent.
    let oracle = ctx.oracle("oracle", OracleConfig::primary().lsd(false))?;
    oracle.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    oracle.api.wait_for(
        &h,
        Duration::from_secs(120),
        "oracle to download from the web seed",
        |t| t.is_complete(),
    )?;
    fx.verify_data(&oracle.save_path)?
        .map_err(|e| anyhow::anyhow!("oracle data mismatch: {e}"))?;
    let all = server.requests();
    let theirs: Vec<_> = all
        .iter()
        .filter(|r| oracle.actor.addrs().contains(&r.from.ip()))
        .collect();
    ensure!(
        !theirs.is_empty(),
        "the web seed saw no request from the oracle"
    );
    let head = |r: &crate::tap::webseed::WebRequest| {
        format!(
            "{} | {}",
            r.request_line,
            r.headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join(" | ")
        )
    };
    ctx.note(format!(
        "web seed requests: ours {} (first: {}) oracle {} (first: {})",
        ours.len(),
        head(&ours[0]),
        theirs.len(),
        head(theirs[0])
    ));
    // L2-ish: header *names* and order.
    let names = |r: &crate::tap::webseed::WebRequest| {
        r.headers.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>()
    };
    ctx.note(format!(
        "header order: ours {:?} oracle {:?}",
        names(&ours[0]),
        names(theirs[0])
    ));
    ensure!(
        ours.iter()
            .all(|r| r.range.as_deref().is_some_and(|x| x.starts_with("bytes=")))
    );
    ensure!(
        theirs
            .iter()
            .all(|r| r.range.as_deref().is_some_and(|x| x.starts_with("bytes=")))
    );
    let ua_ours = ours[0]
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.clone());
    let ua_theirs = theirs[0]
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.clone());
    ensure!(
        ua_ours == ua_theirs,
        "L1 User-Agent on web seed requests: {ua_ours:?} vs {ua_theirs:?}"
    );
    let p = ctx.file("tap-webseed.jsonl");
    server.save_jsonl(&p)?;
    ctx.artifact("tap-webseed.jsonl", &p);
    Ok(())
}

/// Rule 2 on the wire: with DHT, PEX and LSD enabled in the session, a
/// private torrent produces no DHT lookup or announce, no LSD datagram and no
/// `ut_pex` message from us, and our LTEP handshake advertises neither
/// `ut_pex` nor `ut_metadata` (Q11). The oracle seeds; a silent tap peer
/// (with `p`) connects to us and records everything we send; a tap DHT node
/// is our bootstrap router and records every KRPC message from us; a pcap on
/// the bridge records every multicast datagram.
fn private_no_pex_lsd(ctx: &mut Ctx) -> Result<()> {
    let pcap_path = ctx.file("private.pcap");
    let pcap = Pcap::start(ctx.lab.bridge(), &pcap_path, "udp port 6771")?;
    let router_ip = ctx.host_alias(4)?;
    let router = crate::tap::dht::TapDht::start(
        crate::tap::dht::TapDhtConfig::new(vec![SocketAddr::new(router_ip, 6881)])
            .node_id([0xd4; 20])
            .learn(true),
    )?;
    let router_addr = router.local_addrs()[0];
    let tracker = tap_tracker(ctx)?;
    let fx = Arc::new(Fixture::generate(
        FixtureSpec::small("private.bin")
            .with_size(4 << 20)
            .with_piece_length(64 << 10)
            .private(true)
            .with_tracker(&tracker.http_url(0)),
    ));
    let h = fx.info_hash_hex();
    let oracle = ctx.oracle("oracle", OracleConfig::primary().lsd(true))?;
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
    let torrent_path = ctx.file("private.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default()
            .profile("qbt")
            .lsd(true)
            .pex(true)
            .dht_bootstrap(vec![router_addr])
            .download_limit(256 * 1024),
        &torrent_path,
    )?;
    client.wait_for(Duration::from_secs(30), "a peer", |s| s.peers >= 1)?;
    // A second peer connects to us and stays: if we did PEX, it would receive
    // a message within a couple of seconds.
    let tap_ip = ctx.host_alias(3)?;
    let tap = silent_with_port(&fx, tap_ip, 6893)?;
    let our_addr = SocketAddr::new(client.actor.addr(), client.status().unwrap().listen_port);
    tap.connect_async(our_addr);
    ensure!(
        tap.wait_for(Duration::from_secs(20), |c| c
            .iter()
            .any(|c| c.handshake.is_some() && c.ext_handshake().is_some())),
        "tap could not connect to us"
    );
    std::thread::sleep(Duration::from_secs(8));
    let st = client.wait_for(Duration::from_secs(120), "download to complete", |s| {
        s.complete
    })?;
    ensure!(st.private, "status must report the torrent private");
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    std::thread::sleep(Duration::from_secs(3));
    client.shutdown()?;
    tap.stop();
    // 1. Nothing PEX-shaped from us, and Q11's `m` map.
    let caps = tap.captures();
    let ours: Vec<&PeerCapture> = caps.iter().filter(|c| c.handshake.is_some()).collect();
    ensure!(!ours.is_empty(), "tap recorded no connection from us");
    for c in &ours {
        let ext = c
            .ext_handshake()
            .ok_or_else(|| anyhow::anyhow!("no LTEP handshake"))?;
        let m = ext
            .get("m")
            .and_then(|m| m.as_object())
            .ok_or_else(|| anyhow::anyhow!("no m"))?;
        let keys: Vec<&String> = m.keys().collect();
        ctx.note(format!(
            "our private m map: {keys:?}; ext keys {:?}",
            ext.as_object().map(|o| o.keys().collect::<Vec<_>>())
        ));
        ensure!(
            !m.contains_key("ut_pex"),
            "ut_pex advertised on a private torrent"
        );
        ensure!(
            !m.contains_key("ut_metadata"),
            "ut_metadata advertised on a private torrent"
        );
        ensure!(
            ext.get("metadata_size").is_none(),
            "metadata_size on a private torrent"
        );
        let pex_msgs = c
            .recv()
            .filter(|e| {
                e.kind == "extended" && e.detail.get("ext_id").and_then(|v| v.as_u64()) == Some(1)
            })
            .count();
        ensure!(
            pex_msgs == 0,
            "we sent {pex_msgs} ut_pex messages on a private torrent"
        );
    }
    ensure!(
        !st.events
            .iter()
            .any(|e| e.starts_with("PexPeers") || e.starts_with("LsdPeer")),
        "private torrent produced PEX/LSD events: {:?}",
        st.events
    );
    // 2. The DHT ran (we bootstrapped from the router) but never looked the
    // private torrent up or announced it.
    let our_ips = client.actor.addrs();
    let krpc = router.events();
    let from_us: Vec<_> = krpc
        .iter()
        .filter(|e| e.dir == "recv" && our_ips.contains(&e.remote.ip()))
        .collect();
    ensure!(
        from_us.iter().any(|e| e.kind == "query:get_peers"),
        "our DHT node never queried the router: the check would be vacuous"
    );
    let ih_hex = fx.info_hash_hex();
    let about_private: Vec<String> = from_us
        .iter()
        .filter(|e| {
            e.kind == "query:announce_peer"
                || e.body()
                    .and_then(|b| b.get("info_hash"))
                    .and_then(|h| h.get("hex"))
                    .and_then(|h| h.as_str())
                    == Some(ih_hex.as_str())
        })
        .map(|e| format!("{} {}", e.kind, e.decoded))
        .collect();
    ctx.note(format!(
        "krpc from us: {} messages, {} about the private torrent",
        from_us.len(),
        about_private.len()
    ));
    ensure!(
        about_private.is_empty(),
        "DHT traffic about a private torrent: {about_private:?}"
    );
    let p = ctx.file("tap-dht-private.jsonl");
    router.save_jsonl(&p)?;
    ctx.artifact("tap-dht-private.jsonl", &p);
    // 3. No LSD datagram from us on the wire.
    let mut pcap = pcap;
    if let Some(p) = pcap.as_mut() {
        p.stop();
        std::thread::sleep(Duration::from_millis(300));
        let packets = lsd_packets(&pcap_path)?;
        let ours: Vec<_> = packets
            .iter()
            .filter(|(ip, _)| our_ips.contains(ip))
            .collect();
        ctx.note(format!(
            "lsd datagrams in pcap: total {} from us {}",
            packets.len(),
            ours.len()
        ));
        ensure!(
            ours.is_empty(),
            "we sent LSD announces for a private torrent: {ours:?}"
        );
        ctx.artifact("private.pcap", &pcap_path);
    } else {
        anyhow::bail!("tcpdump is required for the private-torrent wire check");
    }
    let p = ctx.file("tap-peer-private.jsonl");
    tap.save_jsonl(&p)?;
    ctx.artifact("tap-peer-private.jsonl", &p);
    Ok(())
}
