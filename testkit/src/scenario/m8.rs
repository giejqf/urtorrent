// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! 0.3.0 (DHT, BEP 5) scenarios. Capture first: what the oracle's DHT node
//! sends (bootstrap, lookups, announces, the peer-wire `port` message) and
//! how it answers every kind of query, observed by tap DHT nodes it is
//! bootstrapped from.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};

use super::{Ctx, ScenarioDef, Tag};
use crate::bencode::Value;
use crate::client::ClientConfig;
use crate::fixtures::{Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::{Encryption, OracleConfig};
use crate::peerwire::reserved;
use crate::tap::dht::{TapDht, TapDhtConfig, args, shape};
use crate::tap::peer::{Role, TapEncryption, TapPeer, TapPeerConfig};
use crate::webapi::AddTorrent;

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "capture_dht",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It, Tag::Capture],
            run: capture_dht,
        },
        ScenarioDef {
            name: "dht_leech_from_oracle",
            shapes: &[Shape::V4, Shape::V6, Shape::Dual],
            tags: &[Tag::It],
            run: dht_leech_from_oracle,
        },
        ScenarioDef {
            name: "magnet_dht_from_oracle",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It],
            run: magnet_dht_from_oracle,
        },
        ScenarioDef {
            name: "dht_seed_to_oracle",
            shapes: &[Shape::V4],
            tags: &[Tag::It],
            run: dht_seed_to_oracle,
        },
        ScenarioDef {
            name: "dht_shape",
            shapes: &[Shape::V4],
            tags: &[Tag::It, Tag::Diff],
            run: dht_shape,
        },
    ]
}

/// A tracker-less torrent: the oracle can only find its peer through the DHT.
fn dht_fixture(name: &str) -> Arc<Fixture> {
    Arc::new(Fixture::generate(
        FixtureSpec::small(name)
            .with_size(1 << 20)
            .with_piece_length(64 << 10),
    ))
}

fn capture_dht(ctx: &mut Ctx) -> Result<()> {
    let d1_ip = ctx.host_alias(2)?;
    let d2_ip = ctx.host_alias(3)?;
    let peer_ip = ctx.host_alias(4)?;
    let fx = dht_fixture("dht.bin");
    let peer_addr = SocketAddr::new(peer_ip, 6890);

    // Tap DHT node 2: a plain node the oracle learns about from node 1 (the
    // second hop of its traversal).
    let d2 =
        TapDht::start(TapDhtConfig::new(vec![SocketAddr::new(d2_ip, 6881)]).node_id([0x22; 20]))?;
    // Tap DHT node 1: the oracle's bootstrap node. Hands out node 2 and, for
    // the fixture, the tap peer as a value.
    let d1 = TapDht::start(
        TapDhtConfig::new(vec![SocketAddr::new(d1_ip, 6881)])
            .node_id([0x11; 20])
            .node([0x22; 20], SocketAddr::new(d2_ip, 6881))
            .peer(fx.info_hash, peer_addr),
    )?;
    // The seeding tap peer advertises the DHT reserved bit so the oracle
    // sends `port`.
    let mut res = [0u8; 8];
    reserved::set(&mut res, reserved::LTEP);
    reserved::set(&mut res, reserved::FAST);
    reserved::set(&mut res, reserved::DHT);
    let tap_peer = TapPeer::start(
        TapPeerConfig::new(fx.info_hash, Role::Seeder)
            .listen(vec![peer_addr])
            .bind_addr(peer_ip)
            .fixture(fx.clone())
            .reserved(res)
            .encryption(TapEncryption::Disabled)
            .linger(Duration::from_secs(30)),
    )?;

    let mut cfg = OracleConfig::primary()
        .dht(true)
        .encryption(Encryption::Disable);
    cfg.extra_session_settings.push((
        "DHTBootstrapNodes".into(),
        fmt_hostport(SocketAddr::new(d1_ip, 6881)),
    ));
    let oracle = ctx.oracle("oracle", cfg)?;
    let h = fx.info_hash_hex();
    oracle.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    // The oracle bootstraps from node 1, learns node 2, looks the torrent up,
    // finds the tap peer and downloads from it; then announces itself.
    oracle
        .api
        .wait_for(&h, Duration::from_secs(120), "oracle leech via DHT", |t| {
            t.is_complete()
        })?;
    ensure!(
        d1.wait_for(Duration::from_secs(60), |e| e
            .iter()
            .any(|e| e.is_query_from("announce_peer", oracle.actor.addr()))),
        "oracle never announced to node 1"
    );
    ensure!(
        d2.wait_for(Duration::from_secs(30), |e| e
            .iter()
            .any(|e| e.dir == "recv" && e.kind.starts_with("query:"))),
        "oracle never queried node 2 (multi-hop traversal)"
    );

    let probes = probe_node(
        &d1,
        SocketAddr::new(oracle.actor.addr(), 6881),
        fx.info_hash,
    )?;
    for (name, r) in &probes {
        match r {
            Some(v) => ctx.note(format!(
                "probe {name}: {}",
                shape(&crate::peerwire::value_to_json(v))
            )),
            None => ctx.note(format!("probe {name}: no reply")),
        }
    }
    ensure!(
        probes.iter().filter(|(_, r)| r.is_some()).count() >= 8,
        "too few probe replies: {:?}",
        probes
            .iter()
            .map(|(n, r)| (n, r.is_some()))
            .collect::<Vec<_>>()
    );
    // Let the oracle's refresh traffic show for a while (informational).
    std::thread::sleep(Duration::from_secs(20));

    for (name, tap) in [("tap-dht-1.jsonl", &d1), ("tap-dht-2.jsonl", &d2)] {
        let p = ctx.file(name);
        tap.save_jsonl(&p)?;
        ctx.artifact(name, &p);
    }
    let p = ctx.file("tap-peer-dht.jsonl");
    tap_peer.save_jsonl(&p)?;
    ctx.artifact("tap-peer-dht.jsonl", &p);

    // Notes: the shapes of what the oracle sent us.
    let oracle_ip = oracle.actor.addr();
    let mut seen = std::collections::BTreeSet::new();
    for e in d1.events().iter().chain(d2.events().iter()) {
        if e.dir == "recv" && e.remote.ip() == oracle_ip {
            seen.insert(format!("{} {}", e.kind, shape(&e.decoded)));
        }
    }
    for s in seen {
        ctx.note(format!("oracle -> tap: {s}"));
    }
    for c in tap_peer.captures() {
        let kinds: Vec<String> = c
            .events
            .iter()
            .filter(|e| e.dir == "recv")
            .map(|e| e.kind.clone())
            .take(8)
            .collect();
        ctx.note(format!("peer conn {} first recv kinds: {kinds:?}", c.id));
    }
    ensure!(
        tap_peer
            .captures()
            .iter()
            .any(|c| c.events.iter().any(|e| e.dir == "recv" && e.kind == "port")),
        "oracle sent no `port` message to a DHT-capable peer"
    );
    Ok(())
}

fn fmt_hostport(a: SocketAddr) -> String {
    match a.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", a.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", a.port()),
    }
}

/// Every kind of query, good and bad, against `node` from tap `d`: the
/// replies are what a DHT discriminator compares.
fn probe_node(
    d: &TapDht,
    node: SocketAddr,
    info_hash: [u8; 20],
) -> Result<Vec<(String, Option<Value>)>> {
    let t = Duration::from_secs(5);
    let ih = Value::Bytes(info_hash.to_vec());
    let target = Value::Bytes(vec![0x33; 20]);
    let mut probes: Vec<(String, Option<Value>)> = Vec::new();
    let mut push = |name: &str, r: Option<Value>| probes.push((name.to_string(), r));
    push("ping", d.query(node, "ping", args(&[]), t));
    push(
        "find_node",
        d.query(node, "find_node", args(&[("target", target.clone())]), t),
    );
    let gp = d.query(node, "get_peers", args(&[("info_hash", ih.clone())]), t);
    let token = gp
        .as_ref()
        .and_then(|r| r.get("r"))
        .and_then(|r| r.get("token"))
        .and_then(Value::as_bytes)
        .map(<[u8]>::to_vec);
    push("get_peers", gp);
    push(
        "get_peers scrape",
        d.query(
            node,
            "get_peers",
            args(&[("info_hash", ih.clone()), ("scrape", Value::Int(1))]),
            t,
        ),
    );
    push(
        "get_peers noseed",
        d.query(
            node,
            "get_peers",
            args(&[("info_hash", ih.clone()), ("noseed", Value::Int(1))]),
            t,
        ),
    );
    push(
        "get_peers unknown hash",
        d.query(node, "get_peers", args(&[("info_hash", target.clone())]), t),
    );
    if let Some(tok) = token.clone() {
        push(
            "announce_peer",
            d.query(
                node,
                "announce_peer",
                args(&[
                    ("info_hash", ih.clone()),
                    ("port", Value::Int(6890)),
                    ("token", Value::Bytes(tok)),
                ]),
                t,
            ),
        );
        push(
            "get_peers after announce",
            d.query(node, "get_peers", args(&[("info_hash", ih.clone())]), t),
        );
        push(
            "get_peers scrape after announce",
            d.query(
                node,
                "get_peers",
                args(&[("info_hash", ih.clone()), ("scrape", Value::Int(1))]),
                t,
            ),
        );
    }
    push(
        "announce_peer bad token",
        d.query(
            node,
            "announce_peer",
            args(&[
                ("info_hash", ih.clone()),
                ("port", Value::Int(6890)),
                ("token", Value::Bytes(b"nope".to_vec())),
            ]),
            t,
        ),
    );
    push(
        "sample_infohashes",
        d.query(
            node,
            "sample_infohashes",
            args(&[("target", target.clone())]),
            t,
        ),
    );
    push(
        "get",
        d.query(node, "get", args(&[("target", target.clone())]), t),
    );
    push(
        "unknown with target",
        d.query(node, "frobnicate", args(&[("target", target.clone())]), t),
    );
    push(
        "unknown without target",
        d.query(node, "frobnicate", args(&[]), t),
    );
    push(
        "find_node missing target",
        d.query(node, "find_node", args(&[]), t),
    );
    push(
        "find_node short target",
        d.query(
            node,
            "find_node",
            args(&[("target", Value::Bytes(vec![1, 2, 3]))]),
            t,
        ),
    );
    // Malformed: not a dictionary, and a dict without `y`: no reply expected.
    d.send_raw(node, b"li1ee")?;
    d.send_raw(node, b"d1:t2:xxe")?;
    std::thread::sleep(Duration::from_secs(2));
    Ok(probes)
}

/// A tap DHT node acting as a real router / storage node.
fn router(ctx: &mut Ctx, alias: u8) -> Result<TapDht> {
    let ip = ctx.host_alias(alias)?;
    TapDht::start(
        TapDhtConfig::new(vec![SocketAddr::new(ip, 6881)])
            .node_id([0xd0 + alias; 20])
            .learn(true),
    )
}

/// Our client for the DHT scenarios: like the oracle's primary capture
/// configuration, uTP is off (with it on, announces carry `implied_port`,
/// Q21).
fn dht_client_config(routers: &[SocketAddr]) -> ClientConfig {
    ClientConfig::default()
        .profile("qbt")
        .lsd(false)
        .pex(false)
        .protocol("tcp")
        .dht_bootstrap(routers.to_vec())
}

/// The oracle seeds a tracker-less torrent and announces it to the DHT; we
/// find it through the DHT alone (router -> nodes -> the router's peer
/// store) and download it.
fn dht_leech_from_oracle(ctx: &mut Ctx) -> Result<()> {
    let d = router(ctx, 2)?;
    let d_addr = d.local_addrs()[0];
    let fx = dht_fixture("dhtleech.bin");
    let mut cfg = OracleConfig::primary()
        .dht(true)
        .encryption(Encryption::Disable);
    cfg.extra_session_settings
        .push(("DHTBootstrapNodes".into(), fmt_hostport(d_addr)));
    let oracle = ctx.oracle("oracle", cfg)?;
    fx.write_data(&oracle.save_path)?;
    let h = fx.info_hash_hex();
    oracle.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    oracle
        .api
        .wait_for(&h, Duration::from_secs(60), "oracle seeding", |t| {
            t.is_seeding()
        })?;
    ensure!(
        d.wait_for(Duration::from_secs(60), |e| e
            .iter()
            .any(|e| e.is_query_from("announce_peer", oracle.actor.addr()))),
        "oracle never announced to the router"
    );
    let torrent_path = ctx.file("dhtleech.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client("urt", dht_client_config(&[d_addr]), &torrent_path)?;
    let st = client.wait_for(Duration::from_secs(120), "download via DHT", |s| s.complete)?;
    ensure!(st.dht_nodes >= 1, "no DHT nodes in our table: {st:?}");
    ensure!(
        st.events.iter().any(|e| e.starts_with("DhtPeers")),
        "no DhtPeers event: {:?}",
        st.events
    );
    ensure!(
        st.events
            .iter()
            .any(|e| e.starts_with("PeerConnected") && e.contains(&oracle.actor.addr().to_string())),
        "never connected to the oracle"
    );
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    // We announced ourselves as well.
    let our_ip = client.actor.addr();
    ensure!(
        d.wait_for(Duration::from_secs(30), |e| e
            .iter()
            .any(|e| e.is_query_from("announce_peer", our_ip))),
        "we never announced to the router"
    );
    client.shutdown()?;
    let p = ctx.file("tap-dht-router.jsonl");
    d.save_jsonl(&p)?;
    ctx.artifact("tap-dht-router.jsonl", &p);
    Ok(())
}

/// BEP 9 + BEP 5 against the oracle: a magnet link with no tracker at all.
/// We look the hash up in the DHT before knowing anything else, find the
/// oracle seeder, fetch the metadata from it and download.
fn magnet_dht_from_oracle(ctx: &mut Ctx) -> Result<()> {
    let d = router(ctx, 2)?;
    let d_addr = d.local_addrs()[0];
    let fx = dht_fixture("dhtmagnet.bin");
    let mut cfg = OracleConfig::primary()
        .dht(true)
        .encryption(Encryption::Disable);
    cfg.extra_session_settings
        .push(("DHTBootstrapNodes".into(), fmt_hostport(d_addr)));
    let oracle = ctx.oracle("oracle", cfg)?;
    fx.write_data(&oracle.save_path)?;
    let h = fx.info_hash_hex();
    oracle.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    oracle
        .api
        .wait_for(&h, Duration::from_secs(60), "oracle seeding", |t| {
            t.is_seeding()
        })?;
    ensure!(
        d.wait_for(Duration::from_secs(60), |e| e
            .iter()
            .any(|e| e.is_query_from("announce_peer", oracle.actor.addr()))),
        "oracle never announced to the router"
    );
    let actor = ctx.actor("urt")?;
    let magnet = format!("magnet:?xt=urn:btih:{h}&dn=dhtmagnet.bin");
    let mut client = crate::client::UrtClient::launch_magnet(
        &actor,
        dht_client_config(&[d_addr]).encryption("disabled"),
        &magnet,
    )?;
    let st = client.wait_for(Duration::from_secs(120), "metadata via DHT", |s| {
        s.has_metadata
    })?;
    ensure!(st.name == "dhtmagnet.bin", "name {}", st.name);
    let st = client.wait_for(Duration::from_secs(120), "download via DHT", |s| s.complete)?;
    ensure!(
        st.events.iter().any(|e| e.starts_with("DhtPeers")),
        "no DhtPeers event: {:?}",
        st.events
    );
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    client.shutdown()?;
    Ok(())
}

/// Mirror: we seed and announce; the oracle (DHT only) finds and downloads
/// from us.
fn dht_seed_to_oracle(ctx: &mut Ctx) -> Result<()> {
    let d = router(ctx, 2)?;
    let d_addr = d.local_addrs()[0];
    let fx = dht_fixture("dhtseed.bin");
    let torrent_path = ctx.file("dhtseed.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    // Data in place before launch: the client checks it on add and seeds.
    let actor = ctx.actor("urt")?;
    let save = actor.log_dir.join("data");
    std::fs::create_dir_all(&save)?;
    fx.write_data(&save)?;
    let mut client =
        crate::client::UrtClient::launch(&actor, dht_client_config(&[d_addr]), &torrent_path)?;
    client.wait_for(Duration::from_secs(60), "our seed", |s| s.complete)?;
    let our_ip = client.actor.addr();
    ensure!(
        d.wait_for(Duration::from_secs(60), |e| e
            .iter()
            .any(|e| e.is_query_from("announce_peer", our_ip))),
        "we never announced to the router"
    );
    let mut cfg = OracleConfig::primary()
        .dht(true)
        .encryption(Encryption::Disable);
    cfg.extra_session_settings
        .push(("DHTBootstrapNodes".into(), fmt_hostport(d_addr)));
    let oracle = ctx.oracle("oracle", cfg)?;
    let h = fx.info_hash_hex();
    oracle.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
        &h,
    )?;
    oracle
        .api
        .wait_for(&h, Duration::from_secs(120), "oracle leech via DHT", |t| {
            t.is_complete()
        })?;
    let st = client.status().unwrap_or_default();
    ensure!(
        st.events.iter().any(|e| e.starts_with("PeerConnected")),
        "the oracle never connected to us: {:?}",
        st.events
    );
    client.shutdown()?;
    Ok(())
}

/// Differential: the `capture_dht` setup, oracle then us (qbt profile), with
/// the DHT fingerprint (bootstrap / lookup / announce shapes, replies to the
/// probes, `port` position) compared L1/L2.
fn dht_shape(ctx: &mut Ctx) -> Result<()> {
    use crate::discriminator::{self, Fingerprint};
    let d1_ip = ctx.host_alias(2)?;
    let d2_ip = ctx.host_alias(3)?;
    let peer_ip = ctx.host_alias(4)?;
    let fx = dht_fixture("dhtshape.bin");
    let peer_addr = SocketAddr::new(peer_ip, 6890);
    let mut res = [0u8; 8];
    reserved::set(&mut res, reserved::LTEP);
    reserved::set(&mut res, reserved::FAST);
    reserved::set(&mut res, reserved::DHT);

    // One run of the capture setup for `who`; returns the fingerprint.
    let run = |ctx: &mut Ctx, who: &str| -> Result<Fingerprint> {
        let d2 = TapDht::start(
            TapDhtConfig::new(vec![SocketAddr::new(d2_ip, 6881)]).node_id([0x22; 20]),
        )?;
        let d1 = TapDht::start(
            TapDhtConfig::new(vec![SocketAddr::new(d1_ip, 6881)])
                .node_id([0x11; 20])
                .node([0x22; 20], SocketAddr::new(d2_ip, 6881))
                .peer(fx.info_hash, peer_addr),
        )?;
        let tap_peer = TapPeer::start(
            TapPeerConfig::new(fx.info_hash, Role::Seeder)
                .listen(vec![peer_addr])
                .bind_addr(peer_ip)
                .fixture(fx.clone())
                .reserved(res)
                .encryption(TapEncryption::Disabled)
                .linger(Duration::from_secs(30)),
        )?;
        let (ip, node) = if who == "oracle" {
            let mut cfg = OracleConfig::primary()
                .dht(true)
                .encryption(Encryption::Disable);
            cfg.extra_session_settings.push((
                "DHTBootstrapNodes".into(),
                fmt_hostport(SocketAddr::new(d1_ip, 6881)),
            ));
            let mut oracle = ctx.oracle("oracle", cfg)?;
            let h = fx.info_hash_hex();
            oracle.api.add_torrent(
                &AddTorrent::file(&fx.torrent).save_path(&oracle.save_path.to_string_lossy()),
                &h,
            )?;
            oracle
                .api
                .wait_for(&h, Duration::from_secs(120), "oracle leech via DHT", |t| {
                    t.is_complete()
                })?;
            ensure!(
                d1.wait_for(Duration::from_secs(60), |e| e
                    .iter()
                    .filter(|e| e.is_query_from("announce_peer", oracle.actor.addr()))
                    .count()
                    >= 2),
                "oracle: fewer than two announces (leech + seed)"
            );
            let probes = probe_node(
                &d1,
                SocketAddr::new(oracle.actor.addr(), 6881),
                fx.info_hash,
            )?;
            std::thread::sleep(Duration::from_secs(3));
            let ip = oracle.actor.addr();
            let cap = tap_peer
                .captures()
                .into_iter()
                .find(|c| c.remote.ip() == ip);
            let fp = discriminator::dht_fingerprint(&d1.events(), &[ip], &probes, cap.as_ref());
            oracle.shutdown()?;
            (ip, fp)
        } else {
            let torrent_path = ctx.file("dhtshape.torrent");
            std::fs::write(&torrent_path, &fx.torrent)?;
            let mut client = ctx.client(
                "urt",
                dht_client_config(&[SocketAddr::new(d1_ip, 6881)]).encryption("disabled"),
                &torrent_path,
            )?;
            client.wait_for(Duration::from_secs(120), "download via DHT", |s| s.complete)?;
            let ip = client.actor.addr();
            ensure!(
                d1.wait_for(Duration::from_secs(60), |e| e
                    .iter()
                    .filter(|e| e.is_query_from("announce_peer", ip))
                    .count()
                    >= 2),
                "us: fewer than two announces (leech + seed)"
            );
            let probes = probe_node(
                &d1,
                SocketAddr::new(ip, client.status().unwrap().listen_port),
                fx.info_hash,
            )?;
            std::thread::sleep(Duration::from_secs(3));
            let cap = tap_peer
                .captures()
                .into_iter()
                .find(|c| c.remote.ip() == ip);
            let fp = discriminator::dht_fingerprint(&d1.events(), &[ip], &probes, cap.as_ref());
            client.shutdown()?;
            (ip, fp)
        };
        let p = ctx.file(&format!("tap-dht-{who}.jsonl"));
        d1.save_jsonl(&p)?;
        ctx.artifact(&format!("tap-dht-{who}.jsonl"), &p);
        let p = ctx.file(&format!("tap-dht2-{who}.jsonl"));
        d2.save_jsonl(&p)?;
        ctx.artifact(&format!("tap-dht2-{who}.jsonl"), &p);
        ctx.note(format!("{who} ({ip}): {node:?}"));
        Ok(Fingerprint {
            dht: node,
            ..Default::default()
        })
    };

    let oracle_fp = run(ctx, "oracle")?;
    let ours = run(ctx, "us")?;
    let diffs = discriminator::diff(&oracle_fp, &ours);
    for d in &diffs {
        ctx.note(format!("DIFF {d}"));
    }
    ensure!(diffs.is_empty(), "L1/L2 DHT differences: {diffs:?}");
    Ok(())
}
