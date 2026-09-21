// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! 0.4.0 (uTP, BEP 29) scenarios. Capture first: two oracles restricted to
//! uTP transfer a torrent while a pcap on the lab bridge records every
//! datagram; the decoded uTP headers are the golden shape (SYN, first
//! packets, extensions, window and MTU behaviour, FIN).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};

use super::{Ctx, ScenarioDef, Tag};
use crate::capture::Pcap;
use crate::client::ClientConfig;
use crate::fixtures::{Fixture, FixtureSpec};
use crate::lab::Shape;
use crate::oracle::{BtProtocol, Encryption, OracleConfig};
use crate::tap::tracker::{TapTracker, TapTrackerConfig};
use crate::utp_capture::{self, UtpRecord};
use crate::webapi::AddTorrent;

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "capture_utp",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It, Tag::Capture],
            run: capture_utp,
        },
        ScenarioDef {
            name: "utp_leech_from_oracle",
            shapes: &[Shape::V4, Shape::V6, Shape::Dual],
            tags: &[Tag::It],
            run: utp_leech_from_oracle,
        },
        ScenarioDef {
            name: "utp_seed_to_oracle",
            shapes: &[Shape::V4, Shape::V6],
            tags: &[Tag::It],
            run: utp_seed_to_oracle,
        },
        ScenarioDef {
            name: "utp_shape",
            shapes: &[Shape::V4],
            tags: &[Tag::It, Tag::Diff],
            run: utp_shape,
        },
    ]
}

/// Wait until `ip` has announced to the tap tracker (so the next announce
/// from another peer gets it back).
fn wait_announced(tracker: &TapTracker, ip: IpAddr) -> Result<()> {
    ensure!(
        tracker.wait_for(Duration::from_secs(30), |ev| ev
            .iter()
            .any(|e| e.kind == "announce" && e.from.ip() == ip)),
        "{ip} never announced"
    );
    Ok(())
}

/// Stop a pcap and decode its uTP packets.
fn finish_pcap(pcap: &mut Option<Pcap>, path: &std::path::Path) -> Result<Vec<UtpRecord>> {
    if let Some(p) = pcap.as_mut() {
        p.stop();
    }
    std::thread::sleep(Duration::from_millis(500));
    utp_capture::read_utp(path)
}

/// We are uTP-only and leech from an oracle seeder with both transports
/// enabled: the connection must run over uTP (our dial), the data must
/// arrive intact, and the oracle must see a uTP peer.
fn utp_leech_from_oracle(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker_http(ctx)?;
    let fx = utp_fixture("utpleech.bin", &tracker.http_url(0));
    let h = fx.info_hash_hex();
    let pcap_path = ctx.file("utp.pcap");
    let mut pcap = Pcap::start(ctx.lab.bridge(), &pcap_path, "udp and not port 6771")?;
    let seeder = ctx.oracle(
        "seeder",
        OracleConfig::primary()
            .protocol(BtProtocol::Both)
            .lsd(false),
    )?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder seeding", |t| {
            t.is_seeding()
        })?;
    wait_announced(&tracker, seeder.actor.addr())?;
    let torrent_path = ctx.file("utpleech.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let mut client = ctx.client(
        "urt",
        ClientConfig::default()
            .profile("qbt")
            .lsd(false)
            .protocol("utp"),
        &torrent_path,
    )?;
    let st = client.wait_for(Duration::from_secs(120), "download over uTP", |s| {
        s.complete
    })?;
    fx.verify_data(&client.save_path)?
        .map_err(|e| anyhow::anyhow!("client data mismatch: {e}"))?;
    let peers = seeder.api.peers(&h)?;
    ctx.note(format!(
        "oracle's view of us: {:?}",
        peers
            .iter()
            .map(|p| format!("{}:{} {} conn={}", p.ip, p.port, p.client, p.connection))
            .collect::<Vec<_>>()
    ));
    let ours: Vec<String> = st
        .peers_seen
        .iter()
        .chain(st.peer_list.iter())
        .map(|p| format!("{} {} incoming={}", p.addr, p.transport, p.incoming))
        .collect();
    ctx.note(format!("our peers: {ours:?}"));
    // Both ends dial uTP first (libtorrent assumes support), so either
    // direction may win; the transport must be uTP either way.
    ensure!(
        st.peers_seen
            .iter()
            .chain(st.peer_list.iter())
            .any(|p| p.transport == "Utp"),
        "no uTP connection recorded: {ours:?}"
    );
    ensure!(
        !st.peers_seen
            .iter()
            .chain(st.peer_list.iter())
            .any(|p| p.transport == "Tcp"),
        "a TCP connection slipped through with TCP disabled: {ours:?}"
    );
    std::thread::sleep(Duration::from_secs(2));
    client.shutdown()?;
    let records = finish_pcap(&mut pcap, &pcap_path)?;
    let jsonl = ctx.file("utp-packets.jsonl");
    utp_capture::save_jsonl(&records, &jsonl)?;
    ctx.artifact("utp-packets.jsonl", &jsonl);
    let our_ips = client.actor.addrs();
    for line in summarise(&records, &our_ips, &seeder.actor.addrs()) {
        ctx.note(line);
    }
    ensure!(
        records
            .iter()
            .any(|r| r.kind == "syn" && our_ips.contains(&r.src.ip())),
        "our SYN is not in the capture"
    );
    ensure!(
        records
            .iter()
            .any(|r| r.kind == "data" && seeder.actor.addrs().contains(&r.src.ip())),
        "no ST_DATA from the oracle in the capture"
    );
    Ok(())
}

/// We seed (both transports); an oracle restricted to uTP finds us through
/// the tracker and dials us over uTP: our acceptor path.
fn utp_seed_to_oracle(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker_http(ctx)?;
    let fx = utp_fixture("utpseed.bin", &tracker.http_url(0));
    let h = fx.info_hash_hex();
    let pcap_path = ctx.file("utp.pcap");
    let mut pcap = Pcap::start(ctx.lab.bridge(), &pcap_path, "udp and not port 6771")?;
    let torrent_path = ctx.file("utpseed.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;
    let actor = ctx.actor("urt")?;
    fx.write_data(&actor.log_dir.join("data"))?;
    let mut client = crate::client::UrtClient::launch(
        &actor,
        ClientConfig::default().profile("qbt").lsd(false),
        &torrent_path,
    )?;
    client.wait_for(Duration::from_secs(60), "seeding", |s| s.complete)?;
    wait_announced(&tracker, client.actor.addr())?;
    let leecher = ctx.oracle(
        "leecher",
        OracleConfig::primary().protocol(BtProtocol::Utp).lsd(false),
    )?;
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    leecher.api.wait_for(
        &h,
        Duration::from_secs(120),
        "oracle (uTP only) to complete from us",
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
    std::thread::sleep(Duration::from_secs(2));
    let st = client
        .status()
        .ok_or_else(|| anyhow::anyhow!("no client status"))?;
    let ours: Vec<String> = st
        .peers_seen
        .iter()
        .chain(st.peer_list.iter())
        .map(|p| format!("{} {} incoming={}", p.addr, p.transport, p.incoming))
        .collect();
    ctx.note(format!("our peers: {ours:?}"));
    ensure!(
        st.peers_seen
            .iter()
            .chain(st.peer_list.iter())
            .any(|p| p.transport == "Utp" && p.incoming),
        "no incoming uTP connection recorded: {ours:?}"
    );
    ctx.note(format!(
        "uploaded={} utp_connections={}",
        st.uploaded, st.utp_connections
    ));
    ensure!(
        st.uploaded >= fx.total_len,
        "uploaded {} < {}",
        st.uploaded,
        fx.total_len
    );
    client.shutdown()?;
    let records = finish_pcap(&mut pcap, &pcap_path)?;
    let jsonl = ctx.file("utp-packets.jsonl");
    utp_capture::save_jsonl(&records, &jsonl)?;
    ctx.artifact("utp-packets.jsonl", &jsonl);
    let our_ips = client.actor.addrs();
    for line in summarise(&records, &our_ips, &leecher.actor.addrs()) {
        ctx.note(line);
    }
    ensure!(
        records
            .iter()
            .any(|r| r.kind == "syn" && our_ips.contains(&r.dst.ip())),
        "the oracle's SYN is not in the capture"
    );
    Ok(())
}

/// Differential: the uTP shapes of the oracle and of us, in both roles.
/// Leech phase: an oracle seeder (both transports) is dialled over uTP by
/// the client under test (connector shapes: SYN, first data). Seed phase:
/// the client under test seeds and an oracle leecher (uTP only) dials it
/// (acceptor shapes: SYN-ACK, first data, MTU ladder, FIN). The two
/// fingerprints merge into one per client and must not differ.
fn utp_shape(ctx: &mut Ctx) -> Result<()> {
    use crate::discriminator::{self, Fingerprint, UtpFingerprint};
    let tracker = tap_tracker_http(ctx)?;
    let fx = utp_fixture("utpshape.bin", &tracker.http_url(0));
    let h = fx.info_hash_hex();
    let torrent_path = ctx.file("utpshape.torrent");
    std::fs::write(&torrent_path, &fx.torrent)?;

    // Leech phase for `who`: returns the connector fingerprint.
    let leech = |ctx: &mut Ctx, who: &str| -> Result<UtpFingerprint> {
        let pcap_path = ctx.file(&format!("leech-{who}.pcap"));
        let mut pcap = Pcap::start(ctx.lab.bridge(), &pcap_path, "udp and not port 6771")?;
        let seeder = ctx.oracle(
            &format!("sl-{who}"),
            OracleConfig::primary()
                .protocol(BtProtocol::Both)
                .encryption(Encryption::Disable)
                .lsd(false),
        )?;
        fx.write_data(&seeder.save_path)?;
        seeder.api.add_torrent(
            &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
            &h,
        )?;
        seeder
            .api
            .wait_for(&h, Duration::from_secs(60), "seeder seeding", |t| {
                t.is_seeding()
            })?;
        wait_announced(&tracker, seeder.actor.addr())?;
        let ips = if who == "oracle" {
            let mut leecher = ctx.oracle(
                &format!("ll-{who}"),
                OracleConfig::primary()
                    .protocol(BtProtocol::Utp)
                    .encryption(Encryption::Disable)
                    .lsd(false),
            )?;
            leecher.api.add_torrent(
                &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
                &h,
            )?;
            leecher
                .api
                .wait_for(&h, Duration::from_secs(120), "oracle leech over uTP", |t| {
                    t.is_complete()
                })?;
            std::thread::sleep(Duration::from_secs(3));
            let ips = leecher.actor.addrs();
            leecher.shutdown()?;
            ips
        } else {
            let mut client = ctx.client(
                "ul-us",
                ClientConfig::default()
                    .profile("qbt")
                    .lsd(false)
                    .encryption("disabled")
                    .protocol("utp"),
                &torrent_path,
            )?;
            client.wait_for(Duration::from_secs(120), "our leech over uTP", |s| {
                s.complete
            })?;
            std::thread::sleep(Duration::from_secs(3));
            let ips = client.actor.addrs();
            client.shutdown()?;
            ips
        };
        let mut seeder = seeder;
        seeder.shutdown()?;
        let records = finish_pcap(&mut pcap, &pcap_path)?;
        let jsonl = ctx.file(&format!("leech-{who}.jsonl"));
        utp_capture::save_jsonl(&records, &jsonl)?;
        ctx.artifact(&format!("leech-{who}.jsonl"), &jsonl);
        let fp = discriminator::utp_fingerprint(&records, &ips)
            .ok_or_else(|| anyhow::anyhow!("{who}: no uTP packets from the leecher"))?;
        ctx.note(format!("{who} as connector: {fp:?}"));
        Ok(fp)
    };

    // Seed phase for `who`: returns the acceptor fingerprint.
    let seed = |ctx: &mut Ctx, who: &str| -> Result<UtpFingerprint> {
        let pcap_path = ctx.file(&format!("seed-{who}.pcap"));
        let mut pcap = Pcap::start(ctx.lab.bridge(), &pcap_path, "udp and not port 6771")?;
        let (ips, mut stop): (Vec<IpAddr>, Box<dyn FnMut() -> Result<()>>) = if who == "oracle" {
            let mut seeder = ctx.oracle(
                &format!("ss-{who}"),
                OracleConfig::primary()
                    .protocol(BtProtocol::Both)
                    .encryption(Encryption::Disable)
                    .lsd(false),
            )?;
            fx.write_data(&seeder.save_path)?;
            seeder.api.add_torrent(
                &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
                &h,
            )?;
            seeder
                .api
                .wait_for(&h, Duration::from_secs(60), "seeder seeding", |t| {
                    t.is_seeding()
                })?;
            wait_announced(&tracker, seeder.actor.addr())?;
            let ips = seeder.actor.addrs();
            (ips, Box::new(move || seeder.shutdown()))
        } else {
            let actor = ctx.actor("us-us")?;
            fx.write_data(&actor.log_dir.join("data"))?;
            let mut client = crate::client::UrtClient::launch(
                &actor,
                ClientConfig::default()
                    .profile("qbt")
                    .lsd(false)
                    .encryption("disabled"),
                &torrent_path,
            )?;
            client.wait_for(Duration::from_secs(60), "seeding", |s| s.complete)?;
            wait_announced(&tracker, client.actor.addr())?;
            let ips = client.actor.addrs();
            (ips, Box::new(move || client.shutdown()))
        };
        let mut leecher = ctx.oracle(
            &format!("ls-{who}"),
            OracleConfig::primary()
                .protocol(BtProtocol::Utp)
                .encryption(Encryption::Disable)
                .lsd(false),
        )?;
        leecher.api.add_torrent(
            &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
            &h,
        )?;
        leecher.api.wait_for(
            &h,
            Duration::from_secs(120),
            "oracle leech from the seeder",
            |t| t.is_complete(),
        )?;
        // Two seeds part on their own; give the FIN exchange a moment.
        std::thread::sleep(Duration::from_secs(4));
        leecher.shutdown()?;
        stop()?;
        let records = finish_pcap(&mut pcap, &pcap_path)?;
        let jsonl = ctx.file(&format!("seed-{who}.jsonl"));
        utp_capture::save_jsonl(&records, &jsonl)?;
        ctx.artifact(&format!("seed-{who}.jsonl"), &jsonl);
        let fp = discriminator::utp_fingerprint(&records, &ips)
            .ok_or_else(|| anyhow::anyhow!("{who}: no uTP packets from the seeder"))?;
        ctx.note(format!("{who} as acceptor: {fp:?}"));
        Ok(fp)
    };

    // The FIN shapes come from the leech phase, where the client under test
    // closes on its own (upload-to-upload, reason 6). In the seed phase the
    // seeder's close reason depends on a race the oracle itself loses at
    // times: the leecher's last `have` and its FIN can land in one receive
    // round, in which case libtorrent (and we, see utp `end_round`) drop
    // the `have` and close on plain end-of-stream without a reason.
    let merge = |c: UtpFingerprint, a: UtpFingerprint| UtpFingerprint {
        syn_shape: c.syn_shape,
        first_data_shape: c.first_data_shape,
        first_kinds: c.first_kinds,
        initial_wnd: c.initial_wnd,
        syn_ack_shape: a.syn_ack_shape,
        acceptor_first_data: a.acceptor_first_data,
        mtu_ladder: a.mtu_ladder,
        max_datagram: a.max_datagram,
        fin_shape: c.fin_shape,
        fin_ack_ext: c.fin_ack_ext,
        sack_seen: c.sack_seen || a.sack_seen,
    };
    let oracle_fp = Fingerprint {
        utp: Some(merge(leech(ctx, "oracle")?, seed(ctx, "oracle")?)),
        ..Default::default()
    };
    let ours = Fingerprint {
        utp: Some(merge(leech(ctx, "us")?, seed(ctx, "us")?)),
        ..Default::default()
    };
    let diffs = discriminator::diff(&oracle_fp, &ours);
    for d in &diffs {
        ctx.note(format!("DIFF {d}"));
    }
    ensure!(diffs.is_empty(), "L1/L2 uTP differences: {diffs:?}");
    Ok(())
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

fn utp_fixture(name: &str, tracker: &str) -> Arc<Fixture> {
    Arc::new(Fixture::generate(
        FixtureSpec::small(name)
            .with_size(4 << 20)
            .with_piece_length(256 << 10)
            .with_tracker(tracker),
    ))
}

/// Oracle seeder -> oracle leecher, uTP only, cleartext (MSE is orthogonal
/// to the transport and would hide the first payload bytes).
fn capture_utp(ctx: &mut Ctx) -> Result<()> {
    let tracker = tap_tracker_http(ctx)?;
    let fx = utp_fixture("utp.bin", &tracker.http_url(0));
    let h = fx.info_hash_hex();
    let pcap_path = ctx.file("utp.pcap");
    let mut pcap = Pcap::start(ctx.lab.bridge(), &pcap_path, "udp and not port 6771")?;
    ensure!(pcap.is_some(), "tcpdump is required for the uTP capture");

    let cfg = OracleConfig::primary()
        .protocol(BtProtocol::Utp)
        .encryption(Encryption::Disable)
        .lsd(false);
    let seeder = ctx.oracle("seeder", cfg.clone())?;
    fx.write_data(&seeder.save_path)?;
    seeder.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&seeder.save_path.to_string_lossy()),
        &h,
    )?;
    seeder
        .api
        .wait_for(&h, Duration::from_secs(60), "seeder seeding", |t| {
            t.is_seeding()
        })?;
    let leecher = ctx.oracle("leecher", cfg)?;
    leecher.api.add_torrent(
        &AddTorrent::file(&fx.torrent).save_path(&leecher.save_path.to_string_lossy()),
        &h,
    )?;
    leecher.api.wait_for(
        &h,
        Duration::from_secs(120),
        "leecher complete over uTP",
        |t| t.is_complete(),
    )?;
    fx.verify_data(&leecher.save_path)?
        .map_err(|e| anyhow::anyhow!("leecher data mismatch: {e}"))?;
    let peers = leecher.api.peers(&h)?;
    ctx.note(format!(
        "leecher's peers: {:?}",
        peers
            .iter()
            .map(|p| format!("{}:{} {} conn={}", p.ip, p.port, p.client, p.connection))
            .collect::<Vec<_>>()
    ));
    // Two seeds part: the FIN exchange lands in the capture. Then remove the
    // torrent from the leecher so any lingering connection closes too.
    std::thread::sleep(Duration::from_secs(5));
    leecher.api.delete(&h, false)?;
    std::thread::sleep(Duration::from_secs(3));
    let records = finish_pcap(&mut pcap, &pcap_path)?;
    ensure!(!records.is_empty(), "no uTP packets in the capture");
    // The full decode stays in the run directory; the golden is the compact
    // shape summary (the pcap is git-ignored, kept in the run directory).
    let jsonl = ctx.file("utp-packets.jsonl");
    utp_capture::save_jsonl(&records, &jsonl)?;
    let shape = ctx.file("utp-shape.json");
    std::fs::write(
        &shape,
        serde_json::to_string_pretty(&utp_capture::shape_summary(&records))?,
    )?;
    ctx.artifact("utp-shape.json", &shape);

    let seeder_ips = seeder.actor.addrs();
    let leecher_ips = leecher.actor.addrs();
    for line in summarise(&records, &seeder_ips, &leecher_ips) {
        ctx.note(line);
    }
    ensure!(
        records.iter().any(|r| r.kind == "syn"),
        "no uTP SYN in the capture"
    );
    ensure!(
        records
            .iter()
            .any(|r| r.kind == "data" && seeder_ips.contains(&r.src.ip())),
        "the seeder sent no ST_DATA"
    );
    Ok(())
}

/// Human-readable notes about a uTP capture: per-direction packet kinds, the
/// SYN and the first packets of each side, extension use, payload sizes and
/// window sizes.
pub fn summarise(records: &[UtpRecord], a_ips: &[IpAddr], b_ips: &[IpAddr]) -> Vec<String> {
    let side = |ip: IpAddr| {
        if a_ips.contains(&ip) {
            "A"
        } else if b_ips.contains(&ip) {
            "B"
        } else {
            "?"
        }
    };
    let mut out = Vec::new();
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for r in records {
        *kinds
            .entry(format!("{} {}", side(r.src.ip()), r.kind))
            .or_default() += 1;
    }
    out.push(format!("uTP packets by side/kind: {kinds:?}"));
    // Connections: keyed by the SYN's connection id.
    let syns: Vec<&UtpRecord> = records.iter().filter(|r| r.kind == "syn").collect();
    out.push(format!("SYNs: {}", syns.len()));
    for s in syns.iter().take(4) {
        out.push(format!(
            "SYN from {} ({}): conn_id={} seq={} ack={} wnd={} ts_diff={} ext={:?} len={}",
            s.src,
            side(s.src.ip()),
            s.connection_id,
            s.seq_nr,
            s.ack_nr,
            s.wnd_size,
            s.timestamp_diff_us,
            s.extensions,
            s.len
        ));
    }
    // First 12 packets in order.
    for r in records.iter().take(12) {
        out.push(format!(
            "{:>8.4} {}->{} {:<5} id={} seq={} ack={} wnd={} tsd={} ext={:?} sack={:?} pl={} len={}",
            r.ts,
            side(r.src.ip()),
            side(r.dst.ip()),
            r.kind,
            r.connection_id,
            r.seq_nr,
            r.ack_nr,
            r.wnd_size,
            r.timestamp_diff_us,
            r.extensions,
            r.sack_len,
            r.payload_len,
            r.len
        ));
    }
    // Extensions and payload sizes.
    let mut ext_kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut payload_sizes: BTreeMap<usize, usize> = BTreeMap::new();
    let mut wnd: BTreeMap<&str, BTreeMap<u32, usize>> = BTreeMap::new();
    for r in records {
        if !r.extensions.is_empty() {
            *ext_kinds
                .entry(format!(
                    "{} {} ext{:?} sack_len={:?}",
                    side(r.src.ip()),
                    r.kind,
                    r.extensions,
                    r.sack_len
                ))
                .or_default() += 1;
        }
        if r.kind == "data" {
            *payload_sizes.entry(r.payload_len).or_default() += 1;
        }
        *wnd.entry(side(r.src.ip()))
            .or_default()
            .entry(r.wnd_size)
            .or_default() += 1;
    }
    out.push(format!("extensions: {ext_kinds:?}"));
    out.push(format!("ST_DATA payload sizes: {payload_sizes:?}"));
    for (s, m) in &wnd {
        let mut v: Vec<(u32, usize)> = m.iter().map(|(k, v)| (*k, *v)).collect();
        v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        v.truncate(8);
        out.push(format!("wnd_size from {s} (top): {v:?}"));
    }
    // Close: FIN and RESET packets, close reasons.
    for r in records
        .iter()
        .filter(|r| r.kind == "fin" || r.kind == "reset")
    {
        out.push(format!(
            "{:>8.4} {}->{} {} id={} seq={} ack={} ext={:?} close_reason={:?} pl={}",
            r.ts,
            side(r.src.ip()),
            side(r.dst.ip()),
            r.kind,
            r.connection_id,
            r.seq_nr,
            r.ack_nr,
            r.extensions,
            r.close_reason,
            r.payload_len
        ));
    }
    // Acks per data packet (cadence, informational).
    let data = records.iter().filter(|r| r.kind == "data").count();
    let state = records.iter().filter(|r| r.kind == "state").count();
    out.push(format!("ST_DATA {data} vs ST_STATE {state}"));
    // Largest datagram = path MTU probing result.
    if let Some(m) = records.iter().map(|r| r.len).max() {
        out.push(format!("largest uTP datagram: {m} bytes"));
    }
    out
}
