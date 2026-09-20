// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Replay the golden oracle captures (AGENTS.md 7.1 layer 4) through the wire
//! state machine: every frame the oracle sent must decode, the whole stream
//! must drive a `Connection` without a protocol error, and our LTEP handshake
//! under the qbt profile must be byte-exact with the oracle's.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::path::PathBuf;

use metainfo::Bitfield;
use serde_json::Value;
use wire::{Connection, ConnectionParams, Event, ExtHandshake, Handshake, Message, Role};

fn golden(rel: &str) -> Option<Vec<Value>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testkit/golden")
        .join(rel);
    let text = std::fs::read_to_string(p).ok()?;
    Some(
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect(),
    )
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hs_from_hex(hex: &str) -> Handshake {
    Handshake::parse(&unhex(hex)).unwrap().unwrap()
}

/// Every message the oracle sent (as recorded raw) decodes.
#[test]
fn every_captured_frame_decodes() {
    let mut frames = 0;
    for file in [
        "capture_peer_plain/v4/tap-peer-plain-oracle-initiator.jsonl",
        "capture_peer_plain/v4/tap-peer-plain-oracle-responder.jsonl",
        "capture_peer_plain/v6/tap-peer-plain-oracle-initiator.jsonl",
        "capture_peer_plain/v6/tap-peer-plain-oracle-responder.jsonl",
        "capture_defaults/v4/tap-peer-defaults.jsonl",
    ] {
        let Some(conns) = golden(file) else { continue };
        for c in conns {
            for ev in c["events"].as_array().unwrap() {
                if ev["dir"] != "recv" || ev["kind"] == "handshake" {
                    continue;
                }
                let Some(raw) = ev["raw_hex"].as_str() else {
                    continue;
                };
                let bytes = unhex(raw);
                let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
                assert_eq!(len + 4, bytes.len(), "{file}: frame length");
                let msg = Message::decode(&bytes[4..])
                    .unwrap_or_else(|e| panic!("{file}: {} failed to decode: {e}", ev["kind"]));
                assert_eq!(kind_name(&msg), ev["kind"].as_str().unwrap(), "{file}");
                frames += 1;
            }
        }
    }
    assert!(frames > 100, "decoded {frames} frames");
}

fn kind_name(m: &Message) -> &'static str {
    match m {
        Message::KeepAlive => "keep_alive",
        Message::Choke => "choke",
        Message::Unchoke => "unchoke",
        Message::Interested => "interested",
        Message::NotInterested => "not_interested",
        Message::Have(_) => "have",
        Message::Bitfield(_) => "bitfield",
        Message::Request(_) => "request",
        Message::Piece { .. } => "piece",
        Message::Cancel(_) => "cancel",
        Message::Port(_) => "port",
        Message::Suggest(_) => "suggest",
        Message::HaveAll => "have_all",
        Message::HaveNone => "have_none",
        Message::Reject(_) => "reject",
        Message::AllowedFast(_) => "allowed_fast",
        Message::Extended { .. } => "extended",
    }
}

/// Play the tap-peer's side of the oracle-initiator capture: the oracle
/// connects to us (seeder), we unchoke, it requests every block.
#[test]
fn replay_oracle_leeching_from_us() {
    let Some(conns) = golden("capture_peer_plain/v4/tap-peer-plain-oracle-initiator.jsonl") else {
        eprintln!("golden capture missing; skipping");
        return;
    };
    let c = conns
        .iter()
        .find(|c| c["handshake"].is_object())
        .expect("a connection with a handshake");
    let peer_hs = hs_from_hex(c["handshake"]["raw_hex"].as_str().unwrap());
    // 2 MiB / 64 KiB = 32 pieces in the fixture.
    let pieces = 32usize;
    let mut conn = Connection::new(ConnectionParams {
        role: Role::Responder,
        info_hash: peer_hs.info_hash,
        our_peer_id: *b"-TP0001-784722000000",
        profile: profile::Profile::qbt_5_2_3_lt2_0_14(),
        piece_count: Some(pieces),
        our_have: Bitfield::all_set(pieces),
        listen_port: 6890,
        peer_ip: c["remote"]
            .as_str()
            .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
            .map(|a| a.ip()),
        metadata_size: Some(714),
    });
    let mut requests = 0;
    let mut haves = 0;
    let mut got_ext = false;
    for ev in c["events"].as_array().unwrap() {
        if ev["dir"] != "recv" {
            continue;
        }
        let bytes = unhex(ev["raw_hex"].as_str().unwrap());
        let events = conn
            .receive(&bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", ev["kind"]));
        for e in events {
            match e {
                Event::Handshaked { .. } => {
                    assert!(conn.ltep() && conn.fast());
                    // As the tap-peer did: unchoke right away.
                    conn.choke(false);
                }
                Event::ExtHandshake(ext) => {
                    got_ext = true;
                    assert_eq!(ext.v.as_deref(), Some("qBittorrent/5.2.3"));
                    assert_eq!(ext.reqq, Some(2000));
                    assert_eq!(ext.p, Some(6881));
                    assert_eq!(ext.peer_id_for("ut_pex"), Some(1));
                    assert_eq!(ext.peer_id_for("ut_holepunch"), Some(4));
                }
                Event::Request(r) => {
                    requests += 1;
                    conn.piece(r, &vec![0u8; r.length as usize]);
                }
                Event::HaveChanged => haves += 1,
                Event::Interested | Event::NotInterested | Event::KeepAlive => {}
                other => panic!("unexpected event {other:?}"),
            }
        }
    }
    assert!(got_ext);
    assert_eq!(requests, 128, "4 blocks x 32 pieces");
    // have_none + 32 haves
    assert_eq!(haves, 33);
    assert!(conn.peer_have().is_seed(pieces));
    assert!(conn.incoming_requests().is_empty());
}

/// Our LTEP handshake under the qbt profile is byte-exact with the oracle's
/// (given the same connection facts: outgoing, port 6881, yourip,
/// metadata_size), both leeching and seeding.
///
/// The v6 initiator capture is the documented exception (docs/quirks.md Q6):
/// the lab's ULA prefix has no internet route, so libtorrent treats its v6
/// listen socket as "local network" and omits `p`. The test pins that the
/// *only* difference is the missing `p`, so the quirk stays visible.
#[test]
fn qbt_ltep_handshake_is_byte_exact() {
    let profile = profile::Profile::qbt_5_2_3_lt2_0_14();
    // (file, outgoing, seeding, oracle listen port is routable)
    let cases = [
        (
            "capture_peer_plain/v4/tap-peer-plain-oracle-initiator.jsonl",
            true,
            false,
            true,
        ),
        (
            "capture_peer_plain/v4/tap-peer-plain-oracle-responder.jsonl",
            false,
            true,
            true,
        ),
        (
            "capture_peer_plain/v6/tap-peer-plain-oracle-initiator.jsonl",
            true,
            false,
            false,
        ),
        (
            "capture_peer_plain/v6/tap-peer-plain-oracle-responder.jsonl",
            false,
            true,
            false,
        ),
    ];
    let mut checked = 0;
    for (file, outgoing, seeding, routable) in cases {
        let Some(conns) = golden(file) else { continue };
        for c in conns.iter().filter(|c| c["handshake"].is_object()) {
            let ext_ev = c["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["dir"] == "recv" && e["kind"] == "extended")
                .expect("oracle ext handshake");
            let oracle_payload = unhex(ext_ev["detail"]["raw_hex"].as_str().unwrap());
            let oracle = ExtHandshake::parse(&oracle_payload).unwrap();
            // The facts the handshake depends on, taken from the capture.
            let yourip: Option<IpAddr> = oracle.yourip;
            let mut ours = ExtHandshake::build(
                &profile.ltep,
                profile.ltep_version,
                outgoing,
                6881,
                yourip,
                oracle.metadata_size,
                seeding,
            );
            if outgoing && !routable {
                // Q6: the oracle omitted `p` here. Pin it.
                assert_eq!(oracle.p, None, "{file}: Q6 no longer holds");
                ours.p = None;
            }
            assert_eq!(
                bencode::hex(&ours.encode()),
                bencode::hex(&oracle_payload),
                "{file}: LTEP handshake differs"
            );
            checked += 1;
        }
    }
    assert!(checked >= 2, "checked {checked} handshakes");
}

/// The oracle's handshake reserved bytes match the qbt profile.
#[test]
fn qbt_reserved_bits_match_capture() {
    let Some(conns) = golden("capture_peer_plain/v4/tap-peer-plain-oracle-initiator.jsonl") else {
        return;
    };
    let c = conns.iter().find(|c| c["handshake"].is_object()).unwrap();
    let hs = hs_from_hex(c["handshake"]["raw_hex"].as_str().unwrap());
    assert_eq!(
        hs.reserved,
        profile::Profile::qbt_5_2_3_lt2_0_14().peer.reserved
    );
    assert!(hs.peer_id.starts_with(b"-qB5230-"));
}

/// The oracle's `allowed_fast` grants to tap-peer equal our BEP 6 set for the
/// same address, info-hash and piece count, in the same order.
#[test]
fn allowed_fast_set_matches_oracle() {
    let mut checked = 0;
    for file in [
        "capture_peer_plain/v4/tap-peer-plain-oracle-responder.jsonl",
        "capture_peer_plain/v6/tap-peer-plain-oracle-responder.jsonl",
    ] {
        let Some(conns) = golden(file) else { continue };
        for c in conns.iter().filter(|c| c["handshake"].is_object()) {
            let hs = hs_from_hex(c["handshake"]["raw_hex"].as_str().unwrap());
            let local: std::net::SocketAddr = c["local"].as_str().unwrap().parse().unwrap();
            let granted: Vec<u32> = c["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| e["dir"] == "recv" && e["kind"] == "allowed_fast")
                .map(|e| e["detail"]["index"].as_u64().unwrap() as u32)
                .collect();
            if granted.is_empty() {
                continue;
            }
            // Fixture B: 1 MiB / 64 KiB = 16 pieces. Q7: the oracle seeds the
            // set with the full address, not the BEP 6 /24.
            let ours = wire::allowed_fast_set(
                local.ip(),
                &hs.info_hash,
                16,
                granted.len() as u32,
                profile::Profile::qbt_5_2_3_lt2_0_14()
                    .peer
                    .allowed_fast_addr,
            );
            assert_eq!(ours, granted, "{file}: allowed-fast set differs");
            let bep = wire::allowed_fast_set(
                local.ip(),
                &hs.info_hash,
                16,
                granted.len() as u32,
                profile::AllowedFastAddr::Bep6Masked,
            );
            assert_ne!(bep, granted, "{file}: Q7 no longer holds");
            checked += 1;
        }
    }
    assert!(checked >= 1, "no capture with allowed_fast grants");
}
