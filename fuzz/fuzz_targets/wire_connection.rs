// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The connection state machine fed arbitrary bytes after a valid handshake
//! (first byte selects the peer's reserved bits): must never panic, and every
//! error must be a clean `Protocol`/`TooLarge`/`InfoHashMismatch`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use metainfo::Bitfield;
use wire::{Connection, ConnectionParams, Handshake, Role};

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let pieces = 1 + (flags as usize % 40);
    let mut conn = Connection::new(ConnectionParams {
        role: if flags & 1 == 0 {
            Role::Initiator
        } else {
            Role::Responder
        },
        info_hash: [3; 20],
        our_peer_id: *b"-UR0010-fuzzfuzzfuzz",
        profile: profile::Profile::qbt_5_2_3_lt2_0_14(),
        piece_count: if flags & 2 == 0 { Some(pieces) } else { None },
        piece_length: if flags & 2 == 0 { Some(32 * 1024) } else { None },
        our_have: Bitfield::new(pieces),
        listen_port: 6881,
        peer_ip: None,
        metadata_size: Some(100),
        advertise_port: true,
        private: false,
        dht_port: None,
    });
    let hs = Handshake {
        reserved: [0, 0, 0, 0, 0, if flags & 4 != 0 { 0x10 } else { 0 }, 0, if flags & 8 != 0 { 0x05 } else { 0 }],
        info_hash: [3; 20],
        peer_id: [b'x'; 20],
    };
    let _ = conn.take_outbound();
    if conn.receive(&hs.encode()).is_err() {
        return;
    }
    // Exercise the outgoing side too so bookkeeping is non-trivial.
    conn.choke(false);
    conn.interested(true);
    let _ = conn.request(wire::Request {
        index: 0,
        begin: 0,
        length: 16384,
    });
    // Chunk size varies so frames arrive whole (parsed in place), cut across
    // chunks (assembled by the framer) and byte by byte.
    let chunk_len = match flags >> 4 {
        0..=3 => 1,
        4..=7 => 7,
        8..=11 => 64,
        _ => rest.len().max(1),
    };
    for chunk in rest.chunks(chunk_len) {
        match conn.receive(chunk) {
            Ok(_) => {}
            Err(_) => break,
        }
        let _ = conn.take_outbound();
    }
});
