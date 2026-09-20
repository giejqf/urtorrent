// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 5 KRPC datagram parser, plus the whole node's incoming path (a
//! hostile datagram must never panic or make the node misbehave), and an
//! encode/decode round trip of whatever parsed.

#![no_main]

use std::net::SocketAddr;
use std::time::Instant;

use dht::krpc::{self, Message};
use libfuzzer_sys::fuzz_target;

struct Lcg(u64);
impl profile::Rng for Lcg {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (self.0 >> 33) as u32
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = krpc::decode(data) {
        let from: SocketAddr = "10.1.2.3:6881".parse().unwrap();
        let again = match &m {
            Message::Query(q) => krpc::encode_query(q),
            Message::Response(r) => {
                krpc::encode_response(&r.tid, from, &r.reply, r.version.as_deref())
            }
            Message::Error(e) => krpc::encode_error(
                &e.tid,
                e.code,
                &e.message,
                e.r.map(|(id, _)| (id, from)),
                e.version.as_deref(),
            ),
        };
        let _ = krpc::decode(&again).expect("our own encoding parses");
    }
    let _ = krpc::decode_query_head(data);
    let now = Instant::now();
    let mut rng = Lcg(1);
    let mut node = dht::Node::new(dht::Config::default(), false, now, &mut rng);
    let from: SocketAddr = "10.9.8.7:6881".parse().unwrap();
    node.incoming(from, data, now, &mut rng, None);
    while node.poll_action().is_some() {}
    node.tick(now + std::time::Duration::from_secs(20), &mut rng);
});
