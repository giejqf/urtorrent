// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 29 uTP: the header/extension parser and a live connection's whole
//! incoming path. The first byte selects the target state (a fresh
//! acceptor, a connecting socket, or an established pair); the rest is the
//! hostile datagram. Nothing may panic, and the socket must keep
//! accounting sane (no negative in-flight bytes, bounded buffers).

#![no_main]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use utp::{Clock, Config, Header, Manager, Socket};

struct Lcg(u64);
impl profile::Rng for Lcg {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (self.0 >> 33) as u32
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, pkt)) = data.split_first() else {
        return;
    };
    let _ = Header::parse(pkt);
    if let Some(h) = Header::parse(pkt) {
        let _ = utp::header::walk_extensions(&h, pkt, |_, _| {});
    }
    let now = Instant::now();
    let clock = Clock::new(now, 7);
    let mut rng = Lcg(3);
    let a: SocketAddr = "10.1.2.3:6881".parse().unwrap();
    let b: SocketAddr = "10.1.2.4:6881".parse().unwrap();
    match mode % 3 {
        0 => {
            let mut m = Manager::new(Config::default(), clock, true, 64);
            m.incoming(a, pkt, now, &mut rng);
            m.drained(now);
            m.tick(now + Duration::from_secs(5));
            let _ = m.poll_outgoing();
        }
        1 => {
            let mut s = Socket::connect(Config::default(), clock, b, 0x1000, 1472, now, &mut rng);
            let _ = s.poll_outgoing();
            s.incoming(b, pkt, now, &mut rng);
            s.write(vec![1; 3000], now);
            s.tick(now + Duration::from_secs(4));
            while s.poll_outgoing().is_some() {}
            while s.read().is_some() {}
        }
        _ => {
            // An established pair: the packet is aimed at A (id patched in).
            let mut ma = Manager::new(Config::default(), clock, true, 64);
            let mut mb = Manager::new(Config::default(), clock, true, 64);
            let ka = ma.connect(b, now, &mut rng);
            let mut t = now;
            for _ in 0..4 {
                for (to, o) in ma.poll_outgoing() {
                    mb.incoming(a, &o.data, t, &mut rng);
                    let _ = to;
                }
                mb.drained(t);
                for (_, o) in mb.poll_outgoing() {
                    ma.incoming(b, &o.data, t, &mut rng);
                }
                ma.drained(t);
                if let Some(s) = ma.get_mut(ka) {
                    s.write(vec![2; 5000], t);
                }
                t += Duration::from_millis(10);
            }
            let mut p = pkt.to_vec();
            if p.len() >= 4 && mode & 0x80 != 0 {
                p[0] = (p[0] & 0xf0) | 1;
                p[2..4].copy_from_slice(&ka.0.to_be_bytes());
            }
            ma.incoming(b, &p, t, &mut rng);
            ma.drained(t);
            if let Some(s) = ma.get_mut(ka) {
                s.write(vec![3; 100], t);
                let _ = s.bytes_in_flight();
                while s.read().is_some() {}
            }
            ma.tick(t + Duration::from_secs(70));
            let _ = ma.poll_outgoing();
            ma.detach(ka, t);
            ma.tick(t + Duration::from_secs(140));
        }
    }
});
