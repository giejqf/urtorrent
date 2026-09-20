// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! External-address voting, ported from libtorrent's `ip_voter`
//! (`src/ip_voter.cpp`, BSD-3; see `NOTICE`). Trackers (`external ip`) and
//! peers (LTEP `yourip`) tell us what address they see us at; one voter per
//! listen-socket family collects those votes and settles on an address once
//! the evidence is consistent enough. libtorrent keeps one voter per listen
//! socket (one per interface address); we listen on the wildcard address per
//! family, so the voter is per family, which is the same thing on a host with
//! one address per family.
//!
//! What the address is used for (docs/quirks.md Q6):
//!
//! - LTEP `p` on outgoing connections is sent only when the family's external
//!   address equals the connection's local address, or is still the default
//!   (v4-unspecified), which only ever matches IPv4 connections;
//! - BEP 40 canonical priority ranks candidates against our external address.
//!
//! Vote rules (libtorrent): unspecified, loopback and local (RFC 1918, link
//! local, ULA) addresses never count; a vote must be of the address's own
//! family; each source may vote once per candidate and once for a new
//! candidate; the first accepted vote sets the address; afterwards a change
//! needs a clear majority and at least 25 votes, re-evaluated at most every
//! five minutes unless 50 votes piled up.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Who cast a vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A tracker's `external ip`.
    Tracker,
    /// A peer's LTEP `yourip`.
    Peer,
    /// A DHT node's `ip` reply field (BEP 42).
    Dht,
}

#[derive(Debug, Clone)]
struct Candidate {
    addr: IpAddr,
    votes: u32,
    voters: HashSet<IpAddr>,
}

/// One family's voter.
#[derive(Debug)]
pub struct IpVoter {
    /// `None` is libtorrent's default-constructed address: IPv4 unspecified.
    external: Option<IpAddr>,
    candidates: Vec<Candidate>,
    total_votes: u32,
    valid_external: bool,
    last_rotate: Instant,
}

/// Most distinct sources remembered per candidate (libtorrent uses fixed-size
/// bloom filters; a set with a cap is the bounded equivalent).
const MAX_VOTERS: usize = 4096;
/// Most candidate addresses kept.
const MAX_CANDIDATES: usize = 40;

/// libtorrent `aux::is_local`: addresses that cannot be our external one.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (o[1] & 0xf0) == 16)
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
                || o[0] == 127
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] & 0xffc0) == 0xfec0 // site local (deprecated)
                || (s[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || v6.to_ipv4_mapped().is_some()
        }
    }
}

impl IpVoter {
    /// A voter with no votes.
    pub fn new(now: Instant) -> IpVoter {
        IpVoter {
            external: None,
            candidates: Vec::new(),
            total_votes: 0,
            valid_external: false,
            last_rotate: now,
        }
    }

    /// The settled external address (`None` = unspecified IPv4 default).
    pub fn external_address(&self) -> Option<IpAddr> {
        self.external
    }

    fn maybe_rotate(&mut self, now: Instant) -> bool {
        if self.total_votes < 50
            && (now.duration_since(self.last_rotate) < Duration::from_secs(300)
                || self.total_votes == 0)
            && self.valid_external
        {
            return false;
        }
        if self.candidates.is_empty() {
            return false;
        }
        // Most votes first.
        self.candidates.sort_by_key(|c| std::cmp::Reverse(c.votes));
        if self.candidates.len() == 1 {
            if self.candidates[0].votes < 2 {
                return false;
            }
        } else if self.candidates[0].votes * 2 / 3 <= self.candidates[1].votes {
            return false;
        }
        let best = self.candidates[0].addr;
        let changed = self.external != Some(best);
        self.external = Some(best);
        self.total_votes = 0;
        self.candidates.clear();
        self.last_rotate = now;
        self.valid_external = true;
        changed
    }

    /// Record that `source` says our address is `ip`. Returns whether the
    /// external address changed.
    pub fn cast_vote(&mut self, ip: IpAddr, _kind: Source, source: IpAddr, now: Instant) -> bool {
        if ip.is_unspecified() || is_local(ip) || ip.is_loopback() {
            return false;
        }
        if ip.is_ipv4() != source.is_ipv4() {
            return false;
        }
        // libtorrent also keeps a filter of sources that nominated a new
        // candidate, but 2.0.14 never adds to it (only its per-candidate
        // filters are live), so a source may nominate several addresses and
        // vote once for each; mirrored here.
        let idx = match self.candidates.iter().position(|c| c.addr == ip) {
            Some(i) => i,
            None => {
                if self.candidates.len() > MAX_CANDIDATES {
                    // Evict the weakest candidate (libtorrent flips a coin
                    // first; deterministic here is as good).
                    self.candidates.sort_by_key(|c| std::cmp::Reverse(c.votes));
                    self.candidates.pop();
                }
                self.candidates.push(Candidate {
                    addr: ip,
                    votes: 0,
                    voters: HashSet::new(),
                });
                self.candidates.len() - 1
            }
        };
        {
            let c = &mut self.candidates[idx];
            if c.voters.contains(&source) || c.voters.len() >= MAX_VOTERS {
                return self.maybe_rotate(now);
            }
            c.voters.insert(source);
            c.votes += 1;
        }
        self.total_votes += 1;
        if self.valid_external {
            return self.maybe_rotate(now);
        }
        let best = self
            .candidates
            .iter()
            .max_by_key(|c| c.votes)
            .map(|c| c.addr);
        if best == self.external {
            return self.maybe_rotate(now);
        }
        if self.external.is_some() {
            return if self.total_votes >= 25 {
                self.maybe_rotate(now)
            } else {
                false
            };
        }
        self.external = best;
        true
    }

    /// libtorrent `session_impl::listen_port(ssl, local_addr)`: whether our
    /// listen port may be advertised (LTEP `p`) on an outgoing connection whose
    /// local address is `local`.
    pub fn advertise_port_for(&self, local: IpAddr) -> bool {
        match self.external {
            // Default-constructed address: IPv4 unspecified, so it matches
            // any IPv4 local address and no IPv6 one (Q6).
            None => local.is_ipv4(),
            Some(a) => a == local,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn local_addresses_never_win() {
        let now = Instant::now();
        let mut v = IpVoter::new(now);
        for (a, src) in [
            ("10.1.2.3", "1.2.3.4"),
            ("192.168.1.1", "1.2.3.4"),
            ("172.16.5.5", "1.2.3.4"),
            ("127.0.0.1", "1.2.3.4"),
            ("0.0.0.0", "1.2.3.4"),
            ("fd77:1::2", "2001:db8::1"),
            ("fe80::1", "2001:db8::1"),
            ("::ffff:1.2.3.4", "2001:db8::1"),
        ] {
            assert!(!v.cast_vote(ip(a), Source::Peer, ip(src), now), "{a}");
        }
        assert_eq!(v.external_address(), None);
        // Family mismatch between vote and source.
        assert!(!v.cast_vote(ip("2001:db8::5"), Source::Peer, ip("1.2.3.4"), now));
        // Q6: nothing voted: v4 advertises, v6 does not.
        assert!(v.advertise_port_for(ip("10.0.0.2")));
        assert!(!v.advertise_port_for(ip("fd77::2")));
    }

    #[test]
    fn first_vote_sets_then_majority_changes() {
        let now = Instant::now();
        let mut v = IpVoter::new(now);
        assert!(v.cast_vote(
            ip("2001:db8::10"),
            Source::Tracker,
            ip("2001:db8:9::1"),
            now
        ));
        assert_eq!(v.external_address(), Some(ip("2001:db8::10")));
        assert!(v.advertise_port_for(ip("2001:db8::10")));
        assert!(!v.advertise_port_for(ip("2001:db8::11")));
        // The same source cannot vote twice; a lone dissenter changes nothing.
        assert!(!v.cast_vote(
            ip("2001:db8::10"),
            Source::Tracker,
            ip("2001:db8:9::1"),
            now
        ));
        assert!(!v.cast_vote(ip("2001:db8::99"), Source::Peer, ip("2001:db8:9::2"), now));
        assert_eq!(v.external_address(), Some(ip("2001:db8::10")));
        // 25+ votes with a clear majority for another address rotate.
        let mut changed = false;
        for i in 0..40u16 {
            let src: IpAddr = format!("2001:db8:a::{i:x}").parse().unwrap();
            changed |= v.cast_vote(ip("2001:db8::99"), Source::Peer, src, now);
        }
        assert!(changed);
        assert_eq!(v.external_address(), Some(ip("2001:db8::99")));
    }

    #[test]
    fn nat_v4_stops_advertising_the_port() {
        // A public v4 address voted in differs from the private local one:
        // libtorrent then omits `p` on v4 too.
        let now = Instant::now();
        let mut v = IpVoter::new(now);
        assert!(v.cast_vote(ip("203.0.113.7"), Source::Tracker, ip("198.51.100.1"), now));
        assert!(!v.advertise_port_for(ip("192.168.1.20")));
        assert!(v.advertise_port_for(ip("203.0.113.7")));
    }
}
