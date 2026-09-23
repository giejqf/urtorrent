// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Banned address ranges (libtorrent's `ip_filter` rules, blocking only):
//! sorted, merged, per family, so a long block list costs a binary search
//! on every accept, dial and candidate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Inclusive ranges of addresses, IPv4 and IPv6 apart.
#[derive(Debug, Default)]
pub struct IpRanges {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}

fn key(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(a) => (false, u128::from(u32::from(a))),
        IpAddr::V6(a) => (true, u128::from(a)),
    }
}

fn addr(v6: bool, k: u128) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(k))
    } else {
        IpAddr::V4(Ipv4Addr::from(k as u32))
    }
}

impl IpRanges {
    fn list(&mut self, v6: bool) -> &mut Vec<(u128, u128)> {
        if v6 { &mut self.v6 } else { &mut self.v4 }
    }

    /// Add `first..=last` (same family, `first <= last`: checked by the
    /// caller), merging with what it touches.
    pub fn insert(&mut self, first: IpAddr, last: IpAddr) {
        let (v6, a) = key(first);
        let (_, b) = key(last);
        let list = self.list(v6);
        list.push((a, b));
        list.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(list.len());
        for &(s, e) in list.iter() {
            match merged.last_mut() {
                Some(m) if s <= m.1.saturating_add(1) => m.1 = m.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        *list = merged;
    }

    /// Remove `first..=last`, splitting the ranges it cuts.
    pub fn remove(&mut self, first: IpAddr, last: IpAddr) {
        let (v6, a) = key(first);
        let (_, b) = key(last);
        let list = self.list(v6);
        let mut out = Vec::with_capacity(list.len() + 1);
        for &(s, e) in list.iter() {
            if e < a || s > b {
                out.push((s, e));
                continue;
            }
            if s < a {
                out.push((s, a - 1));
            }
            if e > b {
                out.push((b + 1, e));
            }
        }
        *list = out;
    }

    /// Whether `ip` falls in a range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (v6, k) = key(ip);
        let list = if v6 { &self.v6 } else { &self.v4 };
        let i = list.partition_point(|r| r.1 < k);
        list.get(i).is_some_and(|r| r.0 <= k)
    }

    /// Every range, IPv4 first, in order.
    pub fn ranges(&self) -> Vec<(IpAddr, IpAddr)> {
        self.v4
            .iter()
            .map(|&(s, e)| (addr(false, s), addr(false, e)))
            .chain(self.v6.iter().map(|&(s, e)| (addr(true, s), addr(true, e))))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ranges_merge_split_and_answer() {
        let mut r = IpRanges::default();
        r.insert(ip("10.0.0.0"), ip("10.0.0.255"));
        r.insert(ip("10.0.1.0"), ip("10.0.1.9"));
        r.insert(ip("10.0.0.100"), ip("10.0.0.120"));
        assert_eq!(r.ranges(), vec![(ip("10.0.0.0"), ip("10.0.1.9"))]);
        assert!(r.contains(ip("10.0.1.9")) && !r.contains(ip("10.0.1.10")));
        assert!(!r.contains(ip("9.255.255.255")));
        r.remove(ip("10.0.0.50"), ip("10.0.0.60"));
        assert_eq!(
            r.ranges(),
            vec![
                (ip("10.0.0.0"), ip("10.0.0.49")),
                (ip("10.0.0.61"), ip("10.0.1.9"))
            ]
        );
        assert!(!r.contains(ip("10.0.0.55")) && r.contains(ip("10.0.0.61")));
        r.insert(ip("fd00::"), ip("fd00::ffff"));
        assert!(r.contains(ip("fd00::1")) && !r.contains(ip("fd01::")));
        assert!(!r.contains(ip("10.0.0.55")), "families apart");
        r.remove(ip("0.0.0.0"), ip("255.255.255.255"));
        assert_eq!(r.ranges(), vec![(ip("fd00::"), ip("fd00::ffff"))]);
    }
}
