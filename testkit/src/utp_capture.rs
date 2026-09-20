// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Reading uTP (BEP 29) traffic out of a pcap file: a minimal pcap / Ethernet
//! / IPv4 / IPv6 / UDP walker and the 20-byte uTP header decoder, producing
//! one record per datagram for golden captures and the discriminator. The
//! harness never trusts the library under test, so this is independent of
//! `crates/utp`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// A UDP datagram from a pcap.
#[derive(Debug, Clone)]
pub struct UdpPacket {
    /// Seconds since the capture's first packet.
    pub ts: f64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// Read every UDP datagram in a pcap file (Ethernet link type).
pub fn read_udp(path: &Path) -> Result<Vec<UdpPacket>> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if data.len() < 24 {
        bail!("pcap too short");
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (le, nanos) = match magic {
        0xa1b2_c3d4 => (true, false),
        0xd4c3_b2a1 => (false, false),
        0xa1b2_3c4d => (true, true),
        0x4d3c_b2a1 => (false, true),
        _ => bail!("not a pcap file (magic {magic:#x})"),
    };
    let rd32 = |b: &[u8]| -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        }
    };
    let linktype = rd32(&data[20..24]);
    if linktype != 1 {
        bail!("unsupported pcap link type {linktype} (need Ethernet)");
    }
    let mut out = Vec::new();
    let mut pos = 24;
    let mut first: Option<f64> = None;
    while pos + 16 <= data.len() {
        let sec = rd32(&data[pos..]) as f64;
        let frac = rd32(&data[pos + 4..]) as f64;
        let incl = rd32(&data[pos + 8..]) as usize;
        pos += 16;
        if pos + incl > data.len() {
            break;
        }
        let frame = &data[pos..pos + incl];
        pos += incl;
        let ts = sec + if nanos { frac / 1e9 } else { frac / 1e6 };
        let t0 = *first.get_or_insert(ts);
        if let Some(p) = parse_frame(frame, ts - t0) {
            out.push(p);
        }
    }
    Ok(out)
}

fn parse_frame(frame: &[u8], ts: f64) -> Option<UdpPacket> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let l3 = &frame[14..];
    match ethertype {
        0x0800 => {
            if l3.len() < 20 || l3[9] != 17 {
                return None;
            }
            let ihl = usize::from(l3[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([l3[2], l3[3]]));
            let src = Ipv4Addr::new(l3[12], l3[13], l3[14], l3[15]);
            let dst = Ipv4Addr::new(l3[16], l3[17], l3[18], l3[19]);
            let l4 = l3.get(ihl..total.min(l3.len()))?;
            udp(IpAddr::V4(src), IpAddr::V4(dst), l4, ts)
        }
        0x86dd => {
            if l3.len() < 40 || l3[6] != 17 {
                return None; // no extension-header walking: the lab has none
            }
            let plen = usize::from(u16::from_be_bytes([l3[4], l3[5]]));
            let mut s = [0u8; 16];
            s.copy_from_slice(&l3[8..24]);
            let mut d = [0u8; 16];
            d.copy_from_slice(&l3[24..40]);
            let l4 = l3.get(40..(40 + plen).min(l3.len()))?;
            udp(
                IpAddr::V6(Ipv6Addr::from(s)),
                IpAddr::V6(Ipv6Addr::from(d)),
                l4,
                ts,
            )
        }
        _ => None,
    }
}

fn udp(src: IpAddr, dst: IpAddr, l4: &[u8], ts: f64) -> Option<UdpPacket> {
    if l4.len() < 8 {
        return None;
    }
    let sp = u16::from_be_bytes([l4[0], l4[1]]);
    let dp = u16::from_be_bytes([l4[2], l4[3]]);
    let len = usize::from(u16::from_be_bytes([l4[4], l4[5]]));
    let payload = l4.get(8..len.min(l4.len()))?.to_vec();
    Some(UdpPacket {
        ts,
        src: SocketAddr::new(src, sp),
        dst: SocketAddr::new(dst, dp),
        payload,
    })
}

/// One decoded uTP packet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UtpRecord {
    pub ts: f64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// `syn`, `data`, `state`, `fin`, `reset`.
    pub kind: String,
    pub version: u8,
    /// Extension types present, in order (1 = selective ack, 3 = close
    /// reason, others verbatim).
    pub extensions: Vec<u8>,
    /// Selective-ack bitmask length in bytes, if present.
    pub sack_len: Option<usize>,
    /// libtorrent close reason (extension 3), if present.
    pub close_reason: Option<u32>,
    pub connection_id: u16,
    pub timestamp_us: u32,
    pub timestamp_diff_us: u32,
    pub wnd_size: u32,
    pub seq_nr: u16,
    pub ack_nr: u16,
    /// Payload bytes after the header and extensions.
    pub payload_len: usize,
    /// Whole datagram length.
    pub len: usize,
}

/// Decode a datagram as uTP; `None` when it is not (KRPC, tracker, ...).
pub fn decode(p: &UdpPacket) -> Option<UtpRecord> {
    let b = &p.payload;
    if b.len() < 20 {
        return None;
    }
    let version = b[0] & 0x0f;
    let ty = b[0] >> 4;
    if version != 1 || ty > 4 {
        return None;
    }
    let kind = match ty {
        0 => "data",
        1 => "fin",
        2 => "state",
        3 => "reset",
        _ => "syn",
    };
    let u16at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    let u32at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let mut extensions = Vec::new();
    let mut sack_len = None;
    let mut close_reason = None;
    let mut ext = b[1];
    let mut pos = 20;
    while ext != 0 {
        if pos + 2 > b.len() {
            return None;
        }
        let next = b[pos];
        let len = usize::from(b[pos + 1]);
        let body = b.get(pos + 2..pos + 2 + len)?;
        extensions.push(ext);
        match ext {
            1 => sack_len = Some(len),
            3 if len == 4 => {
                close_reason = Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
            }
            _ => {}
        }
        pos += 2 + len;
        ext = next;
    }
    Some(UtpRecord {
        ts: p.ts,
        src: p.src,
        dst: p.dst,
        kind: kind.into(),
        version,
        extensions,
        sack_len,
        close_reason,
        connection_id: u16at(2),
        timestamp_us: u32at(4),
        timestamp_diff_us: u32at(8),
        wnd_size: u32at(12),
        seq_nr: u16at(16),
        ack_nr: u16at(18),
        payload_len: b.len() - pos,
        len: b.len(),
    })
}

/// Every uTP packet in a pcap, in order.
pub fn read_utp(path: &Path) -> Result<Vec<UtpRecord>> {
    Ok(read_udp(path)?.iter().filter_map(decode).collect())
}

/// Write records as JSON lines.
pub fn save_jsonl(records: &[UtpRecord], path: &Path) -> Result<()> {
    let mut out = String::new();
    for r in records {
        out.push_str(&serde_json::to_string(r)?);
        out.push('\n');
    }
    std::fs::write(path, out)?;
    Ok(())
}

/// A compact, diff-friendly summary of a capture for the golden directory:
/// the first packets, every SYN/FIN/RESET, every packet carrying an
/// extension (capped), and the payload-size histogram.
pub fn shape_summary(records: &[UtpRecord]) -> serde_json::Value {
    let mut sizes: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    let mut kinds: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for r in records {
        *kinds.entry(format!("{} {}", r.src, r.kind)).or_default() += 1;
        if r.kind == "data" {
            *sizes.entry(r.payload_len).or_default() += 1;
        }
    }
    let first: Vec<&UtpRecord> = records.iter().take(30).collect();
    let control: Vec<&UtpRecord> = records
        .iter()
        .filter(|r| r.kind == "syn" || r.kind == "fin" || r.kind == "reset")
        .collect();
    let with_ext: Vec<&UtpRecord> = records
        .iter()
        .filter(|r| !r.extensions.is_empty())
        .take(50)
        .collect();
    serde_json::json!({
        "packets": records.len(),
        "kinds": kinds,
        "first": first,
        "control": control,
        "with_extensions": with_ext,
        "data_payload_sizes": sizes.iter().map(|(k, v)| (k.to_string(), *v)).collect::<std::collections::BTreeMap<_, _>>(),
        "largest_datagram": records.iter().map(|r| r.len).max(),
    })
}

/// Load records written by [`save_jsonl`].
pub fn load_jsonl(path: &Path) -> Result<Vec<UtpRecord>> {
    let text = std::fs::read_to_string(path)?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(Into::into))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_syn_and_a_sack_data_packet() {
        // ST_SYN, no extension, conn 0x1234, seq 7, ack 0.
        let mut syn = vec![0x41, 0, 0x12, 0x34];
        syn.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0]);
        let p = UdpPacket {
            ts: 0.0,
            src: "10.1.0.1:1".parse().unwrap(),
            dst: "10.2.0.1:2".parse().unwrap(),
            payload: syn,
        };
        let r = decode(&p).unwrap();
        assert_eq!(r.kind, "syn");
        assert_eq!(r.connection_id, 0x1234);
        assert_eq!(r.seq_nr, 7);
        assert!(r.extensions.is_empty());
        // ST_DATA with a 4-byte selective ack then 3 payload bytes.
        let mut data = vec![0x01, 1, 0, 9];
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&[0, 4, 0xff, 0, 0, 0]);
        data.extend_from_slice(b"abc");
        let p2 = UdpPacket {
            payload: data,
            ..p.clone()
        };
        let r = decode(&p2).unwrap();
        assert_eq!(r.kind, "data");
        assert_eq!(r.extensions, vec![1]);
        assert_eq!(r.sack_len, Some(4));
        assert_eq!(r.payload_len, 3);
        // Not uTP.
        let p3 = UdpPacket {
            payload: b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:aa1:y1:qe".to_vec(),
            ..p.clone()
        };
        assert!(decode(&p3).is_none());
    }
}
