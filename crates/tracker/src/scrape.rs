// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! BEP 48 HTTP scrape: URL derivation (the first `announce` in the URL's
//! *path* becomes `scrape`; libtorrent searches the whole URL, which breaks
//! hosts named `announce.*`, so the BEP's rule is followed), the request,
//! and the `files` response with the common `flags.min_request_interval`
//! and per-file `name` extras.

use std::collections::BTreeMap;

use bencode::{Decoder, Value};
use metainfo::InfoHash;
use profile::Profile;

use crate::Error;
use crate::url::Url;

/// Per-torrent scrape counts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScrapeEntry {
    /// Seeders (`complete`).
    pub complete: u32,
    /// Completed downloads (`downloaded`).
    pub downloaded: u32,
    /// Leechers (`incomplete`).
    pub incomplete: u32,
    /// The torrent's name, when the tracker includes one (an extension many
    /// trackers add; not in BEP 48).
    pub name: Option<String>,
}

/// A parsed scrape response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScrapeResponse {
    /// Entries by info-hash.
    pub files: BTreeMap<InfoHash, ScrapeEntry>,
    /// `flags.min_request_interval`: seconds the tracker asks clients to
    /// wait between scrapes (the de-facto extension BEP 48 omits).
    pub min_request_interval: Option<u32>,
}

/// The scrape URL for an announce URL, or `None` if the tracker offers none:
/// BEP 48 replaces the first `announce` in the URL's path with `scrape`.
pub fn scrape_url(announce: &str) -> Option<String> {
    // The path starts at the first `/` after the authority.
    let after_scheme = announce.find("://").map_or(0, |i| i + 3);
    let path_start = announce[after_scheme..]
        .find('/')
        .map(|i| after_scheme + i)?;
    let query_start = announce[path_start..]
        .find(['?', '#'])
        .map_or(announce.len(), |i| path_start + i);
    let rel = announce[path_start..query_start].find("announce")?;
    let pos = path_start + rel;
    let mut s = announce.to_string();
    s.replace_range(pos..pos + 8, "scrape");
    Some(s)
}

/// Build the HTTP scrape request for `hashes` against `url` (already the
/// scrape URL). Headers follow the profile's announce shape.
pub fn http_request(url: &Url, hashes: &[InfoHash], profile: &Profile) -> Vec<u8> {
    let mut target = url.path.clone();
    match &url.query {
        Some(q) if !q.is_empty() => {
            target.push('?');
            target.push_str(q);
            target.push('&');
        }
        _ => target.push('?'),
    }
    let esc = profile.http.escape;
    let params: Vec<String> = hashes
        .iter()
        .map(|h| format!("info_hash={}", esc.escape(h)))
        .collect();
    target.push_str(&params.join("&"));
    let mut out = format!("GET {target} HTTP/1.1\r\n");
    for h in profile.http.headers {
        match h {
            profile::AnnounceHeader::Host => {
                out.push_str("Host: ");
                out.push_str(&url.host_header(profile.http.host_port));
                out.push_str("\r\n");
            }
            profile::AnnounceHeader::UserAgent => {
                out.push_str("User-Agent: ");
                out.push_str(profile.user_agent);
                out.push_str("\r\n");
            }
            profile::AnnounceHeader::AcceptEncodingGzip => {
                out.push_str("Accept-Encoding: gzip\r\n")
            }
            profile::AnnounceHeader::ConnectionClose => out.push_str("Connection: close\r\n"),
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Parse a scrape response body.
pub fn parse_response(body: &[u8]) -> Result<ScrapeResponse, Error> {
    let root = Decoder::new(body)
        .decode_all()
        .map_err(|_| Error::Response("not bencode"))?;
    if let Some(reason) = root.get_str("failure reason").and_then(Value::as_bytes) {
        return Err(Error::Failure(
            String::from_utf8_lossy(&reason[..reason.len().min(512)]).into_owned(),
        ));
    }
    let files = root
        .get_str("files")
        .and_then(Value::as_dict)
        .ok_or(Error::Response("no files dict"))?;
    let mut out = BTreeMap::new();
    for (k, v) in files.iter().take(10_000) {
        let Ok(hash) = <[u8; 20]>::try_from(*k) else {
            continue;
        };
        let get = |key: &str| -> u32 {
            v.get_str(key)
                .and_then(Value::as_int)
                .filter(|n| *n >= 0)
                .map_or(0, |n| n.min(i64::from(u32::MAX)) as u32)
        };
        out.insert(
            hash,
            ScrapeEntry {
                complete: get("complete"),
                downloaded: get("downloaded"),
                incomplete: get("incomplete"),
                name: v
                    .get_str("name")
                    .and_then(Value::as_bytes)
                    .map(|b| String::from_utf8_lossy(&b[..b.len().min(256)]).into_owned()),
            },
        );
    }
    let min_request_interval = root
        .get_str("flags")
        .and_then(|f| f.get_str("min_request_interval"))
        .and_then(Value::as_int)
        .filter(|n| *n >= 0)
        .map(|n| n.min(i64::from(u32::MAX)) as u32);
    Ok(ScrapeResponse {
        files: out,
        min_request_interval,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_derivation() {
        assert_eq!(
            scrape_url("http://t/announce").as_deref(),
            Some("http://t/scrape")
        );
        assert_eq!(
            scrape_url("http://t/abc/announce.php?pk=1").as_deref(),
            Some("http://t/abc/scrape.php?pk=1")
        );
        assert_eq!(scrape_url("http://t/a"), None);
        assert_eq!(
            scrape_url("udp://t:6969/announce").as_deref(),
            Some("udp://t:6969/scrape")
        );
        // BEP 48: only the path section counts.
        assert_eq!(
            scrape_url("http://announce.example.org/announce").as_deref(),
            Some("http://announce.example.org/scrape")
        );
        assert_eq!(scrape_url("http://announce.example.org/tracker"), None);
        assert_eq!(scrape_url("http://t/x?announce=1"), None);
        assert_eq!(scrape_url("http://t"), None);
        assert_eq!(
            scrape_url("https://t:443/pk/announce/?x=announce").as_deref(),
            Some("https://t:443/pk/scrape/?x=announce")
        );
    }

    #[test]
    fn request_and_response() {
        let p = Profile::qbt_5_2_3_lt2_0_14();
        let url = Url::parse("http://10.0.0.1:7070/scrape").unwrap();
        let req = http_request(&url, &[[0xAA; 20], [b'a'; 20]], &p);
        let s = String::from_utf8(req).unwrap();
        assert!(s.starts_with("GET /scrape?info_hash=%aa%aa"), "{s}");
        assert!(s.contains("&info_hash=aaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\nHost: 10.0.0.1:7070\r\nUser-Agent: qBittorrent/5.2.3\r\n"));
        let mut body = b"d5:filesd20:".to_vec();
        body.extend_from_slice(&[0xAA; 20]);
        body.extend_from_slice(
            b"d8:completei3e10:downloadedi9e10:incompletei1e4:name3:fooee5:flagsd20:min_request_intervali1800eee",
        );
        let r = parse_response(&body).unwrap();
        assert_eq!(
            r.files.get(&[0xAA; 20]),
            Some(&ScrapeEntry {
                complete: 3,
                downloaded: 9,
                incomplete: 1,
                name: Some("foo".into()),
            })
        );
        assert_eq!(r.min_request_interval, Some(1800));
        assert!(parse_response(b"d14:failure reason3:bade").is_err());
        assert!(parse_response(b"de").is_err());
        // The BEP 48 example, verbatim.
        let ex = b"d5:filesd20:xxxxxxxxxxxxxxxxxxxxd8:completei11e10:downloadedi13772e10:incompletei19ee20:yyyyyyyyyyyyyyyyyyyyd8:completei21e10:downloadedi206e10:incompletei20eeee";
        let r = parse_response(ex).unwrap();
        assert_eq!(r.files.len(), 2);
        assert_eq!(r.files[&[b'y'; 20]].downloaded, 206);
        assert_eq!(r.min_request_interval, None);
    }
}
