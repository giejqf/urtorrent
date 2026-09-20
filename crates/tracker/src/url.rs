// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! A minimal URL parser for tracker URLs (`http`, `https`, `udp`). Handles
//! bracketed IPv6 hosts, explicit ports, paths and existing query strings
//! (PT-style passkeys); rejects userinfo and anything we do not speak.

use std::net::{IpAddr, Ipv6Addr};

use crate::Error;

/// A parsed tracker URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// `http`, `https` or `udp`.
    pub scheme: String,
    /// Host name or IP literal (without brackets).
    pub host: String,
    /// Explicit port, if any.
    pub port: Option<u16>,
    /// Path (`/` if empty).
    pub path: String,
    /// Query string without the `?`, if any.
    pub query: Option<String>,
}

impl Url {
    /// Parse `s`.
    pub fn parse(s: &str) -> Result<Url, Error> {
        let (scheme, rest) = s.split_once("://").ok_or(Error::Url("no scheme"))?;
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https" | "udp") {
            return Err(Error::Url("unsupported scheme"));
        }
        let (authority, path_query) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(Error::Url("userinfo not supported"));
        }
        let (host, port) = if let Some(after) = authority.strip_prefix('[') {
            let (h, p) = after
                .split_once(']')
                .ok_or(Error::Url("unterminated ipv6 literal"))?;
            h.parse::<Ipv6Addr>()
                .map_err(|_| Error::Url("bad ipv6 literal"))?;
            let port = match p.strip_prefix(':') {
                Some(p) => Some(p.parse().map_err(|_| Error::Url("bad port"))?),
                None if p.is_empty() => None,
                None => return Err(Error::Url("junk after ipv6 literal")),
            };
            (h.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_string(),
                    Some(p.parse().map_err(|_| Error::Url("bad port"))?),
                ),
                None => (authority.to_string(), None),
            }
        };
        if host.is_empty() {
            return Err(Error::Url("empty host"));
        }
        let (path, query) = match path_query.split_once('?') {
            Some((p, q)) => (p, Some(q.to_string())),
            None => (path_query, None),
        };
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        Ok(Url {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    /// The scheme's default port.
    pub fn default_port(&self) -> u16 {
        match self.scheme.as_str() {
            "https" => 443,
            "udp" => 0,
            _ => 80,
        }
    }

    /// The effective port.
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.default_port())
    }

    /// The host as an IP address, if it is a literal.
    pub fn host_ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// Whether the scheme is `https`.
    pub fn is_tls(&self) -> bool {
        self.scheme == "https"
    }

    /// Render the `Host` header value.
    pub fn host_header(&self, style: profile::HostPortStyle) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match (style, self.port) {
            (profile::HostPortStyle::OmitDefault, Some(p)) if p != self.default_port() => {
                format!("{host}:{p}")
            }
            (profile::HostPortStyle::OmitDefault, _) => host,
            (profile::HostPortStyle::Always, _) => format!("{host}:{}", self.effective_port()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_forms() {
        let u = Url::parse("http://10.77.142.1:7070/announce").unwrap();
        assert_eq!(u.host, "10.77.142.1");
        assert_eq!(u.port, Some(7070));
        assert_eq!(u.path, "/announce");
        assert_eq!(
            u.host_header(profile::HostPortStyle::OmitDefault),
            "10.77.142.1:7070"
        );
        let u = Url::parse("https://tracker.example/announce.php?passkey=abc").unwrap();
        assert_eq!(u.effective_port(), 443);
        assert_eq!(u.query.as_deref(), Some("passkey=abc"));
        assert_eq!(
            u.host_header(profile::HostPortStyle::OmitDefault),
            "tracker.example"
        );
        assert_eq!(
            u.host_header(profile::HostPortStyle::Always),
            "tracker.example:443"
        );
        let u = Url::parse("http://[fd77:8e::1]:7070/announce").unwrap();
        assert_eq!(u.host, "fd77:8e::1");
        assert_eq!(
            u.host_header(profile::HostPortStyle::OmitDefault),
            "[fd77:8e::1]:7070"
        );
        assert_eq!(u.host_ip(), Some("fd77:8e::1".parse().unwrap()));
        let u = Url::parse("udp://tracker:6969").unwrap();
        assert_eq!(u.path, "/");
        assert_eq!(u.port, Some(6969));
    }

    #[test]
    fn rejects_junk() {
        assert!(Url::parse("announce").is_err());
        assert!(Url::parse("ftp://x/").is_err());
        assert!(Url::parse("http://user@x/").is_err());
        assert!(Url::parse("http://:80/").is_err());
        assert!(Url::parse("http://[::1/").is_err());
        assert!(Url::parse("http://x:99999/").is_err());
    }
}
