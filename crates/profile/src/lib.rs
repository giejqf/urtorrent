// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
// Parts of the qbt profile data follow libtorrent-rasterbar (BSD-3-Clause),
// Copyright (c) Arvid Norberg and contributors; see NOTICE.

//! Identity and wire-shape profiles (AGENTS.md 6). Identity is **data, not
//! code**: everything a tracker or a peer can observe that is not dictated by
//! the protocol itself — peer-id prefix and tail generator, `User-Agent`, LTEP
//! `v`, announce parameter *order*, header set and order, `key` format,
//! reserved bits, the LTEP `m` map, the first-messages sequence — is described
//! by a [`Profile`] and consumed by `tracker`, `wire` and `session`. Nothing
//! else in the codebase may hardcode an identity string or an ordering that a
//! profile owns.
//!
//! Two profiles ship:
//!
//! - [`Profile::native`]: our own honest identity.
//! - [`Profile::qbt_5_2_3_lt2_0_14`]: the conformance target, whose values are
//!   transcribed from the golden captures in `testkit/golden` (the oracle's
//!   captured behaviour is the spec; nothing here comes from memory). Fields
//!   the current captures cannot pin down are marked `UNVERIFIED` in comments
//!   and are on the M4 list.
//!
//! This crate is pure data plus the two generators that need randomness
//! (peer-id tail, announce key); both take an injected [`Rng`] so the
//! consuming state machines stay deterministic in tests.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// A source of randomness injected into the generators (sans-IO rule: no
/// ambient randomness in protocol crates).
pub trait Rng {
    /// A uniformly random 32-bit value.
    fn next_u32(&mut self) -> u32;

    /// A uniformly random value in `0..n` (`n > 0`). Uses rejection sampling
    /// so small alphabets are not biased.
    fn below(&mut self, n: u32) -> u32 {
        if n <= 1 {
            return 0;
        }
        let zone = u32::MAX - (u32::MAX % n);
        loop {
            let v = self.next_u32();
            if v < zone {
                return v % n;
            }
        }
    }
}

/// How long a generated peer id lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdLifetime {
    /// A fresh id for every torrent (libtorrent 2.0: `torrent::m_peer_id`).
    PerTorrent,
    /// One id for the whole session.
    PerSession,
}

/// Which peer id the BitTorrent handshake carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePeerId {
    /// The same id the torrent announces with.
    SameAsAnnounce,
    /// A fresh id for every peer connection (libtorrent 2.0 passes
    /// `generate_peer_id()` to each `peer_connection`, incoming and outgoing;
    /// docs/quirks.md Q19).
    PerConnection,
}

/// How the 20-byte peer id is built: a fixed prefix plus a random tail drawn
/// from an alphabet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdShape {
    /// The fixed prefix (e.g. `-qB5230-`).
    pub prefix: &'static str,
    /// Alphabet the random tail is drawn from.
    pub tail_alphabet: &'static [u8],
    /// Per torrent or per session (the announce id).
    pub lifetime: PeerIdLifetime,
    /// What the peer-wire handshake carries.
    pub handshake: HandshakePeerId,
}

impl PeerIdShape {
    /// Generate a peer id: `prefix` followed by `20 - prefix.len()` random
    /// characters from `tail_alphabet`.
    pub fn generate(&self, rng: &mut dyn Rng) -> [u8; 20] {
        let mut id = [0u8; 20];
        let prefix = self.prefix.as_bytes();
        let n = prefix.len().min(20);
        id[..n].copy_from_slice(&prefix[..n]);
        for slot in id.iter_mut().skip(n) {
            let idx = rng.below(self.tail_alphabet.len().max(1) as u32) as usize;
            *slot = self.tail_alphabet.get(idx).copied().unwrap_or(b'0');
        }
        id
    }
}

/// One query parameter of an HTTP announce, in the order the profile emits
/// them. Conditional parameters are omitted when they do not apply (`event`
/// when there is none, `trackerid` when the tracker never gave one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceParam {
    /// `info_hash`.
    InfoHash,
    /// `peer_id`.
    PeerId,
    /// `port`.
    Port,
    /// `uploaded`.
    Uploaded,
    /// `downloaded`.
    Downloaded,
    /// `left`.
    Left,
    /// `corrupt` (libtorrent extra).
    Corrupt,
    /// `key`.
    Key,
    /// `event` (only when there is one).
    Event,
    /// `numwant`.
    Numwant,
    /// `compact`.
    Compact,
    /// `no_peer_id`.
    NoPeerId,
    /// `supportcrypto=1`, emitted only while encryption is not disabled
    /// (`AnnounceRequest::crypto_supported`; libtorrent 2.0.14 has no
    /// `requirecrypto`).
    SupportCrypto,
    /// `redundant` (libtorrent extra).
    Redundant,
    /// `trackerid` (only when the tracker returned one).
    TrackerId,
    /// BEP 7 `ipv4=<addr>`, once per address in
    /// `AnnounceRequest::ipv4_hints` (libtorrent: the explicitly bound,
    /// public IPv4 listen addresses, private torrents only).
    Ipv4Hints,
    /// BEP 7 `ipv6=<addr>` (percent-escaped), once per address in
    /// `AnnounceRequest::ipv6_hints`.
    Ipv6Hints,
}

/// How the announce `key` is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStyle {
    /// A 32-bit value as 8 upper-case hex digits, zero padded.
    HexUpper8,
}

impl KeyStyle {
    /// Render `key` in this style.
    pub fn render(self, key: u32) -> String {
        match self {
            KeyStyle::HexUpper8 => format!("{key:08X}"),
        }
    }
}

/// Percent-encoding style for binary query values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeStyle {
    /// Lower-case hex; `A-Z a-z 0-9 - _ . ! ~ * ( )` are left literal.
    LowerHexLibtorrent,
    /// Lower-case hex; only RFC 3986 unreserved (`A-Z a-z 0-9 - _ . ~`) literal.
    LowerHexRfc3986,
}

impl EscapeStyle {
    /// Whether byte `b` is emitted literally.
    pub fn is_unreserved(self, b: u8) -> bool {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            return true;
        }
        match self {
            EscapeStyle::LowerHexLibtorrent => matches!(b, b'!' | b'*' | b'(' | b')'),
            EscapeStyle::LowerHexRfc3986 => false,
        }
    }

    /// Percent-encode `bytes`.
    pub fn escape(self, bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 3);
        for &b in bytes {
            if self.is_unreserved(b) {
                out.push(b as char);
            } else {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
        }
        out
    }
}

/// An HTTP request header the announce carries, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceHeader {
    /// `Host: host[:port]`.
    Host,
    /// `User-Agent: <profile user agent>`.
    UserAgent,
    /// `Accept-Encoding: gzip`.
    AcceptEncodingGzip,
    /// `Connection: close`.
    ConnectionClose,
}

/// Whether the `Host` header carries the port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPortStyle {
    /// Omit the port when it is the scheme default (80 / 443).
    OmitDefault,
    /// Always include the port.
    Always,
}

/// When a new announce `key` is generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifetime {
    /// One key per torrent for the life of the session.
    PerTorrent,
    /// One key for the whole session.
    PerSession,
}

/// The shape of an HTTP announce (AGENTS.md 6, L2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAnnounceShape {
    /// Query parameters in emission order.
    pub params: &'static [AnnounceParam],
    /// Request headers in emission order.
    pub headers: &'static [AnnounceHeader],
    /// `Host` header port style.
    pub host_port: HostPortStyle,
    /// Percent-encoding style.
    pub escape: EscapeStyle,
    /// `key` rendering.
    pub key: KeyStyle,
    /// `key` lifetime.
    pub key_lifetime: KeyLifetime,
    /// `numwant` for regular announces.
    pub numwant: u32,
    /// `numwant` sent with `event=stopped`.
    pub numwant_stopped: u32,
    /// Value of `compact`.
    pub compact: bool,
    /// Value of `no_peer_id`.
    pub no_peer_id: bool,
    /// Whether `supportcrypto=1` is announced at all when encryption is on
    /// (libtorrent `announce_crypto_support`).
    pub supportcrypto: bool,
}

/// One entry of the LTEP handshake `m` map: extension name and the local id
/// we assign to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtepExtension {
    /// Extension name as it appears in `m`.
    pub name: &'static str,
    /// The message id we assign (peers send us this id for that extension).
    pub id: u8,
}

/// The shape of the LTEP extended handshake (BEP 10) we send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtepShape {
    /// The `m` map (bencode sorts keys on the wire; this is the set + ids).
    pub m: &'static [LtepExtension],
    /// The `m` map for **private** torrents (BEP 27): libtorrent attaches
    /// neither `ut_pex` nor `ut_metadata` to a private torrent, and sends no
    /// `metadata_size` (docs/quirks.md Q11).
    pub m_private: &'static [LtepExtension],
    /// `reqq`: the request queue depth we advertise.
    pub reqq: u32,
    /// Whether `complete_ago` is sent (libtorrent extra; `-1` when unknown).
    pub complete_ago: bool,
    /// Whether `yourip` is sent.
    pub yourip: bool,
    /// Whether `p` (listen port) is sent on outgoing connections.
    pub p_on_outgoing: bool,
    /// Whether `p` is sent on incoming connections.
    pub p_on_incoming: bool,
    /// Whether `upload_only: 1` is sent while seeding.
    pub upload_only_when_seeding: bool,
    /// Whether `metadata_size` is sent when we have the metadata.
    pub metadata_size: bool,
}

/// What we send right after the handshake, in order (AGENTS.md 6, L2
/// "first-messages sequence").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstMessage {
    /// The LTEP extended handshake (only if both sides set the LTEP bit).
    ExtendedHandshake,
    /// `have_all` / `have_none` when the fast extension is negotiated and we
    /// have all / no pieces; otherwise a `bitfield`, omitted when we have no
    /// pieces and fast is off (libtorrent `write_bitfield`). Nothing at all
    /// before the metadata is known (magnet links).
    HaveState,
}

/// Which address bytes seed the BEP 6 allowed-fast set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedFastAddr {
    /// As BEP 6 specifies: IPv4 masked to the /24 (`ip & 0xffffff00`); for
    /// IPv6 (unspecified by the BEP) the /64 prefix.
    Bep6Masked,
    /// As libtorrent does: the full address bytes (4 or 16), no masking
    /// (docs/quirks.md Q7).
    LibtorrentFull,
}

/// Peer-wire shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerShape {
    /// Reserved bytes in the handshake.
    pub reserved: [u8; 8],
    /// How the allowed-fast set is seeded.
    pub allowed_fast_addr: AllowedFastAddr,
    /// Messages sent immediately after the handshake, in order.
    pub first_messages: &'static [FirstMessage],
    /// Number of `allowed_fast` pieces we grant (BEP 6) on the peer's first
    /// `interested`, skipping pieces it has; 0 disables.
    pub allowed_fast_count: u32,
    /// Maximum number of outstanding incoming requests we accept per peer
    /// (what `reqq` advertises).
    pub max_incoming_requests: u32,
}

/// Message Stream Encryption shape (AGENTS.md 6 L2: method selection,
/// `crypto_provide` / `select`, padding distribution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MseShape {
    /// When both methods are offered and allowed, select RC4 (libtorrent
    /// `prefer_rc4`). The oracle selected RC4 for `provide = 3`
    /// (`capture_peer_allow_mse`).
    pub prefer_rc4: bool,
    /// Pads are uniform in `0..=pad_max` (libtorrent `random(512)`).
    pub pad_max: u16,
}

/// DHT (BEP 5) shape: what a DHT node observes about us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtShape {
    /// The `v` stamped on every KRPC message. libtorrent: `"LT"` + major
    /// byte + `(minor << 4 | tiny)` byte (`4c 54 02 0e` for 2.0.14,
    /// `testkit/golden/capture_dht`).
    pub version: [u8; 4],
    /// Default bootstrap routers (`host:port`), used unless the caller sets
    /// their own. qBittorrent 5.2.3's list (data read from its settings, not
    /// code).
    pub bootstrap_nodes: &'static [&'static str],
}

/// A complete identity/wire profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Profile name (`native`, `qbt_5_2_3_lt2_0_14`).
    pub name: &'static str,
    /// Peer-id generator.
    pub peer_id: PeerIdShape,
    /// HTTP `User-Agent`.
    pub user_agent: &'static str,
    /// LTEP handshake `v` (client name and version).
    pub ltep_version: &'static str,
    /// HTTP announce shape.
    pub http: HttpAnnounceShape,
    /// LTEP handshake shape.
    pub ltep: LtepShape,
    /// Peer-wire shape.
    pub peer: PeerShape,
    /// MSE shape.
    pub mse: MseShape,
    /// DHT shape.
    pub dht: DhtShape,
}

/// Handshake reserved-bit positions (byte index, mask), BEP 3/6/10.
pub mod reserved {
    /// BEP 10 extension protocol: byte 5, bit 0x10.
    pub const LTEP: (usize, u8) = (5, 0x10);
    /// BEP 6 fast extension: byte 7, bit 0x04.
    pub const FAST: (usize, u8) = (7, 0x04);
    /// BEP 5 DHT: byte 7, bit 0x01.
    pub const DHT: (usize, u8) = (7, 0x01);

    /// Set `bit` in `r`.
    pub fn set(r: &mut [u8; 8], bit: (usize, u8)) {
        r[bit.0] |= bit.1;
    }

    /// Whether `bit` is set in `r`.
    pub fn has(r: &[u8; 8], bit: (usize, u8)) -> bool {
        r[bit.0] & bit.1 != 0
    }
}

/// Announce params in the order the oracle emits them
/// (`testkit/golden/capture_tracker_http/*/tap-tracker.jsonl`, every announce).
const QBT_ANNOUNCE_PARAMS: &[AnnounceParam] = &[
    AnnounceParam::InfoHash,
    AnnounceParam::PeerId,
    AnnounceParam::Port,
    AnnounceParam::Uploaded,
    AnnounceParam::Downloaded,
    AnnounceParam::Left,
    AnnounceParam::Corrupt,
    AnnounceParam::Key,
    AnnounceParam::Event,
    AnnounceParam::Numwant,
    AnnounceParam::Compact,
    AnnounceParam::NoPeerId,
    AnnounceParam::SupportCrypto,
    AnnounceParam::Redundant,
    // The tail follows libtorrent 2.0.14 http_tracker_connection.cpp (no
    // capture shows it: the lab's addresses are RFC 1918 / ULA, which
    // libtorrent treats as local, and no tap tracker returns a tracker id):
    // `&trackerid=` when the tracker gave one, then `&ipv4=` / `&ipv6=` for
    // private torrents (docs/quirks.md Q22).
    AnnounceParam::TrackerId,
    AnnounceParam::Ipv4Hints,
    AnnounceParam::Ipv6Hints,
];

/// Headers in the order the oracle emits them (same captures).
const QBT_ANNOUNCE_HEADERS: &[AnnounceHeader] = &[
    AnnounceHeader::Host,
    AnnounceHeader::UserAgent,
    AnnounceHeader::AcceptEncodingGzip,
    AnnounceHeader::ConnectionClose,
];

/// LTEP `m` map as captured (`capture_peer_plain`, extended handshake):
/// `{lt_donthave: 7, share_mode: 8, upload_only: 3, ut_holepunch: 4,
/// ut_metadata: 2, ut_pex: 1}`. `ut_holepunch` cannot work without uTP; it is
/// advertised for L2 exactness and answered as a disabled feature
/// (`docs/quirks.md` Q2).
const QBT_LTEP_M: &[LtepExtension] = &[
    LtepExtension {
        name: "ut_pex",
        id: 1,
    },
    LtepExtension {
        name: "ut_metadata",
        id: 2,
    },
    LtepExtension {
        name: "upload_only",
        id: 3,
    },
    LtepExtension {
        name: "ut_holepunch",
        id: 4,
    },
    LtepExtension {
        name: "lt_donthave",
        id: 7,
    },
    LtepExtension {
        name: "share_mode",
        id: 8,
    },
];

/// The oracle's `m` map for private torrents (`capture_peer_private`):
/// `{lt_donthave: 7, share_mode: 8, upload_only: 3, ut_holepunch: 4}`.
const QBT_LTEP_M_PRIVATE: &[LtepExtension] = &[
    LtepExtension {
        name: "upload_only",
        id: 3,
    },
    LtepExtension {
        name: "ut_holepunch",
        id: 4,
    },
    LtepExtension {
        name: "lt_donthave",
        id: 7,
    },
    LtepExtension {
        name: "share_mode",
        id: 8,
    },
];

/// Our own `m` map: what is implemented (`ut_pex`, `ut_metadata`,
/// `upload_only`; the ids follow libtorrent's so peers see familiar values).
const NATIVE_LTEP_M: &[LtepExtension] = &[
    LtepExtension {
        name: "ut_pex",
        id: 1,
    },
    LtepExtension {
        name: "ut_metadata",
        id: 2,
    },
    LtepExtension {
        name: "upload_only",
        id: 3,
    },
];

/// Our own private map: no peer exchange, no metadata exchange.
const NATIVE_LTEP_M_PRIVATE: &[LtepExtension] = &[LtepExtension {
    name: "upload_only",
    id: 3,
}];

/// Both profiles: LTEP handshake, then the have-state. The allowed-fast set
/// is not a first message: libtorrent sends it on the peer's first
/// `interested` (`capture_peer_plain`: `extended, have_all, unchoke` and
/// only then `allowed_fast`), skipping pieces the peer has.
const FIRST_MESSAGES: &[FirstMessage] = &[FirstMessage::ExtendedHandshake, FirstMessage::HaveState];

/// The characters libtorrent draws the peer-id tail from (`url_random`):
/// alphanumerics plus `- _ . ! ~ * ( )`. Every one of the 70 characters was
/// observed across the 46 peer ids in `testkit/golden` (`capture_keys`).
const QBT_TAIL_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*()";

/// Our own tail alphabet (alphanumerics only, unambiguous in logs).
const NATIVE_TAIL_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

impl Profile {
    /// Our own honest identity (the default profile).
    pub fn native() -> Profile {
        Profile {
            name: "native",
            peer_id: PeerIdShape {
                // Azureus style, one character per component; a component
                // of ten or more takes a letter as libtorrent's
                // `fingerprint` does (`A` = 10): 0.10.0 is `0A00`.
                prefix: "-UR0B30-",
                tail_alphabet: NATIVE_TAIL_ALPHABET,
                lifetime: PeerIdLifetime::PerSession,
                handshake: HandshakePeerId::SameAsAnnounce,
            },
            user_agent: "urtorrent/0.11.3",
            ltep_version: "urtorrent 0.11.3",
            http: HttpAnnounceShape {
                params: QBT_ANNOUNCE_PARAMS,
                headers: QBT_ANNOUNCE_HEADERS,
                host_port: HostPortStyle::OmitDefault,
                escape: EscapeStyle::LowerHexRfc3986,
                key: KeyStyle::HexUpper8,
                key_lifetime: KeyLifetime::PerTorrent,
                numwant: 200,
                numwant_stopped: 0,
                compact: true,
                no_peer_id: true,
                supportcrypto: true,
            },
            ltep: LtepShape {
                m: NATIVE_LTEP_M,
                m_private: NATIVE_LTEP_M_PRIVATE,
                reqq: 250,
                complete_ago: false,
                yourip: true,
                p_on_outgoing: true,
                p_on_incoming: true,
                upload_only_when_seeding: false,
                metadata_size: true,
            },
            peer: PeerShape {
                // LTEP + fast; no DHT bit: we do not implement DHT.
                reserved: [0, 0, 0, 0, 0, 0x10, 0, 0x04],
                allowed_fast_addr: AllowedFastAddr::Bep6Masked,
                first_messages: FIRST_MESSAGES,
                allowed_fast_count: 5,
                max_incoming_requests: 250,
            },
            mse: MseShape {
                prefer_rc4: true,
                pad_max: 512,
            },
            dht: DhtShape {
                // Our own honest version tag: `UR` + the minor version.
                version: *b"UR\x00\x0b",
                bootstrap_nodes: &["dht.libtorrent.org:25401", "router.bittorrent.com:6881"],
            },
        }
    }

    /// The conformance target: qBittorrent 5.2.3 on libtorrent 2.0.14, as
    /// captured from the pinned oracle (`testkit/oracle.lock`).
    pub fn qbt_5_2_3_lt2_0_14() -> Profile {
        Profile {
            name: "qbt_5_2_3_lt2_0_14",
            peer_id: PeerIdShape {
                prefix: "-qB5230-",
                tail_alphabet: QBT_TAIL_ALPHABET,
                // 40 torrents in one oracle announced 40 different peer ids
                // (`capture_keys`).
                lifetime: PeerIdLifetime::PerTorrent,
                // Every handshake carries a fresh id, unrelated to the
                // announce id: `capture_pex` (two connections of one torrent
                // to two taps: two ids), `capture_magnet` (two consecutive
                // connections: two ids), none equal to the tracker's (Q19).
                handshake: HandshakePeerId::PerConnection,
            },
            user_agent: "qBittorrent/5.2.3",
            ltep_version: "qBittorrent/5.2.3",
            http: HttpAnnounceShape {
                params: QBT_ANNOUNCE_PARAMS,
                headers: QBT_ANNOUNCE_HEADERS,
                // UNVERIFIED: captures only cover a non-default port (7070),
                // where the port is present.
                host_port: HostPortStyle::OmitDefault,
                // `%e9%8b%27%01%d6%9bI%e7...%c2%2c...` (lower hex, `I` literal,
                // `'`/`,` escaped) and peer ids with literal `!`, `(`, `)`, `~`.
                escape: EscapeStyle::LowerHexLibtorrent,
                // `key=FF2033B3`, `C8445FFC`, ...: 8 upper-case hex digits
                // (`%08X` in libtorrent's http_tracker_connection.cpp).
                key: KeyStyle::HexUpper8,
                // 40 torrents, 40 distinct keys, each constant across its
                // torrent's announces (`capture_keys`).
                key_lifetime: KeyLifetime::PerTorrent,
                numwant: 200,
                numwant_stopped: 0,
                compact: true,
                no_peer_id: true,
                supportcrypto: true,
            },
            ltep: LtepShape {
                m: QBT_LTEP_M,
                m_private: QBT_LTEP_M_PRIVATE,
                reqq: 2000,
                complete_ago: true,
                yourip: true,
                // `p: 6881` appears on the oracle's outgoing connection
                // (`oracle-initiator` capture) and is absent on the incoming
                // one (`oracle-responder` capture). On outgoing v6
                // connections it is absent until an external address is
                // known (docs/quirks.md Q6); `wire` applies that rule.
                p_on_outgoing: true,
                p_on_incoming: false,
                // `upload_only: 1` in the seeding capture only.
                upload_only_when_seeding: true,
                metadata_size: true,
            },
            peer: PeerShape {
                // `0000000000100005` = LTEP + fast + DHT (docs/quirks.md Q1).
                reserved: [0, 0, 0, 0, 0, 0x10, 0, 0x05],
                // The captured grants only reproduce with the unmasked
                // address (docs/quirks.md Q7).
                allowed_fast_addr: AllowedFastAddr::LibtorrentFull,
                first_messages: FIRST_MESSAGES,
                // Five `allowed_fast` messages in the seeding capture.
                allowed_fast_count: 5,
                max_incoming_requests: 2000,
            },
            mse: MseShape {
                // `capture_peer_allow_mse`: provide 3 -> select 2.
                prefer_rc4: true,
                // `capture_peer_forced`: pads 292, 488, 77, 484 (random(512)).
                pad_max: 512,
            },
            dht: DhtShape {
                // `capture_dht`: every query and reply carries `v = 4c54020e`.
                version: [0x4c, 0x54, 0x02, 0x0e],
                // qBittorrent 5.2.3 `Session\DHTBootstrapNodes` default.
                bootstrap_nodes: &[
                    "dht.libtorrent.org:25401",
                    "dht.transmissionbt.com:6881",
                    "router.bittorrent.com:6881",
                ],
            },
        }
    }

    /// Look a profile up by name.
    pub fn by_name(name: &str) -> Option<Profile> {
        match name {
            "native" => Some(Profile::native()),
            "qbt_5_2_3_lt2_0_14" | "qbt" => Some(Profile::qbt_5_2_3_lt2_0_14()),
            _ => None,
        }
    }

    /// Whether this profile advertises the LTEP bit.
    pub fn supports_ltep(&self) -> bool {
        reserved::has(&self.peer.reserved, reserved::LTEP)
    }

    /// Whether this profile advertises the fast-extension bit.
    pub fn supports_fast(&self) -> bool {
        reserved::has(&self.peer.reserved, reserved::FAST)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter(u32);
    impl Rng for Counter {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            self.0
        }
    }

    #[test]
    fn peer_id_has_prefix_and_alphabet_tail() {
        let p = Profile::qbt_5_2_3_lt2_0_14();
        let id = p.peer_id.generate(&mut Counter(1));
        assert_eq!(&id[..8], b"-qB5230-");
        for &c in &id[8..] {
            assert!(QBT_TAIL_ALPHABET.contains(&c), "{c}");
        }
        assert_eq!(p.peer_id.lifetime, PeerIdLifetime::PerTorrent);
        let n = Profile::native().peer_id.generate(&mut Counter(2));
        assert_eq!(&n[..8], b"-UR0B30-");
        assert!(n[8..].iter().all(u8::is_ascii_alphanumeric));
    }

    #[test]
    fn escape_matches_captured_style() {
        // info_hash from the golden capture: e98b2701d69b49e78b07a50e0bc22c8a9dacee20
        let ih = [
            0xe9, 0x8b, 0x27, 0x01, 0xd6, 0x9b, 0x49, 0xe7, 0x8b, 0x07, 0xa5, 0x0e, 0x0b, 0xc2,
            0x2c, 0x8a, 0x9d, 0xac, 0xee, 0x20,
        ];
        assert_eq!(
            EscapeStyle::LowerHexLibtorrent.escape(&ih),
            "%e9%8b%27%01%d6%9bI%e7%8b%07%a5%0e%0b%c2%2c%8a%9d%ac%ee%20"
        );
        assert_eq!(
            EscapeStyle::LowerHexLibtorrent.escape(b"-qB5230-PyFu!8(YVAlz"),
            "-qB5230-PyFu!8(YVAlz"
        );
        assert_eq!(EscapeStyle::LowerHexRfc3986.escape(b"a!b"), "a%21b");
    }

    #[test]
    fn key_style() {
        assert_eq!(KeyStyle::HexUpper8.render(0xFF2033B3), "FF2033B3");
        assert_eq!(KeyStyle::HexUpper8.render(0x1), "00000001");
    }

    #[test]
    fn reserved_bits() {
        let q = Profile::qbt_5_2_3_lt2_0_14();
        assert!(q.supports_ltep() && q.supports_fast());
        assert!(reserved::has(&q.peer.reserved, reserved::DHT));
        let n = Profile::native();
        assert!(n.supports_ltep() && n.supports_fast());
        assert!(!reserved::has(&n.peer.reserved, reserved::DHT));
    }

    #[test]
    fn rng_below_is_in_range() {
        let mut r = Counter(7);
        for _ in 0..1000 {
            assert!(r.below(70) < 70);
        }
        assert_eq!(r.below(1), 0);
        assert_eq!(r.below(0), 0);
    }
}
