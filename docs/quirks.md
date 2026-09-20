# Quirks

Places where the oracle (qBittorrent 5.2.3 / libtorrent 2.0.14) and a BEP
disagree, or where our capability gaps show. Under the `qbt_5_2_3_lt2_0_14`
profile the oracle wins (AGENTS.md 9). Each entry names the golden capture
that proves it.

## Q1. DHT reserved bit is set even with DHT disabled

Capture: `testkit/golden/capture_peer_plain/*/tap-peer-plain-oracle-initiator.jsonl`
(oracle configured with `Session\DHTEnabled=false`) shows reserved bytes
`00 00 00 00 00 10 00 05` = LTEP + fast + **DHT**. The same bytes appear with
DHT enabled (`capture_defaults`). libtorrent sets the DHT bit from the
`enable_dht`-independent "DHT support compiled in" state.

Consequence for 0.1.0 (no DHT): the qbt profile advertises the DHT bit for
L1/L2 exactness. We never send `PORT`, and we ignore incoming `PORT`. The
oracle itself does not send `PORT` to a peer whose reserved bits lack DHT
(`capture_defaults`: no `port` message received by tap-peer), so a peer that
does not advertise DHT is never misled.

## Q2. LTEP `m` advertises `ut_holepunch`, `share_mode`, `lt_donthave`

Capture: `capture_peer_plain` extended handshake:
`m = {lt_donthave: 7, share_mode: 8, upload_only: 3, ut_holepunch: 4, ut_metadata: 2, ut_pex: 1}`,
plus `complete_ago`, `metadata_size`, `p`, `reqq: 2000`, `v`, `yourip`, and
`upload_only: 1` when seeding.

0.1.0 has no uTP, so `ut_holepunch` cannot work. Under the qbt profile the
`m` map is advertised verbatim (L2); incoming `ut_holepunch` messages are
answered the way the oracle answers with uTP disabled (to be captured in M5:
`capture_holepunch`). `share_mode` and `lt_donthave` are implemented
(trivial). The `native` profile advertises only what it implements.

## Q3. "Allow encryption" connects out in plaintext to unknown peers

Capture: `capture_peer_encrypted` (oracle `Session\Encryption=0`, qBt "Allow
encryption") - the oracle's outgoing connection to tap-peer is a plaintext
handshake, no MSE attempt. libtorrent (`bt_peer_connection::on_connected`,
`pe_enabled`) toggles a per-peer `pe_support` flag: the first attempt is
plaintext; if it fails before the handshake completes, the next attempt to
that peer is encrypted (and vice versa). The session mirrors this with
`Torrent::mse_retry`. `Force` (`capture_peer_forced`): MSE always,
`crypto_provide = 2`, pads `random(512)`, the BitTorrent handshake travels as
IA (`len(IA) = 68`). `capture_peer_allow_mse`: for `provide = 3` the oracle
selects RC4 -> qBittorrent runs with `prefer_rc4 = true`
(`profile::MseShape`).

## Q4. Tracker `interval` is clamped to libtorrent's `min_announce_interval`

Observation while building `capture_tracker_http`: with the tap-tracker
answering `interval: 30`, the oracle did not re-announce within 45 s; libtorrent
never announces more often than `min_announce_interval` (5 min default).
Behavioural (L3): we adopt the same default constant and honour
`min interval` semantics; exact timing is not a gate.

## Q5. Incoming peers are refused briefly after a torrent starts

Observation: right after a torrent is added and checked (WebAPI already
reports `stalledUP`), incoming connections are closed without a handshake for
up to ~1 s. Harness consequence only: tap-peer retries. Not a fidelity item.

## Q6. LTEP `p` is omitted on outgoing v6 connections until an external address is known

Capture: `capture_peer_plain/v4/tap-peer-plain-oracle-initiator.jsonl` has
`p: 6881` in the oracle's extended handshake; the same scenario in
`capture_peer_plain/v6/...-oracle-initiator.jsonl` has **no `p`**, with or
without a default route in the namespace.

Mechanism (libtorrent 2.0.14 `bt_peer_connection::write_extensions` →
`session_impl::listen_port(ssl, local_addr)`): the port is sent only when a
listen socket's *external address* (an `ip_voter` fed by tracker `external
ip` replies and peers' `yourip`) equals the connection's local address, or is
unspecified **of the same family**. A voter with no votes yields a v4
unspecified address, so v4 connections match right away while v6 ones match
only once a global v6 address has been voted in; the lab's ULA prefix never
qualifies (`is_local` rejects fc00::/7), so `p` never appears there.

Consequence: `wire::ConnectionParams::advertise_port` carries the decision;
the session sets it to "connection is IPv4" until external-address voting
exists (candidate for M6 alongside PEX). Pinned in
`crates/wire/tests/replay.rs`.

## Q7. Allowed-fast set is seeded with the full peer address, not the BEP 6 /24

Capture: `capture_peer_plain/v4/tap-peer-plain-oracle-responder.jsonl` (oracle
seeding to tap-peer at 10.77.142.3, 16 pieces) shows `allowed_fast` for
`[7, 12, 5, 3, 11]`; the v6 capture (tap-peer at fd77:8e::3) shows
`[6, 9, 13, 11, 1]`. BEP 6 says to hash `(ip & 0xffffff00) || info_hash`, which
gives `[9, 13, 0, 6, 11]` for the v4 case. Hashing the **unmasked** 4 / 16
address bytes reproduces both captures exactly (libtorrent
`bt_peer_connection::send_allowed_set` uses `address::to_bytes()`).

Consequence: `profile::PeerShape::allowed_fast_addr` — `LibtorrentFull` for the
qbt profile (L2), `Bep6Masked` for `native`. Interop is unaffected either way
(the receiver only records the indices it is told). Pinned in
`crates/wire/tests/replay.rs`.

## Q8. `supportcrypto=1` is only announced while encryption is enabled

Observation (`diff_identity` with the oracle at `Session\Encryption=2`,
"disable"): the announce carries no `supportcrypto` parameter at all; at the
default setting ("allow", the golden captures) it is `supportcrypto=1`.
libtorrent emits `supportcrypto=1` when encryption is allowed and
`requirecrypto=1` when it is forced (position UNVERIFIED until the M5 forced
capture). Consequence: the parameter is a function of the MSE mode, not a
constant of the profile; `profile` will model it when MSE lands (M5). Until
then the qbt profile announces `supportcrypto=1`, the oracle's default.

## Q9. One announce per listen socket

Capture: `testkit/golden/capture_tracker_dual` (a hostname tracker resolving
to both families, dual-stack oracle): every announce is sent twice, once from
the IPv4 listen socket and once from the IPv6 one, with the same `peer_id`,
`key` and parameters, and each socket runs its own `started` -> `completed` ->
`stopped` sequence. For an IP-literal tracker only the matching family's
socket announces (the dual-stack golden of `capture_tracker_http` shows a
single v4 sequence and no errors). BEP 3 has no such notion; libtorrent's
`announce_endpoint` per listen socket does. `tracker::Announcer` keeps one
state per endpoint and the session routes each endpoint's announce through
its family; mismatching IP-literal endpoints are disabled silently.

`ipv4=` / `ipv6=` announce parameters are sent by libtorrent only for
**private** torrents and only for globally routable listen addresses
(torrent.cpp, `announce_with_tracker`); the lab's addresses are private, so
this is not yet capturable here (open item for a public-address test).

## Q10. UDP tracker: one attempt per request, BEP 41 URL data

Capture: `capture_tracker_udp`. The oracle retransmits nothing within a
request: a `connect` that gets no reply fails after the receive timeout and
the tracker enters the ordinary announce backoff (attempts at +39 s and
+65 s in the capture), instead of BEP 15's 15·2ⁿ retransmits. Every announce
carries option 2 (URL data) with the URL's path and query (`\x02\x09/announce`),
`ip = 0`, `num_want` = the profile's `numwant` (0 on `stopped`), and the same
`key` as the HTTP announces. Connection ids are reused for 60 s. The UDP
source port is the listen port. `tracker::udp` reproduces all of it; the
`udp_tracker` scenario shows no UDP-side tells vs the oracle.
