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

Consequence: the qbt profile advertises the DHT bit unconditionally for
L1/L2 exactness (the `native` profile only while a DHT node runs). Until
0.3.0 we never sent `PORT`; since 0.3.0 `PORT` follows the oracle's rules
(Q20): sent only while a DHT node runs, so with the DHT disabled the bit is
advertised and `PORT` is not sent, exactly like the oracle with
`DHTEnabled=false`. The oracle does not send `PORT` to a peer whose reserved
bits lack DHT (`capture_defaults`: no `port` message received by tap-peer), so
a peer that does not advertise DHT is never misled.

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

## Q11. Private torrents drop `ut_pex`, `ut_metadata` and `metadata_size`

Capture: `capture_peer_private` (oracle on a `private=1` torrent, both roles).
The LTEP handshake's `m` is `{lt_donthave: 7, share_mode: 8, upload_only: 3,
ut_holepunch: 4}` and carries no `metadata_size`; everything else (`reqq`,
`v`, `yourip`, `p` on outgoing, `upload_only: 1` when seeding, `complete_ago`)
is unchanged. libtorrent never creates the `ut_pex` / `ut_metadata` plugins
for a private torrent (`create_ut_pex_plugin`, `create_ut_metadata_plugin`),
so the ids are simply absent. Consequence: `profile::LtepShape::m_private`
and the `private` flag on `wire::ConnectionParams`; a `ut_pex` message under
a stale id is an unknown extension and is dropped. Pinned byte-exact in
`crates/wire/tests/replay.rs`; the no-traffic guarantee (rule 2) is checked on
the wire by the `private_no_pex_lsd` scenario (pcap + tap-peer).

## Q12. `left=16384` before the metadata is known

Capture: `capture_magnet/v4/tap-tracker-magnet.jsonl` — the oracle's first
announce for a magnet link carries `left=16384` (`downloaded=0`); once the
metadata is known the real size follows. libtorrent uses 16 KiB when
`bytes_left()` is unknown (`torrent.cpp`, `announce_with_tracker`). BEP 3 has
no way to say "unknown", and `left` here is not a claim about data we hold
(rule 1); we announce the same value in the same situation.

## Q13. qBittorrent stops and re-adds a magnet torrent when its metadata arrives

Capture: `capture_magnet`. Two milliseconds after receiving the metadata the
oracle closes its peer connection, announces `stopped` (`left=1048576` now
that it knows), then announces `started` again about a second later and
reconnects with a fresh connection that carries `metadata_size`, `have_none`
and `interested`. This is qBittorrent re-creating the torrent from the
received metadata, not libtorrent (`set_metadata` keeps connections). It is
an L3 behaviour we do **not** copy: we keep the connection, send our
have-state (`bitfield` / `have_none`) and a BEP 21 `upload_only` message on
it, as libtorrent's `on_metadata` does, and keep the single `started`.

Also from this capture: **without metadata libtorrent sends no have-state at
all** (no `have_none`, no `bitfield`) after the handshake; the LTEP handshake
omits `metadata_size`; the first `ut_metadata` request is for piece 0 and has
no `total_size`. `wire::Connection` with `piece_count: None` matches
(`qbt_magnet_mode_matches_capture`).

## Q14. The allowed-fast set waits for `interested`; a preemptive `unchoke` comes first

Capture: `capture_peer_plain/v4/tap-peer-plain-oracle-responder.jsonl` (and
`capture_peer_private`): the oracle seeding to a tap leecher sends `extended`,
`have_all`, then `unchoke`, and only after the tap's `interested` the five
`allowed_fast` messages. libtorrent unchokes a fresh peer right away when it
has pieces and a slot is free (`maybe_unchoke_this_peer`) and defers
`send_allowed_set` to the first `interested`, skipping pieces the peer already
has (and granting every piece the peer lacks when the torrent has no more
pieces than the set size). Our profile data used to list allowed-fast as a
first message; the first-messages sequence is now `[extended, have-state]`
for both profiles, the allowed set goes out on `interested`, and the engine
unchokes preemptively when it has pieces.

Also confirmed from `write_bitfield`: with the fast extension off and no
pieces, libtorrent sends no `bitfield` at all.

## Q15. PEX cadence and eligibility (BEP 11 as libtorrent does it)

Capture: `capture_pex` (oracle seeding to two silent tap leechers that
advertise `p`). The first `ut_pex` to a peer is sent on the first one-second
tick at which the torrent has more than one peer (4.7 s after start in the
capture, when the second tap had connected); it lists every exchangeable
connection *including the recipient*, with all six keys present (`added`,
`added.f`, `added6`, `added6.f`, `dropped`, `dropped6`; empty strings when
empty). Later messages carry the torrent-wide delta rebuilt once a minute,
and are skipped when the delta is empty. Exchangeable: connections past the
handshake that libtorrent dialled, or incoming ones that sent a listen port
(`p`). Flags: `0x02` seed, `0x01` encrypted connection, `0x08` advertised
`ut_holepunch`; `0x04` (uTP) and `0x10` are never set by 2.0.14 (it masks
`0x10` on receipt). Receiving more than six messages a minute or one over
500 KiB is a disconnect. The engine's `pex` module reproduces this; the
`pex_discovery` scenario shows no tells against the golden.

## Q16. LSD: one announce per listen socket, three datagrams each

Capture: `lsd_discovery` pcaps. Each `lsd_announce` is three datagrams (at
once, +2 s, +4 s), and the oracle runs one LSD instance *per listen socket*
(three sockets on the lab actor: three datagrams at the same instant with
different `cookie`s). The datagram text is exactly libtorrent's
`render_lsd_packet` (`Infohash` lowercase hex, `cookie` `%x`, a blank line
plus a stray `\r\n` at the end). We send one announce per address family
with a session-wide cookie; the datagram itself is byte-identical after
normalising port, hash and cookie. Re-announce cadence is
`local_service_announce_interval` (5 min) divided among the torrents,
round-robin. Announces from our own cookie are ignored.

## Q17. Web seed requests

Capture: `web_seed_only`. The oracle fetches with `GET <path> HTTP/1.1`,
headers in the order `Host`, `User-Agent`, `Connection: keep-alive`,
`Range: bytes=a-b`, no `Accept-Encoding`, and asks for whole runs of pieces
in one request (the whole 2 MiB file in the capture; libtorrent caps at
16 MiB). We match the request line and header order/values and request
contiguous runs capped at 4 MiB over a kept-alive connection (an accepted L3
difference in request count).

## Q18. `completed` is announced only by a full seed

libtorrent (`torrent::finished` → `if (is_seed()) completed()`) announces
`event=completed` only when every piece is present; a selective download that
finished its wanted files sends no `completed` and keeps announcing the real
`left` (the skipped bytes). BEP 3 says `completed` is sent "when the download
completes", which is ambiguous for selective downloads. We follow libtorrent:
it is the truthful reading (rule 1) and what trackers expect from qBittorrent.
Checked in the `file_priorities` scenario (no `completed` after the selective
finish, one after the full download).

## Q19. A fresh peer id for every peer connection; the announce id is another

Captures: `capture_pex` (one torrent, two tap peers: the oracle's two
handshakes carry two different peer ids), `capture_magnet` (two consecutive
connections to the same tap: two ids), `capture_peer_plain` (the handshake id
is not the id announced to the tracker for that torrent). libtorrent 2.0
passes `aux::generate_peer_id(settings)` to every `peer_connection`
(`session_impl::incoming_connection`, `torrent::connect_to_peer`), while
trackers see the torrent's own `m_peer_id`. Two consequences we mirror:

- `profile::PeerIdShape::handshake = PerConnection` for the qbt profile: the
  handshake id is generated per connection (L1: a tap seeing two connections
  with one id, or a tracker + tap seeing the same id twice, would tell us
  apart). The `native` profile keeps one id everywhere.
- Duplicate-connection arbitration cannot rely on peer ids between two
  libtorrents (they never repeat), so libtorrent decides **by IP**
  (`peer_list::new_connection`): equal directions drop the newcomer,
  otherwise the side with the lower *listen* port keeps its outgoing
  connection, equal ports toss a coin. The peer-id rule
  (`bt_peer_connection::on_receive`: the greater id initiates) still exists
  for clients with stable ids. The engine implements both; a connection
  dropped as a duplicate does not back the address off (the coin can fall
  the wrong way on both sides at once, and the next tick simply dials again).
  This replaced our earlier "lower peer id initiates" rule, which disagreed
  with the oracle and stalled `kill9_resume` once LSD made simultaneous
  connects common.

Pinned in `crates/wire/tests/replay.rs`; the discriminator compares
"handshake id equals announce id" between the oracle and us.

## Q20. DHT (BEP 5) wire shape: libtorrent's extras

Capture: `testkit/golden/capture_dht/{v4,v6}/tap-dht-*.jsonl` (oracle with DHT
on and uTP off, bootstrapped from a tap DHT node, probed with every query
kind). Confirmed in libtorrent 2.0.14 `rpc_manager.cpp`, `node.cpp`,
`refresh.cpp`, `get_peers.cpp`. Everything here is mirrored by `crates/dht`
and checked byte-for-byte or by shape in `dht_shape` (`xtask diff`):

- **`v` on every message** is `"LT"` + `0x02` + `0x0e` (`4c 54 02 0e`):
  `LT` + major byte + `(minor << 4 | tiny)` for 2.0.14. It is *not* derived
  from the peer-id fingerprint. Profile data: `DhtShape::version`.
- **Transaction ids** are 2 random bytes.
- **Responses carry `ip`** (6 / 18 byte compact endpoint of the requester,
  BEP 42) and **`r.p`** (the requester's port as an integer) on every reply.
- **Errors keep `r`**: once the top level parsed, an error reply is `{e,
  ip, r: {id, p}, t, v, y: "e"}` — the `r` dictionary built before the query
  was rejected stays in. Error texts come from `verify_message`: `missing
  'target' key`, `invalid value for 'info_hash'`, plus `invalid token`,
  `invalid port`, `unknown message`. Code 203 for all of them.
- **Unknown methods with a `target` or `info_hash` argument are answered
  with nodes**, not an error; only an unknown method without one gets
  `unknown message`.
- **Bootstrap** is a `get_peers` traversal for the node's own id with a
  random secret tail, and queries to the *router* nodes carry `a.bs: 1`
  (non-router nodes reached during the same traversal do not).
- **A seed's lookup asks for `noseed: 1`** and its `announce_peer` says
  `seed: 1`; a leecher's lookup has neither and announces `seed: 0`. With
  uTP disabled the announce has no `implied_port` and `port` is the TCP
  listen port. After finishing a download the torrent is re-announced as a
  seed within seconds.
- **Refresh**: every 5 s one routing-table node is probed with `get_peers`
  for a random id in its bucket's range (`ping` when the bucket is full);
  routers never enter the routing table and never receive refreshes.
- **`port` (peer wire)** is sent right after the have-state to a peer whose
  handshake has the DHT bit, only while a DHT node runs, and in reply to a
  `port` from a peer that did not advertise the bit. With DHT disabled the
  oracle still advertises the bit (Q1) but never sends `port`.

Capability gap: BEP 44 `put` is not implemented (we answer `unknown
message`; the oracle stores the item). `get` is answered like the oracle's
"no such item" reply (nodes + token). A DHT-aware discriminator that probes
`put` would tell us apart; `dht_shape` does not.

## Q21. uTP (BEP 29) wire shape: libtorrent's `utp_stream`

Capture: `testkit/golden/capture_utp/{v4,v6}/utp-shape.json` (two oracles,
uTP only, cleartext). Confirmed in libtorrent 2.0.14 `utp_stream.cpp`,
`utp_socket_manager.cpp`, `torrent.cpp`, `torrent_peer.cpp`,
`peer_connection.cpp`. Everything here is mirrored by `crates/utp` and the
engine and checked by shape in `utp_shape` (`xtask diff`):

- **The oracle dials every new peer over uTP first.**
  `torrent_peer::supports_utp` starts true ("assume peers support utp"); a
  peer is dialled over TCP only after a uTP attempt to it failed (then
  immediately, `fast_reconnect`), or when uTP is disabled. A PEX `added`
  flag `0x04` re-enables uTP for an address. **Accepted difference (L3,
  maintainer decision 2026-09-20):** we dial TCP first by default because it
  performs better, and go to uTP for an address only after its TCP dial
  failed or was closed before the handshake; `TransportPolicy::PreferUtp`
  reproduces the oracle's order when wanted. Our own PEX entries carry the
  flag for peers connected over uTP, as the oracle's do.
- **SYN**: type/version `0x41`, no extension, `connection_id` = the id we
  will *receive* on (the peer replies with it and sends data with id + 1),
  `wnd_size` 0, `ack_nr` 0, `timestamp_difference` 0, 20 bytes. It is never
  retransmitted: an unconfirmed connection fails at its first (3 s) timeout.
- **SYN-ACK** is a bare ST_STATE with a random `seq_nr`, `ack_nr` = the SYN's
  `seq_nr`, `wnd_size` 1 048 576 (the receive buffer capacity). The
  connector's first ST_DATA carries `seq = syn + 1` and `ack = peer_seq - 1`
  (a STATE consumes no sequence number). The acceptor acks that data with a
  bare STATE before its own first ST_DATA (the ack is deferred to the end
  of the receive round; the BitTorrent handshake reply comes from the peer
  layer afterwards).
- **Path-MTU probing**: the search runs between a 548-byte floor
  (`576 - 20 - 8`) and the link ceiling (`1500 - 8 - 20` = 1472 for v4,
  1452 for v6, 1280-based for Teredo). Probes carry the mid-point size, all
  other packets the floor; an acked probe raises the floor, so payload
  sizes climb 528, 990, 1221, 1336, 1394, 1423, 1437, 1444, 1448, 1450, 1451
  (v4) and the largest datagram is `ceiling - 1` (1471 / 1451). Probes are
  sent with DF on IPv4 only.
- **Extensions**: selective acks (type 1) sized `ceil(reorder span / 8)`
  bytes whenever the reorder buffer is non-empty; the close reason (type 3,
  4 bytes: two reserved + a `close_reason_t` code) on the FIN and on any
  ack sent after the reason was set. Two seeds parting send reason 6
  (`upload_to_upload`); a peer closing on end-of-stream sends none.
- **Data delivered in the same receive round as the FIN is dropped.**
  libtorrent copies the payload into the outstanding read and then reports
  the read with `eof` when the FIN completes the stream in the same round;
  `peer_connection::on_receive_data` discards the bytes on any error. The
  visible effect: a leecher's last `have` followed at once by its FIN is
  not acted upon by the seeder, whose FIN then carries no close reason
  (when the two land in different rounds the `have` completes the peer's
  bitfield and the seeder closes with reason 6). Timing-dependent in the
  oracle; we reproduce the rule (`utp::Socket::end_round`), and `utp_shape`
  compares the FIN shape in the role where the client closes on its own.
- **Unknown connections get no ST_RESET**; stray non-SYN packets and SYNs
  with uTP disabled are ignored silently.
- **`implied_port`** appears in DHT announces only with uTP enabled
  (Q20 noted its absence with uTP off); with uTP on the oracle announces
  `implied_port: 1`. Our DHT announce follows the same rule.

Accepted differences: the number of floor-sized packets between two probe
steps and the ack cadence depend on how fast the application drains its
buffers (L3 timing); a burst's exact pacing differs (we submit 32 datagrams
per ring round trip, libtorrent one per `sendto`).

## Q22. BEP 7 `ipv4=` / `ipv6=` announce hints: private torrents, explicit public listen addresses only

Source: libtorrent 2.0.14 `torrent.cpp` (`announce_with_tracker`) and
`http_tracker_connection.cpp`. No lab capture can show it: the hints are
emitted only for listen sockets bound to a *specific* address that is
neither loopback nor "local" (RFC 1918 / link-local / ULA), and the lab's
addresses are all RFC 1918 or ULA. The rule, mirrored in
`session::engine::tracker_task::build_request` and rendered by
`AnnounceParam::{Ipv4Hints, Ipv6Hints}`:

- only for **private** torrents (`priv()`), and never in anonymous mode;
- one `&ipv4=<dotted>` per IPv4 listen address and one `&ipv6=<text>`
  (percent-escaped, so `%3a`) per IPv6 listen address, in that order;
- placed after `&redundant=` and `&trackerid=`, i.e. at the very end of the
  query;
- nothing for a wildcard listen address (the common case), so most peers
  never send them.

libtorrent's `announce_ip` setting (`&ip=`) is not implemented: qBittorrent
leaves it empty by default.

## Q23. Fast extension (BEP 6) leniencies

Source: libtorrent 2.0.14 `peer_connection.cpp` (`incoming_piece`,
`incoming_reject_request`, `incoming_cancel`, `incoming_request`,
`send_choke`); confirmed in every lab transfer with the oracle. Where BEP 6
says MUST/SHOULD close and libtorrent does not, the oracle wins:

- **A piece that was never requested** is counted as redundant and the
  connection kept (BEP 6: MUST close). Blocks for requests *we cancelled*
  are accepted as data: BEP 6 promises exactly one response per request
  and a cancelled request's response may well be the piece.
- **A reject for a request we never made** is ignored (BEP 6: SHOULD
  close); one for a cancelled request is its expected single response.
- **A cancel** of a request still in our queue is answered with a reject
  (libtorrent `incoming_cancel`); a request already handed to the disk is
  no longer in the queue, so the piece is its one response.
- **Choking** rejects every queued request except those for pieces in the
  peer's allowed-fast set, which stay queued and are served (BEP 6 SHOULD
  NOT reject them; libtorrent `send_choke`).
- **Requests while choked** are rejected; a peer that keeps asking is
  dropped (libtorrent gives it two seconds after the choke, we count 300
  rejects: the state machine has no clock), and one that pulls more than
  three pieces' worth of blocks from one allowed-fast piece while choked
  is dropped too (`too_many_requests_when_choked`).
- **Suggest piece** is honoured as a preference (libtorrent keeps the last
  16 suggestions per peer and requests them first); we never *send*
  suggestions, like the oracle at its default `suggest_mode`.

## Q24. Announce `downloaded` excludes corrupt and redundant bytes

Source: libtorrent 2.0.14 `torrent.cpp` (`announce_with_tracker`):
`downloaded = total_payload_download - failed_bytes - redundant_bytes`
(`report_true_downloaded` is off by default), so the figure never exceeds the
torrent size, "which upsets some trackers". `corrupt=` and `redundant=`
carry the excluded bytes. `TorrentStatus::downloaded` stays the gross count
of payload received; `build_request` subtracts.
