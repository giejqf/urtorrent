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
handshake, no MSE attempt. libtorrent only tries the encrypted handshake first
when the peer is known to support it (tracker `crypto_flags` / previous
failure) or when encryption is *required*. The `Force` case is captured in M5.

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

## Q6. LTEP `p` is omitted on outgoing connections from a non-routable listen socket

Capture: `capture_peer_plain/v4/tap-peer-plain-oracle-initiator.jsonl` has
`p: 6881` in the oracle's extended handshake; the same scenario in
`capture_peer_plain/v6/...-oracle-initiator.jsonl` has **no `p`**. The lab's v6
prefix is a ULA (`fd77:8e::/64`) with no default route, and libtorrent flags a
listen socket whose interface has no route to the internet as "local network";
`session_impl::listen_port(...)` skips such sockets, so the outgoing
handshake carries no port. With a globally routable v6 address `p` would be
present (as for v4 here, where the private range is not treated this way).

Consequence: the `p` key depends on the *routability of our listen socket*,
not just on the connection direction. `profile` records `p_on_outgoing`; the
session decides routability per listen socket (M5, full dual-stack matrix).
`crates/wire/tests/replay.rs` pins the v6 difference so it stays visible.
