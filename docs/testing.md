# Testing guide

## Layers (AGENTS.md 7.1)

| Layer | Where | Command |
|---|---|---|
| Unit / property | each crate's `tests` + `proptest` | `cargo xtask check` |
| Fuzz | `fuzz/` | `cargo xtask fuzz <target> [secs]` |
| Replay | crate tests fed from `testkit/golden` | `cargo xtask check` |
| Integration | `testkit/src/scenario` | `cargo xtask it [--shape v4\|v6\|dual] [scenario]` |
| Differential | scenarios tagged `Diff` (`diff_identity`, `mse_shape`, `dual_stack_announce`, `pex_discovery`, `web_seed_only`, `dht_shape`, `utp_shape`, `magnet_private_shape`, ...) | `cargo xtask diff` |
| Captures | scenarios tagged `Capture` | `cargo xtask capture` |
| Enforcement | `xtask syscalls` (uring probe + real session under `strace -f -Y`) | `cargo xtask syscalls` |
| Soak / perf | `testkit/src/bin/urt-soak.rs` | `cargo xtask soak [transfer\|many\|all] [--size 20G] [--torrents 500]` (see `docs/perf.md`) |

## The lab

`testkit::lab` builds a bridge on the host (`urt<id>`) with a private v4 /16
and v6 /32 and a network namespace per actor (see ADR 0002). Client actors
(oracle, transmission, our client) each get a namespace and one address per
family the shape asks for, in their own /24 and /64 (`10.<id>.<n>.1`,
`fd77:<id>:<n>::1`): libtorrent's DHT keeps one node per /24 or /64 per
bucket and per lookup, so distinct prefixes are what make multi-hop DHT
behaviour observable. Harness-side actors (tap-tracker, tap-peer, tap-dht,
opentracker) run in the harness process or as host processes bound to bridge
addresses (`10.<id>.0.1` plus aliases `10.<id>.<2..9>.1`).

The library under test runs as the `urt-client` binary (`testkit/src/bin`),
launched into its own namespace like the oracle. It writes a JSON status
snapshot (`status.json`: state, counters, trackers, peers seen, recent events)
several times a second and takes commands from a control file (`shutdown`,
`pause`, `resume`, `reannounce`, `save-resume`), so scenarios need no signals
for a graceful stop. `testkit::client::UrtClient` wraps both.

`transmission-daemon` (Transmission 4) is the second independent peer. Two
things about it are non-obvious: it refuses to open any peer connection
unless the namespace has a default route (it derives its source address from
a route to a public IP), so every actor gets one through the harness bridge
while a `FORWARD ... -j DROP` rule keeps the lab offline; and Ubuntu's
AppArmor profile confines it to `/var/lib/transmission-daemon`, so a local
override for `testkit/runs` is needed (`cargo xtask doctor` prints it).

Each lab also gets an `/etc/hosts` name, `tracker.urt<id>.lab`, resolving to
the harness's IPv4 and IPv6 bridge addresses, so dual-stack announce
behaviour can be observed against a hostname (`lab clean` removes stale
entries).

The tap-peer speaks MSE (using the library's `mse` crate: interop with the
oracle validates it, since a symmetric mistake cannot complete a handshake
with libtorrent) and records the peer's `crypto_provide` / `select` and pad
lengths (`PeerCapture::mse`). It also serves `ut_metadata` from its fixture
(so the oracle can be observed in magnet mode) and publishes live snapshots
of open connections, so a lingering silent tap can be inspected while it is
still connected (`TapPeer::captures` / `wait_for`).

`tap-webseed` is a GetRight-style range server for a fixture that records
raw requests; the `web_seed_only` scenario has the oracle and us fetch the
same torrent from it and compares request line and header order.

Rule 2 (private torrents) is checked on the wire by `private_no_pex_lsd`: a
pcap of the bridge must hold no LSD datagram from our address, and a silent
tap connected to us must receive no `ut_pex` message and see an `m` map
without `ut_pex` / `ut_metadata` (Q11). It needs `tcpdump`.

Run artifacts land in `testkit/runs/<stamp>-<scenario>-<shape>/` (gitignored):
actor stdout/stderr, oracle profiles and logs, tap logs (`*.jsonl`), pcaps.
Pass `--keep` to leave the namespaces up after a run; `testkit lab clean`
removes stale labs.

## Golden captures

`testkit/golden/<scenario>/<shape>/*.jsonl` are produced by `cargo xtask
capture` from the pinned oracle and committed. They are **the spec** for
identity and wire shape (AGENTS.md 6). Formats:

- `tap-tracker*.jsonl`: one `TapEvent` per request: raw request bytes (hex),
  parsed request line / headers / ordered query parameters, response bytes.
- `tap-peer*.jsonl`: one `PeerCapture` per connection: both handshakes
  (raw + decoded reserved bits), every message in order with direction,
  timestamps and raw frame (except piece payloads), decoded LTEP dictionaries.
- `tap-dht*.jsonl`: one `DhtEvent` per KRPC datagram either way: direction,
  kind (`query:<q>` / `response` / `error`), transaction id, raw bytes and
  the decoded dictionary (binary strings as hex). `capture_dht` also records
  the oracle's replies to a fixed probe list (every query kind, good and
  bad); the `dht_shape` scenario replays that list against us.
- `utp-shape.json`: a compact summary of a pcap of uTP traffic decoded by
  `testkit::utp_capture` (the first packets, every SYN/FIN/RESET, packets
  carrying extensions, the ST_DATA payload-size histogram, the largest
  datagram). The pcap itself stays in the run directory (git-ignored).

Bumping `testkit/oracle.lock` regenerates all of them in the same PR.

## The discriminator

`testkit::discriminator` turns tap-tracker events, tap-peer captures and
tap-dht events into a `Fingerprint` (L1 identifiers and L2 wire shape only:
peer-id prefix, `User-Agent`, header and parameter order, escape style,
`key` format, `numwant`/flags, reserved bits, LTEP `m`/keys/`reqq`/`v`, the
first-messages sequence; for the DHT the `v` tag, transaction id length,
bootstrap / lookup / announce argument sets, replies to the probe list and
the `port` position; for uTP the SYN, SYN-ACK and first-data shapes, the
initial window, the path-MTU probe ladder and largest datagram, the FIN
shape and FIN-ack extensions, from a pcap). `diff(a, b)` lists the tells; `classify` compares against the
oracle's fingerprint computed from the committed goldens. `diff_identity`
runs the oracle, us (qbt and native) and Transmission through the same taps
and asserts the discriminator separates exactly the right ones. When a new
tell is found: add it to the discriminator first (red), then fix it (green).
