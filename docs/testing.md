# Testing guide

The developer commands, the test layers, and the network lab the
integration tests run in.

## Commands

| Command | What it does |
|---|---|
| `cargo xtask check [--quick]` | `cargo fmt --check`, clippy `-D warnings`, `cargo test --workspace`, `cargo doc` with warnings denied, the dependency policy (`cargo deny` bans / licences / sources / advisories, and the tokio feature and reactor audit), and `cargo semver-checks` against the latest `v*` tag. `--quick` keeps only fmt, clippy and the dependency policy. `cargo-deny` and `cargo-semver-checks` are skipped with a note when not installed |
| `cargo xtask doctor` | checks kernel version, io_uring availability (sysctl and probe), memlock, passwordless sudo, the lab tools, the Transmission AppArmor override, Docker's seccomp profile, the cached oracle binary and the optional cargo tools |
| `cargo xtask it [--shape v4\|v6\|dual] [--keep] [scenario ...]` | integration scenarios (tag `It`) in the netns lab; every shape the scenario declares unless `--shape` picks one |
| `cargo xtask diff [--shape ...] [--keep] [scenario ...]` | differential scenarios (tag `Diff`): oracle and us through the same taps, then the discriminator |
| `cargo xtask capture [--shape ...] [scenario ...]` | capture scenarios (tag `Capture`) against the pinned oracle; a passing run is promoted to `testkit/golden` |
| `cargo xtask bench [--shape ...] [scenario ...]` | resource benchmarks against the oracle (`bench_leech`, `bench_seed`, `bench_many`), release build; results in `docs/perf.md` |
| `cargo xtask fuzz <target> [secs]` | `cargo +nightly fuzz run <target>` for `secs` seconds (default 60); needs nightly and `cargo-fuzz` |
| `cargo xtask syscalls` | runs the uring probe and a real two-engine transfer under `strace` and fails on any `epoll_*` / `poll` / `select` or off-ring socket or file data syscall from the engine threads; needs `strace` |
| `cargo xtask soak [transfer\|many\|all] [--size N] [--piece N] [--torrents N] [--utp] [--zero-copy] [--inline-disk]` | perf and leak exercise, release build, two engines on loopback (below). The mode comes first; the default is `all` |

`it`, `diff`, `capture` and `bench` build the testkit binaries and run
`testkit` (`cargo run -p testkit --bin testkit -- <command>`). The testkit
binary also has `list` (every scenario with its shapes and tags), `run
<scenario>` (any tag, no promotion), `lab clean` (remove stale bridges,
namespaces and `/etc/hosts` entries) and `oracle ensure` (download the
oracle binary now).

`soak` runs `testkit/src/bin/urt-soak.rs`. `transfer` moves one torrent of
`--size` bytes (default 2G; pieces 1 MiB, or 4 MiB from 4 GiB up, unless
`--piece` is given); `many` adds `--torrents` one-piece torrents (default
500) and removes them again. It fails on an incomplete transfer, data that
does not verify, or fds still held after removal or shutdown. `--utp` runs
uTP-only engines, `--zero-copy` turns on `zero_copy_send`, `--inline-disk`
turns off `disk_thread`. Scratch data goes to `target/soak`.

### Lab prerequisites

`it`, `diff`, `capture` and `bench` need:

- **Passwordless sudo** for `ip netns`, `nsenter` (util-linux) and
  `tcpdump`. The lab also uses it for `iptables` / `ip6tables` and its
  `/etc/hosts` entries.
- **`opentracker`** from apt. On Debian and Ubuntu builds that are IPv4-only,
  also `opentracker-ipv6` for the v6 and dual shapes (`doctor` tells).
- **`transmission-daemon`** from apt, for the scenarios that use it
  (`seed_to_transmission`, `diff_identity`). Ubuntu's AppArmor profile
  needs a local override for `testkit/runs`; `doctor` prints it.
- **`tcpdump`** for pcaps. `private_no_pex_lsd` and the uTP scenarios
  (`capture_utp`, `utp_leech_from_oracle`, `utp_seed_to_oracle`,
  `utp_shape`) need it; `lsd_discovery` skips its datagram check without
  it; other scenarios skip their pcap.
- **`curl`**: the pinned oracle binary (`testkit/oracle.lock`, checksum
  verified) is downloaded on first use into `~/.cache/urtorrent/oracle`
  (`URT_ORACLE_CACHE` overrides the location).

`cargo xtask doctor` checks all of these.

## Layers (AGENTS.md 7.1)

| Layer | Where | Command |
|---|---|---|
| Unit / property | each crate's tests, `proptest` | `cargo xtask check` |
| In-process gates | `crates/session/tests` (below) | `cargo xtask check` |
| Fuzz | `fuzz/fuzz_targets` | `cargo xtask fuzz <target> [secs]` |
| Replay | crate tests fed from `testkit/golden` | `cargo xtask check` |
| Integration | `testkit/src/scenario` | `cargo xtask it` |
| Differential | scenarios tagged `Diff`: `diff_identity`, `mse_shape`, `dual_stack_announce`, `pex_discovery`, `web_seed_only`, `dht_shape`, `utp_shape`, `magnet_private_shape`, `magnet_hold`, `partial_seed_shape` | `cargo xtask diff` |
| Captures | scenarios tagged `Capture` | `cargo xtask capture` |
| Enforcement | uring probe and a real session under `strace -f -y -Y` | `cargo xtask syscalls` |
| Benchmark | `testkit/src/scenario/bench.rs`: RSS and CPU against the oracle | `cargo xtask bench` |
| Soak / perf | `testkit/src/bin/urt-soak.rs` | `cargo xtask soak` |

### In-process gates

Each file in `crates/session/tests` runs real engines in one process on
loopback:

| File | Covers |
|---|---|
| `leech.rs` | leeching from a sans-IO seeder through a small HTTP tracker; counters and the `started` / `completed` / `stopped` sequence |
| `seed.rs` | two engines: upload path, rate limits, recheck after corruption, pause / resume |
| `files.rs` | file priorities with the parts file, move storage |
| `partial.rs` | seeding a partial selection; restart and check find the same pieces |
| `resume.rs` | resume blobs, unfinished pieces, `needs_resume_save` |
| `queue.rs` | the active-torrent queue and the per-torrent / session limits |
| `api.rs` | the 0.2.0 API additions (preallocation, pause-all, tracker edits, removal with files, stats) |
| `daemon.rs` | what an HTTP daemon needs: the `.torrent` back, pieces, runtime settings, bans, web seeds, renames |
| `gaps.rs` | the 0.12–0.14 daemon gaps: error recovery, missing content, holds, tracker endpoints, piece priorities, IP ranges, the slow flag, ... |
| `listen.rs` | listen sockets, DHT and profile changed live |
| `races.rs` | operations overlapping work in flight (rechecks, storage moves, removal, shutdown) |
| `dualstack.rs`, `selfconn.rs` | dual-stack edge cases and connections to ourselves |
| `copies.rs` | copy budgets on the data path (`docs/perf.md`) |
| `extensions.rs` | magnets over `ut_metadata`, PEX, `upload_only`, web seeds, private torrents |
| `dht.rs` | finding a seeder through the DHT alone |
| `utp.rs` | uTP transfers, MSE over uTP, transport policies and fallbacks |
| `hostile.rs` | malicious peers against a live engine (next section) |

## Hostile peers

Anything that eats bytes from the network is untrusted (AGENTS.md 9). The
gates run at four levels.

**Parsers.** There is a `cargo-fuzz` target per parser in
`fuzz/fuzz_targets`: `bencode_decode`, `bencode_roundtrip`,
`metainfo_parse`, `magnet_parse`, `wire_message`, `wire_connection`,
`ltep_handshake`, `pex_message`, `metadata_message`, `announce_response`,
`scrape_response`, `udp_reply`, `http_response`, `mse_responder`,
`lsd_datagram`, `resume_parse`, `dht_krpc`, `utp_packet`,
`identify_client`. Every length is bounded before it is trusted:

| Bound | Value |
|---|---|
| `wire::MAX_FRAME` | 1 MiB |
| `wire::MAX_BLOCK` | 128 KiB |
| `wire::MAX_BITFIELD` | 1 MiB |
| `wire::MAX_EXT_PAYLOAD` | 256 KiB |
| `wire::ext::MAX_METADATA_SIZE` | 8 MiB |
| `tracker::http::MAX_BODY` | 4 MiB, also after gzip |
| `dht::krpc::MAX_PACKET` | 1500 bytes |
| bencode nesting | 32 |

**The state machine** (`crates/wire/src/conn.rs` unit tests): out-of-range
indices and lengths, wrong bitfield sizes, fast-extension messages without
the extension, requests while choked (300, then the peer is dropped),
allowed-fast abuse, 4096 queued requests, cancels, duplicate and self
connections.

**A live engine** (`crates/session/tests/hostile.rs`, raw sockets against a
seeding session):

- slow-loris handshakes are dropped at one 10 s deadline for the whole
  handshake, however many reads, while a real peer still completes;
- an idle-connection flood is refused at the connection limit (pending
  handshakes count);
- a 4 GiB length prefix, random bytes after the handshake, a wrong
  info-hash and an HTTP request are dropped without allocation;
- requests past the end of a piece (also the short last piece), out of
  range, empty or oversized end the connection with nothing served;
- PEX floods are disconnected (libtorrent's cadence rule), and the
  per-torrent peer list is capped at 3000 for every source
  (`max_peerlist_size`; waiting candidates are evicted, never connected
  peers);
- 5000-deep bencode nesting and 300 KiB extension payloads are refused;
- unrequested blocks are never written; they count as both `downloaded`
  and `redundant` (so the announce gains nothing), on the torrent and on
  the sending connection, and the connection is kept.

**In the lab**: `hash_fail_ban` (a tap-peer serving corrupt pieces is
banned once its trust score reaches `BAN_AT`), `encryption_matrix`,
`private_no_pex_lsd`.

## The lab

`testkit::lab` builds a bridge on the host (`urt<id>`) with a private IPv4
/16 and IPv6 /32, and a network namespace per actor (ADR 0002).

- **Addressing.** Client actors (oracle, Transmission, our client) each get
  a namespace and one address per family the shape asks for, each in its
  own /24 and /64: `10.<id>.<n>.1` and `fd77:<id>:<n>::1`. libtorrent's DHT
  keeps one node per /24 or /64 per bucket and per lookup, so distinct
  prefixes are what make multi-hop DHT behaviour observable. Harness-side
  actors (tap-tracker, tap-peer, tap-dht, opentracker) run in the harness
  process or as host processes on bridge addresses: `10.<id>.0.1` plus
  aliases `10.<id>.<2..9>.1`.
- **Offline.** Every actor gets a default route through the bridge
  (Transmission refuses to open peer connections without one), and a
  `FORWARD ... -j DROP` rule keeps the lab off the internet.
- **Tracker hostname.** Each lab adds an `/etc/hosts` name,
  `tracker.urt<id>.lab`, resolving to the harness's IPv4 and IPv6 bridge
  addresses, so dual-stack announce behaviour can be observed against a
  hostname.

The library under test runs as the `urt-client` binary
(`testkit/src/bin`), launched into its own namespace like the oracle;
`testkit::client::UrtClient` drives it. It writes a JSON status snapshot
(`status.json`: state, counters, files, trackers, peers seen, recent
events) every 200 ms and takes one command at a time from a control file:
`shutdown`, `pause`, `resume`, `reannounce`, `save-resume`, `recheck`,
`release`, `scrape`, `prio <csv>`, `move <path>`, `add <torrent>`. No
signals are needed for a graceful stop.

`transmission-daemon` (Transmission 4) is the second independent peer.

The tap-peer speaks MSE through the library's `mse` crate. Interop with the
oracle validates it, since a symmetric mistake cannot complete a handshake
with libtorrent. It records the peer's `crypto_provide` / `select` and pad
lengths (`PeerCapture::mse`), serves `ut_metadata` from its fixture (so
the oracle can be observed in magnet mode), and publishes live snapshots
of open connections, so a silent tap can be inspected while still
connected (`TapPeer::captures` / `wait_for`).

`tap-webseed` is a GetRight-style range server that records raw requests;
`web_seed_only` has the oracle and us fetch the same torrent from it and
compares request lines and header order.

Rule 2 (private torrents) is checked on the wire by `private_no_pex_lsd`:
a pcap of the bridge must hold no LSD datagram from our address, and a
silent tap connected to us must receive no `ut_pex` message and see an `m`
map without `ut_pex` / `ut_metadata` (Q11), and the tap-dht router must see
no KRPC about the torrent while our DHT node runs.

Run artifacts land in `testkit/runs/<stamp>-<scenario>-<shape>/`
(gitignored): actor stdout / stderr, oracle profiles and logs, tap logs
(`*.jsonl`), pcaps. `--keep` leaves the namespaces up after a run;
`testkit lab clean` removes them.

## Golden captures

`cargo xtask capture` writes `testkit/golden/<scenario>/<shape>/` from the
pinned oracle, and the results are committed. They are **the spec** for
identity and wire shape (AGENTS.md 6). Formats:

- `tap-tracker*.jsonl`: one `TapEvent` per request: raw request bytes
  (hex), parsed request line, headers and ordered query parameters, and the
  response bytes.
- `tap-peer*.jsonl`: one `PeerCapture` per connection: both handshakes (raw
  and decoded reserved bits), every message in order with direction,
  timestamp and raw frame (except piece payloads), and the decoded LTEP
  dictionaries.
- `tap-dht*.jsonl`: one `DhtEvent` per KRPC datagram either way:
  direction, kind (`query:<q>` / `response` / `error`), transaction id, raw
  bytes and the decoded dictionary (binary strings as hex). `capture_dht`
  also records the oracle's replies to a fixed probe list (every query
  kind, good and bad), which `dht_shape` replays against us.
- `utp-shape.json`: a summary of a uTP pcap decoded by
  `testkit::utp_capture`: the first packets, every SYN / FIN / RESET,
  packets carrying extensions, the ST_DATA payload-size histogram and the
  largest datagram. The pcap itself stays in the run directory.
- `magnet-hold.json`, `missing-files.json`, `partial-seed.json`: what the
  oracle did in those scenarios as its WebAPI reported it (states,
  progress, files on disk).

Bumping `testkit/oracle.lock` regenerates all of them in the same PR.

## The discriminator

`testkit::discriminator` turns tap-tracker events, tap-peer captures,
tap-dht events and uTP pcaps into a `Fingerprint` of L1 identifiers and L2
wire shape only:

- trackers and peers: peer-id prefix, `User-Agent`, header and parameter
  order, escape style, `key` format, `numwant` and flags, reserved bits,
  LTEP `m` / keys / `reqq` / `v`, the first-messages sequence;
- UDP tracker: the first actions, `num_want` (also on `stopped`), `ip = 0`
  and the options;
- MSE: `crypto_provide` / `select`, the IA length, the method, pad lengths
  in range;
- PEX: the key set, flag consistency, whether the recipient is listed;
- DHT: the `v` tag, transaction id length, the bootstrap / lookup /
  announce argument sets, replies to the probe list, the `port` position;
- uTP: the SYN, SYN-ACK and first-data shapes, the initial window, the
  path-MTU probe ladder and largest datagram, the FIN shape and FIN-ack
  extensions.

`diff(a, b)` lists the tells; `classify` compares against the oracle's
fingerprint computed from the committed goldens. `diff_identity` runs the
oracle, us (qbt and native profiles) and Transmission through the same
taps and asserts the discriminator separates exactly the right ones. When
a new tell turns up, add it to the discriminator first (red), then fix it
(green).
