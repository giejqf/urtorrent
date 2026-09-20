# AGENTS.md

Guide for coding agents working on this repository. Read it fully before touching code.
Working name: **`urtorrent`** (placeholder; rename freely).

## 1. What this project is

A Rust BitTorrent **library** (not an app) for Linux, in the spirit of libtorrent-rasterbar:
downloading and seeding only, with all data-path I/O on **io_uring**, first-class
**IPv4 + IPv6**, and wire behaviour that matches a pinned qBittorrent build closely enough
that trackers and peers see nothing unusual.

### Non-goals

- Torrent creation, RSS, search, web UI, GUI, scheduler, IP-filter file formats.
- Any OS other than Linux. No epoll/kqueue/IOCP fallback. Do not add one.
- **DHT (BEP 5/32) and uTP (BEP 29) are out of scope for 0.1.0** (maintainer decision,
  2026-09-19). 0.1.0 is TCP-only and tracker/PEX/LSD-driven. Keep the design open for them.
- I2P, SOCKS/HTTP proxies, SSL torrents, share mode, super-seeding (revisit later if asked).
- BEP 52 (v2/hybrid) is *deferred*, not rejected. See section 4.

### Non-negotiable rules

1. **Accounting is always truthful.** `uploaded`, `downloaded`, `left`, `corrupt`, `event`
   and the have/bitfield state we advertise must reflect reality. Never add knobs, hooks or
   test helpers that let these be faked. The identity work in section 6 is about wire
   compatibility, not ratio cheating. Reject any task that asks otherwise.
2. **Private torrents (BEP 27) are sacred.** `private=1` means zero DHT, PEX and LSD traffic
   for that torrent, enforced by a test that inspects packets, not by code review.
3. **Tests never touch the public internet.** No public trackers, no public DHT bootstrap
   nodes, no real swarms. Everything runs in isolated network namespaces / internal Docker
   networks.
4. **The critical path is io_uring, with no possible fallback.** Critical path = peer
   sockets (accept/connect/send/recv), torrent file I/O (read/write/fsync/fallocate) and
   the timers that drive them. `mio`, `polling`, `async-io` and every other
   epoll/kqueue/IOCP reactor must not appear anywhere in the library's dependency tree
   (enforced by `cargo-deny`). `tokio` is the **public API surface only** (5.6): it is
   allowed in `session`/`urtorrent` with `default-features = false` and only the `sync`
   feature; the `rt`, `net`, `fs`, `io-util`, `time` and `process` features are banned in
   the library graph, so tokio can never own a socket, a file or a timer in this
   library. Off the critical path (DNS, reading config, enumerating resume files at
   startup) plain blocking std calls on a helper thread are fine. See 5.3.
5. **Do not weaken, skip or delete a failing test to get green.** Fix the code or escalate.

## 2. Feasibility notes (so nobody is surprised later)

- The protocol core (bencode, metainfo, peer wire, HTTP/UDP tracker, storage, choker, piece
  picker) is well-trodden ground. Low risk.
- uTP and DHT, the two largest optional work items, are deferred past 0.1.0. That removes
  most of the schedule risk.
- **io_uring in Rust** is the biggest *engineering-discipline* risk: completion-based I/O
  fights the borrow checker (buffers must outlive cancelled futures). Section 5 has rules.
- **The qBittorrent profile is best effort**, with priorities set by the maintainer:
  identifiers and wire shape must match exactly; **timing nuances and the TLS fingerprint
  are accepted differences** and are not release gates. Section 6 defines this precisely.
- Things that look small and are not: dual-stack announce semantics, crash-safe resume
  data, tracker tier/backoff semantics, and advertising capabilities we lack (see 6,
  "capability gaps").

## 3. The oracle

The reference implementation ("oracle") is a **pinned** headless qBittorrent:

| Item | Pin (as of 2026-09) | Notes |
|---|---|---|
| qBittorrent | `qbittorrent-nox` **5.2.3** | latest stable at project start |
| libtorrent | **2.0.14** primary, **1.2.20** secondary | qBt ships both lines; they differ on the wire (e.g. v2 support) |
| Binary source | `userdocs/qbittorrent-nox-static` release, checksum-pinned | static, reproducible, no distro drift |

Rules:

- The pin lives in `testkit/oracle.lock` (version, URL, sha256). Bumping it is a deliberate
  PR that regenerates all golden captures.
- **The oracle's captured behaviour is the spec** for anything in section 6. Do not encode
  fingerprint details from memory, blog posts, or this file. Capture, then implement.
- libtorrent source (BSD-3) is the secondary reference for *why* the oracle behaves as it
  does. You may read it and port logic with attribution. **qBittorrent is GPL: do not copy
  code from it.** Reading it to find which libtorrent settings it changes is fine; record
  those settings as data in the profile.
- Drive the oracle through its WebAPI (`/api/v2/...`) from `testkit`. Config is generated
  per test into a throwaway profile dir; no shared state between tests.

## 4. Protocol scope

Tiering reflects what public BT and private-tracker (PT) communities actually use.

**Tier 1 - required for a usable PT/BT client**

| Spec | What |
|---|---|
| BEP 3 | Core: metainfo, peer wire, HTTP tracker |
| BEP 23, BEP 7 | Compact peers, IPv6 peers (`peers6`) |
| BEP 12 | Multi-tracker tiers (libtorrent semantics, not the letter of the BEP) |
| BEP 15 | UDP tracker, incl. IPv6 |
| BEP 48 | Scrape (HTTP + UDP) |
| BEP 27 | Private torrents |
| BEP 6 | Fast extension (have-all/none, reject, suggest, allowed-fast) |
| BEP 10 | Extension protocol (LTEP) |
| BEP 21 | `upload_only` |
| MSE/PE | Message Stream Encryption (RC4 + DH), modes: forced / enabled / disabled |
| BEP 47 | Padding files and file attributes |
| - | File priorities / selective download, resume data, force recheck, move storage |
| - | Rate limits, connection limits, choker (leech + seed algorithms), piece picker with rarest-first, end-game, sequential |

**Tier 2 - in 0.1.0, after Tier 1 is solid**

| Spec | What |
|---|---|
| BEP 9 | `ut_metadata`, magnet links (tracker/PEX-sourced peers only in 0.1.0) |
| BEP 11 | PEX (`added`, `added6`, flags, dropped) |
| BEP 40 | Canonical peer priority |
| BEP 14 | Local Service Discovery |
| BEP 19 | Web seeds (GetRight style) |

**Tier 3 - post-0.1.0, design must not preclude**

BEP 5/32 DHT, BEP 29 uTP, BEP 55 `ut_holepunch` (needs uTP to be useful), BEP 52 v2/hybrid
torrents (merkle trees, SHA-256), BEP 17 web seeds, UPnP/NAT-PMP/PCP port mapping.

"Must not preclude" concretely: the listen port's UDP socket is owned by `uring` with a
demultiplexer hook (UDP tracker today; DHT/uTP later), and `session` talks to peers
through a transport trait that TCP implements today.

Note: the libtorrent 2.0 oracle speaks v2. If a Tier-1/2 capture shows v2-related bits on
v1-only torrents, that becomes a fidelity item and gets pulled forward; otherwise v2 waits.

## 5. Architecture

### 5.1 Workspace layout

```
crates/
  bencode/     zero-copy decode, canonical encode, preserves raw info-dict bytes
  metainfo/    .torrent + magnet parsing, file tree, piece<->file span mapping
  wire/        peer protocol codec + per-connection state machine   (sans-IO)
  mse/         encryption handshake + RC4 stream                    (sans-IO)
  tracker/     HTTP + UDP announce/scrape builders and parsers      (sans-IO)
  (dht/, utp/  reserved names, post-0.1.0)
  picker/      piece picker, request scheduling
  profile/     identity profiles as data (section 6)
  uring/       io_uring reactor, buffer pools, timers, TCP/UDP/file ops
  storage/     disk layout, preallocation, hashing pipeline, resume data
  session/     the engine: wires everything together; public API lives here
  urtorrent/   facade crate re-exporting the stable public API
testkit/       oracle + tracker + peer orchestration, capture, normalise, diff
xtask/         dev commands
docs/adr/      architecture decision records
```

### 5.2 Sans-IO is the core design rule

Every protocol crate is a pure state machine: bytes/events/`Instant` in, bytes/actions out.
No sockets, no clocks, no randomness except through injected traits. This is what makes the
project testable: deterministic unit tests, fuzzing, replaying oracle captures straight
into our state machines, and simulated-time tests for timeouts and backoff.

Only `uring`, `storage` and `session` may perform I/O.

### 5.3 io_uring layer (`uring` crate)

- Build directly on the **`io-uring`** crate with our own small thread-per-core reactor.
  Rationale: we need precise control over multishot ops, provided buffer rings, registered
  files/buffers, zero-copy send and linked timeouts, and the "everything is io_uring"
  requirement means no runtime may quietly fall back to epoll or a blocking thread pool.
  (compio and monoio were considered; record the final choice in `docs/adr/0001-runtime.md`.
  If an existing runtime is adopted instead, it must be configured so fallback is a hard
  error.)
- **Kernel baseline: 6.1 LTS.** Probe features at startup with `IORING_REGISTER_PROBE` and
  fail with a clear error listing what is missing. Newer opcodes (e.g. bind/listen,
  ftruncate, uring setsockopt) are optional fast paths behind probes.
- **Scope of the io_uring requirement (maintainer decision).** Every performance-critical
  path is io_uring and *cannot* fall back:
  - Critical (uring only): peer TCP accept/connect/send/recv/shutdown/close, torrent file
    open/read/write/fsync/fallocate/close, UDP tracker and LSD datagrams (they share the
    ring anyway), HTTP(S) tracker sockets, web-seed sockets, all timers driving these.
  - Non-critical (anything that works): DNS via blocking `getaddrinfo` on a small helper
    thread, config/resume-file enumeration at startup, one-time socket setup
    (`setsockopt`, `bind`, `listen`), directory creation.
- **Enforcement, not convention:**
  1. `compile_error!` on non-Linux targets in `uring`.
  2. `cargo-deny` bans `mio`, `polling`, `async-io` and any crate with an
     epoll/kqueue/IOCP backend from the library dependency graph. `tokio` is permitted
     with `default-features = false, features = ["sync"]` only; a `cargo tree -e features`
     check in `xtask check` fails if `tokio/rt`, `tokio/net`, `tokio/fs`, `tokio/time` or
     `tokio/io-util` is enabled anywhere under the library crates.
  3. If `io_uring_setup` fails or a required opcode is missing, session creation returns a
     hard error. There is no "degraded mode" and no feature flag to add one.
  4. `cargo xtask syscalls` runs a transfer under a seccomp filter (or strace) and fails
     if the library threads issue `epoll_*`, `poll`, `ppoll`, `select`, or
     `read/write/pread/pwrite/send*/recv*` on sockets or torrent files. Helper-thread DNS
     is whitelisted by thread name.
- **Buffer ownership.** Any buffer handed to the kernel is owned by the reactor until its
  CQE arrives. Dropping a future must never free a buffer with an in-flight SQE: cancel
  with `ASYNC_CANCEL` and let the reactor reclaim it. No API takes `&mut [u8]` for an
  async op; use owned pooled buffers. This rule is the main source of `unsafe`; keep all
  of it inside `uring`, with `// SAFETY:` comments and miri/loom-style tests where possible.
- Network: multishot accept, multishot recv with provided buffer rings for TCP,
  `recvmsg` multishot for the UDP sockets (UDP tracker now; DHT/uTP demux later),
  `send_zc` for piece payloads where it measures faster.
- TLS for HTTPS trackers and web seeds: **rustls** (pure Rust, maintainer decision), used
  through its buffer-in/buffer-out API so ciphertext moves over `uring`. No OpenSSL, no
  native-tls. Note rustls's default crypto providers (the *ring* crypto crate, aws-lc-rs)
  contain C/assembly; if "pure Rust" must hold for crypto primitives too, use the
  RustCrypto-based provider and accept that it is less mature. Record the choice in an ADR.
- CPU work (SHA-1/SHA-256 hashing, RC4 on bulk data if it shows up in profiles) goes to a
  small dedicated thread pool. That is compute, not I/O, and is allowed.
- Threading model: one network ring thread to start; disk ring(s) separate once
  benchmarks justify them (M2 runs torrent file I/O on the network ring; `storage` is
  agnostic about which ring polls it, see ADR 0004). Shard later only with benchmarks
  in hand. The engine owns its threads; the caller's tokio runtime never polls a uring
  future. See 5.6 for how the two meet.

### 5.4 Storage

- Sparse files by default, optional `fallocate` preallocation. Correct handling of
  multi-file piece spans, zero-length files, padding files, file priorities (pieces that
  straddle an unwanted file go to a parts file).
- Write path: block arrives -> pooled buffer -> uring write; piece complete -> hash job ->
  on pass, mark + `have`; on fail, discard, attribute blame, ban repeat offenders.
- Resume data: own versioned format, written atomically (tmp + fsync + renameat + dir
  fsync). `kill -9` at any moment must never yield a torrent that claims pieces it does not
  have. When unsure, recheck.
- Path safety: reject `..`, absolute paths, NULs, overlong names; sanitise exactly once in
  `metainfo`. This is a security boundary - fuzz it.

### 5.5 IPv4 + IPv6

- Separate v4 and v6 listen sockets (`IPV6_V6ONLY=1`), TCP and UDP each. Never use
  v4-mapped addresses internally; normalise on ingress.
- Follow the oracle's dual-stack announce behaviour (libtorrent announces per listen
  endpoint). Capture it; do not guess.
- `peers6`, PEX `added6`, UDP tracker over v6, LSD over v6. Filter link-local / unspecified / multicast / own addresses from every peer
  source.
- Every integration scenario runs in three network shapes: v4-only, v6-only, dual-stack.

### 5.6 Public API: tokio-native, engine-owned threads

Maintainer decision: the library integrates with **tokio**. The shape:

- `Session::builder().build().await` spawns the engine's own OS threads (network ring,
  disk ring(s), hash pool) and returns a `Session` handle that is `Clone + Send + Sync`.
  Dropping the last handle, or calling `shutdown().await`, sends `stopped` to trackers,
  flushes resume data and joins the threads.
- Every public operation is an `async fn` (`add_torrent`, `pause`, `set_file_priorities`,
  `save_resume_data`, ...). Internally each is a message on a `tokio::sync::mpsc` channel
  to the engine plus a `tokio::sync::oneshot` reply. Those primitives are
  runtime-agnostic (they never touch the tokio reactor), so the `await` completes on
  whatever runtime the caller uses, and it is tokio in practice.
- Events (piece finished, torrent finished, tracker reply, peer error, ...) arrive on
  `Session::events() -> impl Stream<Item = Event>` backed by `tokio::sync::broadcast` or
  `mpsc`; slow consumers see an explicit `Event::Lagged { dropped }` rather than blocking
  the engine.
- Snapshots (`TorrentStatus`, `PeerInfo`, session stats) are plain `Clone` structs copied
  out of the engine; the caller never holds a reference into engine state.
- The facade crate ships a `tokio` feature that is **on by default** and adds the
  `Stream`/`StreamExt` conveniences; with it off the same API works on any executor. Do
  not let this feature leak tokio I/O features into the graph (rule 4).
- Boundary rule: nothing tokio owns is ever handed to `uring`, and nothing `uring` owns is
  ever polled by tokio. A `tokio::net::TcpStream` can never become a peer connection. If a
  design needs that, it is the wrong design.
- Examples and `testkit` drive the library from `#[tokio::main]`; that is the supported
  and tested integration path.

## 6. Identity and fidelity

Identity is **data, not code**: `profile/` holds declarative profiles. Two ship:
`native` (our own honest peer-id prefix and user agent) and `qbt_5_2_3_lt2_0_14` (the
conformance target; the 1.2.20 variant follows). Callers choose; nothing else in the
codebase may hardcode an identity string or an ordering that a profile owns.

The qbt profile is **best effort with explicit priorities** (maintainer decision):
L1 is mandatory, L2 is the target and a release gate, L3 and TLS are accepted nuances.

**L1 - Identifiers (bit-exact, highest priority, never regress).** Peer-id prefix and the
generator for its random tail (alphabet, length, lifetime), HTTP `User-Agent`, LTEP `v`,
announce `key` format and lifetime, UDP tracker `key`. An L1 mismatch is a release blocker.

**L2 - Wire shape (bit-exact after normalisation, release gate).**

- HTTP announce/scrape: parameter set, **parameter order**, percent-encoding style and hex
  case, `key` format and lifetime, `numwant`, `compact`/`no_peer_id`, crypto flags, extra
  libtorrent params (`corrupt`, `redundant`, ...), IP params, header set and header order,
  HTTP version, connection reuse, gzip handling, redirect handling.
- UDP tracker: connect/announce field values, connection-id caching, retransmit schedule.
- Peer handshake: reserved bits per torrent type; first-messages sequence
  (bitfield vs have-all/none, allowed-fast, LTEP handshake position).
- LTEP handshake: exact key set, `m` map names and IDs, `reqq`, `yourip`, `p`,
  `metadata_size`, `upload_only` and when each appears.
- MSE: method selection, `crypto_provide`/`select`, padding length distribution.

**L3 - Behaviour (accepted nuance, not a gate).** Announce *semantics* still matter and
are tested as correctness: `started` / `completed` exactly once / `stopped` on shutdown,
honouring `interval`/`min interval`, tier failover. Exact *timing* does not: jitter,
backoff curves, request pipelining depth, choke rotation phase, keep-alive and PEX
cadence only need to be sane and in the oracle's ballpark. Use the oracle's defaults as
starting constants because they are good defaults, then stop. Do not spend effort on
statistical timing mimicry.

**Accepted differences (document, do not chase):**

- **TLS fingerprint.** We use rustls; the oracle uses OpenSSL. The ClientHello differs
  and that is fine. Still do the cheap things: send SNI, offer ALPN only if the oracle
  does, use system/webpki roots sensibly.
- **Timing**, as above.
- **Capability gaps.** The oracle supports DHT and uTP; 0.1.0 does not. Default policy:
  advertise the same handshake reserved bits and LTEP `m` entries as the oracle so L1/L2
  stay exact, and handle the consequences gracefully (ignore `PORT` messages; answer
  unsupported extension messages the way the oracle answers a disabled feature). Where
  that would mislead a peer into wasted work beyond a dropped message, prefer what the
  oracle sends *with that feature disabled in its settings* - capture that configuration
  too. Record each case in `docs/quirks.md`.

**Acceptance = the discriminator test, scoped to L1 + L2.** `testkit` contains a
classifier fed what a tracker (HTTP layer and above) or a tap peer can observe, excluding
TLS and timing. It must fail to separate the oracle from us under the qbt profile while
still flagging Transmission and our `native` profile (proving it has teeth). When anyone
finds a new L1/L2 tell, first add it to the discriminator (red), then fix it (green).

## 7. Testing

### 7.1 Layers

1. **Unit** - sans-IO crates: golden vectors, table tests, simulated time.
2. **Property** - `proptest`: bencode round-trips, piece/file span maths, picker
   invariants, choker fairness, rate-limiter bounds.
3. **Fuzz** - `cargo-fuzz` targets for every parser that eats untrusted bytes: bencode,
   metainfo, peer wire, LTEP, PEX, tracker responses (HTTP + UDP), HTTP response framing, MSE,
   LSD, resume data. Corpus seeded from oracle captures.
4. **Replay** - feed recorded oracle sessions into our state machines; assert no errors
   and equivalent responses.
5. **Integration** - real processes (7.2).
6. **Differential** - same scenario, oracle vs us, normalised diff (7.3).
7. **Soak/perf** - multi-hour seeding of thousands of torrents, 100 GiB sparse transfer at
   line rate on loopback, fd/memory leak checks.

### 7.2 Integration environment

All actors run in an isolated environment (Docker Compose on an `internal: true` network
with both an IPv4 and an IPv6 subnet, or `ip netns` + veth for bare-metal CI).

- **Trackers:** `opentracker` (HTTP+UDP, v4/v6), a second independent implementation
  (`chihaya` or `torrust-tracker`), one configured PT-style (passkey in announce URL,
  private torrents, client whitelist enabled with the oracle's identity on the list), and
  **`tap-tracker`**: our own test-only tracker that logs raw request bytes (post-TLS)
  before answering. HTTPS via a test CA.
- **Peers:** `qbittorrent-nox` oracle (both libtorrent lines), `transmission-daemon` as an
  independent implementation, and **`tap-peer`**: scriptable test-only peer that records
  every byte it receives and can misbehave on purpose (bad hashes, stalls, garbage, slow
  loris, protocol violations).
- **Torrent fixtures:** generated by test tooling (`mktorrent` or a small script in
  `testkit`) - creation is not a library feature. Cover: single/multi-file, piece sizes
  16 KiB-16 MiB, last-piece edge cases, zero-length files, padding files, unicode and
  hostile paths, private flag, multi-tier trackers, thousands of files.
- io_uring in containers: recent Docker default seccomp profiles block the `io_uring_*`
  syscalls, and hosts may set `kernel.io_uring_disabled`. The container running *our*
  code needs a custom seccomp profile; `xtask doctor` must detect and explain both.

### 7.3 Differential procedure

1. Run scenario with client = oracle. Record: tap-tracker logs, tap-peer logs, pcap.
2. Run same scenario with client = us (qbt profile).
3. Normalise declared-random fields only (peer-id tail, `key`, ports, transaction IDs,
   connection IDs, DH keys/padding, timestamps). The normalisation list is reviewed code;
   adding to it needs justification in the PR.
4. Diff L1/L2 byte-exact and run the discriminator. L3 differences are reported as
   informational output only. The oracle runs with DHT and uTP **disabled** in its
   settings for the primary captures (closest to what 0.1.0 implements), plus one default-
   settings capture to document the capability-gap quirks.

Golden captures are committed (small) or content-addressed in CI cache (pcaps).

### 7.4 Scenario matrix (each x {v4, v6, dual} where meaningful)

Leech from oracle seeder - seed to oracle leecher - seed to Transmission - mixed swarm -
HTTP / HTTPS / UDP tracker - tracker down, tier failover, backoff - PT-style tracker with
passkey + whitelist accepts us - private torrent emits no DHT/PEX/LSD - encryption
forced/enabled/disabled on each side - oracle with uTP enabled still connects to us over
TCP - magnet via ut_metadata with tracker-sourced peers - PEX discovery - LSD discovery - web seed only - pause/resume -
`kill -9` and resume - force recheck with corrupted data on disk - file priorities incl.
parts file - move storage - hash-fail peer gets banned - rate limits honoured - `completed`
sent exactly once, `stopped` sent on shutdown, stats never go backwards.

## 8. Milestones

Each milestone ends with its integration scenarios green in CI.

- **M0 Harness first.** Workspace, CI, `testkit` that boots tracker + two oracle instances
  and transfers a torrent between them; tap-tracker and tap-peer; first golden captures.
  *No library code before the oracle can be observed.*
- **M1 Foundations.** `bencode`, `metainfo`, `uring` (TCP, UDP, files, timers, buffer
  pools, enforcement checks from 5.3), `storage` with hashing.
- **M2 Leech.** `wire`, HTTP `tracker`, basic picker; download from an oracle seeder.
- **M3 Seed.** Choker, fast extension, upload path, resume data, recheck, rate limits.
- **M4 Identity.** `profile`, L1 + L2 diffs green for HTTP tracker, handshake, LTEP;
  HTTPS via rustls; discriminator v1; capability-gap quirks documented.
- **M5 Reach.** UDP tracker, scrape, full IPv6/dual-stack matrix, MSE.
  *PT-complete: private-tracker users are fully served here.*
- **M6 Extensions.** PEX, `ut_metadata`/magnet, `upload_only`, LSD, web seeds, BEP 40.
- **M7 0.1.0 hardening.** Soak, perf, fuzz time, API review, docs. **Release 0.1.0.**
- **Post-0.1.0:** DHT, uTP (+ holepunch), BEP 52, port mapping, each as its own minor
  release (0.2.0, 0.3.0, ...).

## 9. Working conventions

- Rust stable, edition 2024; MSRV pinned in `rust-toolchain.toml`. `#![forbid(unsafe_code)]`
  in every crate except `uring`. `#![deny(missing_docs)]`
  on public API.
- Errors: `thiserror` enums in libraries, no `anyhow` outside `testkit`/`xtask`. No
  `unwrap`/`expect`/indexing panics on any path reachable from network or disk input.
  Remote input must never be able to panic or OOM us: every length field is bounded.
- Logging via `tracing`; no `println!`. Peer-visible bytes are loggable at `trace` for
  diffing.
- Dependencies: keep the tree small; every new dependency is justified in the PR. Crypto
  primitives (SHA-1, SHA-256, RC4, DH bignum) come from audited crates, not hand-rolled.
- Commands (create in M0, keep working forever):
  - `cargo xtask check` - fmt, clippy `-D warnings`, unit + property tests, doc build
  - `cargo xtask doctor` - kernel version, uring probe, seccomp/sysctl, memlock, Docker
  - `cargo xtask it [scenario]` - integration tests
  - `cargo xtask diff [scenario]` - differential run + discriminator
  - `cargo xtask capture` - regenerate golden captures from the pinned oracle
  - `cargo xtask fuzz <target> [secs]`
  - `cargo xtask syscalls` - assert no non-uring data-path syscalls
- Definition of done for any change: `xtask check` green; relevant `it`/`diff` scenarios
  green; new parser => new fuzz target; new wire-visible behaviour => profile entry +
  differential coverage; design-level decisions => ADR.
- When the oracle and a BEP disagree, **the oracle wins under the qbt profile** and the
  disagreement is documented in `docs/quirks.md`. When the oracle's behaviour is a bug that
  would harm peers or trackers, stop and escalate to the maintainer instead of copying it.
- **Versioning (SemVer, Cargo rules).** First release is `0.1.0`; nothing is called 1.0
  until the public API has been stable across at least two minor releases. In `0.x`,
  a bump of the minor version is the breaking-change signal and a patch bump must be
  API-compatible (Cargo treats `0.x.y` -> `0.x.z` as compatible; verify with
  `cargo semver-checks` in CI). All workspace crates share one version and are released
  together; internal crates that are not part of the facade's public API are still
  published under the same version to keep `cargo publish` simple. Keep a `CHANGELOG.md`
  in Keep-a-Changelog format; every user-visible change gets a line in the same PR.
  Resume-data and profile file formats carry their own format version independent of the
  crate version, and every released version must read every format version it ever wrote.
- **Licence: Apache-2.0.** SPDX header on every source file. Logic ported from
  libtorrent (BSD-3) keeps its copyright notice in the file and an entry in `NOTICE`.
  Never copy from qBittorrent (GPL) or any other copyleft client.
- When something here is wrong or unclear, fix this file in the same PR.

## 10. Decisions and open questions

### Decided by the maintainer (2026-09-19)

- **0.1.0 scope excludes DHT and uTP.** TCP-only; peers come from trackers, PEX, LSD.
- **io_uring is mandatory on every performance-critical path with no fallback of any
  kind** (no epoll, kqueue, IOCP, poll). Non-critical work such as DNS may use whatever
  works. Details and enforcement in 5.3.
- **TLS is pure Rust (rustls).** The qbt profile is best effort: identifiers first, wire
  shape second; timing and TLS fingerprint differences are acceptable.
- **Versioning: SemVer, first release 0.1.0.** See section 9 for the policy.
- **Public API integrates with tokio** (5.6); the engine still runs on its own uring
  threads and tokio never owns I/O inside the library.
- Defaults accepted: oracle line 5.2.3 / libtorrent 2.0.14 only for now; BEP 52 post-0.1.0;
  kernel baseline 6.1 LTS; rustls with its default crypto provider; `native` is the
  default profile.
- **Licence: Apache-2.0.**

### Still open

None at present. Add new ones here, with the default being assumed, rather than
blocking on them; ask the maintainer in the PR that depends on the answer.
