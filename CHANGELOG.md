# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- M0 harness: workspace, CI, `xtask` dev commands, `testkit` with an isolated
  netns lab, pinned qBittorrent oracle, opentracker, tap-tracker, tap-peer and
  golden captures.
- M1 foundations:
  - `bencode`: zero-copy, canonical, panic-free decoder/encoder that preserves
    raw info-dict bytes for stable info-hashes; fuzzed.
  - `metainfo`: `.torrent` and magnet parsing, file tree, piece/file span
    mapping, BEP 47 padding/attrs, path-safety boundary; fuzzed.
  - `uring`: an io_uring reactor with a single-threaded executor, pooled owned
    buffers with cancel-safe ownership, TCP/UDP/file/timer operations, and
    `IORING_REGISTER_PROBE` feature probing that fails hard when the baseline is
    missing (no fallback).
  - Enforcement: `compile_error!` off Linux, `cargo-deny` reactor/tokio bans,
    the `xtask check` tokio-feature audit, and `xtask syscalls` (strace) proving
    the data path is io_uring-only.
  - `storage`: bitfield, dedicated SHA-1 hashing pool, the piece
    read/write/verify path over io_uring (multi-file spans, BEP 47 padding),
    force-recheck, and crash-safe versioned resume data (tmp + fsync + rename +
    dir fsync).
  - `cargo-fuzz` targets for bencode, metainfo, magnet and resume-data parsers.
- M2 leech:
  - `profile`: identity as data — `native` and `qbt_5_2_3_lt2_0_14` (peer-id
    prefix and tail alphabet, `User-Agent`, LTEP `v`, announce parameter and
    header order, `key` style, reserved bits, LTEP `m`, first-messages
    sequence), transcribed from the golden captures.
  - `wire`: sans-IO peer-wire codec (BEP 3/6/10), bounded framing, LTEP
    extended handshake, and a per-connection state machine with protocol
    validation; replay tests against the golden captures, including a
    byte-exact LTEP handshake under the qbt profile.
  - `tracker`: HTTP announce builder (profile-ordered, byte-exact against the
    capture), announce response parser (compact peers, `peers6`, dict peers),
    HTTP/1.1 response framing with gzip, and the `Announcer` tier/backoff/
    event state machine (libtorrent semantics, simulated-time tests).
  - `picker`: rarest-first with partial-piece preference, priorities,
    sequential mode, end-game duplicates + cancellation; property-tested.
  - `uring`: eventfd `Notifier` for cross-thread wakeups; `peer_addr`,
    `TCP_NODELAY`; teardown now cancels in-flight operations.
  - `storage`: `HashPool::verify_async` completes through the notifier so
    hashing overlaps disk I/O.
  - `session`: the engine (ADR 0004) — tracker announces over io_uring HTTP,
    outgoing and incoming peers, request pipelining, hash verification with
    blame/bans, truthful counters, resume data on completion/periodically/
    shutdown, `started`/`completed`/`stopped` sequencing, pause/resume/remove,
    events with `Lagged`. Leech-only: we never unchoke (M3 adds the choker and
    upload path).
  - `urtorrent`: the facade crate (`tokio` feature adds `StreamExt`).
  - `testkit`: `urt-client` (the library as a lab actor, status/control
    files) and the `leech_from_oracle` scenario (v4, v6, dual): bytes on disk,
    truthful counters, announce sequence, parameter/header order vs the oracle.
  - Fuzz targets: `wire_message`, `wire_connection`, `ltep_handshake`,
    `announce_response`, `http_response`.
  - `docs/quirks.md` Q6: LTEP `p` omitted on non-routable listen sockets.
- M3 seed:
  - Upload path: per-peer request queue served from disk with outbound
    backpressure; truthful `uploaded`; seed-to-seed connections closed.
  - Choker (session-wide slots, libtorrent-style: rate-ranked with an
    optimistic slot when leeching, round-robin when seeding, immediate unchoke
    on interest while a slot is free).
  - BEP 6 allowed-fast grants as a profile-driven first message; the set is
    seeded the way the oracle does it (`docs/quirks.md` Q7, pinned by a golden
    replay test) or per the BEP for `native`.
  - Rate limits: session and per-torrent token buckets on both directions,
    applied in the reader/writer; `Session::set_rate_limits`,
    `set_torrent_rate_limits`, builder `upload_limit`/`download_limit`.
  - `Session::force_recheck`; asynchronous initial check (`add_torrent` returns
    immediately, `Checking` state); resume data trusted only while every
    content file exists.
  - Blame: trust points per address, immediate ban for a sole supplier of a
    bad piece, exclusive re-download of a shared bad piece to pin the culprit.
  - Announcer: `start()` after `stop()` re-announces at once; in-flight
    announces land before `stopped` is decided.
  - testkit: Transmission driver (RPC), default route per actor plus a FORWARD
    drop rule (Transmission needs a route; the lab still cannot reach the
    internet), `xtask doctor` AppArmor check; scenarios `seed_to_oracle`,
    `seed_to_transmission` (v4/v6/dual), `pause_resume`, `kill9_resume`,
    `recheck_corrupted`, `hash_fail_ban`, `rate_limits`.
- M4 identity:
  - HTTPS trackers over rustls (ADR 0003): explicit aws-lc-rs provider,
    Mozilla roots + `SessionBuilder::root_certificate_pem` + `SSL_CERT_FILE`,
    ciphertext over io_uring; `https_tracker` scenario (v4/v6) and golden.
  - Profile facts pinned by capture and libtorrent 2.0.14 source: peer id
    per torrent (L1 lifetime), tail alphabet fully observed, `key` = `%08X`
    per torrent, `supportcrypto=1` only while encryption is enabled (Q8), the
    `p` rule (Q6, external-address vote semantics). `AnnounceRequest` gained
    `crypto_supported`; `ConnectionParams` gained `advertise_port`.
  - The discriminator (`testkit::discriminator`): tracker- and peer-side
    fingerprints from tap captures, golden-oracle classifier, human-readable
    L1/L2 tells; `cargo xtask diff` runs `diff_identity`, where the live
    oracle, us (qbt), us (native) and Transmission are all observed by the
    same taps: no tells for the qbt profile, tells for the other two.
  - `capture_keys` scenario (40 torrents) and its golden.
  - NOTICE entries for logic confirmed against libtorrent.
- M5 reach (PT-complete):
  - UDP tracker (BEP 15) as captured from the oracle (Q10): connect / announce
    / scrape, BEP 41 URL data, 60 s connection-id cache, one attempt per
    request; the listen port's UDP sockets with a demultiplexer in the engine.
  - Scrape (BEP 48) over HTTP and UDP: `Session::scrape`, `ScrapeReply`.
  - MSE: the `mse` crate (DH, RC4, initiator/responder state machines with
    libtorrent's shape), `EncryptionMode` (disabled / enabled / forced),
    plaintext-then-MSE retry (Q3), incoming detection, `prefer_rc4` from
    capture; `PeerInfo::encrypted`.
  - Dual-stack: one announce state per listen socket (Q9), announces routed
    per family, IP-literal endpoint mismatch disabled silently; lab hostname
    `tracker.urt<id>.lab` via `/etc/hosts`.
  - testkit: MSE in the tap-peer; captures capture_tracker_udp,
    capture_scrape, capture_peer_forced, capture_peer_allow_mse,
    capture_tracker_dual; scenarios udp_tracker (v4/v6/dual), http_scrape,
    encryption_matrix, mse_shape (Diff), dual_stack_announce (dual, Diff),
    tracker_failover, pt_tracker, oracle_utp_tcp_fallback; UDP and MSE sides
    of the discriminator.
  - Fuzz: mse_responder, udp_reply, scrape_response.
