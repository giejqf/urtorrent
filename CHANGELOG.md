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
