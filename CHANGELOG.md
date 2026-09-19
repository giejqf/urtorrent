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
