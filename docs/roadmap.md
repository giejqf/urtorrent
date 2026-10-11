# Roadmap and release history

Each milestone ended with its integration scenarios green in CI
(AGENTS.md 8). [CHANGELOG.md](../CHANGELOG.md) has the details of every release.

## Released

| Release | What it delivered |
|---|---|
| M0 Harness | netns lab, pinned oracle, opentracker, tap-tracker, tap-peer, first golden captures |
| M1 Foundations | `bencode`, `metainfo`, `uring` (reactor, probe, enforcement), `storage` (hashing, resume), fuzz targets |
| M2 Leech | `profile`, `wire`, `tracker`, `picker`, the `session` engine and the `urtorrent` facade; leeching from the oracle in v4 / v6 / dual |
| M3 Seed | choker, upload path, allowed-fast, rate limits, force recheck, resume after `kill -9`, blame and bans; seeding to the oracle and to Transmission |
| M4 Identity | HTTPS via rustls, per-torrent peer id and `key`, discriminator v1 and `xtask diff`: the oracle and the qbt profile are indistinguishable, Transmission and `native` are flagged |
| M5 Reach | UDP tracker, scrape, MSE in every mode, per-listen-socket dual-stack announces, tier failover and backoff, PT-style tracker; private-tracker complete |
| M6 Extensions | PEX, `ut_metadata` and magnets, `upload_only`, LSD, web seeds, BEP 40; private torrents proven silent on the wire |
| **0.1.0** (M7 Hardening) | file priorities with a parts file, move storage, torrent files opened on the ring, `xtask syscalls`, `xtask soak`, fuzzing, API review |
| **0.2.0** Performance | external-address voting, a dedicated disk ring, hash-as-you-write, 10 000 torrents per session, indexed picker, provided-buffer-ring receives and vectored / zero-copy sends (ADR 0006) |
| **0.3.0** DHT | `crates/dht` (BEP 5 / 42 / 43 / 51, ported from libtorrent) on the listen port's UDP socket; indistinguishable from the oracle's node (ADR 0007) |
| **0.4.0** uTP | `crates/utp` (BEP 29, ported from libtorrent's `utp_stream`), `TransportPolicy` with TCP first by default (ADR 0008) |
| **0.5.0** Magnet / LTEP | `x.pe`, `ws` and `so=` in magnet links, tracker-less magnets over the DHT, additive LTEP re-handshakes, `reqq` honoured |
| **0.6.0** Gates | user-space copy budgets counted and gated (`SessionStats::copied_bytes`), dual-stack edge cases gated in-process and in the lab |
| **0.7.0** Configuration | the active-torrent queue (`ActiveLimits`, ADR 0009), per-torrent upload slots, runtime limits; [config.md](config.md) |
| **0.8.0** Daemon readiness | `torrent_file`, per-piece state, cheap list snapshots, runtime switches, session-wide IP bans, live web seeds, `rename_file` |
| **0.9.0** Live settings | `set_listen`, `set_dht`, `set_profile`: nothing on a preferences page needs a session rebuild |
| **0.10.0** Hostile peers | slow-loris and idle floods bounded, peer lists capped, live-engine gates for malformed peers (`hostile.rs`) |
| **0.11.x** Resume blobs, races | `resume_data` / `AddTorrent::resume_data` ([resume.md](resume.md)), overlapping-operation gates (`races.rs`), `xtask bench` against the oracle ([perf.md](perf.md)), RustSec advisories enforced |
| **0.12.0** Daemon gaps | errored torrents recover (`ErrorKind`), `hold_after_metadata` / `release`, list-view status fields, `PeerBanned` |
| **0.13.x** Daemon extras | tracker rows per listen endpoint, `FileCompleted`, piece priorities, banned address ranges, partial seeds `upload_only`, `set_queue_position` |
| **0.14.x** Daemon gaps | tracker `interval` / `min interval` and response time, `force_reannounce_tracker`, check progress; published on crates.io; 0.14.3: a stopped torrent reads 0 B/s |

## Next

- The daemon itself, an HTTP API on top of the library (a separate repository).
- BEP 55 `ut_holepunch`.
- UPnP / NAT-PMP / PCP port mapping.
- BEP 44 DHT items (a documented gap, [quirks.md](quirks.md) Q20).

Not planned: BEP 52 (v2 / hybrid torrents), and the non-goals in AGENTS.md 1.
