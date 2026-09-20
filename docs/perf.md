# Performance and soak notes

Numbers from `cargo xtask soak` on the development VM (2 vCPU, 3 GiB RAM,
one SATA-class disk), release build, both engines in one process on
loopback, 2026-09-20. They are a baseline for regressions, not a benchmark
of the protocol.

| Exercise | Result |
|---|---|
| `soak transfer --size 20G` (4 MiB pieces) | seeder recheck 54 s (377 MiB/s SHA-1 on one worker); transfer 145 s = 141 MiB/s sustained, disk-write bound; `downloaded` exact, `corrupt=0`, `redundant=0`; peak RSS 35 MiB; fds back to baseline after shutdown |
| `soak transfer --size 2G` (1 MiB pieces) | 179 MiB/s; peak RSS 14 MiB |
| `soak many --torrents 500` | 500 torrents added to two engines in ~1 s; all seeding/leeching within seconds; ~2 fds per torrent while loaded (one file handle per engine), back to baseline after `remove_torrent`; RSS ~50 MiB |

What the soak checks (and fails on): completion, exact `downloaded`, no
corrupt pieces, sampled content, fd count back to baseline after shutdown, no
fds held after every torrent is removed.

Known limits at 0.1.0:

- Disk I/O shares the network ring thread (ADR 0004 §4). On this VM the
  transfer is disk-bound before the ring is; a separate disk ring is the
  planned next step once a faster disk shows the ring competing.
- SHA-1 runs on `hash_threads` (default 2) workers; hashing throughput scales
  with that setting.
- Web seed requests are capped at 4 MiB each (libtorrent asks for up to
  16 MiB); an accepted L3 difference.
