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

### Disk ring A/B (2026-09-20, after 0.1.0)

Interleaved `soak transfer --size 2G` runs on the same VM, `sync` between
runs: v0.1.0 single ring 112 / 136 MiB/s; separate `urt-disk` thread
(default now) 134 MiB/s; `disk_thread(false)` (inline) 106 MiB/s. Run-to-run
variance on this VM is about ±20% (page-cache state, writeback of the
previous run), so the three are indistinguishable here; the CPU is the
bottleneck (both engines, both disk rings and four SHA-1 workers share two
cores). A first version with one global barrier per verify cost ~35%: a
verify must only wait for earlier writes to *its* piece (ADR 0004 §4).

### Hash-as-you-write (2026-09-20)

Pieces are hashed as their blocks are written (a per-piece SHA-1 cursor over
the contiguous prefix; blocks ahead of the cursor sit in a ≤1 MiB stash or
are read back from the page cache when reached) instead of being read back
whole and re-hashed once complete; recheck and fallback verification use a
pool of piece-sized buffers instead of a fresh allocation per piece. Three
interleaved `soak transfer --size 2G` rounds against the previous binary:
user CPU 14.2 → 13.4 s (−6%; the memcpy of every piece and its allocation),
sys CPU 7.7 → 8.5 s (more, smaller hash jobs), wall time within noise
(12.6–20.4 s both), peak RSS 13 → 11 MiB (thread) / 13 → 9 MiB (inline).
`Storage::hash_readback_bytes` is 0 for an in-order download. The saving
grows with piece size (a 16 MiB piece is a 16 MiB copy avoided per piece).

Known limits:

- On a two-core host the extra thread buys nothing measurable; it matters
  where disk latency would stall peer sockets. `SessionBuilder::disk_thread`
  chooses.
- SHA-1 runs on `hash_threads` (default 2) workers; hashing throughput scales
  with that setting.
- Web seed requests are capped at 4 MiB each (libtorrent asks for up to
  16 MiB); an accepted L3 difference.
