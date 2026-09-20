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

### Scale pass (2026-09-20)

`soak many` at 5 000 and 10 000 torrents (two engines, every torrent
downloaded by B from A):

| Torrents | Add (both engines) | All downloaded | fds loaded | peak RSS |
|---|---|---|---|---|
| 5 000 | 1.8 s | 7.2 s | 1 040 | 195 MiB |
| 10 000 | 3.7 s | 40 s | 1 039 | 234 MiB |

Before the pass, 5 000 torrents held 10 016 fds (every content file of both
engines open forever) and peaked at 288 MiB. What changed: an LRU file pool
capped at `max_open_files` (512) shared by every store on the disk ring,
shared piece-buffer pools per piece length (each store used to keep two idle
piece-sized buffers: megabytes per torrent at large piece sizes), one
session-level tick queue instead of a timer per torrent, self-timed rate
limiter waits instead of a 100 ms walk over every limiter, O(1) MSE stream-key
lookup (one SHA-1 per torrent at add time instead of one per torrent per
incoming encrypted connection), a session connection counter instead of a
walk, and concurrency gates for checking (1), announces (32) and resume
saves (4). The remaining per-torrent footprint is dominated by receive
buffers while peers are connected (64 KiB per connection); provided buffer
rings (step 3) remove that.

### Data path: buffer rings, batched receive, vectored sends (2026-09-20)

`soak transfer --size 2G` (1 MiB pieces), interleaved with the previous
binary, `cpu` = user + system of the whole process (both engines):

| Build | Rate | CPU | Notes |
|---|---|---|---|
| picker build | 109–119 MiB/s | 13.0 + 8.3 s | single-shot 64 KiB recv per connection, 4 copies per uploaded block |
| + multishot recv ring, chunked sends, copy-free file ops | 116–126 MiB/s | 13.3 + 14.0 s | *worse*: `io_uring_enter` 570k → 1.26M, context switches 743k → 1.37M — an always-armed receive delivers small chunks and each woke the disk ring for one block |
| + drain queued chunks per wakeup (`try_next`, ≤32) | 176–182 MiB/s | 10.7 + 4.8 s | −28% CPU, +50% throughput; 16 KiB pieces: 58 → 172 MiB/s |
| + `zero_copy_send` (SENDMSG_ZC) | 167–176 MiB/s | 10.8 + 5.3 s | within noise, a little more system time: default off |

RSS: 27 MiB with two rings of 256 × 32 KiB (8 MiB each) versus 11 MiB
before; per connection the receive memory went from 64 KiB to nothing while
idle. `xtask syscalls` still shows no off-ring data syscalls. ADR 0006 has
the design.

### Picker index and extent affinity (2026-09-20)

`soak transfer --size 2G` with 16 KiB pieces (131 072 pieces, one block
each), interleaved with the previous binary:

| Build | Rate | Notes |
|---|---|---|
| before | 6 MiB/s (331 s) | every pick scanned all 131k pieces |
| indexed picker | 21 MiB/s (98 s) | bursts of 50 MiB/s then stalls at 0: dirty pages pinned at the 20% limit with `Writeback` stuck at ~1 MB, because random 16 KiB writes across a 2 GiB sparse file leave the kernel random I/O to write back |
| + extent affinity | 58 MiB/s (35 s) | no stalls; CPU-bound now (30 s CPU for 131k pieces: per-piece verify/have/event overhead, step 3 territory) |

1 MiB pieces: 119 → 126 → 160 MiB/s across the same three builds (the last
is within the ±20% noise plus better write locality). Rarest-first cost model
is libtorrent's: a pick costs the candidates ahead of the peer's pieces in
(priority, availability) order, never the piece count; pieces nobody has are
skipped outright; a seed joining moves every wanted piece one bucket (200k
pieces in ~7 ms release).

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

### uTP (2026-09-20, 0.4.0)

`soak transfer --size 1G` (1 MiB pieces, both engines in one process, release
build); the default policy dials TCP, `--utp` runs uTP-only engines:

| Transport | Rate | CPU (user + sys) | Notes |
|---|---|---|---|
| TCP (default) | 232 MiB/s | 5.4 + 2.5 s | unchanged data path (ADR 0006) |
| uTP (`--utp`) | 62 MiB/s | 8.1 + 8.2 s | one 1471-byte datagram per packet, an ack per receive round, payload copied once into the reorder queue and once into packets |

This gap is why TCP stays the default transport (`TransportPolicy::PreferTcp`)
rather than libtorrent's uTP-first order. uTP is the compatibility
transport, not the fast path: LEDBAT yields to TCP by design and
libtorrent's own uTP tops out in the same range on loopback (the
oracle-to-oracle capture moved 4 MiB in ~60 ms). Two things
mattered for it to work at all at this rate: draining the UDP socket with
one multishot `recvmsg` per socket (256 × 2 KiB provided buffers, up to 64
datagrams per wakeup), and an ordered per-socket send queue that submits
32 datagrams per ring round trip — submitting a whole congestion window as
one burst reordered packets and overflowed the receiver's socket buffer,
which the oracle answered with selective acks and retransmits. Zero-copy
sends and larger batches are the obvious next steps if uTP throughput
ever matters. `xtask syscalls` covers both transports.
