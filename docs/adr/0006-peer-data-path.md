# ADR 0006: Peer data path — provided buffer rings, chunked sends, transport enum

Date: 2026-09-20. Status: accepted.

## Context

Through 0.1.0 a peer connection received with one single-shot `recv` at a
time into a pooled 64 KiB buffer (memory per connected peer, one SQE per
receive, zero-filled on reuse) and sent by concatenating every queued message
into one `Vec<u8>`, which copied each uploaded block three times before the
kernel's own copy (into the byte queue, into the rate-limit slice, into the
`send_all` retry buffer). The disk side copied every written block once more
and read blocks through zeroed temporaries. AGENTS.md 5.3 asks for multishot
receives on provided buffer rings and zero-copy sends "where they measure
faster", and section 4 asks the peer state machine to talk to its socket
through an abstraction uTP can implement later.

## Decision

1. **Receive: one multishot `recv` per connection into a session-wide
   provided buffer ring.** `uring::BufRing` registers `recv_ring_entries`
   (256) buffers of `recv_buf_size` (32 KiB) with `IORING_REGISTER_PBUF_RING`;
   `TcpStream::recv_multi` arms `IORING_OP_RECV` with `IOSQE_BUFFER_SELECT`
   once and yields `RingBuf` guards that return their buffer to the ring on
   drop. When the ring is empty the kernel ends the multishot with `ENOBUFS`
   and `RecvMulti::next` re-arms it as soon as a buffer comes back, so the
   caller only sees data, end of stream or a socket error. Both opcodes are
   inside the 6.1 baseline and are now *required* (`probe::missing_baseline`
   lists `recv_multi`); there is no single-shot fallback for peers.
   Handshakes still use single-shot `recv` (a few small reads).

   The reactor grew a `Lifecycle::Multi` slot (queued `(result, flags)`
   completions, finished on the CQE without `IORING_CQE_F_MORE`) and a
   `Recycle` hook so buffers named by CQEs nobody consumes (a dropped
   connection) go back to the ring. A retired ring is unregistered and freed
   by the runtime between ticks, never from `Drop` (the last `Rc` can go
   away while the reactor is borrowed).

   **Batching matters more than the ring.** The first version processed one
   chunk per wakeup and was *slower* than 0.1.0 (io_uring_enter calls and
   context switches doubled: an always-armed receive delivers small chunks
   as they land, and each chunk's block write woke the disk ring). The peer
   loop now drains every already-queued chunk (`RecvMulti::try_next`, up to
   32) into the framer before acting, so the batch's writes leave for the
   disk ring together. That took a 2 GiB loopback transfer from
   116–126 MiB/s to 176–182 MiB/s with 28% less CPU.

2. **Send: chunked outbound, one vectored `sendmsg` per batch.** `wire`
   queues control bytes in a chunk and each piece payload as its own chunk
   (`Connection::piece` takes the `Vec<u8>` the disk read returned;
   `take_outbound_chunks`). The writer sends the batch with one
   `IORING_OP_SENDMSG` over up to 64 iovecs, resuming from the byte offset
   on short sends; under an upload limit it sends grant-sized byte ranges of
   the same chunks. No user-space copy of an uploaded block remains.

   `zero_copy_send` (off by default) switches payload-sized batches to
   `IORING_OP_SENDMSG_ZC`. The reactor keeps the chunks (shared through an
   `Rc`) in the slot until the notification CQE, while the future resolves
   at the first CQE (`ResultOp`). On loopback it measured within noise with
   slightly more system time (`docs/perf.md`); it stays available for real
   NICs.

3. **Copy-free primitives.** `File::{write_all_at, read_exact_at,
   read_exact_into}` and `TcpStream::send_all` resubmit from an offset into
   the same buffer instead of copying the remainder; `Storage::write_block`
   writes the block buffer itself when the block lies in one file and hashes
   from it afterwards; `read_block` reads straight into the block buffer;
   recycled receive buffers are not zero-filled (`Buffer` tracks its
   initialised high-water mark, so `set_len` stays sound).

4. **`Transport` enum in `session`.** Peer code sees `Transport::{Tcp}` with
   `connect_tcp`, `recv` (handshake), `receiver(&BufRing)`,
   `send_all_chunks[_zc]`, `peer_addr`, `set_nodelay`; `PeerInfo.transport`
   reports the variant. uTP becomes a second variant (its datagrams can use
   the same buffer-ring mechanism on the UDP socket) without touching the
   peer state machine.

5. **Ring flags.** Rings are created with `IORING_SETUP_SINGLE_ISSUER |
   IORING_SETUP_DEFER_TASKRUN` (one thread per ring is the design), falling
   back to `COOP_TASKRUN` and then plain setup on kernels that refuse them.

## Consequences

- Idle connections hold no receive memory; the session holds
  `entries × buf_size` (8 MiB by default) per network ring instead of
  64 KiB per peer. A stalled consumer starves the ring and the kernel stops
  reading those sockets: disk backpressure becomes TCP backpressure.
- Download rate limits are charged *after* a chunk arrives (the bytes are
  already in the ring), so a limited connection can burst up to one ring's
  worth before the limiter delays the next processing step. Averages over a
  second are unaffected (`rate_limits` scenario).
- More `unsafe` in `uring` (ring memory, iovecs, `set_len`); all of it is
  commented and exercised by `crates/uring/tests/io.rs` (ring starvation and
  re-arm, drop mid-stream, zero-copy sends).
- Registered (fixed) buffers for file I/O were not done: on this hardware
  the remaining cost is the kernel's page-cache copy and SHA-1, which fixed
  buffers do not remove. Revisit with NVMe measurements.
