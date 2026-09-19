# ADR 0001: io_uring runtime

- Status: accepted (2026-09-19)
- Relates to: AGENTS.md 5.3

## Context

Every performance-critical I/O path (peer sockets, torrent files, the timers
that drive them, UDP tracker / LSD datagrams, HTTP(S) tracker and web-seed
sockets) must run on io_uring with no possible fallback to epoll, a blocking
thread pool or any other reactor. Three options were considered:

1. **`compio`** - a completion-based runtime with io_uring on Linux. Mature
   API, but it carries a *polling* fallback driver (`polling` crate, epoll)
   selected by feature flags and runtime probing, and its buffer-ownership
   model is generic over several backends. Making the fallback a hard error
   means forking or vendoring configuration, and its dependency tree pulls in
   crates that `cargo-deny` must ban.
2. **`monoio`** - thread-per-core, io_uring-first. Also ships a `legacy`
   (epoll/mio) driver and falls back to it when io_uring is unavailable
   unless features are pruned carefully; buffer ownership is right, but
   provided-buffer rings, multishot recv and zero-copy send are only
   partially exposed.
3. **Own reactor on the `io-uring` crate** (tokio-rs/io-uring: thin, safe-ish
   bindings over the raw interface). Full control over multishot accept /
   recv, provided buffer rings, registered files and buffers, `send_zc`,
   linked timeouts, `IORING_REGISTER_PROBE`, and `submit_with_args` timeouts.
   No fallback exists because none is written. Cost: we own the executor,
   the buffer pool and all the `unsafe`.

## Decision

Option 3: build `crates/uring` directly on the `io-uring` crate with a small
single-threaded executor per ring thread (one network ring, separate disk
ring(s)), owned pooled buffers, and completion-driven futures. The `uring`
crate is the only crate in the workspace allowed to contain `unsafe`.

Enforcement (5.3): `compile_error!` on non-Linux, `cargo-deny` bans on
`mio`/`polling`/`async-io`/`async-std`, a tokio feature audit in
`xtask check`, a hard error from session creation if `io_uring_setup` fails or
a required opcode is missing (probe), and `xtask syscalls` (strace) asserting
no `epoll_*`/`poll`/`select`/socket `read`/`write` from library threads.

## Consequences

- Buffer ownership is a hard rule: a buffer handed to the kernel belongs to the
  reactor until its CQE arrives; futures cancel with `ASYNC_CANCEL` and the
  reactor reclaims the buffer. No API takes `&mut [u8]` for an async op.
- The public API stays tokio-native (5.6) through runtime-agnostic
  `tokio::sync` channels; tokio never polls a uring future.
- Kernel baseline 6.1 LTS; newer opcodes are optional fast paths behind probes.
