# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-09-21

The configuration a client needs from the library, checked against what
qBittorrent maps onto libtorrent (`docs/config.md`): the active-torrent
queue, per-torrent upload slots, add-time limits and runtime changes of the
session limits. Frontend policy (share limits, schedulers, categories) stays
out by design.

### Added

- The active-torrent queue (ADR 0009, docs/quirks.md Q26):
  `ActiveLimits { downloads, seeds, total, count_slow }` via
  `SessionBuilder::active_limits` / `Session::set_active_limits` (default
  unlimited); per torrent `AddTorrent::auto_managed`,
  `Session::set_auto_managed`, `force_resume`, `move_in_queue(QueueMove)`;
  `TorrentState::Queued`; `TorrentStatus::{auto_managed, queue_position}`.
  `pause` takes a torrent out of the queue, `resume` hands it back (it may
  wait as `Queued`). Slow torrents (below 2 KiB/s for 60 s) hold no slot
  unless `count_slow`. Resume data format 4 persists `auto_managed` and the
  queue order (format 1–3 files still load).
- Per-torrent upload slots: `AddTorrent::max_uploads`,
  `Session::set_max_uploads`, `TorrentStatus::max_uploads` (the choker
  yields a capped torrent's slots to the next torrent's peers).
- Add-time limits: `AddTorrent::{upload_limit, download_limit, max_peers}`.
- Runtime session limits: `Session::{set_max_connections,
  set_max_peers_per_torrent, set_unchoke_slots}`.
- `PeerInfo::{am_choking, peer_interested}` (both directions of choke and
  interest are now reported).
- `docs/config.md`: library knobs, frontend responsibilities, and what is
  deliberately not offered.

### Changed

- `Session::add_peer` dials the address at the next tick even when an
  earlier attempt left it in reconnect backoff (libtorrent `connect_peer`).
- The reconnect backoff after a disconnect counts from the time the
  connection was made, not from the disconnect (libtorrent
  `min_reconnect_time` against `last_connected`): a peer that was connected
  for over a minute is redialled at once after a pause / resume.
- A `resume` during a pause's wind-down (`stopped` announces in flight) is
  applied once the pause completes instead of overlapping two lifecycles.
- The `native` profile's identity strings are `-UR0700-` / `urtorrent/0.7.0`
  / DHT `UR\x00\x07`.

## [0.6.0] - 2026-09-21

Gates for dual-stack edge cases and user-space copies on the data path, and
BEP 52 (v2/hybrid torrents) taken off the roadmap.

### Added

- `SessionStats::copied_bytes`: every user-space copy of payload on the data
  path is counted, and `crates/session/tests/copies.rs` gates the budgets
  (TCP download one copy per byte, TCP upload none, uTP two each way; with
  and without rate limits, over blocks that straddle files). `docs/perf.md`
  has the table.
- Dual-stack gates in `crates/session/tests/dualstack.rs` and `selfconn.rs`:
  one peer reached over both families (dialled by one side, or one direction
  each) keeps exactly one connection; an engine without a family never dials
  that family; v4-mapped addresses from any peer source are dialled as the
  IPv4 peer they name; a tracker listing one seeder under `peers`, `peers6`
  and v4-mapped in `peers6` yields one connection; an address of our own
  handed back by a tracker or a peer is recognised as a self-connection and
  never dialled again. Lab scenarios `pex_discovery`, `lsd_discovery`,
  `private_no_pex_lsd`, `magnet_via_ut_metadata`, `web_seed_only`,
  `https_tracker`, `http_scrape`, `dht_leech_from_oracle` and
  `utp_leech_from_oracle` now run in the dual shape too; `tracker_failover`,
  `magnet_dht_from_oracle` and `utp_seed_to_oracle` in v6.
- docs/quirks.md Q25 (dual-stack duplicates, self-connections, address
  normalisation).

### Changed

- The receive path copies a block once instead of twice: peer-wire frames
  are parsed in place in the received chunk (`wire::Frame::Borrowed`), a
  frame cut by a chunk boundary is assembled once and handed over as the
  block itself (`wire::Frame::Owned`, `wire::Block` with its payload offset,
  `Storage::write_block_from`, `File::write_range_all_at`). Blocks straddling
  files are written from their ranges of the same buffer (no per-slice copy),
  and uTP moves whole chunk batches into its write queue instead of copying
  them.
- Peer addresses are normalised on ingress: a v4-mapped IPv6 address from a
  tracker, PEX, the DHT, LSD or a magnet's `x.pe` is the IPv4 peer it names.
  Candidates of a family without a listen socket are dropped instead of
  dialled from an unbound socket (`listen_v4` / `listen_v6` docs).
- The same peer id on two connections of the same direction but different
  families keeps the IPv6 one (libtorrent's order-based rule made the two
  ends drop different connections); opposite directions keep libtorrent's
  rule. Self-connections are recognised by the peer ids we put on outgoing
  connections (libtorrent `is_self_connection`; needed under the qbt
  profile's per-connection ids) and by endpoints, and the address is never
  dialled on our listen port again.
- Lab assertions on `downloaded` allow the end-game redundancy of two
  connections to the oracle (one per family, Q25): `downloaded - total <=
  redundant`, `corrupt == 0`, data verified on disk.
- The `native` profile's identity strings are `-UR0600-` / `urtorrent/0.6.0`
  / DHT `UR\x00\x06`.

### Removed

- BEP 52 (v2 / hybrid torrents) from the roadmap (maintainer decision:
  not widely adopted). Hybrid torrents keep working through their v1 half.

## [0.5.0] - 2026-09-21

Magnet links and the extension protocol, checked against BEP 9, 10, 11 and
27 and the oracle (new capture `capture_magnet_private`).

### Added

- Magnet links (BEP 9): `x.pe=` peer hints are dialled right away (host
  names through the DNS helper, `PeerSource::Manual`), `ws=` web seeds are
  added, and BEP 53 `so=` selects the files to download once the metadata
  arrives (explicit `AddTorrent::file_priorities` win). `MagnetLink` gained
  `peers`, `web_seeds` and `select_only` (breaking for struct literals,
  hence the minor bump).
- A tracker-less magnet link is looked up in the DHT before any metadata
  is known (BEP 9 "SHOULD use the DHT"); lab scenario
  `magnet_dht_from_oracle`, in-process test in `crates/session/tests/dht.rs`.
- Scenarios `capture_magnet_private` (the oracle's LTEP `m` before and after
  a private torrent's metadata arrives via magnet) and
  `magnet_private_shape` (differential on the same).

### Fixed

- BEP 10: a repeated extension handshake is merged (its `m` is additive, 0
  disables, unmentioned extensions keep their ids); the peer's `reqq` now
  caps our request pipeline.
- BEP 9: unknown `ut_metadata` message types are ignored instead of ending
  the connection.
- BEP 11: the `seed` flag (0x02) follows libtorrent — a complete have-set,
  not BEP 21 upload-only alone.
- The `native` profile's identity strings are `-UR0500-` / `urtorrent/0.5.0`.

## [0.4.1] - 2026-09-20

Conformance pass over BEP 6 (fast extension), BEP 7 (IPv6 tracker
extension), BEP 20 (peer-id conventions), BEP 23 (compact peers) and BEP 48
(scrape), checked against the BEP texts and libtorrent 2.0.14.

### Fixed

- BEP 6: a cancel of a still-queued request is answered with a reject, and
  a piece or reject that answers a request *we* cancelled is recognised
  (exactly one response per request); choking no longer rejects requests
  for pieces in the peer's allowed-fast set; a peer that keeps requesting
  while choked, or pulls more than three pieces' worth of blocks from one
  allowed-fast piece while choked, is dropped (libtorrent's limits); the
  peer's `suggest piece` messages are requested first (last 16 per peer).
  `docs/quirks.md` Q23 records where libtorrent's leniency is kept over
  the BEP's MUST.
- BEP 48: the scrape URL replaces `announce` in the URL's *path* only (a
  host such as `announce.example.org` no longer breaks it); the
  `flags.min_request_interval` extension is honoured between scrapes of
  the same tracker and per-file `name` is parsed.
- BEP 7: `ipv4=` / `ipv6=` hints are sent as libtorrent sends them, for
  private torrents from explicitly bound public listen addresses
  (`docs/quirks.md` Q22); the announce parameter order's tail
  (`trackerid`, `ipv4`, `ipv6`) is now source-verified.
- Announces report `downloaded` as libtorrent does: payload received minus
  corrupt and redundant bytes, so the figure never exceeds the torrent
  (`docs/quirks.md` Q24). `TorrentStatus::downloaded` stays the gross count.
- A plaintext attempt refused by a peer that requires encryption (Q3) is
  retried encrypted on the same transport, not treated as a TCP failure.
- BEP 20: the `native` profile's peer id carries the version digits in
  Azureus order (`-UR0410-` for 0.4.1; 0.4.0 had shipped `-UR0040-`, which
  decodes as 0.0.4). User-Agent / LTEP `v` are `urtorrent/0.4.1`.

### Added

- `wire::identify::client_name`: BEP 20 client identification from the
  peer id (Azureus, Shadow, Mainline and the one-off schemes the BEP
  lists, plus the codes in use today); `PeerInfo::client` falls back to it
  when a peer sends no LTEP `v`. Fuzz target `identify_client`.
- `picker::Picker::pick_preferring` (preferred pieces first).

## [0.4.0] - 2026-09-20

uTP (BEP 29). TCP stays the default transport; uTP accepts incoming
connections and reaches peers TCP cannot (`TransportPolicy`). The wire shape
matches the oracle's on every probed detail (`utp_shape`, `xtask diff`).

### Added

- `crates/utp`: a sans-IO uTP implementation ported from libtorrent 2.0.14's
  `utp_stream` (ADR 0008): LEDBAT with slow start, RTT-based retransmission
  timeouts, fast resends, selective acks, nagle, the close-reason
  extension, path-MTU discovery with libtorrent's probe ladder, and the
  per-port connection table (`utp::Manager`) with deferred acks.
- `SessionBuilder::transports(TransportPolicy)`: `PreferTcp` (default: dial
  TCP, accept both, one immediate uTP attempt for an address whose TCP dial
  failed or died before the handshake), `PreferUtp` (libtorrent's uTP-first
  order with TCP fallback), `UtpOnly` (qBittorrent's "μTP only"), `TcpOnly`.
  `PeerTransport::Utp`; `PeerInfo::transport` reports it.
  `SessionStats::utp_connections`.
- Close reasons: our disconnect reasons travel in the FIN as libtorrent's
  `close_reason_t` codes (`both seeds` = 6, ...).
- `uring::UdpSocket::recv_multi` (multishot `recvmsg` into a provided
  buffer ring), `uring::RecvMsgMulti`, `RingBuf::advance`,
  `UdpSocket::set_dont_fragment`, `uring::monotonic_micros`,
  `uring::Error::is_message_too_long`.
- Testkit: `capture_utp` goldens (`utp-shape.json`), a pcap reader and uTP
  decoder (`testkit::utp_capture`), `UtpFingerprint` in the discriminator,
  scenarios `utp_leech_from_oracle` (v4/v6), `utp_seed_to_oracle`,
  `utp_shape` (differential); `urt-client --protocol both|tcp|utp|utp-first`.
  `xtask soak --utp`. Fuzz
  target `utp_packet`. `xtask syscalls` transfers over TCP and uTP.
- `docs/quirks.md` Q21 (uTP wire shape, the oracle's uTP-first dialling as
  an accepted difference, the FIN-round data drop, `implied_port` with uTP
  on).

### Changed

- The listen port's UDP sockets receive through one multishot `recvmsg`
  per socket (DHT, UDP trackers and uTP share it) and send through an
  ordered per-socket queue, 32 datagrams per ring round trip.
- DHT announces carry `implied_port: 1` while incoming uTP is enabled
  (libtorrent's rule); the DHT lab scenarios run our client with uTP off,
  matching the oracle's primary capture configuration.
- `oracle_utp_tcp_fallback` runs us TCP-only so the oracle's TCP fallback
  is what gets exercised.
- The `native` profile's version tags are `0.4.0` / `-UR0040-`.

## [0.3.0] - 2026-09-20

The DHT (BEP 5). Peers now also come from the Mainline DHT; the public API
grew (builder options, `Session::{dht_state, add_dht_node}`, new
`PeerSource` / `Event` variants, `SessionStats::dht_*`), hence the minor
bump. Tests never touch the public internet: in-process tests disable the
DHT or bootstrap from each other, the lab bootstraps from tap nodes.

### Added

- `crates/dht`: a sans-IO Mainline DHT node (BEP 5, 42, 43, 51; libtorrent's
  extensions `ip` / `p` / `bs` / `noseed` / `seed` / BEP 33 scrape filters),
  ported from libtorrent 2.0.14 with attribution: routing table with the
  extended bucket sizes and replacement cache, lookups with branch factor 5
  and 1 s / 15 s timeouts, bootstrap and 5-second refresh, token rotation,
  peer store, DoS blocker, BEP 42 ids from the voted external address. KRPC
  messages are byte-exact against the oracle's captures
  (`testkit/golden/capture_dht`).
- Engine integration (ADR 0007): one node per listen family on the listen
  port's UDP sockets via the demultiplexer hook; found peers arrive as
  `PeerSource::Dht`; torrents are announced round-robin every 15 min / N
  (new and just-finished ones within 4 s), never private ones; peers' `port`
  messages feed the routing table; we send `port` after the have-state to
  DHT-capable peers (`wire::ConnectionParams::dht_port`, the `native`
  profile's handshake now sets the DHT bit while a node runs).
- API: `SessionBuilder::{dht, dht_bootstrap_nodes, dht_read_only,
  dht_state}`, `Session::{dht_state, add_dht_node}`, `Event::{DhtBootstrapped,
  DhtPeers}`, `SessionStats::{dht_nodes, dht_lookups, dht_stored_peers}`,
  `profile::DhtShape` (the `v` tag and qBittorrent's default routers).
- Testkit: `tap-dht` (recording, scriptable DHT node with a router mode),
  scenarios `capture_dht`, `dht_leech_from_oracle` (v4 / v6),
  `dht_seed_to_oracle`, `dht_shape` (differential, in `xtask diff`),
  `private_no_pex_lsd` extended to the DHT; the DHT fingerprint in the
  discriminator; fuzz target `dht_krpc`.

### Changed

- The netns lab gives every actor its own /24 (v4) and /64 (v6):
  `10.<id>.0.0/16` and `fd77:<id>::/32` per lab (ADR 0002 amended), because
  libtorrent's DHT keeps one node per /24 or /64 per bucket and per lookup.
- The `native` profile's version tags are `0.3.0` / `-UR0030-`.

## [0.2.0] - 2026-09-20

Performance and completeness release. The public API grew (new `Session`
methods, new fields on `TorrentStatus` / `PeerInfo` / `SessionStats` /
`AddTorrent`), hence the minor bump; nothing was removed. Resume data is now
format version 3 (every earlier version still loads). Kernel baseline stays
6.1: multishot receive into provided buffer rings is now required (no
single-shot fallback for peer sockets).

### Added

- API completeness: `Session::{remove_torrent_with_files, find_torrent,
  pause_all, resume_all, add_tracker, remove_tracker, set_max_peers}`;
  `AddTorrent::preallocate` (`fallocate` on creation); `TorrentStatus::{
  active_time, seeding_time, max_peers, next_announce_in}` with the two
  clocks persisted in resume data (format v3); `PeerInfo::{download_rate,
  upload_rate, connected_for, transport}`; `SessionStats::{connections,
  disk_jobs_pending, hash_jobs_pending, hash_readback_bytes,
  recv_buffers_free, recv_buffers}` (`storage::DiskStats`,
  `HashPool::outstanding`). `tracker::Announcer::{add_tracker,
  remove_tracker}` (in-flight jobs are matched by URL, so positions may
  shift underneath them); `Storage::delete_files`; `DiskStore::create_files(
  preallocate)`.
- Scale pass for thousands of torrents: `SessionBuilder::{max_open_files,
  max_checking, max_concurrent_announces}` (LRU file pool shared by every
  store, one torrent checked at a time with `TorrentState::QueuedForChecking`
  for the rest, bounded announce and resume-save concurrency), O(1) MSE
  stream-key lookup (`mse::SkeyIndex`), a session tick queue instead of a
  timer per torrent, self-timed rate-limiter waits, shared piece-buffer
  pools; 10 000 torrents in one session verified by `xtask soak many`
  (numbers in `docs/perf.md`).
- Peer data path (ADR 0006): every peer socket receives with one multishot
  `recv` into a session-wide provided buffer ring (`uring::BufRing`,
  `TcpStream::recv_multi`, `RingBuf` guards; `SessionBuilder::recv_ring`),
  queued chunks are
  framed per wakeup, and a batch of `piece` messages leaves as one vectored
  `sendmsg` over the block buffers read from disk (`wire::Connection::piece`
  takes the `Vec<u8>`, `take_outbound_chunks`) — no user-space copy of an
  uploaded block remains. `File::{write_all_at, read_exact_at}` and
  `TcpStream::send_all` resubmit from an offset instead of copying;
  `File::read_exact_into`; `Storage::write_block` writes the block buffer
  itself; receive buffers are no longer zero-filled on reuse. Optional
  zero-copy sends (`SessionBuilder::zero_copy_send`, `IORING_OP_SENDMSG_ZC`,
  off by default). Rings use `SINGLE_ISSUER | DEFER_TASKRUN`. `recv_multi`
  joined the required opcode baseline. `PeerInfo.transport` and the
  `PeerTransport` enum name the transport (TCP; uTP-ready `Transport` enum in
  the engine). A 2 GiB loopback transfer: 116 → 180 MiB/s at 28% less CPU.
- Indexed piece picker: completion, bytes left and end-game are cached
  counters; `pick` walks partial pieces plus untouched pieces bucketed by
  priority and availability (pieces nobody has are never scanned) instead of
  every piece; a `have` from a peer is a constant-time update
  (`wire::Event::HaveChanged { added }`) and gaining a piece only re-checks
  interest in peers that have it. Piece extent affinity (libtorrent's
  `piece_extent_affinity`, ported; **on by default here**, off in the oracle):
  a few recently started 4 MiB extents are finished before rarest-first
  moves on, so small pieces are written in runs the kernel can write back
  (`SessionBuilder::piece_extent_affinity`). A 2 GiB transfer with 16 KiB
  pieces went from 6 MiB/s (with writeback stalls) to 58 MiB/s; 1 MiB
  pieces unchanged. `xtask soak transfer --piece N`; the soak reports CPU
  time.

- External-address voting (libtorrent `ip_voter` semantics): trackers'
  `external ip` and peers' `yourip` vote per listen family; LTEP `p` on
  outgoing connections follows the libtorrent rule against the voted
  address (Q6 is now the implemented mechanism, not an approximation); BEP 40
  ranks against the external address; `Event::ExternalAddress`,
  `SessionStats::{external_v4, external_v6}`.
- A dedicated disk ring: torrent file I/O and hashing completions run on the
  `urt-disk` io_uring thread (`storage::DiskRing` / `DiskStore`, ADR 0004 §4
  amended), with per-piece ordering and full barriers for check / priorities
  / move / sync; peers batch the writes of one receive buffer, the uploader
  pipelines reads. `SessionBuilder::disk_thread(false)` keeps disk I/O on the
  network ring. `uring::Bridge` is the shared cross-thread completion path.
- `xtask syscalls` judges the `urt-disk` thread too; `urt-soak
  --inline-disk` for A/B runs.
- Hash-as-you-write: `Storage` keeps a SHA-1 cursor per piece being
  downloaded and hashes blocks as they land (stash ≤1 MiB per piece for
  blocks ahead of the cursor, page-cache read-back beyond it; padding hashed
  as zeros whatever a peer sent), so a completed piece is no longer read
  back and re-hashed; `verify_piece` returns the cursor's verdict and falls
  back to a read-back for pieces found on disk. `HashPool::update_async`
  (incremental updates, no more buffer clone per job), `HashState`,
  `Storage::hash_readback_bytes`; recheck / fallback hashing uses a pool of
  piece-sized buffers (`BufferPool::put`).

## [0.1.0] - 2026-09-20

First release: TCP-only, tracker / PEX / LSD-driven downloading and seeding on
io_uring, IPv4 + IPv6, with the `qbt_5_2_3_lt2_0_14` identity profile
indistinguishable from the pinned oracle at L1 / L2 (AGENTS.md 6). DHT, uTP and
BEP 52 are deferred to later minor releases.

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
- M6 extensions:
  - `ut_metadata` / magnet links (BEP 9): `AddTorrent::magnet`,
    `TorrentState::FetchingMetadata`, `Event::MetadataReceived`; fetch with
    libtorrent's request/penalty rules, serving in 16 KiB pieces, `left=16384`
    until the metadata is known (Q12); connections without metadata send no
    have-state and are sized when it arrives (Q13).
  - PEX (BEP 11) with the oracle's cadence, eligibility and flags (Q15);
    `Event::PexPeers`, `PeerSource::Pex`, `SessionBuilder::pex`.
  - `upload_only` (BEP 21): sent on completion / metadata, honoured on
    receipt (upload-upload connections closed); `PeerInfo::upload_only`.
  - Local Service Discovery (BEP 14): multicast sockets over io_uring,
    libtorrent's datagram and retry schedule (Q16), `Event::LsdPeer`,
    `PeerSource::Lsd`, `SessionBuilder::lsd`; the codec lives in
    `tracker::lsd`.
  - Web seeds (BEP 19): one kept-alive HTTP connection per `url-list` entry,
    range requests with the oracle's header order (Q17), contiguous picking,
    failure backoff, blame drops a seed that served bad data;
    `Event::WebSeedError`, `TorrentStatus::web_seeds`.
  - BEP 40 canonical peer priority (`wire::peer_priority`, CRC32-C) ranks
    connection candidates.
  - Private torrents (rule 2): `m` without `ut_pex` / `ut_metadata` and no
    `metadata_size` (Q11); no PEX, no LSD, PEX/LSD-sourced addresses refused;
    `TorrentStatus::private`.
  - Allowed-fast now goes out on the peer's first `interested`, skipping its
    pieces, after a preemptive unchoke (Q14), matching the oracle's
    first-messages sequence as a seed.
  - `Session::add_peer` (manual peer source), `PeerSource` on `PeerInfo`,
    outgoing connections bound to the configured listen address.
  - testkit: `tap-webseed` (range server recording raw requests), tap-peer
    serves `ut_metadata` and publishes live captures, `urt-client --magnet /
    --no-lsd / --no-pex / --add-peer`; captures capture_peer_private,
    capture_pex, capture_magnet; scenarios pex_discovery (Diff),
    magnet_via_ut_metadata, lsd_discovery, web_seed_only (Diff),
    private_no_pex_lsd (v4 / v6); PEX side of the discriminator.
  - Fuzz: pex_message, metadata_message, lsd_datagram.
- M7 hardening:
  - File priorities / selective download (Tier 1): `AddTorrent::file_priorities`,
    `Session::set_file_priorities`, `TorrentStatus::files` /
    `total_wanted{,_done}`, `wanted_progress`; pieces straddling a skipped
    file park their skipped bytes in a parts file (`.<name>.parts`), exported
    when the file becomes wanted; skipped files are never created; a finished
    selective download is upload-only but announces `completed` only as a
    full seed (ADR 0005). Resume data format 2 persists priorities.
  - `Session::move_storage` (rename, or copy across filesystems, with peer I/O
    held meanwhile) and `Event::StorageMoved`; `Session::set_sequential`;
    `SessionBuilder::max_connections` (session-wide, default 500);
    `SessionStats::{download_rate, upload_rate}`.
  - Torrent files are opened through the ring (`IORING_OP_OPENAT`, now in the
    probed baseline); `Storage` file access is async end to end.
  - `xtask syscalls` also runs a real two-engine transfer under `strace -Y`
    and judges only the engine threads (`urt-net`, `urt-hash-*`; `urt-dns`
    may block); `xtask soak` (release build): many-torrents and big loopback
    transfer with fd / RSS checks; baselines in `docs/perf.md`.
  - `xtask check` runs `cargo semver-checks` against the latest release tag
    when available.
  - testkit: `urt-client --file-priorities`, `prio` / `move` control commands,
    scenarios `file_priorities` and `move_storage` against the oracle.
  - Every fuzz target run for 90 s without findings.
  - L1 fix (Q19): the handshake peer id is generated per connection under the
    qbt profile (libtorrent 2.0 does; the announce id stays per torrent), and
    duplicate connections are arbitrated the way libtorrent does (by IP and
    listen port, then by peer id); the discriminator checks the
    handshake-vs-announce id relation.
