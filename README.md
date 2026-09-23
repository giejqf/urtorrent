# urtorrent

A Rust BitTorrent library for Linux in the spirit of libtorrent-rasterbar:
downloading and seeding, all data-path I/O on **io_uring**, first-class
IPv4 + IPv6, and wire behaviour that matches a pinned qBittorrent build closely
enough that trackers and peers see nothing unusual.

Read [AGENTS.md](AGENTS.md) first: it is the project charter (scope, rules,
architecture, milestones). Design decisions live in [docs/adr](docs/adr),
oracle-vs-BEP disagreements in [docs/quirks.md](docs/quirks.md), the test
layers in [docs/testing.md](docs/testing.md), soak/perf baselines in
[docs/perf.md](docs/perf.md) and the configuration a client gets from the
library (versus what stays in the frontend) in [docs/config.md](docs/config.md),
and how a torrent's state survives a restart in [docs/resume.md](docs/resume.md).

## Status

| Milestone | State |
|---|---|
| M0 Harness | done: netns lab, pinned oracle, opentracker, tap-tracker, tap-peer, first golden captures |
| M1 Foundations | done: `bencode`, `metainfo`, `uring` (reactor + probe + enforcement), `storage` (hashing + resume), fuzz targets |
| M2 Leech | done: `profile`, `wire`, `tracker`, `picker`, `session` engine + `urtorrent` facade; `leech_from_oracle` green in v4 / v6 / dual |
| M3 Seed | done: choker, upload path, allowed-fast, rate limits, force recheck, resume after `kill -9`, blame/bans; seeding to the oracle and to Transmission green in v4 / v6 / dual |
| M4 Identity | done: HTTPS via rustls, profile facts pinned (per-torrent peer id / key, Q6-Q8), discriminator v1 + `xtask diff` (oracle ≡ us under the qbt profile; Transmission and `native` flagged) |
| M5 Reach | done (PT-complete): UDP tracker, scrape, MSE (all modes vs the oracle), per-listen-socket dual-stack announces, tier failover/backoff, PT-style tracker, uTP-enabled oracle over TCP |
| M6 Extensions | done: PEX, `ut_metadata` / magnets, `upload_only`, LSD, web seeds, BEP 40; private torrents proven silent on the wire (Q11); scenarios green in v4 / v6 |
| M7 Hardening | done: file priorities with a parts file + move storage (Tier 1), torrent files opened on the ring, `xtask syscalls` on a real session, `xtask soak` (20 GiB loopback, 500 torrents), fuzz time, API review; **0.1.0** |
| 0.3.0 DHT | done: `crates/dht` (BEP 5 / 42 / 43 / 51 sans-IO node ported from libtorrent), engine integration on the listen port's UDP demux, `port` messages, per-actor /24s in the lab, `tap-dht`, `dht_leech_from_oracle` / `dht_seed_to_oracle` / `dht_shape` green (our node is indistinguishable from the oracle's on every probed shape); **0.3.0** |
| 0.11.0 Resume blobs | done: `resume_data` / `AddTorrent::resume_data` (libtorrent's `write_resume_data_buf` / `read_resume_data` shape), format 6 with unfinished pieces, trackers, web seeds, timestamps and last peers, `needs_resume_save`; **0.11.0** |
| 0.11.x Races, benchmark | done: overlapping-operation gates (`races.rs`), a recheck no longer strands pieces, the semaphore no longer loses wakeups; `cargo xtask bench` measures RSS and CPU against the oracle (`docs/perf.md`) and found the pipeline ramp and reconnect-backoff bugs; under load the race gates found a block written behind a recheck, in-progress parts left behind when a skipped file became wanted, and a resume restore racing the first peer; the unmaintained `rustls-pemfile` replaced and RustSec advisories enforced; **0.11.4** |
| 0.12.0 Daemon gaps | done: errored torrents recover (`ErrorKind`; missing content reported as the oracle's "missing files" instead of downloaded again), torrents held at their metadata (`hold_after_metadata` / `release`, checked against the oracle's stop condition in `magnet_hold`), list-view status fields (tracker summary, distributed copies, activity times), `PeerBanned`; a torrent outside the queue now starts; **0.12.0** |
| 0.10.0 Hostile peers | done: slow-loris and idle-connection floods bounded (one handshake deadline, pending handshakes count towards the limit), requests past a piece refused, peer lists capped at 3000 per torrent, live-engine gates for malformed peers (`hostile.rs`) on top of the parser fuzzers and the state-machine tests; snapshot structs `#[non_exhaustive]`; **0.10.0** |
| 0.9.0 Live settings | done: listen port / addresses, the DHT node and the identity profile change at runtime (`set_listen`, `set_dht`, `set_profile`), trackers told with `stopped` / `started` pairs; nothing a preferences page exposes needs a session rebuild any more; **0.9.0** |
| 0.8.0 Daemon readiness | done: `torrent_file` (byte-exact re-add after a restart), per-piece state, cheap list snapshots, runtime encryption / transport / PEX / LSD switches and a settings snapshot, session-wide IP bans, live web seeds, `rename_file`, resume data v5 carrying per-torrent settings and renamed files; **0.8.0** |
| 0.7.0 Configuration | done: the active-torrent queue (`ActiveLimits`: max active downloads / seeds / total, slow-torrent exemption, queue order and moves, force start, persisted in resume data v4; ADR 0009), per-torrent upload slots, add-time rate / peer limits, runtime session limits, both choke directions in `PeerInfo`; `docs/config.md` records what the library offers and what is the frontend's; **0.7.0** |
| 0.6.0 Gates | done: user-space copy budgets counted (`SessionStats::copied_bytes`) and gated (TCP download 1 copy / byte, upload 0, uTP 2 each way; receive path parses frames in place), dual-stack edge cases gated in-process (one connection per peer over both families, family-less engines never dial the other family, v4-mapped addresses normalised, self-connections recognised under per-connection peer ids) and in the lab (dual / v6 shapes for the discovery, magnet, DHT, uTP and tracker scenarios); BEP 52 dropped from the roadmap; **0.6.0** |
| 0.5.0 Magnet / LTEP | done: BEP 9 `x.pe` peers, `ws` web seeds and BEP 53 `so=` in magnet links, tracker-less magnets resolved through the DHT (`magnet_dht_from_oracle`), BEP 10 additive re-handshakes and `reqq` honoured, BEP 11 seed flag aligned with libtorrent, `capture_magnet_private` / `magnet_private_shape` (private torrents keep BEP 10 and drop only discovery, Q11); **0.5.0** |
| 0.4.0 uTP | done: `crates/utp` (BEP 29 sans-IO transport ported from libtorrent's `utp_stream`: LEDBAT, selective acks, path-MTU probing, close reasons), `Transport::Utp` on the UDP listen socket with multishot `recvmsg` and an ordered send queue, `TransportPolicy` (TCP first by default, uTP for what TCP cannot reach; libtorrent's uTP-first order on request), `capture_utp` goldens, `utp_leech_from_oracle` / `utp_seed_to_oracle` / `utp_shape` green; **0.4.0** |
| 0.2.0 Performance | done: external-address voting, dedicated disk ring, hash-as-you-write, scale pass (10 000 torrents in one session), indexed picker + extent affinity, provided-buffer-ring receive path + vectored/zero-copy sends (ADR 0006), API completeness (tracker add/remove, `remove_torrent_with_files`, preallocation, per-torrent peer caps, time counters, richer stats); **0.2.0** |

## Developer commands

```
cargo xtask check          # fmt, clippy -D warnings, tests, docs, dependency policy
cargo xtask doctor         # kernel / io_uring / sudo / tools / oracle binaries
cargo xtask it [scenario]  # integration scenarios in the isolated netns lab
cargo xtask capture        # regenerate golden captures from the pinned oracle
cargo xtask diff           # differential run + discriminator (M4)
cargo xtask fuzz <target>  # cargo-fuzz (nightly)
cargo xtask syscalls       # no non-uring data-path syscalls: uring probe + a real session under strace
cargo xtask soak           # perf / leak exercise: many torrents + a big loopback transfer (release build)
```

## Using the library

```rust
use urtorrent::{AddTorrent, Event, Session};

#[tokio::main]
async fn main() -> Result<(), urtorrent::Error> {
    let session = Session::builder().listen_port(6881).build().await?;
    let id = session
        .add_torrent(AddTorrent::metainfo(std::fs::read("x.torrent")?, "downloads"))
        .await?;
    let mut events = session.events();
    while let Some(ev) = events.recv().await {
        if matches!(ev, Event::TorrentFinished { id: done } if done == id) {
            break;
        }
    }
    session.shutdown().await
}
```

Magnet links (`AddTorrent::magnet`), selective download
(`AddTorrent::file_priorities` / `Session::set_file_priorities`, with a parts
file for pieces that straddle skipped files), `Session::move_storage`,
`Session::add_peer`, rate limits, force recheck and crash-safe resume data are
all there; see the `Session` docs for the full surface. Identity is chosen
per session with `SessionBuilder::profile` (`Profile::native()` by default,
`Profile::qbt_5_2_3_lt2_0_14()` for the conformance target).

The engine runs on its own io_uring thread; the caller's tokio runtime only ever
awaits `tokio::sync` channels (AGENTS.md 5.6). `testkit/src/bin/urt-client.rs`
is a complete example and the process the lab runs as "us".

`xtask it` needs passwordless `sudo` (for `ip netns`, `nsenter`, `tcpdump`),
`opentracker` and `transmission-daemon` from apt, and downloads the pinned
oracle binaries (`testkit/oracle.lock`) into `~/.cache/urtorrent/oracle`.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
