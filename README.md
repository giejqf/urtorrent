# urtorrent

A Rust BitTorrent library for Linux in the spirit of libtorrent-rasterbar:
downloading and seeding, all data-path I/O on **io_uring**, first-class
IPv4 + IPv6, and wire behaviour that matches a pinned qBittorrent build closely
enough that trackers and peers see nothing unusual.

Read [AGENTS.md](AGENTS.md) first: it is the project charter (scope, rules,
architecture, milestones). Design decisions live in [docs/adr](docs/adr),
oracle-vs-BEP disagreements in [docs/quirks.md](docs/quirks.md).

## Status

| Milestone | State |
|---|---|
| M0 Harness | done: netns lab, pinned oracle, opentracker, tap-tracker, tap-peer, first golden captures |
| M1 Foundations | done: `bencode`, `metainfo`, `uring` (reactor + probe + enforcement), `storage` (hashing + resume), fuzz targets |
| M2 Leech | done: `profile`, `wire`, `tracker`, `picker`, `session` engine + `urtorrent` facade; `leech_from_oracle` green in v4 / v6 / dual |
| M3 Seed | done: choker, upload path, allowed-fast, rate limits, force recheck, resume after `kill -9`, blame/bans; seeding to the oracle and to Transmission green in v4 / v6 / dual |
| M4 Identity | done: HTTPS via rustls, profile facts pinned (per-torrent peer id / key, Q6-Q8), discriminator v1 + `xtask diff` (oracle ≡ us under the qbt profile; Transmission and `native` flagged) |
| M5 Reach | done (PT-complete): UDP tracker, scrape, MSE (all modes vs the oracle), per-listen-socket dual-stack announces, tier failover/backoff, PT-style tracker, uTP-enabled oracle over TCP |
| M6 Extensions | next |

## Developer commands

```
cargo xtask check          # fmt, clippy -D warnings, tests, docs, dependency policy
cargo xtask doctor         # kernel / io_uring / sudo / tools / oracle binaries
cargo xtask it [scenario]  # integration scenarios in the isolated netns lab
cargo xtask capture        # regenerate golden captures from the pinned oracle
cargo xtask diff           # differential run + discriminator (M4)
cargo xtask fuzz <target>  # cargo-fuzz (nightly)
cargo xtask syscalls       # no non-uring data-path syscalls (M1)
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

The engine runs on its own io_uring thread; the caller's tokio runtime only ever
awaits `tokio::sync` channels (AGENTS.md 5.6). `testkit/src/bin/urt-client.rs`
is a complete example and the process the lab runs as "us".

`xtask it` needs passwordless `sudo` (for `ip netns`, `nsenter`, `tcpdump`),
`opentracker` and `transmission-daemon` from apt, and downloads the pinned
oracle binaries (`testkit/oracle.lock`) into `~/.cache/urtorrent/oracle`.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
