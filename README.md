# urtorrent

[![crates.io](docs/badges/crates-io.svg)](https://crates.io/crates/urtorrent)
[![license](docs/badges/license.svg)](LICENSE)
[![rust](docs/badges/msrv.svg)](rust-toolchain.toml)
[![platform](docs/badges/platform.svg)](docs/getting-started.md#requirements)
[![network](docs/badges/network.svg)](docs/config.md)
[![transports](docs/badges/transports.svg)](docs/config.md)
[![discovery](docs/badges/discovery.svg)](docs/config.md)
[![wire-compat](docs/badges/oracle.svg)](docs/quirks.md)

A BitTorrent library for Linux, in the spirit of libtorrent-rasterbar:

- **io_uring all the way down.** Peer sockets, torrent files and their timers
  run on io_uring, with no epoll or thread-pool fallback.
- **IPv4 and IPv6** as equals: separate listen sockets, per-family announces.
- **Looks like qBittorrent on the wire** when asked to: the
  `qbt_5_2_3_lt2_0_14` profile matches a pinned qBittorrent build's
  identifiers and wire shape, checked against captures of the real client.
- **Honest accounting.** What we report to trackers and peers is what happened.
- **A tokio-native API** over engine-owned threads.

Downloading and seeding only: no torrent creation, RSS or UI.

## Quick start

```toml
[dependencies]
urtorrent = "0.14"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

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

Needs Linux 6.1+ with io_uring enabled. Continue with
[docs/getting-started.md](docs/getting-started.md).

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | requirements, the API model, common tasks |
| [Configuration](docs/config.md) | every knob, and what is left to the application |
| [Resume data](docs/resume.md) | surviving restarts and `kill -9` |
| [Quirks](docs/quirks.md) | where the qBittorrent profile follows the client rather than a BEP |
| [Testing](docs/testing.md) | developer commands, the netns lab, differential tests |
| [Performance](docs/perf.md) | soak and benchmark baselines |
| [Roadmap](docs/roadmap.md) | release history and what comes next |
| [ADRs](docs/adr/) | architecture decisions |
| [AGENTS.md](AGENTS.md) | the project charter: scope, rules, architecture |

## Contributing

Read [AGENTS.md](AGENTS.md) first. `cargo xtask check` must pass (format,
clippy, tests, docs, dependency policy); [docs/testing.md](docs/testing.md)
covers the integration lab and the other commands.

## Licence

Apache-2.0 ([LICENSE](LICENSE)). Parts ported from libtorrent-rasterbar are
BSD-3-Clause; [NOTICE](NOTICE) lists them.
