# Getting started

## Requirements

- Linux 6.1 or newer with io_uring enabled (`kernel.io_uring_disabled = 0`).
  There is no fallback: if the ring cannot be set up, or a required opcode is
  missing, `SessionBuilder::build` fails with an error naming what is missing.
- In a container, a seccomp profile that allows the `io_uring_*` syscalls
  (Docker's default blocks them; `testkit/docker/seccomp-io_uring.json` is one
  that works). `cargo xtask doctor` checks the host.
- Rust 1.98 or newer.

```toml
[dependencies]
urtorrent = "0.14"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## A first download

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

`shutdown().await` sends `stopped` to the trackers, flushes resume data and
joins the engine's threads. Dropping the last `Session` handle starts the
same shutdown without waiting for it.

## How it fits together

- **Engine-owned threads.** `build()` starts the engine's own threads: the
  network ring (`urt-net`), the disk ring (`urt-disk`) and the SHA-1 pool.
  Every public operation is an `async fn` that sends a message to the engine
  over `tokio::sync` channels, so it can be awaited from any runtime; tokio
  never owns a socket, file or timer of the library (AGENTS.md 5.6).
- **Handles and snapshots.** `Session` is `Clone + Send + Sync`. Status
  (`status`, `statuses`, `peers`, `files`, `trackers`, `pieces`, `stats`)
  comes back as plain structs copied out of the engine.
- **Events.** `Session::events()` returns an `EventStream`; a consumer that
  falls behind gets `Event::Lagged { dropped }` instead of slowing the engine.
  With the default `tokio` feature, `urtorrent::StreamExt` adds the `Stream`
  conveniences.

## Common tasks

| Task | API |
|---|---|
| Add a magnet link | `AddTorrent::magnet(uri, save_path)` |
| Download only some files | `AddTorrent::file_priorities`, `Session::set_file_priorities` (pieces that straddle a skipped file go to a parts file) |
| Survive a restart | `AddTorrent::resume_dir`, or `Session::resume_data` + `AddTorrent::resume_data`; see [resume.md](resume.md) |
| Pause, resume, recheck, move | `pause`, `resume`, `force_recheck`, `move_storage` |
| Limit rates and connections | `SessionBuilder::upload_limit` / `download_limit` / `max_connections`, `Session::set_rate_limits`, `set_torrent_rate_limits` |
| Queue torrents | `SessionBuilder::active_limits`, `move_in_queue`, `force_resume` |
| Add peers, trackers, web seeds | `add_peer`, `add_tracker`, `add_web_seed` |
| Turn on uTP, DHT, PEX, LSD, encryption | `SessionBuilder::transports`, `dht`, `pex`, `lsd`, `encryption` (all changeable at runtime) |

[config.md](config.md) lists every knob, and what is deliberately left to the
application. The rustdoc of `Session`, `SessionBuilder` and `AddTorrent` is
the full reference.

## Identity

`SessionBuilder::profile` chooses what trackers and peers see:
`Profile::native()` (the default: urtorrent's own peer-id prefix and user
agent) or `Profile::qbt_5_2_3_lt2_0_14()`, which matches qBittorrent 5.2.3 on
libtorrent 2.0.14 on the wire. [quirks.md](quirks.md) records where that
build differs from the BEPs.

## Logging

The library logs through `tracing`. Targets are the crate names, for example
`RUST_LOG=urtorrent_session=debug`.

## A complete client

`testkit/src/bin/urt-client.rs` is a small command-line client built on the
library; the integration lab runs it as "us" ([testing.md](testing.md)).
