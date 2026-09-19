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
| M1 Foundations | done: `bencode`, `metainfo`, `uring` (reactor + probe + enforcement), fuzz targets |
| M2 Leech | next |

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

`xtask it` needs passwordless `sudo` (for `ip netns`, `nsenter`, `tcpdump`),
`opentracker` and `transmission-daemon` from apt, and downloads the pinned
oracle binaries (`testkit/oracle.lock`) into `~/.cache/urtorrent/oracle`.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
