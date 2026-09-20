# Testing guide

## Layers (AGENTS.md 7.1)

| Layer | Where | Command |
|---|---|---|
| Unit / property | each crate's `tests` + `proptest` | `cargo xtask check` |
| Fuzz | `fuzz/` | `cargo xtask fuzz <target> [secs]` |
| Replay | crate tests fed from `testkit/golden` | `cargo xtask check` |
| Integration | `testkit/src/scenario` | `cargo xtask it [--shape v4\|v6\|dual] [scenario]` |
| Differential | scenarios tagged `Diff` | `cargo xtask diff` |
| Captures | scenarios tagged `Capture` | `cargo xtask capture` |

## The lab

`testkit::lab` builds a bridge on the host (`urt<id>`) with a private v4 and
v6 subnet and a network namespace per actor (see ADR 0002). Client actors
(oracle, transmission, our client) each get a namespace and one address per
family the shape asks for. Harness-side actors (tap-tracker, tap-peer,
opentracker) run in the harness process or as host processes bound to bridge
addresses (`.1` plus aliases `.2`-`.9`).

The library under test runs as the `urt-client` binary (`testkit/src/bin`),
launched into its own namespace like the oracle. It writes a JSON status
snapshot (`status.json`: state, counters, trackers, peers seen, recent events)
several times a second and takes commands from a control file (`shutdown`,
`pause`, `resume`, `reannounce`, `save-resume`), so scenarios need no signals
for a graceful stop. `testkit::client::UrtClient` wraps both.

Run artifacts land in `testkit/runs/<stamp>-<scenario>-<shape>/` (gitignored):
actor stdout/stderr, oracle profiles and logs, tap logs (`*.jsonl`), pcaps.
Pass `--keep` to leave the namespaces up after a run; `testkit lab clean`
removes stale labs.

## Golden captures

`testkit/golden/<scenario>/<shape>/*.jsonl` are produced by `cargo xtask
capture` from the pinned oracle and committed. They are **the spec** for
identity and wire shape (AGENTS.md 6). Formats:

- `tap-tracker*.jsonl`: one `TapEvent` per request: raw request bytes (hex),
  parsed request line / headers / ordered query parameters, response bytes.
- `tap-peer*.jsonl`: one `PeerCapture` per connection: both handshakes
  (raw + decoded reserved bits), every message in order with direction,
  timestamps and raw frame (except piece payloads), decoded LTEP dictionaries.

Bumping `testkit/oracle.lock` regenerates all of them in the same PR.
