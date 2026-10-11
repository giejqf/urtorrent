# ADR 0002: Integration environment is a netns lab; Docker is the alternative

- Status: accepted (2026-09-19, M0)
- Relates to: AGENTS.md rule 3, 7.2; ADR 0007

## Context

Integration and differential tests need several actors (pinned qBittorrent
oracle instances, opentracker, transmission, our client, tap-tracker,
tap-peer) with distinct IPv4 and IPv6 addresses, in v4-only / v6-only /
dual-stack shapes, isolated from the public internet. AGENTS.md allows either
Docker Compose on an internal network or `ip netns` + veth.

Findings while building M0 on the CI-like VM:

- The oracle is a static musl binary; opentracker and transmission are apt
  packages. Nothing needs a container image to run.
- Docker's default seccomp profile blocks `io_uring_*`; running our code in a
  container needs a custom profile (`testkit/docker/seccomp-io_uring.json`).
- Unprivileged user namespaces are restricted on Ubuntu 24.04+
  (`kernel.apparmor_restrict_unprivileged_userns=1`), so the lab needs
  passwordless `sudo` either way.
- Host firewalls (ufw) default INPUT to drop; the lab must open its bridge.

## Decision

The primary environment is a **netns lab** driven by `testkit`:

- One Linux bridge per lab (`urt<id>`) on the host, carrying
  `10.<id>.0.0/16` and `fd77:<id>::/32` (amended 2026-09-20; the lab used to
  be one /24 + /64). Every actor and every harness alias has its own /24 and
  /64 inside it (`10.<id>.<n>.1`, `fd77:<id>:<n>::1`): libtorrent's DHT keeps
  one node per /24 (v4) or /64 (v6) per bucket and per search, so a lab in
  one /24 could never exercise multi-hop DHT behaviour. The harness itself
  lives at `10.<id>.0.1` / `fd77:<id>::1` and adds aliases `n = 2..9` for
  tap actors that must present distinct IPs. Ids whose `10.<id>.0.0/16`
  overlaps a route the host already has are skipped.
- One network namespace per client actor, attached with a veth pair, with a
  v4 address, a v6 address, or both. No default route: actors can only reach
  the lab (rule 3). IPv6 is disabled with sysctl in v4-only namespaces.
  *Amended (0.1.0):* every actor now gets a default route via the harness's
  bridge address (Transmission 4 opens no peer connections without a route
  to a public address), and isolation is enforced instead by a
  `FORWARD -i urt<id> -j DROP` rule (iptables and ip6tables) plus
  `forwarding=0` on the bridge, so nothing leaves the lab even on a host
  with `ip_forward=1` (`testkit/src/lab.rs`, `firewall_allow`).
- Processes enter a namespace through `sudo -n nsenter --net=... -S uid -G gid`
  and run as the unprivileged user, so files they write are ours and they can
  be signalled directly (`kill -9` scenarios).
- `iptables`/`ip6tables` rules for the bridge (INPUT accept, FORWARD drop)
  are added and removed on teardown; `testkit lab clean` removes anything
  stale.
- Packet capture uses `tcpdump` on the bridge (informational; never a gate).
  *Amended (0.1.0, 0.4.0):* some scenarios now assert on the pcap and fail
  without tcpdump: `private_no_pex_lsd` (0.1.0: no LSD datagram about the
  private torrent, rule 2) and the uTP scenarios (0.4.0: `capture_utp`,
  `utp_leech_from_oracle`, `utp_seed_to_oracle`, `utp_shape` decode the uTP
  headers from it). `lsd_discovery` checks the LSD datagrams when tcpdump
  is present.

Docker Compose remains a supported alternative for environments without sudo
(`xtask doctor` explains the seccomp requirement); the scenarios are written
against the `Lab`/`Actor` abstraction so a compose backend can be added
without touching them.

## Consequences

- `xtask it` requires passwordless sudo and iproute2; `xtask doctor` checks.
- Tests never depend on DNS. Where a scenario needs hostnames (dual-stack
  announce semantics), `ip netns exec` with `/etc/netns/<ns>/hosts` will be
  used, keeping the host's `/etc/hosts` untouched. *Amended (0.1.0):* not
  done that way: the lab adds `tracker.urt<id>.lab` (resolving to the
  harness's v4 and v6 bridge addresses) to the host's `/etc/hosts` and
  removes it on teardown; `testkit lab clean` removes stale entries.
