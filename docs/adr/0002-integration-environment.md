# ADR 0002: Integration environment is a netns lab; Docker is the alternative

- Status: accepted (2026-09-19)
- Relates to: AGENTS.md 7.2

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
  `10.77.<id>.0/24` and `fd77:<id>::/64`. The harness itself lives at `.1`
  and can add aliases `.2`-`.9` for tap actors that must present distinct IPs.
- One network namespace per client actor, attached with a veth pair, with a
  v4 address, a v6 address, or both. No default route: actors can only reach
  the lab (rule 3). IPv6 is disabled with sysctl in v4-only namespaces.
- Processes enter a namespace through `sudo -n nsenter --net=... -S uid -G gid`
  and run as the unprivileged user, so files they write are ours and they can
  be signalled directly (`kill -9` scenarios).
- `iptables`/`ip6tables` INPUT accept rules are added for the bridge and
  removed on teardown; `testkit lab clean` removes anything stale.
- Packet capture uses `tcpdump` on the bridge (informational; never a gate).

Docker Compose remains a supported alternative for environments without sudo
(`xtask doctor` explains the seccomp requirement); the scenarios are written
against the `Lab`/`Actor` abstraction so a compose backend can be added
without touching them.

## Consequences

- `xtask it` requires passwordless sudo and iproute2; `xtask doctor` checks.
- Tests never depend on DNS. Where a scenario needs hostnames (dual-stack
  announce semantics), `ip netns exec` with `/etc/netns/<ns>/hosts` will be
  used, keeping the host's `/etc/hosts` untouched.
