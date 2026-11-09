# ADR 0026: Secure-by-Default Protection Scope and Daemon-Stop Semantics

## Status

Accepted. Supersedes ADR 0004, and the startup and shutdown cleanup of ADR 0012.

## Date

2026-11-09

## Context

ADR 0004 closed only allocated (address, port) pairs inside an otherwise `policy accept` chain. An app bound to `[::]:8080` stayed reachable on the node's own Yggdrasil address and its global addresses. A closed socket lost its drop rule on the next poll while keeping its address, and socket-group addresses never got a block rule. ADR 0012 flushed all rules on start and stop, so the host was open whenever the daemon was not running.

## Decision

- **Default protected scope:**
  - every SocketGuard-allocated address, all ports;
  - the entire Yggdrasil interface, because the overlay is an untrusted network and protecting it is the project's promise.
- **Whole-host mode is opt-in.** "Protect this whole host" is an API setting (so both frontends get it), offered at first run. It covers all non-loopback inbound traffic, IPv6 and IPv4, on a chosen subset of interfaces. The setting stores the list; the default selection is every non-loopback interface that has a LAN network.
- **Inside a scope everything is denied** unless a grant allows it (ADR 0027). There are no per-address policies.
- **Always allowed:** `iif lo`; established/related; the ICMPv6 types needed for NDP, MLD and PMTU, plus rate-limited echo; DHCPv6 client replies (udp 547 to 546).
- **Link-local destinations are not exempt.** Inside a protected scope they are default-deny too; otherwise a wildcard bind stays reachable from the LAN via `fe80::`.
- **Lockout guard (daemon side):** enabling whole-host mode is refused if a remote-admin listener (sshd, RDP) has no grant, unless the request sets `force`. Both frontends show the check.
- **Closing the Yggdrasil interface on install is intended**: services exposed to the whole overlay should not stay exposed. Mitigation: `socketguard init` and the daemon's first start detect remote-admin listeners (sshd, RDP) and record an Activity entry plus a log warning; `init` offers to grant them to a peer. Established connections survive.
- **Daemon stop freezes state.** The firewall table/filters and the addresses stay, so services stay reachable for granted peers and closed for everyone else. A restart is not an outage: start-up replaces the ruleset atomically (ADR 0029) instead of flushing it.
- **Only `socketguard disable` or the uninstaller** removes the nftables table, the pf anchor, the WFP filters and the addresses.

## Consequences

- An app listening on all addresses is unreachable on the node's Yggdrasil, global and link-local addresses until granted.
- A stopped or crashed daemon fails closed. Without `disable` and the uninstaller, a user who stops the daemon could be locked out, so both are release blockers.
- Remote admin over Yggdrasil (e.g. sshd on the node's `200:` address) stops accepting new connections on install until granted; the user is warned instead of blocked, since the whole-host lockout guard does not apply here.
- LAN and IPv4 traffic to non-managed addresses stays open unless the user opts into whole-host mode. IPv4 never gets per-app addresses (ADR 0036).
## Amendment (2026-11-09)

Whole-host scopes cover IPv6 only for now. No grant can target an IPv4 address yet (there are no IPv4 locators and IPv4 credentials are rejected), so an IPv4 whole-host scope would cut off the host's IPv4 services with no way to re-allow them. IPv4 whole-host protection returns together with IPv4 grants.

## Amendment (2026-11-09): owned addresses are written ahead and denied until removed

An address could sit on an interface without deny rules: a failed removal was only logged while its row and managed-scope entry were dropped, a crash between the DB update and the removal left an orphan, and an address could be added under an old ruleset when the state for a new one could not be read.

- Schema v3 adds `owned_addresses(addr, interface, network_id, state, since)`, `state` being `active` or `retiring`. An address is inserted `active` before it is added to an interface, set `retiring` before it is taken off, and its row is deleted only after the removal is confirmed (the command succeeded, or the interface no longer holds it).
- The producer's managed scope is every address of an app plus every owned address, retiring ones included, so a retiring address stays denied until it is really gone.
- Every reconcile (and startup, after the first apply) sweeps: owned addresses that no app has are retiring and are removed, and failed removals are retried. `disable` retires all owned addresses and keeps the rows of those it could not remove; the disabled daemon keeps retrying.
- An address is added to an interface only if it is in the managed scope of the last ruleset that was applied successfully. This covers new, re-homed and split addresses, and a state or DB read error before the apply.
