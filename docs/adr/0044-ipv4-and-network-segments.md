# ADR 0044: IPv4 and Network Segments on Protect-Host

## Status

Accepted. Amends ADR 0026 (IPv4 whole-host scopes return) and ADR 0028 (IPv4 credentials).

## Date

2026-11-10

## Context

Per-app addresses are IPv6 only (ADR 0036), so ADR 0026's amendment turned IPv4 whole-host scopes off until IPv4 could be granted. Meanwhile the UI suggested IPv4 peers, the CLI accepted them and the daemon rejected them. Separately, "allow everyone on the management VLAN" could only be expressed by listing addresses.

## Decision

- **IPv4 credentials:** `ip` credentials accept IPv4 addresses and CIDRs.
  - They apply on every protect-host interface that carries IPv4. A grant scoped to a network applies only if that network's interface is one of them.
  - The rule is `iif X, ip saddr {v4}, dport {the app's IPv4 ports}`, to the host's own addresses.
  - With this, protect-host scopes cover IPv4 again.
- **Address family:** the monitor records whether each listening port is v4, v6 or dual. This lives only on `App.ports`; a grant's `PortRef` stays `(port, proto)`.
- **Reach for IPv4:**
  - `IpOnly` where the credential applies.
  - `Unfiltered` ("open to everyone over IPv4") when the app listens on IPv4 and protect-host is off for that interface.
  - `NotReachable` when the app has no IPv4 listener.
- **Segments:**
  - A VLAN subinterface is a LAN network like any other. SocketGuard uses existing VLAN interfaces and never creates them.
  - "Everyone on <network>" is the existing Anyone subject on a network-scoped grant.
  - It is enforced as `iif X && saddr ∈ on-link prefixes of X`, because a router delivers other segments' traffic on the same interface. The on-link prefixes are the network's live IPv6 prefixes, `fe80::/10`, and the interface's IPv4 subnet when protect-host covers it.
  - It needs the usual Anyone confirmation, worded "Open to everyone on <network>?".
- **VLAN ids:** Linux lists them from netlink. Windows has no generic API for them and shows the adapter as a plain LAN interface.

## Consequences

- IPv4 LAN peers become useful, and an app listening on IPv4 shows honestly whether SocketGuard filters it.
- Segment grants follow prefix changes the way scopes do. The interface layer must report IPv4 subnets.
- A segment grant trusts whoever the switch puts on that VLAN, so frontends badge it "segment", not "verified".

## Implementation notes

- **IPv4 rules** have no destination address (`Dst::HostV4` in the desired ruleset): they match the port on any IPv4 address of the host, bound to the protected interface. Ids are `v4:<port>:<proto>:<grant>:<interface>:<app>`.
- **Anyone** (not scoped to a network) also gets an IPv4 rule on every protected interface that carries IPv4, so protect-host does not close IPv4 for an app opened to everyone. Anyone scoped to a LAN or Local network gets the interface's IPv4 subnet instead.
- **Address family** is stored per port (schema v5, `app_ports.family`, default `dual` for old rows). Unix `::` counts as dual-stack (IPV6_V6ONLY is not visible in /proc); Windows `::` as v6-only, merged with the IPv4 sockets of the same port.
- **Reach for an IPv4 credential** is computed per app and grant (`reach_for_app`): the listener family and the protected interfaces decide between `IpOnly`, `Unfiltered` and `NotReachable`.
