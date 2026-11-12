# ADR 0036: Future Directions: WireGuard, mTLS Gateway, IPv4

## Status

Accepted

## Date

2026-11-09

## Context

The model (ADRs 0027, 0028) should leave room for more networks and credential types without building them now, and should record what is deliberately not planned.

## Decision

- **WireGuard is a network on an existing interface.** SocketGuard reads an existing wg interface's peers and does not run WireGuard itself. Each peer's allowed-ips map to a `wg_key` credential, key-verified on that interface.
- **mTLS only through an opt-in TLS gateway.** TLS 1.3 encrypts the client certificate, so nothing at the firewall can validate it passively; only terminating TLS works. A future per-address gateway would terminate mTLS, match a `tls_spki` credential and proxy to localhost. Only the credential type is reserved now.
- **No IPv4 per-app addresses.** IPv4 gets whole-host protection only (ADR 0026).
- **Out-of-process network plugins** (e.g. JSON over stdio, CNI-style) may later complement the in-tree `Network` trait (ADR 0037). The onion network itself is a planned phase, not future work.
- Also future: mDNS/DNS-SD for app names, dynamic DNS, and pflog capture of blocked attempts on macOS.

## Consequences

- Credentials are typed and extensible; adding `wg_key` or `tls_spki` needs no model change.
- Key-verified access outside Yggdrasil waits for WireGuard support or the gateway.
- On IPv4, services are reached on the host's own addresses, which are protected only in whole-host mode.
