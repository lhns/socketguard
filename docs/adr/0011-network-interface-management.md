# ADR-0011: Network Interface IPv6 Management

## Status

Accepted

Superseded in part by ADR 0016 and ADR 0027 (interfaces belong to networks; there is no single interface setting) and ADR 0030 (Windows adds addresses through the IP Helper API).

## Date

2026-03-12

## Context

Each detected socket is assigned a unique IPv6 address. This address must be added to a network interface so the OS can receive traffic on it. When a socket goes stale, the address must be removed.

Decisions needed:
1. Which interface to use?
2. How to add/remove addresses?
3. How to handle errors (address already exists, interface not found)?

## Decision

### Interface Selection

The target interface is configurable via `DaemonConfig.interface`. Defaults:
- **Linux**: `lo` (loopback) — safe for testing, no external traffic
- **macOS**: `lo0` (loopback)
- **Windows**: `Loopback Pseudo-Interface 1`

For production use with Yggdrasil, the user should configure this to the Yggdrasil TUN interface (typically `tun0` on Linux, `utun` on macOS, or the Yggdrasil TAP adapter on Windows).

### Address Management

Addresses are added with a `/128` prefix length (single host address) using platform CLI tools:

| Platform | Add | Remove |
|----------|-----|--------|
| Linux | `ip addr add <addr>/128 dev <iface>` | `ip addr del <addr>/128 dev <iface>` |
| macOS | `ifconfig <iface> inet6 <addr> prefixlen 128 alias` | `ifconfig <iface> inet6 <addr> -alias` |
| Windows | `netsh interface ipv6 add address interface=<iface> address=<addr>/128` | `netsh interface ipv6 delete address interface=<iface> address=<addr>` |

### Error Handling

- **Address already exists**: Treated as success (idempotent). Linux returns "RTNETLINK answers: File exists", macOS returns "already exists", Windows is silent.
- **Interface not found**: Returns an error — the user must configure the correct interface.
- **Permission denied**: Returns an error — the daemon needs elevated privileges.

## Consequences

- The daemon requires root/admin privileges to manage network interface addresses.
- Using the loopback interface by default is safe for development but limits production usefulness — users must configure the right interface.
- `/128` prefix ensures each address is treated as a host address, not a subnet.
- Idempotent add/remove operations make the reconciliation loop safe to run repeatedly.
- Stale address cleanup prevents IPv6 address accumulation on the interface.
