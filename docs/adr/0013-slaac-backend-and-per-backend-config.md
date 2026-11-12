# ADR-0013: SLAAC Backend and Per-Backend Configuration

## Status

Accepted. Note: the legacy single-backend string form (`"backend": "ula"`) was removed in the redesign; use the `backends` list.

## Context

SocketGuard assigns per-socket IPv6 addresses, but the existing backends (ULA, Yggdrasil) have limited reachability:

- **ULA** (`fd00::/8`): Local-only, addresses are not routable beyond the machine.
- **Yggdrasil** (`200::/7`): Routable on the Yggdrasil overlay network, but requires Yggdrasil infrastructure.

Users need addresses that are routable on the local network (LAN) without requiring overlay networks. IPv6 SLAAC (Stateless Address Autoconfiguration) provides this: routers advertise a /64 prefix, and any host on the link can generate addresses within that prefix.

Additionally, each backend has different configuration requirements (ULA needs no interface config, Yggdrasil needs a TUN interface, SLAAC needs a physical NIC and optionally a prefix), but the config had a single flat `backend` + `interface` pair.

## Decision

### 1. Add SLAAC backend

A new `slaac` backend that:
- Discovers the /64 prefix from an existing SLAAC-assigned address on the specified interface, or accepts an explicit prefix.
- Generates random 64-bit interface IDs within that prefix (2^64 address space).
- Checks for address collisions by querying existing addresses on the interface before allocation.
- Adds addresses with /128 prefix length (single host), same as other backends.

### 2. Refactor to per-backend configuration

Replace the flat `backend` + `interface` fields with a tagged union `BackendConfig`:

```json
{"backend": {"type": "slaac", "interface": "Ethernet", "prefix": "2001:db8::/64"}}
{"backend": {"type": "ula", "interface": "Loopback Pseudo-Interface 1"}}
{"backend": {"type": "yggdrasil", "interface": "tun0"}}
```

The legacy flat format (`"backend": "ula", "interface": "lo"`) is still accepted via custom deserialization for backwards compatibility.

### 3. Collision avoidance

Before assigning a generated address, the backend queries existing addresses on the target interface (via `netsh`/`ip`/`ifconfig`). If the address is already in use, it retries with a new random interface ID (up to 10 attempts). Given the 2^64 address space, collisions are astronomically unlikely, but the check is cheap insurance.

### 4. Garbage collection

Stale socket cleanup (already implemented in the reconciliation loop) removes IPv6 addresses from the interface when sockets are no longer detected. This applies equally to SLAAC addresses — they are removed via the same `netsh interface ipv6 delete address` / `ip addr del` mechanism used for ULA and Yggdrasil addresses.

## Consequences

- SLAAC addresses are routable on the LAN (and globally if the prefix is a GUA).
- The firewall ACLs now protect real network-accessible services.
- Per-backend config prevents invalid states (e.g., SLAAC without an interface).
- Backend changes at runtime trigger address migration between interfaces.
- Existing config files with the flat format continue to work.
