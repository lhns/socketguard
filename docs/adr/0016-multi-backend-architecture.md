# ADR 0016: Multi-Backend Architecture

## Status

Superseded by ADR 0027

## Context

SocketGuard originally had a 1:1 model — one backend, one IPv6 address per socket. Users need each socket to have multiple addresses from multiple backends simultaneously (e.g., a ULA address for local access and a SLAAC address for LAN routability).

Some backends (SLAAC, DHCPv6) should support multiple instances (e.g., SLAAC on Ethernet + SLAAC on Wi-Fi), while singletons (ULA, Yggdrasil) are limited to one instance each.

## Decision

### Data Model

- **New `SocketAddress` struct**: Represents one address assigned to a socket from a specific backend instance. Contains `backend_id`, `backend_type`, `address`, `interface`, `prefix_len`, and optional `keypair_id`.

- **Modified `ManagedSocket`**: Replaces `assigned_ipv6`, `backend`, and `keypair_id` fields with `addresses: Vec<SocketAddress>`. Provides `primary_address()`, `assigned_ipv6()`, and `backend()` convenience methods for backwards compatibility.

- **New `socket_addresses` DB table**: Stores address-per-backend-per-socket with PK `(socket_id, backend_id)`. References `sockets(id)` with `ON DELETE CASCADE`.

- **`BackendInstanceConfig`**: Wraps `BackendConfig` with a stable `id` field. Auto-generated as `{type}` for singletons or `{type}-{interface}` for multi-instance, overridable via config.

### Config

- `DaemonConfig.backends: Vec<BackendInstanceConfig>` replaces `backend: BackendConfig`.
- Backwards-compatible deserialization handles:
  - Legacy `"backend": "ula"` string format
  - Object `"backend": { "type": "slaac", ... }` format
  - New `"backends": [...]` array format
- Validation rejects duplicate IDs and multiple singleton instances.

### Engine

- `Engine.backends: HashMap<String, ActiveBackend>` replaces single `backend`.
- Reconciliation allocates addresses from all active backends for new sockets.
- Config change detection handles added/removed backend instances dynamically.
- `add_backend_instance()` and `remove_backend_instance()` manage runtime changes.

### API

- `POST /api/backends` and `DELETE /api/backends/{id}` for runtime backend CRUD.
- `GET /api/backends` returns available types with singleton flags + active instances.
- Socket responses include full `addresses` array.
- Config responses use `backends` array.

### Default Behavior

When a backend instance is activated, every socket automatically gets an address from it. No per-socket opt-in needed.

### Migration

Old `assigned_ipv6`/`backend`/`keypair_id` columns are migrated from `sockets` to `socket_addresses`, then dropped. No rollback path — clean break.

## Consequences

- Sockets can be reachable from multiple networks simultaneously.
- ACL rules apply to all addresses for a socket uniformly.
- Future "advanced mode" can add per-socket backend selection.
- Database migration is one-way; cannot downgrade to pre-0016 schema.
