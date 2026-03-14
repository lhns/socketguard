# ADR 0017: Per-Backend Policy and ACL with Disabled Mode

## Status

Accepted

## Context

ADR 0016 introduced multi-backend architecture where each socket gets addresses from all active backends. However, policy (open/closed) and ACL (allowed source IPs) are applied uniformly across all backends for a socket. Users need finer control:

- A socket might be open on ULA (local-only) but closed with ACL on SLAAC (LAN-routable).
- Some backends should be disabled entirely for a socket — no address allocated, no firewall rules.
- The current two-state policy model (open/closed) lacks a way to opt a socket out of a backend.

## Decision

### New Policy: Disabled

Add a third policy variant `Disabled` alongside `Open` and `Closed`:

- **Disabled**: No IPv6 address is assigned or maintained for this socket+backend. The address is removed from the OS interface and any firewall rules are cleaned up. The `socket_addresses` row is deleted.
- **Closed** (default): Address is assigned, firewall blocks all traffic except ACL-allowed source IPs.
- **Open**: Address is assigned, firewall allows all incoming traffic.

### Policy Moves to SocketAddress

Policy is no longer socket-level. Each `SocketAddress` carries its own `policy` field. The socket-level `ManagedSocket.policy` field becomes `default_policy` — used as the initial policy when a new backend instance is added.

### ACL Scoped to Backend

Each `AclEntry` gains a `backend_id` field. ACL entries are scoped to a specific `(socket_id, backend_id)` pair. When policy is "closed", only ACL entries for that backend are consulted.

### DB Schema Changes

**`socket_addresses` table** — add `policy TEXT NOT NULL DEFAULT 'closed'`:

```sql
ALTER TABLE socket_addresses ADD COLUMN policy TEXT NOT NULL DEFAULT 'closed';
UPDATE socket_addresses SET policy = (
    SELECT policy FROM sockets WHERE sockets.id = socket_addresses.socket_id
);
```

**`acl_entries` table** — add `backend_id TEXT NOT NULL`. Recreate table (SQLite <3.35 compat) and duplicate existing entries to each backend:

```sql
ALTER TABLE acl_entries RENAME TO acl_entries_old;
CREATE TABLE acl_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    socket_id TEXT NOT NULL,
    backend_id TEXT NOT NULL,
    allowed_ip TEXT NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (socket_id, backend_id) REFERENCES socket_addresses(socket_id, backend_id) ON DELETE CASCADE
);
INSERT INTO acl_entries (socket_id, backend_id, allowed_ip, label, created_at)
    SELECT ao.socket_id, sa.backend_id, ao.allowed_ip, ao.label, ao.created_at
    FROM acl_entries_old ao
    JOIN socket_addresses sa ON ao.socket_id = sa.socket_id;
DROP TABLE acl_entries_old;
```

**`sockets.policy`** — renamed semantically to "default_policy" (column name unchanged to avoid table recreation). New backend addresses inherit this value.

### API Changes

**New per-backend routes:**
- `PUT /api/sockets/{id}/backends/{backend_id}/policy` — set policy for one address
- `POST /api/sockets/{id}/backends/{backend_id}/acl/allow` — add ACL entry for one backend
- `DELETE /api/sockets/{id}/backends/{backend_id}/acl/{entry_id}` — remove ACL entry

**Existing routes become fan-out** (apply to all backends):
- `PUT /api/sockets/{id}/policy` — sets policy on all backends
- `POST /api/sockets/{id}/acl/allow` — adds ACL entry to all backends
- `DELETE /api/sockets/{id}/acl/{entry_id}` — deletes ACL entry by ID (already globally unique)

**Response changes:**
- `SocketAddress` gains `policy: string` field.
- `AclEntry` gains `backend_id: string` field.
- `SocketDetailResponse.acl` returns all ACL entries across all backends (each tagged with `backend_id`).

### Engine Behavior

- **Reconciliation**: When a new socket is detected, each backend address is created with `policy = default_policy` (from `sockets.policy`).
- **Disabled handling**: During reconciliation, if an address has `policy = disabled`, it is skipped (no address allocation). The stale cleanup logic naturally removes the OS address and firewall rules.
- **Disabling an existing address**: When policy changes to "disabled", the engine removes the IPv6 address from the OS interface and cleans up firewall rules. The `socket_addresses` row is deleted.
- **Re-enabling**: When policy changes from "disabled" to "closed"/"open", the engine allocates a new address from the backend.

### UI Changes

**SocketDetail.tsx**: The socket-level policy card is replaced with per-address controls. Each address row becomes expandable, showing:
- Policy toggle (disabled / closed / open)
- ACL entries and add form (visible when closed)

**SocketList.tsx**: Policy column shows a summary — if all addresses share the same policy, show it; otherwise show "mixed".

## Consequences

- Full per-backend control: different security postures per network.
- Disabled mode allows opting out of specific backends without removing the backend globally.
- ACL entries are duplicated during migration (one copy per backend), which is correct — each backend starts with the same access list.
- Legacy API routes continue working via fan-out, ensuring Tauri bridge backward compatibility during transition.
- Database migration is one-way; cannot downgrade to pre-0017 schema.
- The `allow_all` and `block_all` firewall traits are unchanged — they already operate per-address.

**Note**: `Policy::Disabled` was superseded by ADR 0018's closed+no-ACL=inactive pattern. The `Group` policy variant replaces the disabled slot.
