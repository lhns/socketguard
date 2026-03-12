# ADR-0005: SQLite for State Persistence

## Status

Accepted

## Date

2026-03-12

## Context

The daemon needs to persist:
- Detected sockets and their assigned IPv6 addresses
- ACL entries per socket
- Keypairs for the Yggdrasil backend
- Socket-to-address mappings that survive daemon restarts

Options considered:
1. **Flat files (JSON/TOML)**: Simple but poor for concurrent access and querying.
2. **SQLite**: Embedded, zero-config, ACID-compliant, single-file database. Well-suited for local daemon state.
3. **External database (PostgreSQL)**: Overkill for a local daemon with a single writer.

## Decision

Use **SQLite** via the `sqlx` crate with async support (`runtime-tokio` feature).

### Schema

Three tables:

```sql
sockets (
    id TEXT PRIMARY KEY,           -- hash of pid+port+protocol
    pid INTEGER, process_name TEXT,
    port INTEGER, protocol TEXT,
    assigned_ipv6 TEXT,
    backend TEXT,                  -- ula/yggdrasil
    policy TEXT DEFAULT 'closed',  -- open/closed/managed
    keypair_id TEXT,
    first_seen TEXT, last_seen TEXT
)

acl_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    socket_id TEXT REFERENCES sockets(id) ON DELETE CASCADE,
    allowed_ip TEXT,
    label TEXT,
    created_at TEXT
)

keypairs (
    id TEXT PRIMARY KEY,
    public_key BLOB,
    private_key_encrypted BLOB,
    derived_ipv6 TEXT,
    created_at TEXT
)
```

- Socket IDs are deterministic hashes of `(pid, port, protocol)` so the same socket maps to the same row across detection cycles.
- `last_seen` is updated each reconciliation cycle; stale sockets (not seen for 3 cycles) are cleaned up.
- ACL entries cascade-delete when their socket is removed.
- Timestamps use RFC 3339 strings for portability.

### Database Location

Configured via `DaemonConfig.db_path`, defaults to `socketguard.db` in the working directory.

## Consequences

- Zero external dependencies — no database server to install or manage.
- Single-file database is easy to back up, move, or reset.
- `sqlx` provides compile-time-checked queries (when using macros) and async operation.
- Schema migrations are handled at startup via `Database::migrate()`.
- The 5-connection pool is sufficient for the daemon's access pattern (single writer, few readers from API).
- Private keys in the `keypairs` table are labeled `_encrypted` but encryption at rest is not yet implemented — this is a future enhancement.
