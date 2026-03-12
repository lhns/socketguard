# ADR-0009: Socket Identity Scheme

## Status

Accepted (revised)

## Date

2026-03-12

## Context

The daemon needs a stable identifier for each detected listening socket to track it across reconciliation cycles, store its ACL, and reference it in API calls.

The original design used `hash(pid, port, protocol)`. This broke on process restarts: a new PID meant a new socket ID, a new IPv6 address, and orphaned ACLs. Services managed by systemd/launchd that restart frequently became unusable.

Candidate identity schemes:

1. **PID + port + protocol**: Simple but changes on every process restart. **Rejected.**
2. **Process name + port + protocol**: Stable across restarts. If `nginx` restarts on port 80, it keeps its IPv6 and ACLs.
3. **Assigned IPv6 address**: Unique but circular — ID is needed before address assignment.
4. **UUID**: Not deterministic — can't detect "same socket" across detection cycles.

## Decision

Use a **deterministic hash of (process_name, port, protocol)** as the socket ID.

```rust
pub fn socket_id(process_name: &str, port: u16, protocol: Protocol) -> String {
    let mut hasher = DefaultHasher::new();
    process_name.hash(&mut hasher);
    port.hash(&mut hasher);
    protocol.to_string().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
```

### PID as metadata, not identity

The PID is stored in `ManagedSocket.pid` and updated on each reconciliation cycle. When a process restarts:
1. The new process opens the same port with the same name
2. `socket_id()` produces the same hash
3. The existing database row is matched
4. The PID field is updated, but the IPv6 address, ACLs, and policy are preserved

The `upsert_socket` SQL uses `ON CONFLICT(id) DO UPDATE SET pid = excluded.pid` to handle this.

### Additional metadata for disambiguation

`ListeningSocket` includes optional fields for richer process identification:
- `exe_path: Option<String>` — full path to the executable (resolved on Linux via `/proc/{pid}/exe`)
- `cmdline: Option<String>` — command line arguments (resolved on Linux via `/proc/{pid}/cmdline`)

These are stored in the database and shown in the CLI/UI for human identification, but are **not** part of the identity hash. This is intentional: the same binary invoked with different arguments on the same port should be treated as the same service.

### Edge cases

- **Multiple instances of the same binary on the same port**: Not possible — only one process can bind a port (except with `SO_REUSEPORT`, where all instances serve the same port and should share the same ACL).
- **Different binaries with the same process name on the same port**: Extremely unlikely. If it happens, the `exe_path` and `cmdline` metadata help the user distinguish them. The ACLs would be shared, which is a reasonable default since they're serving the same port.
- **Process renamed at runtime**: The process name at detection time is what matters. If the name changes, the old socket entry becomes stale and is cleaned up.

## Consequences

- Process restarts preserve IPv6 addresses and ACLs — the primary improvement.
- Services behind process managers (systemd, launchd, Windows services) work correctly.
- The CLI displays truncated IDs (first 8 chars) for readability.
- Old databases with PID-based IDs will have stale entries cleaned up automatically (not seen for 3 poll cycles → deleted).
- Future enhancement: allow manual "pinning" of a specific IPv6 address to a port number, regardless of process name, for maximum stability.
