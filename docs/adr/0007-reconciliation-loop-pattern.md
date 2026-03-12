# ADR-0007: Reconciliation Loop Pattern

## Status

Accepted

## Date

2026-03-12

## Context

The daemon must continuously detect new sockets, assign IPv6 addresses, apply firewall rules, and clean up stale entries. Two approaches:

1. **Event-driven**: Use OS-specific notifications (netlink on Linux, ETW on Windows) to react to socket creation/destruction in real time.
2. **Polling with reconciliation**: Periodically scan for listening sockets and converge state.

## Decision

Use a **polling reconciliation loop** running in a background tokio task. The loop runs every `poll_interval_secs` (default: 5 seconds).

### Reconciliation Cycle

Each cycle performs three phases:

**1. Detect & Assign**
- Call `SocketMonitor::list_listening_sockets()` to get current OS state.
- For each detected socket, compute a deterministic ID from `(pid, port, protocol)`.
- If the socket ID exists in the database, update `last_seen`.
- If new: allocate an IPv6 via the configured backend, add it to the network interface, apply a default "closed" firewall rule, and insert into the database.

**2. Enforce**
- ACL/policy changes made via the API trigger immediate firewall updates (not deferred to the loop).
- The loop ensures convergence if an out-of-band change occurs.

**3. Cleanup**
- Sockets not seen for 3 consecutive poll intervals are considered stale.
- Stale sockets have their firewall rules removed, IPv6 addresses removed from the interface, and database rows deleted.

### Why Not Event-Driven

- Event APIs differ significantly across platforms (netlink, ETW, kqueue) — polling with `list_listening_sockets()` is simpler and already platform-abstracted.
- A 5-second poll interval is sufficient for the use case — socket creation is not a high-frequency event.
- Reconciliation is inherently self-healing: if state drifts (manual firewall change, interface reset), the next cycle corrects it.

## Consequences

- Simple, predictable behavior — easy to reason about and debug.
- Self-healing: external changes are automatically corrected within one poll interval.
- Slight latency (up to `poll_interval_secs`) between a socket appearing and its IPv6 being assigned.
- CPU cost is minimal — listing sockets and diffing against a small SQLite table is fast.
- The poll interval is configurable via the API and config file.
