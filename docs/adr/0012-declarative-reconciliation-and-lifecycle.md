# ADR-0012: Declarative Reconciliation and Lifecycle Management

## Status

Accepted

## Date

2026-03-12

## Context

The daemon had several lifecycle gaps:

1. **No graceful shutdown**: On SIGTERM/Ctrl+C, firewall rules and IPv6 addresses were orphaned on the system.
2. **No startup cleanup**: If the daemon crashed, stale firewall rules from the previous session remained and could conflict with new rules.
3. **Config changes didn't propagate**: `PUT /api/config` updated the in-memory config but the engine held its own `Box<dyn Ipv6Backend>` created at startup. Changing the backend or interface had no effect until restart.
4. **Imperative firewall management**: Firewall rules were only applied when a socket was first detected. If a rule was manually deleted or the daemon crashed mid-cycle, the rule was never re-created.

## Decision

### Declarative reconciliation

Each reconciliation cycle now ensures the OS state matches the desired state in the DB:

- For each known socket: verify the firewall rules match the socket's policy and ACL
- For each stale socket: remove firewall rules and IPv6 addresses
- This is idempotent — running the same cycle twice produces the same result

This follows the controller pattern: desired state (DB) vs current state (OS), with the reconciliation loop converging them.

### Startup reconciliation

On startup, before the first poll cycle:
1. `cleanup_all_rules()` removes all SocketGuard-managed firewall rules (by naming pattern)
2. For each socket in the DB, re-add the IPv6 address to the interface and re-apply firewall rules

This handles the crash recovery case: stale rules from a previous session are wiped and re-created from the DB source of truth.

### Graceful shutdown

The daemon handles SIGTERM (Unix) and Ctrl+C (all platforms) via `tokio::signal`:
1. `axum::serve` shuts down gracefully (finishes in-flight requests)
2. A `watch` channel signals the reconciliation loop to stop
3. `shutdown_cleanup()` removes all firewall rules and IPv6 addresses

### Config change propagation

The engine tracks its current `backend` and `interface`. Each reconciliation cycle compares against the live config:
- **Backend change**: The engine recreates its `Box<dyn Ipv6Backend>`. Existing sockets keep their addresses (you can't retroactively change a socket's IPv6). New sockets use the new backend.
- **Interface change**: All managed IPv6 addresses are migrated from the old interface to the new one (add to new, remove from old).

### Firewall cleanup methods

Each firewall implementation got a `cleanup_all_rules()` method:
- **nftables**: `nft flush table ip6 socketguard && nft delete table ip6 socketguard`
- **pf**: `pfctl -a socketguard -F rules` (plus sub-anchors)
- **wfp**: Scan all rules, delete those matching `SocketGuard_*`

## Consequences

- Daemon crashes no longer leave orphaned firewall rules or IPv6 addresses
- Clean stop via Ctrl+C or SIGTERM properly undoes all system changes
- Config changes via API take effect on the next reconciliation cycle (within `poll_interval_secs`)
- Firewall rules are self-healing: if a rule is manually deleted, the next cycle re-creates it
- The `Engine` is now behind a `RwLock` since `reconcile()` needs `&mut self` for config change detection
