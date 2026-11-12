# ADR 0014: SSE Push Notifications and Native Socket Detection

## Status

Accepted

The event names are history: events are per kind of object (`apps_changed`, `peers_changed`, …), see `docs/api.md`. Push over server-sent events and native detection stand.

## Date

2026-03-13

## Context

The GUI polled the daemon REST API every N seconds to detect socket changes, and the daemon polled `netstat -ano` as a subprocess to detect new listening sockets. Both were wasteful:

1. **GUI polling** created unnecessary HTTP traffic and delayed updates (up to `poll_interval_secs`).
2. **`netstat -ano` subprocess** was slow (~50ms per invocation), spawned a new process each cycle, and required text parsing of its output.
3. **`poll_interval_secs` in the GUI** was a confusing user-facing config option — the user shouldn't need to tune daemon internals.

Research confirmed that Windows has **no user-mode event-based API** for detecting new listening sockets. Polling for socket detection is unavoidable, but we can make it faster and hide it from the user.

## Decision

### 1. Replace GUI polling with Server-Sent Events (SSE)

The daemon exposes `GET /api/events` as an SSE endpoint. The GUI connects once and receives push notifications when state changes. Two event types exist:

- `sockets_changed` — fired after reconciliation detects new/stale sockets, or after API mutations (ACL changes, policy changes)
- `config_changed` — fired after config updates

These are **opaque invalidation signals**: the GUI re-fetches via REST upon receiving them, keeping the data flow simple and the SSE payload minimal.

The Tauri backend maintains a persistent SSE connection with auto-reconnect (3s backoff). It translates SSE events into Tauri app events that React components subscribe to via `@tauri-apps/api/event`.

### 2. Replace `netstat -ano` with native Windows API

`GetExtendedTcpTable` and `GetExtendedUdpTable` replace the `netstat` subprocess. Benefits:

- ~100x faster (in-process syscall vs process spawn + text parsing)
- No string parsing — structured data directly from the kernel
- Queries both IPv4 and IPv6 for TCP and UDP listeners

### 3. Hide poll interval from GUI, set 2s default

`poll_interval_secs` is removed from the GUI Settings page and from the TypeScript types. It remains in the Rust `DaemonConfig` for CLI/advanced users. The default is reduced from 5s to 2s since native API calls are nearly free.

## Consequences

**Positive:**
- GUI updates are near-instant for user-initiated changes (SSE push)
- New sockets appear within 2s (native polling) instead of requiring GUI polling alignment
- Lower CPU usage: no subprocess overhead, no unnecessary HTTP polls
- Simpler GUI code: event subscription replaces polling timer chains
- Settings page is cleaner without the poll interval control

**Negative:**
- SSE connection must be maintained (reconnect logic needed)
- Daemon now has a broadcast channel in AppState (minor memory overhead)
- Native Windows API code uses `unsafe` blocks (mitigated by well-known two-call buffer pattern)
