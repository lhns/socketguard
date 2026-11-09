# ADR 0033: Frontends: Shared Client, CLI First, UI as API Client

## Status

Accepted. Amends ADR 0010.

## Date

2026-11-09

## Context

The CLI covered only sockets, policy and backends. The CLI and the Tauri backend each built their own HTTP requests. The UI kept all state in `App.tsx` with manual refresh, and its TypeScript types were mirrored by hand from `api_types`, so drift went unnoticed.

## Decision

- **`crates/client`:** a typed async client plus an SSE stream over the local transport (ADR 0032), used by both the CLI and the Tauri backend. It propagates W3C trace context (ADR 0034).
- **The CLI (`socketguard`) is the primary frontend and covers the whole API**, with `--json` everywhere. A coverage test enumerates the router's routes and fails unless each has a client method and a CLI command.
- **The UI is a secondary client for everyday flows:** Apps, Peers, Activity and Settings. It talks to the API through the client crate in the Tauri backend and never shells out to the CLI, because CLI output is not a stable contract and the API is. Port split/merge, peer groups, export/apply and `init` stay CLI-only for now.
- **UI stack:** TanStack Query with its cache invalidated by SSE events; TypeScript types generated from `api_types` with `ts-rs`, replacing the hand-written ones in `api.ts`; the existing CSS, no component library.
- Granting to Anyone needs confirmation in both frontends (`--yes` in the CLI).
- ADR 0010's architecture stands (Tauri v2, React, separate daemon); its component list and `reqwest`-over-TCP calls are replaced.

## Consequences

- One request path to test; CLI and UI cannot disagree about the API.
- Anything the UI lacks is available in the CLI, so the UI can stay small.
- API changes surface as TypeScript compile errors instead of runtime bugs.
- The coverage test makes adding a route without a CLI command a CI failure.
