# ADR 0042: The UI Covers the Whole API

## Status

Accepted. Supersedes the UI-scope clause of ADR 0033 (the shared client, CLI coverage and UI stack stand).

## Date

2026-11-10

## Context

ADR 0033 kept the UI to everyday flows and left the rest to the CLI. The first live session showed the cost: no group or network management, no split/merge, process filter, address mode, export/apply or per-network grants, one port and one subject per grant, and a peer had to be created on another page first. The result read as fewer features rather than a better set, and bulk administration was impractical.

## Decision

- The UI covers every API operation. The route-coverage test checks route → client method → CLI command → Tauri command; a pinned allowlist names what is deliberately CLI-only (`completions`, `watch`).
- Two views over the same data and the same grant editor: **Simple** (apps list with multi-select bulk actions and a per-port detail table) and **Advanced** (an access matrix of apps/ports/tags against peers, groups, Anyone and "everyone on <network>", with a network selector and staged changes applied as one batch, ADR 0045).
- One grant editor for one or many apps, ports or tags: several ports, several subjects, optional networks, inline peer creation from a pasted credential, a dry-run reach preview.
- Activity is a log only; decisions are made in Apps. "Disable enforcement" is presented as "Turn SocketGuard off" with its effect spelled out.
- Daemon errors are shown at the field they concern; the 202 `enforcement: pending` notice is shown.

## Consequences

- The UI grows: more pages, a matrix component, more Tauri commands. The coverage test keeps it from drifting behind the API.
- Bulk work no longer needs the CLI.
