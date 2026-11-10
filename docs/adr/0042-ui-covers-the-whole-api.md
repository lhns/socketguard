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

## Amendment (2026-11-10): two lists, one inspector, a read-only overview

The first build followed the decision above and came out incoherent: three tabs (Apps, Access, Peers & groups) that were partly views of each other, the same relation edited in five places with three ways of committing, and bulk work in different dialogs than single edits. The Simple/Advanced switch only chose a tab. This replaces the second and third points of the decision; coverage, Activity and error display stand.

- **Navigation:** Apps · Peers · Activity · Settings. No Access tab and no Simple/Advanced views.
- **List and inspector, used twice.** Apps ("what": tags, apps, system services) and Peers ("who": Anyone and "everyone on <network>", groups, peers) are the same screen: a selectable table, with an inspector beside it that shows the selection. One row gives its detail; several rows give the same sections for all of them, so bulk editing is not a separate UI. Tags and groups are rows of their list.
- **One place per operation.** Access is shown by one list in both directions (who can reach this, what this can reach) and added by one form in the inspector. Tags, groups and members are chosen in a search popover.
- **The access matrix is read-only.** Subjects can be added as columns to the Apps table to see who reaches what; a cell opens the inspector, where the change is made. Editing in the grid duplicated the inspector and needed its own staging.
- **One commit rule.** A change that alters who can reach something is shown first and needs one Apply; a change that alters nobody's reach, or only closes, applies at once. Modal dialogs are left for confirmations (open to anyone, deletions, turning SocketGuard off) and for secrets shown once.
