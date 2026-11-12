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

## Amendment (2026-11-11): rows, a Reserved tab, one way to tag and to grant

Follows ADR 0047.

- **Navigation:** Apps, Reserved, Peers, Activity, Settings.
- **Rows.** Inside an app the inspector has one "Ports" section: "All ports", each port, each attached port group. Every row has the same parts: tags, who can reach it, "Add access", its address. A grant is listed once, on the row it names.
- **Port groups** are a section of the Apps list, like tags, with their own inspector.
- **Reserved** looks like Apps: one entry per reservation, with its own "All ports", its bound rows, its address per network and its port conflicts. A bound row's access is the same grant as under its app.
- **Adding access** offers "All ports", each port and each port group side by side, with nothing preselected.
- **Tags and groups** are added from a "+" pill after the pills, the same on every row.
- **Peers** need no name; pasted values become one peer each, optionally in a new group.
- **Tor inside a reservation:** a grant on a single bound row is shown as not reachable on Tor before it is made.
- The address mode setting, split and merge are gone from the UI.

## Amendment (2026-11-11): one confirmation, not a review and then a confirmation

Replaces the commit rule of the earlier amendment ("show first if reach changes", with a dialog only for Anyone). In use it meant three steps: submit the form, apply the inline review, confirm the dialog.

- An edit that gives nobody new access applies at once; one that only closes gets Undo, as before.
- An edit that gives someone access goes from the form straight to one confirmation dialog. The dialog shows what the daemon's dry run says would change: each grant with its reach per network and any note (for example "not reachable on Tor"). There is no inline review step.
- A change that opens something to Anyone uses the same dialog with a warning and a confirm button that names what it opens. The daemon still requires its confirmation flag.
- All edits use this through the one commit helper: access, tags, peer groups, port groups, reserved addresses, transfer.
