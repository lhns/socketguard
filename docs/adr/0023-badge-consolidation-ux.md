# ADR 0023: Badge Consolidation and UX Improvements

## Status

Superseded by ADR 0027

## Date

2026-03-15

## Context

The SocketFoldout collapsed header showed redundant information for sockets with "group" policy: a per-backend policy badge like `[● ula: group]` AND a separate group reference tag `[group: Web Servers]`. Both convey the same thing — the socket belongs to an ACL group.

Additionally, several minor UX gaps existed:
- No visual indication of inactive backend addresses (closed + no ACL rules) without expanding
- No way to see ACL entry count without expanding a backend address node
- No warning state for the edge case where a socket has "group" policy but no ACL group assigned

## Decision

### 1. Merge policy badge and group name

When a backend address has `group` policy and belongs to an ACL group, the badge now shows the group name inline: `● ula: Web Servers` (styled as `badge-group`). The separate `.group-ref` tag is removed.

Non-group policies remain unchanged: `● ula: closed`, `● ula: open`.

### 2. Inactive label on backend addresses

Backend addresses that are closed with no ACL entries now show `(inactive)` text next to the IPv6 address in the collapsed header, rather than dimming the entire row.

### 3. ACL entry count in collapsed header

When a backend address has `closed` policy with ACL entries, the collapsed header shows `N rules` to indicate entries exist without requiring expansion.

### 4. Warning badge for unassigned group

If a backend address has `group` policy but no ACL group is assigned, the badge shows `● ula: group (unassigned)` with a yellow warning style (`badge-warning`). This is a defensive measure — in practice, selecting group policy auto-assigns an ACL group, and deleting an ACL group reverts members to closed.

## Consequences

- Collapsed headers are more information-dense and less redundant
- Users can scan the tree to identify inactive addresses and rule counts without expanding
- The warning state provides a visual safety net for an unlikely but possible error condition
- New CSS class `.badge-warning` added for yellow warning badges
