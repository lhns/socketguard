# ADR 0024: Label Consistency and ACL Group Checkboxes in Socket Groups

## Status

Accepted

## Date

2026-03-15

## Context

After the badge consolidation work (ADR 0023), several label and feature inconsistencies remained:

1. **Badge format**: When a socket has "group" policy with an ACL group assigned, the badge showed `ula: Web Servers` — dropping the "group:" prefix and making it unclear that "Web Servers" refers to an ACL group rather than a policy name.

2. **Count label inconsistency**: ACL groups showed "N sockets" (should be "N members" since they contain member references), while socket groups showed "N members" (should be "N sockets" since they group sockets). Individual sockets showed no address count in the collapsed header, unlike socket groups which showed "N addrs".

3. **ACL group manage members**: When clicking "Manage Members" on an ACL group, checkboxes appeared next to BackendAddressNodes inside individual SocketFoldouts but NOT inside SocketGroupFoldouts. This meant users couldn't assign socket group addresses to ACL groups without first expanding individual sockets.

## Decision

### 1. Restore "group:" prefix in badge

Badge format changed from `ula: Web Servers` to `ula: group: Web Servers`, making it clear that "Web Servers" is an ACL group name.

### 2. Fix count labels

- ACL group header: "N sockets" → "N members" (they contain member socket references)
- Socket group header: "N members" → "N sockets" (they group sockets together)
- Individual socket header: added "N addrs" count to match socket group format

### 3. Thread ACL group management props through SocketGroupFoldout

Added `managingAclGroup` and `onToggleAclMember` props to SocketGroupFoldout, passed from AppNode. These are forwarded to BackendAddressNode in the "Shared Addresses & Policy" section, enabling ACL group member checkboxes on socket group addresses.

## Consequences

- Badge text is unambiguous — users can distinguish ACL group names from policy names
- Count labels are semantically correct and consistent across the tree
- ACL group management works uniformly across individual sockets and socket groups
- No new components or API changes required — purely UI prop threading and label fixes
