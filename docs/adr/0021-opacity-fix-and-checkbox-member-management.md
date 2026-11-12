# ADR 0021: Opacity Fix and Checkbox-Based Socket Group Member Management

## Status

Superseded by ADR 0027

## Date

2026-03-15

## Context

Two UI issues needed resolution:

1. **Opacity cascade problem**: The `.address-inactive` class applied `opacity: 0.5` to a container div, creating a new stacking context that dimmed all descendants — including policy toggles, ACL forms, and ConfirmDialog modals (even at z-index 999). This made interactive controls inside inactive addresses hard to use.

2. **Redundant member management UI**: Socket group foldouts displayed an inline list of member sockets with add/remove buttons, plus a second list of "addable" sockets. This was redundant with the sibling SocketFoldout nodes already visible in the tree, and created a cluttered UI.

Additionally, PID was displayed at the app level, but the same app can have multiple instances with different PIDs, making per-socket PID display more accurate.

## Decision

### Opacity fix

- Renamed `.address-inactive` to `.address-inactive-label` and applied it only to the collapsed header line (the clickable row showing backend_id, address, and policy badge), not to the container div.
- In `BackendAddressNode.tsx`: moved the class from the outer `tree-l3` div to the header div.
- In `SocketDetail.tsx`: moved the class from the `card` div to the address header row.
- The expanded body (policy toggle, ACL form, ACL table, ConfirmDialog) always renders at full opacity.

### Checkbox-based member management

Replaced the inline member list with a "Manage Members" toggle that shows checkboxes on sibling SocketFoldout nodes:

- **AppNode** holds `managingGroupId` state and derives the managing group from `appSocketGroups`.
- **SocketGroupFoldout** receives `isManaging` and `onToggleManage` props. Shows a "Manage Members" / "Done" button with a member count. Removed `addableSockets`, `handleAddSocket`, `handleRemoveSocket` — no longer needed.
- **SocketFoldout** receives optional `managingGroup` (groupId + members array) and `onToggleMember` callback. When `managingGroup` is set, a checkbox appears before the expand arrow. Each toggle fires an immediate API call (add/remove) followed by a refresh.
- A subtle highlight (`.socket-group-managing`) is applied to the SocketGroupFoldout header when managing.

### PID placement

- Moved PID display from the app-level info section to each SocketFoldout header line, since the same app can have multiple PIDs.

## Consequences

### Positive

- ConfirmDialog modals on inactive addresses render at full opacity — no longer dimmed.
- Policy toggles and ACL forms inside inactive addresses are fully visible and usable.
- Member management is contextual — checkboxes appear on the actual socket nodes instead of a redundant list.
- Fewer API calls needed — toggling a checkbox is a single add/remove call instead of navigating a separate list.
- PID is shown where it's most accurate (per-socket), supporting multi-instance apps.

### Negative

- Users must click "Manage Members" to enter/exit manage mode — one extra click compared to the always-visible add/remove buttons.
- Checkboxes are only visible on sibling SocketFoldout nodes within the same AppNode, which is the correct scope since socket groups are per-app.
