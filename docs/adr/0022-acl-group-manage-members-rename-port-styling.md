# ADR 0022: ACL Group Manage Members, Rename Groups, Port/Protocol Styling

## Status
Accepted

## Date
2026-03-15

## Context

Three UX improvements were needed:

1. **ACL group member management** — There was no way to add sockets to ACL groups via the same intuitive checkbox pattern used for socket groups. Users had to manually set each socket's policy to "group" and assign it to an ACL group per-backend.

2. **Group renaming** — ACL groups had backend API support for renaming (`PUT /api/acl-groups/{id}`) but no frontend UI. Socket groups had no rename support at all (no backend endpoint, no UI).

3. **Port/protocol display** — Port and protocol were shown as separate elements (`80` `/tcp`) with protocol in a muted secondary style. Since port/protocol together form the socket identity (like `80/tcp`), they should be displayed as a single unit.

## Decision

### ACL Group "Manage Members" checkbox workflow

- AppTree holds `managingAclGroupId` state at the top level (same pattern as socket group managing)
- AclGroupNode shows "Manage Members" / "Done" button in its members section
- When managing, all BackendAddressNode headers across all apps show a checkbox
- Checking a backend address calls `addToAclGroup` (idempotent) then `setBackendPolicy(..., "group")`
- Unchecking calls `setBackendPolicy(..., "closed")` as a safe default (we don't track previous state)
- The managing ACL group gets a `.socket-group-managing` highlight class (reused from socket groups)

### Rename groups

- **ACL groups**: Inline rename in the header — edit button shows input + Save/Cancel, calls existing `updateAclGroup(id, label)`
- **Socket groups**: Same inline rename pattern. New backend support added:
  - `UpdateSocketGroupRequest { label: Option<String> }` in api_types
  - `Database::update_socket_group()` — `UPDATE socket_groups SET label = ? WHERE id = ?`
  - `Database::get_socket_group()` — needed for existence check in the handler
  - `PUT /api/socket-groups/{id}` route and handler in daemon API
  - Tauri command `update_socket_group` proxying to the daemon
  - Frontend `updateSocketGroup(id, label)` API function

### Port/protocol styling

Port and protocol merged into a single `<span className="mono">80/tcp</span>` at primary font size. PID remains secondary/muted.

## Consequences

- Consistent member management UX between ACL groups and socket groups (both use checkbox pattern)
- Groups can be renamed inline without leaving the tree view
- Socket identity (`port/protocol`) is visually clearer as a single unit
- ACL group managing state is lifted to AppTree level (same as socket group managing), keeping state flow predictable
