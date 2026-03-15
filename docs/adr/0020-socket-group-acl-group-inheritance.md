# ADR 0020: Socket Group ACL Group Inheritance

## Status

Accepted

## Context

ADR 0018 introduced socket groups (shared IPv6 per backend) and ACL groups (shared policy/ACL for member sockets). Individual sockets can use the "Group" policy to inherit their ACL from a linked ACL group. However, socket groups only support "Closed" and "Open" policies — there is no way for a socket group to inherit ACL from an ACL group.

This creates a UX inconsistency: individual sockets offer three policy choices (Closed, Open, Group) while socket groups only offer two. Users who manage multiple socket groups with similar ACL requirements must configure each one individually.

## Decision

Socket groups now support the "Group" policy, inheriting ACL from a linked ACL group — the same mechanism available to individual sockets.

### Backend changes

- **Schema**: Add nullable `acl_group_id` column to `socket_groups` table, referencing `acl_groups(id)` with `ON DELETE SET NULL`.
- **API**: New endpoint `PUT /api/socket-groups/{id}/acl-group` accepts `{ acl_group_id: string | null }` to set or clear the linked ACL group.
- **Engine**: When `apply_socket_group_acl` encounters `Policy::Group` on a socket group address, it resolves the effective policy and ACL entries from the linked ACL group (via `acl_group_id`). If the ACL group has `Policy::Open`, the address allows all. If `Policy::Closed`, the group's per-backend ACL entries are applied. If no ACL group is linked, the address is treated as inactive.
- **Response**: `SocketGroupResponse` includes `acl_group_id` field.

### Frontend changes

- `SocketGroupFoldout` passes `supportsGroupPolicy: true` to `BackendAddressNode`, along with `aclGroupId` and `aclGroups`.
- `BackendAddressNode` already handles the Group button and dropdown when `supportsGroupPolicy=true`. It now routes ACL group assignment to `setSocketGroupAclGroup` when operating in socket group context (`groupId`).

## Consequences

- **UX consistency**: Both sockets and socket groups offer the same three policy options.
- **Reduced configuration overhead**: Socket groups can share ACL with other sockets via ACL groups.
- **Minimal backend changes**: Reuses existing ACL group infrastructure — only adds a foreign key column and one new endpoint.
- **Backwards compatible**: The `acl_group_id` column is nullable and defaults to `NULL`. Existing socket groups continue to work unchanged. The `SocketGroupResponse` field uses `#[serde(default)]`.
