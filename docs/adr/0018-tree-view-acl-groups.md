# ADR 0018: Tree View UX with ACL Groups and Socket Groups

## Status

Accepted

## Context

The current UI (ADR 0017) has a flat socket list with per-backend policy/ACL controls. Users interact with individual sockets, each showing its backend addresses as cards. This works but has limitations:

- **No app-level grouping**: Sockets are listed flat — nginx's port 80 and 443 appear as separate items with no visual relationship.
- **Repetitive ACL management**: If multiple sockets should share the same allowed IPs, users must configure each one individually.
- **No shared addresses**: Services like FTP (ports 20+21) that should share a single IPv6 per backend require manual coordination.
- **Disabled state is confusing**: The `Policy::Disabled` variant removes addresses from the OS but keeps the DB row. The UX distinction between "disabled" and "closed with no ACL entries" is unclear.

## Decision

### Tree View with Apps at Top Level

Replace the flat socket list with a tree view organized by process name:

```
▾ nginx
    80/tcp
      ULA:   fd00::1234    [closed] [ACL: ...]
      SLAAC: 2001:db8::1234 [open]
    443/tcp
      ULA:   fd00::5678    [group → Web Servers]
▾ sshd
    22/tcp
      ULA:   fd00::9012    [open]
```

Backend filter tabs at the top allow toggling visibility of specific backend types (e.g., show only ULA addresses). Tabs are toggleable — clicking an active tab deselects it to show all.

**Rejected alternative**: Backend tabs as primary navigation (one view per backend). This would split the socket information across views and make cross-backend comparison difficult.

### ACL Groups

ACL groups are top-level entities that provide shared policy + ACL configuration:

- A group has a `label`, `policy` (closed/open), and a set of ACL entries scoped by backend.
- Sockets can be members of at most one ACL group.
- When a socket address has `policy = group`, it inherits the group's policy and ACL entries for that backend.
- If a socket has `policy = group` but is not in any group, it is treated as closed with no ACL (= inactive).

### Socket Groups

Socket groups live under a process and allow multiple sockets to share a single IPv6 address per backend:

- A socket group has a `label` and belongs to a specific `app_name` (process).
- Member sockets share the group's allocated IPv6 address rather than getting individual ones.
- Each socket still has its own individual address too (allocated independently).
- Useful for services like FTP (ports 20+21) that need to be reachable on the same IP.

### Remove Disabled Policy

Replace `Policy::Disabled` with the pattern: **closed + no ACL entries = inactive address**.

- An inactive address is not added to the OS interface (no firewall rules needed).
- The address allocation is preserved in the DB so it can be reactivated.
- The UI shows inactive addresses greyed out.
- Add `Policy::Group` variant instead — means "inherit from ACL group".

Per-address policy modes become: `Closed` / `Open` / `Group`.

### Migration

- Existing `Policy::Disabled` values in `socket_addresses.policy` are migrated to `Closed` (which with no ACL = inactive, achieving the same effect).
- `"disabled"` is accepted in `FromStr` as a backwards-compat alias for `Closed`.

## Consequences

- **Positive**: App-centric view is more intuitive for managing multiple ports of the same service.
- **Positive**: ACL groups eliminate repetitive ACL configuration across sockets.
- **Positive**: Socket groups enable shared IPv6 for multi-port services.
- **Positive**: Removing Disabled simplifies the policy model — "closed + no ACL = inactive" is a natural consequence of the existing semantics.
- **Negative**: More complex data model with two new group concepts.
- **Negative**: Group policy resolution adds indirection — need to look up the group to determine effective policy.
- **Negative**: One-way migration from Disabled to Closed (cannot distinguish "intentionally closed with no ACL" from "was disabled").
- ADR 0017's `Policy::Disabled` is superseded by the closed+no-ACL=inactive pattern.
