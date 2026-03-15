# ADR 0019: UI Tree Structure

## Status

Accepted

## Context

The UI tree view (ADR 0018) has settled into a stable component hierarchy, but the structure is not documented. New conversations and contributors need to understand the L1/L2/L3 hierarchy, how components are shared between socket and socket group contexts, and the inactive address pattern.

## Decision

### Component hierarchy

The tree has three levels:

- **L1 — AppNode** (`AppTree.tsx`): Groups sockets by `process_name`. Contains App Details (PIDs, exe path) as a collapsible info section. Hosts the "+ Socket Group" button.
- **L2 — SocketFoldout / SocketGroupFoldout**: Individual sockets or socket groups. Socket headers show port/protocol. Socket group headers show label and member count. Both expand to show L3 address nodes.
- **L3 — BackendAddressNode** (`BackendAddressNode.tsx`): A single backend address (e.g., ULA, SLAAC). Shows backend ID, address, and policy badge. Expands to show policy toggle and ACL management.

### Shared BackendAddressNode

`BackendAddressNode` is used by both `SocketFoldout` (via `socketId`) and `SocketGroupFoldout` (via `groupId`). The component routes API calls to the correct endpoint based on which ID is provided. Both contexts support the same three policies: Closed, Open, Group.

### SocketDetail standalone page

`SocketDetail` is a full-page detail view opened via "Open full details" (inside the Socket Details info section). It provides a comprehensive view of a single socket with all its ACL entries and metadata.

### Inactive address pattern

An address is visually inactive when `policy === "closed" && acl.length === 0`. The `address-inactive` CSS class applies `opacity: 0.5` to the L3 wrapper. This replaces the old `Policy::Disabled` variant (ADR 0018).

### Info sections

App Details and Socket Details are collapsible info sections, collapsed by default. They use `tree-info-toggle` and `tree-info-content` CSS classes.

### Backend filter bar

`BackendFilterBar` sits at the top of the tree and filters at L3 — only addresses matching the selected backend ID are shown. When no filter is active, all addresses are visible.

### Policy options

All three policies are available for both individual sockets and socket groups:

- **Closed**: Per-address ACL — only explicitly allowed IPs can connect.
- **Open**: Allow all incoming connections (requires confirmation dialog).
- **Group**: Inherit ACL from a linked ACL group (ADR 0020 extends this to socket groups).

## Consequences

- The tree structure is documented for future reference.
- New contributors can understand the component hierarchy without reading all the code.
- The shared `BackendAddressNode` pattern is explicit, reducing confusion about socket vs socket group routing.
