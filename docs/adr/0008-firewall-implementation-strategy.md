# ADR-0008: Firewall Implementation Strategy

## Status

Accepted

## Date

2026-03-12

## Context

SocketGuard must create firewall rules to enforce per-socket ACLs. Each platform has a different firewall subsystem:

- **Linux**: nftables (successor to iptables), netfilter
- **macOS**: pf (Packet Filter, BSD-derived)
- **Windows**: WFP (Windows Filtering Platform), exposed via `netsh advfirewall`

We must decide between using native APIs (C bindings, windows-rs) or CLI wrappers.

## Decision

Use **CLI wrappers** for all platforms in the initial implementation, behind the `Firewall` trait.

### Linux — nftables (`nft` CLI)
- Creates a dedicated `ip6` table named `socketguard` with an `input` chain.
- Rules use comments (`sg_{dest_ip}_{dest_port}`) for identification and cleanup.
- `ensure_table()` is called before each `apply_acl()` to create the table/chain if missing.
- Rules are removed by listing the chain with `--handle`, parsing handle numbers, and deleting by handle.

### macOS — pf (`pfctl` CLI)
- Uses pf anchors: `socketguard/sg_{ip}_{port}` per socket.
- Rules are loaded into the anchor via `pfctl -a <anchor> -f -` (stdin).
- Cleanup flushes the anchor with `pfctl -a <anchor> -F rules`.
- Anchor-based isolation prevents interference with other pf rules.

### Windows — WFP (`netsh advfirewall` CLI)
- Creates named firewall rules: `SocketGuard_{dest_ip}_{dest_port}` for block rules, `SocketGuard_Allow_{dest_ip}_{dest_port}_{src_ip}` for allow rules.
- Allow rules are created first (per source IP), then a catch-all block rule.
- Cleanup deletes rules by name prefix.

### Rule Structure (all platforms)

For **managed** policy with ACL entries `[src1, src2]`:
1. Allow `src1 → dest_ip:port`
2. Allow `src2 → dest_ip:port`
3. Block `* → dest_ip:port`

For **closed** policy: just the block rule.
For **open** policy: remove all rules (allow everything).

### Why CLI Instead of Native APIs

- Simpler implementation — no unsafe code or complex FFI bindings.
- Easier to debug — rules can be inspected with standard tools (`nft list`, `pfctl -sr`, `netsh show`).
- Sufficient performance — firewall rule changes are infrequent.
- Future optimization: replace CLI calls with native APIs (netlink for nftables, WFP via windows-rs) when performance or reliability demands it.

## Consequences

- Requires the relevant CLI tools to be installed and accessible (`nft`, `pfctl`, `netsh`).
- CLI invocation has higher latency than native APIs but is acceptable for infrequent operations.
- The daemon typically needs elevated privileges (root/admin) to modify firewall rules.
- Rule naming conventions prevent conflicts with user-managed firewall rules.
- The `Firewall` trait allows swapping CLI implementations for native API implementations without changing the engine.
