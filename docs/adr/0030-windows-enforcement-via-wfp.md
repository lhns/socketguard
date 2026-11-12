# ADR 0030: Windows Enforcement via the WFP API

## Status

Accepted

Amended below; read the amendments in order. ADR 0054 makes an exception for portable mode: its filters live in a dynamic session, not persistently.

## Date

2026-11-09

## Context

ADR 0008 used `netsh advfirewall`. In Windows Firewall a block rule wins over any allow rule, so "allow these peers, block the rest" cannot be expressed. `netsh` cannot match an interface by alias, so Yggdrasil-only trust (ADR 0028) is impossible. Its rules also live among the user's, and `remove_acl` deleted rules that were not SocketGuard's own. A program allow rule from an installer could bypass SocketGuard.

## Decision

- **Use the WFP API directly** through the `windows` crate, with SocketGuard's own provider and sublayer, and filter weights that put grant allow filters above a block filter per scope.
- **Filters are persistent**, so the host fails closed across reboots and daemon stops (ADR 0026). Only `socketguard disable` and the uninstaller remove them, by provider, never touching other filters.
- Apply replaces the provider's filters atomically, as ADR 0029 requires, rendered from the `DesiredRuleset`.
- **Drops come from a net-event subscription** (`FwpmNetEventSubscribe`), plus filter counters where available (ADR 0034).
- **Feasibility spike first:** one day to create a provider, a sublayer and one allow-above-block filter pair. If it shows the work is large, Windows moves to its own phase.

## Consequences

- Precedence, interface matching and ownership are explicit, and user rules are never touched.
- Unsafe FFI and WFP's API complexity enter the codebase.
- Rules are no longer visible through `netsh`; inspection goes through `netsh wfp show filters` or the SocketGuard CLI.

## Amendment: hardening after the security review

- **Arrival interface.** Rule `iif` and interface scopes use `FWPM_CONDITION_IP_ARRIVAL_INTERFACE` (where the packet arrived), not `IP_LOCAL_INTERFACE` (the interface of the destination address), so the semantics match nftables and pf.
- **Adapters get new LUIDs** when they are recreated (wintun after a Yggdrasil restart). The firewall remembers the alias to LUID map of the last apply; `Firewall::interfaces_changed` re-resolves the aliases (cheap) and the engine re-applies when the answer differs.
- **Unresolvable interfaces fail safe.** A BLOCK scope whose interface alias does not resolve fails the whole apply and the previous filters stay in force (the engine retries each pass); skipping it would silently leave that interface open. A broader block on all interfaces was rejected, because it would cut unrelated traffic whenever an adapter is down. Permits for an unresolvable interface are skipped. Cost: while an adapter is missing, no other change can be applied. Until the adapter returns, filters bound to its old LUID match nothing, which is the gap the retry closes.
- **Always-allowed permits** (weight 15): the DHCPv6 reply permit has a remote `fe80::/10` condition, and both DHCP permits exclude the overlay interface (`NOT_EQUAL` arrival interface; same-field conditions are ORed, so one overlay can be excluded, and SocketGuard allows a single Yggdrasil network).
- **Grant permits are hard permits** (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`), so a grant overrides explicit Windows Firewall block rules for that address and port. This is intended: it is the only way to beat Windows Firewall's default block for an inbound flow.
- **Revocation does not cut established flows.** ALE recv-accept only sees new flows, so a flow admitted by a grant lives until it closes after the grant is revoked. `Firewall::revoke` does nothing on Windows.

## Amendment: second security review

- **Unresolvable interfaces are skipped, not fatal (reverses the "fail safe" bullet above).** A block scope whose interface alias does not resolve is skipped, like permits for it (`drop_unresolved`), and everything else is applied. An absent adapter receives no traffic, so nothing is exposed, and the managed-address destination blocks still cover the managed addresses. The earlier choice (fail the whole apply) kept every other change out while an adapter such as wintun was missing: a revoked LAN grant stayed permitted while the Yggdrasil adapter was absent, and the API reported an error after the DB had changed. The engine re-applies when `interfaces_changed` reports the adapter back (its alias resolved to `None` at apply time, so the LUID differs).
- **DHCPv6 reply permit** also has a local address condition `fe80::/10`.
- `Firewall::verify` reports whether SocketGuard's provider exists (used to detect an existing ruleset next to a fresh database, ADR 0038).
