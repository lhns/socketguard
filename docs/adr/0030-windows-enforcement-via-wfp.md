# ADR 0030: Windows Enforcement via the WFP API

## Status

Accepted

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
