# ADR 0029: Firewall Desired-State Seam

## Status

Accepted. Supersedes ADR 0008 (Windows part: ADR 0030).

## Date

2026-11-09

## Context

ADR 0008 added and deleted rules per socket: comment-tagged rules in an `ip6` table deleted by handle, one pf anchor per socket, named `netsh` rules. Rules for wildcard binds, groups and the rest of the host were missing, the `ip6` table could not cover IPv4, and incremental edits left windows where state was half-applied. Policy resolution existed in four copies in the engine, so the rendered rules could not be tested on their own.

## Decision

- **A pure desired state:**
  `DesiredRuleset = { scopes: Vec<Scope{iif, prefixes, families}>, rules: Vec<Rule{iif: Option, dst, port, proto, sources}> }`.
  It is a pure function of the DB state (ADR 0027) and the network state (e.g. Yggdrasil node info, ADR 0031).
- **One producer** builds it; it replaces the four copies of policy resolution. Each platform renders it; renderers are pure too.
- **Scopes match by interface and prefix**, not by listing addresses, so rotating privacy addresses and addresses added later are covered. A scope ends in a drop; rules above it allow granted sources. The always-allowed list and link-local handling are in ADR 0026.
- **Atomic apply, whole state each time:**
  - nftables: one `inet` table (IPv6 and IPv4 for whole-host mode), rendered whole and swapped with `nft -f`;
  - pf: the `socketguard` anchor is reloaded whole; apply checks the anchor is referenced from the main ruleset and pf is enabled;
  - Windows: WFP API, ADR 0030.
- **Never flush on start or stop** (ADR 0026); start-up applies the freshly rendered state over the frozen one.
- **Counters and drop logging:** named counters on every rule and scope (read with `nft -j list counters`); a rate-limited `log group` on scope drops, read via NFLOG netlink. The NFLOG reader library is an implementation choice. These feed ADR 0034.
- `nft` and `pfctl` remain CLI invocations; only the unit of change moves from rules to whole tables.

## Consequences

- No partially applied rulesets; any drift is corrected by the next full render.
- Renderers get golden tests and enforcement gets netns tests (ADR 0035).
- A large ruleset is re-sent in full on every change. Rule counts are small, so this is accepted.
