# ADR 0029: Firewall Desired-State Seam

## Status

Accepted. Supersedes ADR 0008 (Windows part: ADR 0030).

Amended below; read the amendments in order.

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

## Amendment: hardening after the security review

- **Interface names are validated.** `valid_interface_name` (core): `[A-Za-z0-9._-]` and space, 1 to 64 characters. It is enforced on config load, `POST /api/networks`, `PUT /api/settings/protect-host` and apply documents. The producer drops what is invalid (with a warning), `DesiredRuleset::validate` makes every backend refuse an invalid name, and the renderers sanitize ids and names placed in comments and log prefixes. A name can no longer end a quote or a line in nft or pf.
- **Source networks are aggregated** per rule (`IpNet::aggregate`). nft rejects overlapping elements in an anonymous set (a /64 plus a /128 inside it).
- **Every rule is bound to its network's interface** (`iif`), for Anyone grants and IP-only credentials too, not only Yggdrasil. A forged LAN source arriving on another interface is refused. Rule ids gain the `:<interface>` suffix. `normalize_credential` rejects an `ip` credential that contains `200::/7`.
- **The always-allowed set is narrower.** Neighbour discovery (solicit, advert, router advert) only with hop limit 255 (nft; pf cannot match it, the kernels check it themselves); no redirects, no MLD reports; MLD queries only from `fe80::/10`. DHCPv6 replies only from `fe80::/10` (udp 547 to 546), DHCPv4 67 to 68; neither on overlay interfaces. Echo stays rate-limited on nft; pf cannot rate-limit ICMP, so echo and DHCP are blocked on overlay interfaces and allowed elsewhere.
- **Drift is caught.** `Firewall::verify` (nft: `nft list table inet socketguard`) runs on every reconcile pass; a missing table is re-applied at once. `REAPPLY_EVERY` stays as a backstop. `Firewall::interfaces_changed` does the same for WFP's interface LUIDs (ADR 0030).
- **Revocation cuts established flows.** After a successful apply the engine diffs the old and new ruleset (`revocations`, pure) and calls `Firewall::revoke` for (destination, port, protocol, source) that stopped being allowed. nft runs `conntrack` (list, filter by net, delete by source); without the tool it logs a one-time warning and flows persist until they close. No pure-Rust netlink conntrack client was added: it is a dependency and a protocol for a best-effort cleanup. pf runs `pfctl -k <src> -k <dst>`, which kills every state between the pair, not only the revoked port. A narrowed Anyone grant kills all flows to the destination port.
- **Boot.** `deploy/systemd/socketguard.service` starts the daemon before `network-pre.target`, so the stored state is applied before interfaces come up.

## Amendment: second security review

- **Established flows are checked on every packet (nftables).** The blanket `ct state established,related accept` came before the interface- and source-bound rules, so a spoofed original-direction packet of an established flow, arriving on another interface, was accepted, and revocation depended on the best-effort `conntrack` tool (and on `last_applied`, which is empty after a restart). The input chain now accepts `ct state established ct direction reply` (replies to the host's own outbound connections) and `ct state related` only. Original-direction packets of inbound flows go through the rules, which have no ct match, so a revoked grant cuts the flow at once and the `iif` binding holds for every packet. `Firewall::revoke` stays as a harmless extra that frees conntrack state; correctness no longer depends on it. Cost: one rule evaluation per inbound packet of a granted flow.
- **pf.** `keep state` states are floating by default and survive a ruleset swap, so a revoked grant or a spoofed interface can ride on an old state. The first successful apply of each daemon run calls `Firewall::purge_states`, which runs `pfctl -k any -k <dst>` for every scoped destination (rule destinations and managed addresses). This also covers grants revoked while the daemon was down. Cost: established flows to scoped destinations reconnect once per daemon start.
- **DHCPv6 replies** must also be to `fe80::/10` (nft `ip6 daddr`, pf `to fe80::/10`, WFP local address), not only from it.
