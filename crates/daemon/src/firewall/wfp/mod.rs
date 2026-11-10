//! Windows Filtering Platform backend (ADR 0030, 0029, 0026).
//!
//! Everything lives under SocketGuard's own persistent provider and a persistent sublayer
//! of maximum weight, so the state survives daemon exit and reboot (frozen state) and is
//! removed only by [`Firewall::disable`], never touching other filters.
//!
//! Layers: `ALE_AUTH_RECV_ACCEPT_V4/V6` see only *new* inbound flows. Established traffic
//! is therefore never re-evaluated, which covers "established/related" for free.
//! ICMPv6 NDP/MLD/PMTU messages are not classified at ALE recv-accept, so they need no
//! permit and cannot be blocked by us. ICMP echo requests are classified there and are
//! denied inside a scope unless a rule matches (conservative; not exempted).
//!
//! Per-ruleset layout inside the sublayer (higher weight is evaluated first):
//! - weight 15: hard permits: loopback (by remote address) and DHCP client replies (v6
//!   only from `fe80::/10`; not on the overlay interface);
//! - weight 10: hard permits: one per (rule, source net);
//! - weight 4: blocks: one per scope destination address / scope interface family.
//!
//! Interfaces: rules and scopes match `FWPM_CONDITION_IP_ARRIVAL_INTERFACE`, the interface
//! the packet came in on (ADR 0029's `iif`), not the local interface of the destination
//! address. Aliases are resolved to LUIDs when applying; the resolved map is remembered
//! so [`Firewall::interfaces_changed`] can tell when an adapter was recreated. A filter
//! (permit or block) that names an interface which does not resolve is skipped, with a
//! warning: an absent adapter receives no traffic, managed addresses stay covered by the
//! destination blocks, and the engine re-applies once the adapter is back. Established
//! flows are never re-evaluated by ALE, so a revoked grant lets them live until they close
//! ([`Firewall::revoke`] does nothing here, ADR 0030).
//!
//! `plan` (the pure translation of a ruleset to filter specs) lives in [`plan`] and is
//! compiled and tested on every platform; `native` is the Windows-only FFI.
//!
//! Not used: `FWPM_FILTER_FLAG_BOOTTIME`. Boot-time filters are a separate table enforced
//! before BFE starts and cannot be combined with PERSISTENT, so adding them would mean a
//! second, parallel filter set. Persistent filters are applied as soon as BFE starts; the
//! gap before that is accepted for now.

// Only the Windows backend consumes the plan outside the tests.
#[cfg(target_os = "windows")]
mod native;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod plan;

#[cfg(target_os = "windows")]
pub use native::WfpFirewall;
