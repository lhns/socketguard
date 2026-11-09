//! The desired firewall state (ADR 0029): a platform-independent description that the
//! engine produces as a pure function of its state, and each platform backend applies
//! atomically as a whole.
//!
//! Semantics, evaluated per inbound packet:
//! 1. Always allowed: established/related, loopback, the ICMPv6 types needed for NDP and
//!    PMTU (NDP only with hop limit 255, MLD queries only from link-local sources, echo
//!    rate-limited), and DHCP client replies (v6 only from `fe80::/10`). Neither echo
//!    nor DHCP is allowed on overlay interfaces. Backends that only see new connections
//!    (WFP ALE) get most of this for free.
//! 2. A matching [`Rule`] allows the packet.
//! 3. Otherwise, a packet that falls inside any [`Scope`] is dropped (and counted/logged).
//! 4. Anything outside every scope is left alone.
//!
//! Link-local destinations are NOT exempt: inside a scope they are denied like any other.

use anyhow::{bail, Result};
use ipnet::IpNet;
use socketguard_core::{valid_interface_name, Protocol};
use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredRuleset {
    pub scopes: Vec<Scope>,
    pub rules: Vec<Rule>,
}

impl DesiredRuleset {
    /// Reject interface names that could break out of a firewall script. The producer
    /// never emits such names; this is the backends' last line of defence.
    pub fn validate(&self) -> Result<()> {
        let names = self.rules.iter().filter_map(|r| r.iif.as_deref()).chain(
            self.scopes.iter().filter_map(|s| match &s.matcher {
                ScopeMatch::Interface { name, .. } => Some(name.as_str()),
                ScopeMatch::Destinations(_) => None,
            }),
        );
        for n in names {
            if !valid_interface_name(n) {
                bail!("invalid interface name {n:?} in ruleset");
            }
        }
        Ok(())
    }

    /// The interfaces of overlay scopes, which get no echo and no DHCP.
    pub fn overlay_interfaces(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self
            .scopes
            .iter()
            .filter(|s| s.kind == ScopeKind::Overlay)
            .filter_map(|s| match &s.matcher {
                ScopeMatch::Interface { name, .. } => Some(name.as_str()),
                ScopeMatch::Destinations(_) => None,
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// `s` with everything but `[A-Za-z0-9 :._-]` replaced by `_`, for ids placed in comments
/// and log prefixes where a newline or quote would end the line or string.
pub fn safe_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ' ' | ':' | '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// Stable identifier, used for counters and drop attribution (e.g. "managed",
    /// "overlay:ygg0", "host:eth0"). Must be unique within a ruleset.
    pub id: String,
    pub kind: ScopeKind,
    pub matcher: ScopeMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// SocketGuard-allocated addresses, all ports.
    ManagedAddresses,
    /// An overlay interface protected by default (Yggdrasil).
    Overlay,
    /// Opt-in whole-host protection of an interface.
    WholeHost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeMatch {
    /// Inbound packets whose destination is one of these addresses (any port, any interface).
    Destinations(Vec<IpAddr>),
    /// All inbound packets arriving on this interface, for the given families. Matching by
    /// interface covers every prefix on it, including rotating privacy and link-local addresses.
    Interface { name: String, families: Families },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Families {
    V6,
    V4,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Stable identifier, used for counters (e.g. derived from grant or socket+backend).
    /// Must be unique within a ruleset.
    pub id: String,
    /// When set, the packet must arrive on this interface. Required for sources whose
    /// identity is only guaranteed by that interface (Yggdrasil `200::/7`, WireGuard).
    pub iif: Option<String>,
    pub dst: IpAddr,
    pub port: u16,
    pub proto: Protocol,
    pub sources: Sources,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sources {
    Any,
    /// Non-empty list of allowed source networks (single hosts as /128 or /32).
    Nets(Vec<IpNet>),
}

/// Packet/byte counter for a rule or scope, keyed by its `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counter {
    pub id: String,
    pub packets: u64,
    pub bytes: u64,
}

/// A dropped inbound connection attempt reported by the platform (NFLOG, WFP net events).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropEvent {
    pub at: SystemTime,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub port: Option<u16>,
    pub proto: Option<Protocol>,
    pub iif: Option<String>,
    /// The scope that dropped it, when the platform can tell.
    pub scope_id: Option<String>,
}

pub type DropSink = Box<dyn Fn(DropEvent) + Send + Sync>;

/// Connections that stopped being allowed between two applied rulesets. Established flows
/// survive a ruleset swap (`ct state established`, pf `keep state`), so the backends
/// kill them explicitly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Revocation {
    pub dst: IpAddr,
    pub port: u16,
    pub proto: Protocol,
    /// The revoked source network; None when every source of the destination is revoked
    /// (an Anyone rule that is gone or was narrowed to some sources).
    pub src: Option<IpNet>,
}

/// What `old` allowed that `new` does not, by (destination, port, protocol) and source.
/// Interface bindings are ignored: a flow that stays allowed from the same source is not
/// cut when only its binding moved.
pub fn revocations(old: &DesiredRuleset, new: &DesiredRuleset) -> Vec<Revocation> {
    type Key = (IpAddr, u16, Protocol);
    #[derive(Default)]
    struct Allowed {
        any: bool,
        nets: Vec<IpNet>,
    }
    fn collect(rs: &DesiredRuleset) -> std::collections::BTreeMap<Key, Allowed> {
        let mut m: std::collections::BTreeMap<Key, Allowed> = Default::default();
        for r in &rs.rules {
            let e = m.entry((r.dst, r.port, r.proto)).or_default();
            match &r.sources {
                Sources::Any => e.any = true,
                Sources::Nets(n) => e.nets.extend(n.iter().copied()),
            }
        }
        m
    }
    let new = collect(new);
    let mut out = Vec::new();
    for (key, was) in collect(old) {
        let (dst, port, proto) = key;
        let now = new.get(&key);
        if now.is_some_and(|n| n.any) {
            continue;
        }
        let revoke = |src| Revocation {
            dst,
            port,
            proto,
            src,
        };
        let nets = now.map(|n| n.nets.as_slice()).unwrap_or(&[]);
        if was.any {
            out.push(revoke(None));
            continue;
        }
        for net in &was.nets {
            if !nets.iter().any(|n| n.contains(net)) {
                out.push(revoke(Some(*net)));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, sources: Sources) -> Rule {
        Rule {
            id: id.into(),
            iif: None,
            dst: "fd00::9".parse().unwrap(),
            port: 80,
            proto: Protocol::Tcp,
            sources,
        }
    }
    fn nets(n: &[&str]) -> Sources {
        Sources::Nets(n.iter().map(|s| s.parse().unwrap()).collect())
    }
    fn rs(rules: Vec<Rule>) -> DesiredRuleset {
        DesiredRuleset {
            scopes: vec![],
            rules,
        }
    }

    #[test]
    fn nothing_revoked_when_unchanged_or_widened() {
        let a = rs(vec![rule("a", nets(&["fd00::1/128"]))]);
        assert!(revocations(&a, &a).is_empty());
        let wider = rs(vec![rule("a", nets(&["fd00::/64"]))]);
        assert!(revocations(&a, &wider).is_empty());
        assert!(revocations(&a, &rs(vec![rule("a", Sources::Any)])).is_empty());
        assert!(revocations(&rs(vec![]), &a).is_empty());
    }

    #[test]
    fn removed_rule_and_removed_sources_are_revoked() {
        let old = rs(vec![rule("a", nets(&["fd00::1/128", "fd00::2/128"]))]);
        let r = revocations(&old, &rs(vec![]));
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|x| x.port == 80 && x.src.is_some()));
        let r = revocations(&old, &rs(vec![rule("b", nets(&["fd00::2/128"]))]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].src, Some("fd00::1/128".parse().unwrap()));
    }

    #[test]
    fn narrowing_a_net_revokes_the_part_no_longer_covered() {
        let old = rs(vec![rule("a", nets(&["fd00::/64"]))]);
        let new = rs(vec![rule("a", nets(&["fd00::1/128"]))]);
        let r = revocations(&old, &new);
        assert_eq!(r[0].src, Some("fd00::/64".parse().unwrap()));
    }

    #[test]
    fn anyone_revoked_without_a_source() {
        let old = rs(vec![rule("a", Sources::Any)]);
        let r = revocations(&old, &rs(vec![rule("b", nets(&["fd00::1/128"]))]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].src, None);
        assert_eq!(revocations(&old, &rs(vec![])).len(), 1);
    }

    #[test]
    fn a_moved_interface_binding_revokes_nothing() {
        let mut a = rule("a", nets(&["fd00::1/128"]));
        let mut b = a.clone();
        a.iif = Some("eth0".into());
        b.iif = Some("eth1".into());
        assert!(revocations(&rs(vec![a]), &rs(vec![b])).is_empty());
    }

    #[test]
    fn validate_rejects_hostile_interfaces() {
        let mut r = rule("a", Sources::Any);
        r.iif = Some(format!("eth0{} accept #", '"'));
        assert!(rs(vec![r]).validate().is_err());
        let sc = DesiredRuleset {
            scopes: vec![Scope {
                id: "x".into(),
                kind: ScopeKind::WholeHost,
                matcher: ScopeMatch::Interface {
                    name: format!("a{}b", char::from(10u8)),
                    families: Families::V6,
                },
            }],
            rules: vec![],
        };
        assert!(sc.validate().is_err());
        assert!(DesiredRuleset::default().validate().is_ok());
    }

    #[test]
    fn safe_text_neutralizes_breakouts() {
        assert_eq!(safe_text("ok:Yggdrasil 0.x-1"), "ok:Yggdrasil 0.x-1");
        let hostile = format!("a{q}b{nl}c#d{{}}", q = '"', nl = char::from(10u8));
        assert_eq!(safe_text(&hostile), "a_b_c_d__");
    }
}
