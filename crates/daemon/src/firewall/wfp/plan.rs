//! Planning for the Windows Filtering Platform backend: the pure translation of a
//! [`DesiredRuleset`] into filter specs. No FFI, so it is compiled and unit-tested on every
//! platform; [`super`] turns the specs into WFP filters. See the module docs there for the
//! layout (weights, layers, interface handling).

use crate::firewall::{DesiredRuleset, Dst, Families, ScopeMatch, Sources};
use ipnet::IpNet;
use socketguard_core::Protocol;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) const W_ALWAYS: u8 = 15;
pub(crate) const W_RULE: u8 = 10;
pub(crate) const W_BLOCK: u8 = 4;

pub(crate) const NAME_PREFIX: &str = "SocketGuard";
pub(crate) const SCOPE_NAME_PREFIX: &str = "SocketGuard scope:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    V4,
    V6,
}

impl Layer {
    fn of(ip: &IpAddr) -> Self {
        if ip.is_ipv4() {
            Layer::V4
        } else {
            Layer::V6
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// Hard permit (clear-action-right): later sublayers cannot veto it.
    Permit,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cond {
    LocalAddr(IpAddr),
    LocalPort(u16),
    /// A range of local ports, both ends included (a rule over a port group's range).
    LocalPortRange(u16, u16),
    RemotePort(u16),
    Proto(u8),
    /// A host (full prefix) matches by address, anything else by address+mask.
    Remote(IpNet),
    /// The same for the local (destination) address.
    LocalNet(IpNet),
    /// Arrival interface alias; resolved to a LUID when applying.
    ArrivalIf(String),
    /// Any arrival interface but this one (no condition when the alias does not exist).
    NotArrivalIf(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterSpec {
    pub name: String,
    pub layer: Layer,
    pub action: Action,
    pub weight: u8,
    pub conds: Vec<Cond>,
    /// Set on scope blocks: the scope that a drop by this filter is attributed to.
    pub scope_id: Option<String>,
}

fn proto_number(p: Protocol) -> u8 {
    match p {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
    }
}

fn host_net(ip: IpAddr) -> IpNet {
    IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).expect("full prefix is valid")
}

/// Drop the specs that name an interface alias that does not resolve (`luids` holds the
/// ones that do). An absent adapter receives no traffic, so skipping its filters leaves
/// nothing open: managed addresses stay covered by the destination blocks, and the engine
/// re-applies when `interfaces_changed` reports the adapter back. A `NotArrivalIf` for an
/// absent adapter excludes nothing and is just dropped.
pub(crate) fn drop_unresolved(
    specs: Vec<FilterSpec>,
    luids: &HashMap<String, u64>,
) -> Vec<FilterSpec> {
    let missing = |n: &String| !luids.contains_key(n);
    specs
        .into_iter()
        .filter(|s| {
            !s.conds
                .iter()
                .any(|c| matches!(c, Cond::ArrivalIf(n) if missing(n)))
        })
        .map(|mut s| {
            s.conds
                .retain(|c| !matches!(c, Cond::NotArrivalIf(n) if missing(n)));
            s
        })
        .collect()
}

/// Translate the desired state into filter specs. See the module docs for the layout.
pub(crate) fn plan(desired: &DesiredRuleset) -> Vec<FilterSpec> {
    let mut out = Vec::new();

    if !desired.scopes.is_empty() {
        // Always allowed: loopback (by remote address, independent of WFP's loopback
        // flag) and DHCP client replies (unicast replies are new inbound UDP flows).
        for (layer, net) in [
            (Layer::V6, host_net(Ipv6Addr::LOCALHOST.into())),
            (
                Layer::V4,
                IpNet::new(Ipv4Addr::new(127, 0, 0, 0).into(), 8).unwrap(),
            ),
        ] {
            out.push(FilterSpec {
                name: format!("{NAME_PREFIX} loopback"),
                layer,
                action: Action::Permit,
                weight: W_ALWAYS,
                conds: vec![Cond::Remote(net)],
                scope_id: None,
            });
        }
        // Same-field conditions are ORed, so only one overlay can be excluded; SocketGuard
        // allows a single Yggdrasil network.
        let overlay = desired.overlay_interfaces().first().map(|i| i.to_string());
        for (layer, local, remote, name) in [
            (Layer::V6, 546, 547, "dhcpv6 reply"),
            (Layer::V4, 68, 67, "dhcpv4 reply"),
        ] {
            let mut conds = vec![
                Cond::Proto(17),
                Cond::LocalPort(local),
                Cond::RemotePort(remote),
            ];
            if layer == Layer::V6 {
                // Replies come from a link-local server to our link-local address.
                let link_local: IpNet = "fe80::/10".parse().expect("valid net");
                conds.push(Cond::Remote(link_local));
                conds.push(Cond::LocalNet(link_local));
            }
            conds.extend(overlay.clone().map(Cond::NotArrivalIf));
            out.push(FilterSpec {
                name: format!("{NAME_PREFIX} {name}"),
                layer,
                action: Action::Permit,
                weight: W_ALWAYS,
                conds,
                scope_id: None,
            });
        }
    }

    for rule in &desired.rules {
        let (layer, mut base) = match rule.dst {
            Dst::Addr(a) => (Layer::of(&a), vec![Cond::LocalAddr(a)]),
            // Any IPv4 destination of the host: no address condition on the v4 layer.
            Dst::HostV4 => (Layer::V4, Vec::new()),
        };
        base.push(if rule.ports.is_single() {
            Cond::LocalPort(rule.ports.start)
        } else {
            Cond::LocalPortRange(rule.ports.start, rule.ports.end)
        });
        base.push(Cond::Proto(proto_number(rule.ports.proto)));
        if let Some(iif) = &rule.iif {
            base.push(Cond::ArrivalIf(iif.clone()));
        }
        let name = format!("{NAME_PREFIX} {}", rule.id);
        let spec = |conds| FilterSpec {
            name: name.clone(),
            layer,
            action: Action::Permit,
            weight: W_RULE,
            conds,
            scope_id: None,
        };
        match &rule.sources {
            Sources::Any => out.push(spec(base)),
            Sources::Nets(nets) => {
                for net in nets {
                    if Layer::of(&net.addr()) != layer {
                        tracing::warn!(rule = %rule.id, %net, "source family differs from destination; skipped");
                        continue;
                    }
                    let mut conds = base.clone();
                    conds.push(Cond::Remote(*net));
                    out.push(spec(conds));
                }
            }
        }
    }

    for scope in &desired.scopes {
        let name = format!("{SCOPE_NAME_PREFIX}{}", scope.id);
        let block = |layer, conds| FilterSpec {
            name: name.clone(),
            layer,
            action: Action::Block,
            weight: W_BLOCK,
            conds,
            scope_id: Some(scope.id.clone()),
        };
        match &scope.matcher {
            ScopeMatch::Destinations(addrs) => {
                for a in addrs {
                    out.push(block(Layer::of(a), vec![Cond::LocalAddr(*a)]));
                }
            }
            ScopeMatch::DestinationNet(net) => {
                out.push(block(Layer::of(&net.addr()), vec![Cond::LocalNet(*net)]));
            }
            ScopeMatch::Interface {
                name: iif,
                families,
            } => {
                let layers: &[Layer] = match families {
                    Families::V6 => &[Layer::V6],
                    Families::V4 => &[Layer::V4],
                    Families::Both => &[Layer::V6, Layer::V4],
                };
                for l in layers {
                    out.push(block(*l, vec![Cond::ArrivalIf(iif.clone())]));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{Rule, Scope, ScopeKind};
    use socketguard_core::{PortRange, PortRef};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn scope(id: &str, m: ScopeMatch) -> Scope {
        Scope {
            id: id.into(),
            kind: ScopeKind::ManagedAddresses,
            matcher: m,
        }
    }
    fn rule(id: &str, dst: &str, iif: Option<&str>, sources: Sources) -> Rule {
        Rule {
            id: id.into(),
            iif: iif.map(Into::into),
            dst: Dst::Addr(ip(dst)),
            ports: PortRange::single(PortRef {
                port: 8080,
                proto: Protocol::Tcp,
            }),
            sources,
        }
    }
    fn with_name<'a>(v: &'a [FilterSpec], n: &str) -> Vec<&'a FilterSpec> {
        v.iter().filter(|s| s.name == n).collect()
    }

    #[test]
    fn a_destination_net_scope_blocks_by_local_net_and_a_permit_rule_still_wins() {
        let d = DesiredRuleset {
            scopes: vec![
                scope(
                    "overlay:ygg:addr",
                    ScopeMatch::DestinationNet(net("200:1:2:3::5/128")),
                ),
                scope(
                    "overlay:ygg:subnet",
                    ScopeMatch::DestinationNet(net("300:1:2:3::/64")),
                ),
            ],
            rules: vec![rule(
                "r",
                "300:1:2:3::100",
                Some("Yggdrasil"),
                Sources::Nets(vec![net("200:7::1/128")]),
            )],
        };
        let p = plan(&d);
        let blocks: Vec<_> = p.iter().filter(|s| s.action == Action::Block).collect();
        assert_eq!(blocks.len(), 2);
        assert!(blocks
            .iter()
            .all(|b| b.layer == Layer::V6 && b.weight == W_BLOCK));
        assert_eq!(
            blocks[0].conds,
            vec![Cond::LocalNet(net("200:1:2:3::5/128"))]
        );
        assert_eq!(blocks[1].conds, vec![Cond::LocalNet(net("300:1:2:3::/64"))]);
        assert_eq!(blocks[1].scope_id.as_deref(), Some("overlay:ygg:subnet"));
        // The rule is a hard permit of a higher weight, so it wins over the block of the
        // /64 that contains its address.
        let permit = p.iter().find(|s| s.name == "SocketGuard r").unwrap();
        assert_eq!(permit.action, Action::Permit);
        assert!(permit.weight > W_BLOCK);
    }

    #[test]
    fn empty_ruleset_plans_nothing() {
        assert!(plan(&DesiredRuleset::default()).is_empty());
    }

    #[test]
    fn always_allowed_present_when_scoped() {
        let d = DesiredRuleset {
            scopes: vec![scope("s", ScopeMatch::Destinations(vec![ip("fd00::1")]))],
            rules: vec![],
        };
        let p = plan(&d);
        let permits: Vec<_> = p.iter().filter(|s| s.weight == W_ALWAYS).collect();
        assert_eq!(permits.len(), 4);
        assert!(permits.iter().all(|s| s.action == Action::Permit));
        assert!(permits
            .iter()
            .any(|s| s.layer == Layer::V6 && s.conds == vec![Cond::Remote(net("::1/128"))]));
        assert!(permits
            .iter()
            .any(|s| s.layer == Layer::V4 && s.conds == vec![Cond::Remote(net("127.0.0.0/8"))]));
        assert!(permits
            .iter()
            .any(|s| s.conds.contains(&Cond::LocalPort(546))
                && s.conds.contains(&Cond::RemotePort(547))
                && s.conds.contains(&Cond::Remote(net("fe80::/10")))));
        // DHCPv4 has no link-local source to require.
        assert!(permits.iter().any(|s| s.layer == Layer::V4
            && s.conds.contains(&Cond::RemotePort(67))
            && !s.conds.iter().any(|c| matches!(c, Cond::Remote(_)))));
    }

    #[test]
    fn dhcp_permits_exclude_the_overlay_interface() {
        let d = DesiredRuleset {
            scopes: vec![Scope {
                id: "overlay:ygg0".into(),
                kind: ScopeKind::Overlay,
                matcher: ScopeMatch::Interface {
                    name: "ygg0".into(),
                    families: Families::Both,
                },
            }],
            rules: vec![],
        };
        let p = plan(&d);
        let dhcp: Vec<_> = p.iter().filter(|s| s.name.contains("dhcp")).collect();
        assert_eq!(dhcp.len(), 2);
        assert!(dhcp
            .iter()
            .all(|s| s.conds.contains(&Cond::NotArrivalIf("ygg0".into()))));
    }

    #[test]
    fn dhcpv6_reply_is_link_local_to_link_local() {
        let d = DesiredRuleset {
            scopes: vec![scope(
                "managed",
                ScopeMatch::Destinations(vec![ip("fd00::1")]),
            )],
            rules: vec![],
        };
        let p = plan(&d);
        let v6 = p
            .iter()
            .find(|s| s.name.ends_with("dhcpv6 reply"))
            .expect("dhcpv6 permit");
        assert!(v6.conds.contains(&Cond::Remote(net("fe80::/10"))));
        assert!(v6.conds.contains(&Cond::LocalNet(net("fe80::/10"))));
    }

    #[test]
    fn unresolved_interface_scope_is_skipped_not_fatal() {
        let d = DesiredRuleset {
            scopes: vec![
                scope(
                    "managed",
                    ScopeMatch::Destinations(vec![ip("fd00::1"), ip("301::1")]),
                ),
                Scope {
                    id: "overlay:ygg0".into(),
                    kind: ScopeKind::Overlay,
                    matcher: ScopeMatch::Interface {
                        name: "ygg0".into(),
                        families: Families::Both,
                    },
                },
                scope(
                    "host:Ethernet",
                    ScopeMatch::Interface {
                        name: "Ethernet".into(),
                        families: Families::V6,
                    },
                ),
            ],
            rules: vec![rule(
                "r",
                "fd00::1",
                Some("Ethernet"),
                Sources::Nets(vec![net("fd00::2/128")]),
            )],
        };
        let all = plan(&d);
        let only_ethernet = HashMap::from([("Ethernet".to_string(), 7u64)]);
        let kept = drop_unresolved(all.clone(), &only_ethernet);
        // The absent adapter's block (V6 and V4) is gone, everything else stays: the
        // managed-address blocks, the Ethernet block and the Ethernet permit.
        assert_eq!(all.len() - kept.len(), 2);
        assert!(kept
            .iter()
            .all(|s| !s.conds.contains(&Cond::ArrivalIf("ygg0".into()))));
        assert_eq!(
            kept.iter()
                .filter(|s| s.action == Action::Block && s.scope_id.as_deref() == Some("managed"))
                .count(),
            2
        );
        assert!(kept
            .iter()
            .any(|s| s.conds.contains(&Cond::ArrivalIf("Ethernet".into()))
                && s.action == Action::Permit));
        // The overlay exclusion of the DHCP permits disappears with the adapter.
        assert!(all
            .iter()
            .any(|s| s.conds.contains(&Cond::NotArrivalIf("ygg0".into()))));
        assert!(kept
            .iter()
            .filter(|s| s.name.contains("dhcp"))
            .all(|s| !s.conds.iter().any(|c| matches!(c, Cond::NotArrivalIf(_)))));
        // With every interface present nothing is dropped.
        let both = HashMap::from([("Ethernet".to_string(), 7u64), ("ygg0".to_string(), 8u64)]);
        assert_eq!(drop_unresolved(all.clone(), &both), all);
    }

    #[test]
    fn destination_scope_blocks_per_address_and_family() {
        let d = DesiredRuleset {
            scopes: vec![scope(
                "managed",
                ScopeMatch::Destinations(vec![ip("fd00::1"), ip("10.0.0.1")]),
            )],
            rules: vec![],
        };
        let p = plan(&d);
        let b = with_name(&p, "SocketGuard scope:managed");
        assert_eq!(b.len(), 2);
        assert!(b.iter().all(|s| s.action == Action::Block
            && s.weight == W_BLOCK
            && s.scope_id.as_deref() == Some("managed")));
        assert!(b
            .iter()
            .any(|s| s.layer == Layer::V6 && s.conds == vec![Cond::LocalAddr(ip("fd00::1"))]));
        assert!(b
            .iter()
            .any(|s| s.layer == Layer::V4 && s.conds == vec![Cond::LocalAddr(ip("10.0.0.1"))]));
    }

    #[test]
    fn interface_scope_families() {
        let mk = |f| DesiredRuleset {
            scopes: vec![scope(
                "ygg",
                ScopeMatch::Interface {
                    name: "ygg0".into(),
                    families: f,
                },
            )],
            rules: vec![],
        };
        let blocks = |f| -> Vec<Layer> {
            plan(&mk(f))
                .iter()
                .filter(|s| s.action == Action::Block)
                .map(|s| s.layer)
                .collect()
        };
        assert_eq!(blocks(Families::V6), vec![Layer::V6]);
        assert_eq!(blocks(Families::V4), vec![Layer::V4]);
        assert_eq!(blocks(Families::Both), vec![Layer::V6, Layer::V4]);
        let p = plan(&mk(Families::V6));
        let b = p.iter().find(|s| s.action == Action::Block).unwrap();
        assert_eq!(b.conds, vec![Cond::ArrivalIf("ygg0".into())]);
    }

    #[test]
    fn rule_with_nets_makes_one_permit_per_net_with_iif() {
        let d = DesiredRuleset {
            scopes: vec![],
            rules: vec![rule(
                "r1",
                "fd00::1",
                Some("ygg0"),
                Sources::Nets(vec![net("200::/7"), net("fd00::5/128")]),
            )],
        };
        let p = plan(&d);
        assert_eq!(p.len(), 2);
        for s in &p {
            assert_eq!(s.action, Action::Permit);
            assert_eq!(s.layer, Layer::V6);
            assert_eq!(s.weight, W_RULE);
            assert!(s.conds.contains(&Cond::LocalAddr(ip("fd00::1"))));
            assert!(s.conds.contains(&Cond::LocalPort(8080)));
            assert!(s.conds.contains(&Cond::Proto(6)));
            assert!(s.conds.contains(&Cond::ArrivalIf("ygg0".into())));
        }
        assert!(p[0].conds.contains(&Cond::Remote(net("200::/7"))));
        assert!(p[1].conds.contains(&Cond::Remote(net("fd00::5/128"))));
    }

    #[test]
    fn a_port_range_rule_has_a_range_condition() {
        let mut r = rule("range", "fd00::1", Some("ygg0"), Sources::Any);
        r.ports = "50000-51000/tcp".parse().unwrap();
        let p = plan(&DesiredRuleset {
            scopes: vec![],
            rules: vec![r],
        });
        assert_eq!(p.len(), 1);
        assert!(p[0].conds.contains(&Cond::LocalPortRange(50000, 51000)));
        assert!(!p[0].conds.iter().any(|c| matches!(c, Cond::LocalPort(_))));
        assert!(p[0].conds.contains(&Cond::Proto(6)));
        // A single port stays a plain port condition.
        let one = rule("one", "fd00::1", None, Sources::Any);
        let p = plan(&DesiredRuleset {
            scopes: vec![],
            rules: vec![one],
        });
        assert!(p[0].conds.contains(&Cond::LocalPort(8080)));
    }

    #[test]
    fn rule_any_source_v4_udp_has_no_remote_condition() {
        let mut r = rule("r2", "10.0.0.1", None, Sources::Any);
        r.ports.proto = Protocol::Udp;
        let p = plan(&DesiredRuleset {
            scopes: vec![],
            rules: vec![r],
        });
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].layer, Layer::V4);
        assert!(p[0].conds.contains(&Cond::Proto(17)));
        assert!(!p[0]
            .conds
            .iter()
            .any(|c| matches!(c, Cond::Remote(_) | Cond::ArrivalIf(_))));
    }

    #[test]
    fn host_ipv4_rule_is_on_the_v4_layer_without_a_local_address() {
        let mut r = rule("v4", "10.0.0.1", Some("Ethernet"), Sources::Any);
        r.dst = Dst::HostV4;
        r.sources = Sources::Nets(vec![net("192.168.1.5/32"), net("10.0.20.0/24")]);
        let p = plan(&DesiredRuleset {
            scopes: vec![],
            rules: vec![r],
        });
        assert_eq!(p.len(), 2);
        for s in &p {
            assert_eq!((s.layer, s.action), (Layer::V4, Action::Permit));
            assert!(!s.conds.iter().any(|c| matches!(c, Cond::LocalAddr(_))));
            assert!(s.conds.contains(&Cond::LocalPort(8080)));
            assert!(s.conds.contains(&Cond::ArrivalIf("Ethernet".into())));
        }
        assert!(p[0].conds.contains(&Cond::Remote(net("192.168.1.5/32"))));
        assert!(p[1].conds.contains(&Cond::Remote(net("10.0.20.0/24"))));
        // Everyone: a permit with no remote condition, still on the v4 layer only.
        let mut any = rule("v4any", "10.0.0.1", Some("Ethernet"), Sources::Any);
        any.dst = Dst::HostV4;
        let p = plan(&DesiredRuleset {
            scopes: vec![],
            rules: vec![any],
        });
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].layer, Layer::V4);
        assert!(!p[0].conds.iter().any(|c| matches!(c, Cond::Remote(_))));
    }

    #[test]
    fn mismatched_source_family_is_skipped() {
        let d = DesiredRuleset {
            scopes: vec![],
            rules: vec![rule(
                "r3",
                "fd00::1",
                None,
                Sources::Nets(vec![net("10.0.0.0/8"), net("fd00::/8")]),
            )],
        };
        let p = plan(&d);
        assert_eq!(p.len(), 1);
        assert!(p[0].conds.contains(&Cond::Remote(net("fd00::/8"))));
    }

    #[test]
    fn permits_outweigh_blocks() {
        const { assert!(W_ALWAYS > W_RULE && W_RULE > W_BLOCK) };
        const { assert!(W_ALWAYS <= 15) }; // FWP_UINT8 weights are 0..=15
    }
}
