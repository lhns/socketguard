//! The ruleset producer (ADR 0029): a pure function from a [`Snapshot`] of the daemon's
//! state to the [`DesiredRuleset`] that every platform backend renders and applies whole.
//! It is the only place that resolves policy (open, closed, ACL, ACL group) into rules.
//!
//! The lockout guard for whole-host protection (ADR 0026) lives here too, since it asks
//! "would the ruleset built with this setting still let remote admin in".

use crate::firewall::{DesiredRuleset, Families, Rule, Scope, ScopeKind, ScopeMatch, Sources};
use ipnet::{IpNet, Ipv6Net};
use socketguard_core::{
    AclEntry, AclGroup, BackendType, ListeningSocket, ManagedSocket, Policy, Protocol, SocketGroup,
    SocketGroupAclEntry, SocketGroupAddress,
};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use tracing::warn;

/// Settings key holding the JSON array of interface names under whole-host protection.
pub const PROTECT_HOST_KEY: &str = "protect_host_interfaces";

/// Everything the producer needs, gathered from the DB and config.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub sockets: Vec<SocketSnapshot>,
    pub acl_groups: Vec<AclGroupSnapshot>,
    pub socket_groups: Vec<SocketGroupSnapshot>,
    /// Active backend instances.
    pub backends: Vec<BackendInfo>,
    /// Interfaces under whole-host protection.
    pub protect_host: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SocketSnapshot {
    /// Carries the addresses (with their policy) and `acl_group_id`.
    pub socket: ManagedSocket,
    /// The socket's own ACL entries, all backends.
    pub acl: Vec<AclEntry>,
}

#[derive(Debug, Clone)]
pub struct AclGroupSnapshot {
    pub group: AclGroup,
    pub entries: Vec<AclEntry>,
}

#[derive(Debug, Clone)]
pub struct SocketGroupSnapshot {
    pub group: SocketGroup,
    /// (port, protocol) of each member socket.
    pub members: Vec<(u16, Protocol)>,
    pub addresses: Vec<SocketGroupAddress>,
    pub acl: Vec<SocketGroupAclEntry>,
}

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub id: String,
    pub backend_type: BackendType,
    pub interface: String,
}

/// Parse the stored `protect_host_interfaces` value; absent or invalid means off.
pub fn parse_protect_host(value: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = value
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    v.retain(|s| !s.trim().is_empty());
    v.sort();
    v.dedup();
    v
}

/// What an address's policy resolves to, before interface binding.
enum Resolved {
    Open,
    Nets(Vec<IpNet>),
}

/// Parse an ACL source: a bare address or a CIDR.
fn parse_source(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
}

fn nets<'a>(entries: impl Iterator<Item = &'a str>) -> Resolved {
    Resolved::Nets(
        entries
            .filter_map(|s| {
                let n = parse_source(s);
                if n.is_none() {
                    warn!("Ignoring unparseable ACL source {s:?}");
                }
                n
            })
            .collect(),
    )
}

/// Resolve one address's policy. A group policy resolves through the ACL group;
/// a missing group (or a group whose own policy is group) means closed with no ACL.
fn resolve(
    policy: Policy,
    backend_id: &str,
    own: Vec<(&str, &str)>,
    acl_group_id: Option<&str>,
    acl_groups: &[AclGroupSnapshot],
) -> Resolved {
    let own_nets = |entries: Vec<(&str, &str)>| {
        nets(
            entries
                .into_iter()
                .filter(|(b, _)| *b == backend_id)
                .map(|(_, ip)| ip),
        )
    };
    match policy {
        Policy::Open => Resolved::Open,
        Policy::Closed => own_nets(own),
        Policy::Group => {
            let group = acl_group_id.and_then(|id| acl_groups.iter().find(|g| g.group.id == id));
            match group {
                Some(g) => match g.group.policy {
                    Policy::Open => Resolved::Open,
                    Policy::Closed => own_nets(
                        g.entries
                            .iter()
                            .map(|e| (e.backend_id.as_str(), e.allowed_ip.as_str()))
                            .collect(),
                    ),
                    Policy::Group => Resolved::Nets(Vec::new()),
                },
                None => Resolved::Nets(Vec::new()),
            }
        }
    }
}

/// Whether a network lies inside the Yggdrasil range `200::/7`.
fn in_ygg_range(net: &IpNet) -> bool {
    let ygg: Ipv6Net = "200::/7".parse().unwrap();
    match net {
        IpNet::V6(n) => ygg.contains(n),
        IpNet::V4(_) => false,
    }
}

fn sorted_unique<T: Ord>(v: impl IntoIterator<Item = T>) -> Vec<T> {
    v.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

struct Builder {
    ygg_ifaces: Vec<String>,
    rules: BTreeMap<String, Rule>,
    warnings: BTreeSet<String>,
}

impl Builder {
    /// Emit the rules for one (destination, port, proto) with resolved sources. Sources
    /// inside `200::/7` are only trusted on a Yggdrasil interface (ADR 0028).
    fn emit(&mut self, base_id: String, dst: IpAddr, port: u16, proto: Protocol, r: Resolved) {
        let mut push = |id: String, iif: Option<String>, sources: Sources| {
            self.rules.insert(
                id.clone(),
                Rule {
                    id,
                    iif,
                    dst,
                    port,
                    proto,
                    sources,
                },
            );
        };
        match r {
            Resolved::Open => push(base_id, None, Sources::Any),
            Resolved::Nets(all) => {
                // A source of the other family can never match this destination.
                let (ygg, rest): (Vec<IpNet>, Vec<IpNet>) = all
                    .into_iter()
                    .filter(|n| n.addr().is_ipv4() == dst.is_ipv4())
                    .partition(in_ygg_range);
                let (ygg, rest) = (sorted_unique(ygg), sorted_unique(rest));
                if !rest.is_empty() {
                    push(base_id.clone(), None, Sources::Nets(rest));
                }
                if ygg.is_empty() {
                    return;
                }
                if self.ygg_ifaces.is_empty() {
                    self.warnings.insert(format!(
                        "Dropping 200::/7 sources for {base_id}: no Yggdrasil backend is configured"
                    ));
                }
                for iface in self.ygg_ifaces.clone() {
                    push(
                        format!("{base_id}:ygg:{iface}"),
                        Some(iface),
                        Sources::Nets(ygg.clone()),
                    );
                }
            }
        }
    }
}

/// Build the desired ruleset, also returning warnings the caller may want to log.
pub fn build_with_warnings(snap: &Snapshot) -> (DesiredRuleset, Vec<String>) {
    let ygg_ifaces = sorted_unique(
        snap.backends
            .iter()
            .filter(|b| b.backend_type == BackendType::Yggdrasil)
            .map(|b| b.interface.clone()),
    );
    let mut b = Builder {
        ygg_ifaces: ygg_ifaces.clone(),
        rules: BTreeMap::new(),
        warnings: BTreeSet::new(),
    };
    let mut managed: BTreeSet<IpAddr> = BTreeSet::new();

    for s in &snap.sockets {
        let sock = &s.socket;
        for addr in &sock.addresses {
            managed.insert(IpAddr::V6(addr.address));
            let own = s
                .acl
                .iter()
                .map(|e| (e.backend_id.as_str(), e.allowed_ip.as_str()))
                .collect();
            let resolved = resolve(
                addr.policy,
                &addr.backend_id,
                own,
                sock.acl_group_id.as_deref(),
                &snap.acl_groups,
            );
            b.emit(
                format!(
                    "s:{}:{}:{}:{}",
                    sock.id, addr.backend_id, sock.port, sock.protocol
                ),
                IpAddr::V6(addr.address),
                sock.port,
                sock.protocol,
                resolved,
            );
        }
    }

    for g in &snap.socket_groups {
        let members = sorted_unique(g.members.iter().map(|(p, pr)| (*p, pr.to_string())));
        for addr in &g.addresses {
            managed.insert(IpAddr::V6(addr.address));
            for (port, proto_name) in &members {
                let proto: Protocol = proto_name.parse().expect("round-trips Display");
                let own = g
                    .acl
                    .iter()
                    .map(|e| (e.backend_id.as_str(), e.allowed_ip.as_str()))
                    .collect();
                let resolved = resolve(
                    addr.policy,
                    &addr.backend_id,
                    own,
                    g.group.acl_group_id.as_deref(),
                    &snap.acl_groups,
                );
                b.emit(
                    format!("g:{}:{}:{port}:{proto}", g.group.id, addr.backend_id),
                    IpAddr::V6(addr.address),
                    *port,
                    proto,
                    resolved,
                );
            }
        }
    }

    // Most specific first, which is also how drops get attributed: the managed addresses,
    // then the overlays, then whole-host interfaces.
    let mut scopes = Vec::new();
    if !managed.is_empty() {
        scopes.push(Scope {
            id: "managed".to_string(),
            kind: ScopeKind::ManagedAddresses,
            matcher: ScopeMatch::Destinations(managed.into_iter().collect()),
        });
    }
    for iface in &ygg_ifaces {
        scopes.push(Scope {
            id: format!("overlay:{iface}"),
            kind: ScopeKind::Overlay,
            matcher: ScopeMatch::Interface {
                name: iface.clone(),
                families: Families::Both,
            },
        });
    }
    for iface in sorted_unique(snap.protect_host.iter().filter(|s| !s.is_empty()).cloned()) {
        scopes.push(Scope {
            id: format!("host:{iface}"),
            kind: ScopeKind::WholeHost,
            // IPv6 only: no grant can target an IPv4 address yet, so an IPv4 whole-host
            // scope would cut off the host's IPv4 services with no way to re-allow them.
            matcher: ScopeMatch::Interface {
                name: iface,
                families: Families::V6,
            },
        });
    }

    (
        DesiredRuleset {
            scopes,
            rules: b.rules.into_values().collect(),
        },
        b.warnings.into_iter().collect(),
    )
}

/// Build the desired ruleset, logging warnings.
pub fn build(snap: &Snapshot) -> DesiredRuleset {
    let (rs, warnings) = build_with_warnings(snap);
    for w in warnings {
        warn!("{w}");
    }
    rs
}

// ─── Lockout guard ───────────────────────────────────────────────────────────

/// An interface with the addresses it currently holds.
#[derive(Debug, Clone)]
pub struct HostInterface {
    pub name: String,
    pub addrs: Vec<IpAddr>,
}

/// A remote-admin listener that whole-host protection would cut off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockoutRisk {
    pub process_name: String,
    pub port: u16,
    pub protocol: Protocol,
    pub bind_address: IpAddr,
}

impl std::fmt::Display for LockoutRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} on {}:{}/{} has no grant",
            self.process_name, self.bind_address, self.port, self.protocol
        )
    }
}

fn is_remote_admin(l: &ListeningSocket) -> bool {
    let name = l.process_name.to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    matches!(l.port, 22 | 3389) || matches!(name, "sshd" | "xrdp" | "termservice")
}

/// Check that protecting `interfaces` would not lock out remote administration. A
/// listener is at risk when it is bound to a wildcard or to an address of those
/// interfaces and no rule in the would-be ruleset admits any source for it on them.
pub fn check_protect_host(
    snap: &Snapshot,
    listeners: &[ListeningSocket],
    interfaces: &[HostInterface],
) -> Result<(), Vec<LockoutRisk>> {
    if interfaces.is_empty() {
        return Ok(());
    }
    let would_be = Snapshot {
        protect_host: interfaces.iter().map(|i| i.name.clone()).collect(),
        ..snap.clone()
    };
    let (ruleset, _) = build_with_warnings(&would_be);
    let on_protected = |iif: &Option<String>| match iif {
        None => true,
        Some(n) => interfaces.iter().any(|i| &i.name == n),
    };

    // Destinations that are reachable on a protected interface: its live addresses plus
    // the managed addresses the snapshot places on it.
    let names: BTreeSet<&str> = interfaces.iter().map(|i| i.name.as_str()).collect();
    let mut on_iface: BTreeSet<IpAddr> = interfaces.iter().flat_map(|i| i.addrs.clone()).collect();
    for s in &snap.sockets {
        for a in &s.socket.addresses {
            if names.contains(a.interface.as_str()) {
                on_iface.insert(IpAddr::V6(a.address));
            }
        }
    }
    for g in &snap.socket_groups {
        for a in &g.addresses {
            if names.contains(a.interface.as_str()) {
                on_iface.insert(IpAddr::V6(a.address));
            }
        }
    }

    let mut risks = BTreeSet::new();
    for l in listeners.iter().filter(|l| is_remote_admin(l)) {
        let ip = l.bind_address;
        if ip.is_loopback() {
            continue;
        }
        let exposed = ip.is_unspecified() || interfaces.iter().any(|i| i.addrs.contains(&ip));
        if !exposed {
            continue;
        }
        let allowed = ruleset.rules.iter().any(|r| {
            r.port == l.port
                && r.proto == l.protocol
                && (ip.is_unspecified() || r.dst == ip)
                && on_iface.contains(&r.dst)
                && on_protected(&r.iif)
        });
        if !allowed {
            risks.insert((l.port, l.protocol.to_string(), l.process_name.clone(), ip));
        }
    }
    if risks.is_empty() {
        Ok(())
    } else {
        Err(risks
            .into_iter()
            .map(|(port, proto, process_name, bind_address)| LockoutRisk {
                process_name,
                port,
                protocol: proto.parse().expect("round-trips Display"),
                bind_address,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socketguard_core::SocketAddress;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sock(id: &str, port: u16, addrs: Vec<SocketAddress>) -> SocketSnapshot {
        SocketSnapshot {
            socket: ManagedSocket {
                id: id.into(),
                pid: 1,
                process_name: "app".into(),
                port,
                protocol: Protocol::Tcp,
                addresses: addrs,
                policy: Policy::Closed,
                exe_path: None,
                cmdline: None,
                first_seen: chrono::Utc::now(),
                last_seen: chrono::Utc::now(),
                acl_group_id: None,
                socket_group_ids: vec![],
            },
            acl: vec![],
        }
    }

    fn saddr(backend: &str, bt: BackendType, a: &str, iface: &str, p: Policy) -> SocketAddress {
        SocketAddress {
            backend_id: backend.into(),
            backend_type: bt,
            address: a.parse().unwrap(),
            interface: iface.into(),
            prefix_len: 128,
            policy: p,
        }
    }

    fn acl(sid: &str, backend: &str, src: &str) -> AclEntry {
        AclEntry {
            id: 0,
            socket_id: sid.into(),
            backend_id: backend.into(),
            allowed_ip: src.into(),
            label: None,
            created_at: chrono::Utc::now(),
        }
    }

    fn ula_snap(policy: Policy) -> Snapshot {
        Snapshot {
            sockets: vec![sock(
                "a",
                80,
                vec![saddr("ula", BackendType::Ula, "fd00::1", "lo", policy)],
            )],
            backends: vec![BackendInfo {
                id: "ula".into(),
                backend_type: BackendType::Ula,
                interface: "lo".into(),
            }],
            ..Snapshot::default()
        }
    }

    fn ygg_backend() -> BackendInfo {
        BackendInfo {
            id: "ygg".into(),
            backend_type: BackendType::Yggdrasil,
            interface: "ygg0".into(),
        }
    }

    fn managed(rs: &DesiredRuleset) -> Vec<IpAddr> {
        match &rs
            .scopes
            .iter()
            .find(|s| s.id == "managed")
            .unwrap()
            .matcher
        {
            ScopeMatch::Destinations(d) => d.clone(),
            _ => panic!("managed scope must match destinations"),
        }
    }

    #[test]
    fn open_gives_any_source() {
        let rs = build(&ula_snap(Policy::Open));
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].id, "s:a:ula:80:tcp");
        assert_eq!(rs.rules[0].sources, Sources::Any);
        assert_eq!(rs.rules[0].iif, None);
        assert_eq!(managed(&rs), vec![ip("fd00::1")]);
    }

    #[test]
    fn closed_without_acl_is_denied_not_inactive() {
        let rs = build(&ula_snap(Policy::Closed));
        assert!(rs.rules.is_empty());
        assert_eq!(managed(&rs), vec![ip("fd00::1")]);
    }

    #[test]
    fn closed_with_acl_allows_listed_sources() {
        let mut s = ula_snap(Policy::Closed);
        s.sockets[0].acl = vec![
            acl("a", "ula", "fd00::20"),
            acl("a", "ula", "fd00::10"),
            acl("a", "other", "fd00::99"),
            acl("a", "ula", "fd00::10"),
            acl("a", "ula", "fd00:5::/32"),
            acl("a", "ula", "garbage"),
        ];
        let rs = build(&s);
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(
            rs.rules[0].sources,
            Sources::Nets(vec![
                "fd00::10/128".parse().unwrap(),
                "fd00::20/128".parse().unwrap(),
                "fd00:5::/32".parse().unwrap(),
            ])
        );
    }

    fn with_acl_group(policy: Policy, entries: &[&str]) -> Snapshot {
        let mut s = ula_snap(Policy::Group);
        s.sockets[0].socket.acl_group_id = Some("grp".into());
        s.acl_groups = vec![AclGroupSnapshot {
            group: AclGroup {
                id: "grp".into(),
                label: "g".into(),
                policy,
                created_at: chrono::Utc::now(),
            },
            entries: entries.iter().map(|e| acl("", "ula", e)).collect(),
        }];
        s
    }

    #[test]
    fn group_policy_resolves_through_acl_group() {
        let rs = build(&with_acl_group(Policy::Closed, &["fd00::7"]));
        assert_eq!(
            rs.rules[0].sources,
            Sources::Nets(vec!["fd00::7/128".parse().unwrap()])
        );
        let rs = build(&with_acl_group(Policy::Open, &[]));
        assert_eq!(rs.rules[0].sources, Sources::Any);
        // A group that itself says "group" and an empty group allow nothing.
        assert!(build(&with_acl_group(Policy::Group, &["fd00::7"]))
            .rules
            .is_empty());
        assert!(build(&with_acl_group(Policy::Closed, &[])).rules.is_empty());
    }

    #[test]
    fn missing_acl_group_means_closed() {
        let mut s = with_acl_group(Policy::Open, &[]);
        s.sockets[0].socket.acl_group_id = None;
        let rs = build(&s);
        assert!(rs.rules.is_empty());
        assert_eq!(managed(&rs).len(), 1);
        s.sockets[0].socket.acl_group_id = Some("gone".into());
        assert!(build(&s).rules.is_empty());
    }

    fn socket_group(policy: Policy) -> Snapshot {
        let mut s = Snapshot {
            backends: vec![BackendInfo {
                id: "ula".into(),
                backend_type: BackendType::Ula,
                interface: "lo".into(),
            }],
            ..Snapshot::default()
        };
        s.socket_groups = vec![SocketGroupSnapshot {
            group: SocketGroup {
                id: "sg1".into(),
                label: "web".into(),
                app_name: "web".into(),
                acl_group_id: None,
                created_at: chrono::Utc::now(),
            },
            members: vec![
                (443, Protocol::Tcp),
                (80, Protocol::Tcp),
                (80, Protocol::Tcp),
                (53, Protocol::Udp),
            ],
            addresses: vec![SocketGroupAddress {
                group_id: "sg1".into(),
                backend_id: "ula".into(),
                address: "fd00::9".parse().unwrap(),
                interface: "lo".into(),
                prefix_len: 128,
                policy,
            }],
            acl: vec![SocketGroupAclEntry {
                id: 1,
                group_id: "sg1".into(),
                backend_id: "ula".into(),
                allowed_ip: "fd00::5".into(),
                label: None,
                created_at: chrono::Utc::now(),
            }],
        }];
        s
    }

    #[test]
    fn socket_group_emits_one_rule_per_member() {
        let rs = build(&socket_group(Policy::Closed));
        let ids: Vec<_> = rs.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            ["g:sg1:ula:443:tcp", "g:sg1:ula:53:udp", "g:sg1:ula:80:tcp"]
        );
        assert!(rs.rules.iter().all(|r| r.dst == ip("fd00::9")));
        assert_eq!(managed(&rs), vec![ip("fd00::9")]);

        let rs = build(&socket_group(Policy::Open));
        assert!(rs.rules.iter().all(|r| r.sources == Sources::Any));
    }

    #[test]
    fn socket_group_group_policy_uses_linked_acl_group() {
        let mut s = socket_group(Policy::Group);
        assert!(build(&s).rules.is_empty());
        s.socket_groups[0].group.acl_group_id = Some("grp".into());
        s.acl_groups = vec![AclGroupSnapshot {
            group: AclGroup {
                id: "grp".into(),
                label: "g".into(),
                policy: Policy::Closed,
                created_at: chrono::Utc::now(),
            },
            entries: vec![acl("", "ula", "fd00::77")],
        }];
        let rs = build(&s);
        assert_eq!(rs.rules.len(), 3);
        assert_eq!(
            rs.rules[0].sources,
            Sources::Nets(vec!["fd00::77/128".parse().unwrap()])
        );
    }

    fn ygg_snap() -> Snapshot {
        let mut s = Snapshot {
            sockets: vec![sock(
                "w",
                8080,
                vec![saddr(
                    "ygg",
                    BackendType::Yggdrasil,
                    "301::1",
                    "ygg0",
                    Policy::Closed,
                )],
            )],
            backends: vec![ygg_backend()],
            ..Snapshot::default()
        };
        s.sockets[0].acl = vec![
            acl("w", "ygg", "200:1::5"),
            acl("w", "ygg", "300:2:3:4::/64"),
            acl("w", "ygg", "fd00::5"),
        ];
        s
    }

    #[test]
    fn ygg_sources_are_bound_to_the_ygg_interface() {
        let rs = build(&ygg_snap());
        assert_eq!(rs.rules.len(), 2);
        let plain = &rs.rules[0];
        assert_eq!(plain.id, "s:w:ygg:8080:tcp");
        assert_eq!(plain.iif, None);
        assert_eq!(
            plain.sources,
            Sources::Nets(vec!["fd00::5/128".parse().unwrap()])
        );
        let bound = &rs.rules[1];
        assert_eq!(bound.id, "s:w:ygg:8080:tcp:ygg:ygg0");
        assert_eq!(bound.iif.as_deref(), Some("ygg0"));
        assert_eq!(
            bound.sources,
            Sources::Nets(vec![
                "200:1::5/128".parse().unwrap(),
                "300:2:3:4::/64".parse().unwrap()
            ])
        );
    }

    #[test]
    fn ygg_sources_without_ygg_backend_are_dropped() {
        let mut s = ygg_snap();
        s.backends.clear();
        let (rs, warnings) = build_with_warnings(&s);
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].iif, None);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("no Yggdrasil backend"));
        // Only 200::/7 sources: no rule at all.
        s.sockets[0].acl = vec![acl("w", "ygg", "200:1::5")];
        assert!(build(&s).rules.is_empty());
    }

    #[test]
    fn one_ygg_rule_per_ygg_interface() {
        let mut s = ygg_snap();
        s.backends.push(BackendInfo {
            id: "ygg2".into(),
            backend_type: BackendType::Yggdrasil,
            interface: "ygg1".into(),
        });
        let rs = build(&s);
        let bound: Vec<_> = rs.rules.iter().filter_map(|r| r.iif.as_deref()).collect();
        assert_eq!(bound, ["ygg0", "ygg1"]);
        let ids: BTreeSet<_> = rs.rules.iter().map(|r| &r.id).collect();
        assert_eq!(ids.len(), rs.rules.len());
    }

    #[test]
    fn overlay_scope_per_ygg_backend() {
        let mut s = ula_snap(Policy::Closed);
        s.backends.push(ygg_backend());
        let rs = build(&s);
        let overlay = rs.scopes.iter().find(|s| s.id == "overlay:ygg0").unwrap();
        assert_eq!(overlay.kind, ScopeKind::Overlay);
        assert_eq!(
            overlay.matcher,
            ScopeMatch::Interface {
                name: "ygg0".into(),
                families: Families::Both
            }
        );
        assert_eq!(rs.scopes.len(), 2);
    }

    #[test]
    fn overlay_scope_exists_without_any_socket() {
        let s = Snapshot {
            backends: vec![ygg_backend()],
            ..Snapshot::default()
        };
        let rs = build(&s);
        assert_eq!(rs.scopes.len(), 1);
        assert_eq!(rs.scopes[0].id, "overlay:ygg0");
        assert!(rs.rules.is_empty());
    }

    #[test]
    fn whole_host_scope_per_interface() {
        let mut s = ula_snap(Policy::Closed);
        assert_eq!(build(&s).scopes.len(), 1);
        s.protect_host = vec!["eth1".into(), "eth0".into(), "eth0".into(), "".into()];
        let rs = build(&s);
        let ids: Vec<_> = rs.scopes.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["managed", "host:eth0", "host:eth1"]);
        assert_eq!(rs.scopes[1].kind, ScopeKind::WholeHost);
        assert!(matches!(
            rs.scopes[1].matcher,
            ScopeMatch::Interface {
                families: Families::V6,
                ..
            }
        ));
    }

    #[test]
    fn parse_protect_host_setting() {
        assert!(parse_protect_host(None).is_empty());
        assert!(parse_protect_host(Some("[]")).is_empty());
        assert!(parse_protect_host(Some("not json")).is_empty());
        assert_eq!(parse_protect_host(Some(r#"["b","a","a",""]"#)), ["a", "b"]);
    }

    #[test]
    fn output_is_deterministic() {
        let mut a = ygg_snap();
        a.sockets.push(sock(
            "z",
            22,
            vec![saddr(
                "ula",
                BackendType::Ula,
                "fd00::2",
                "lo",
                Policy::Open,
            )],
        ));
        a.protect_host = vec!["eth0".into(), "eth1".into()];
        let mut b = a.clone();
        b.sockets.reverse();
        b.sockets[0].acl.reverse();
        b.protect_host.reverse();
        b.backends.reverse();
        assert_eq!(build(&a), build(&b));
        let ids: Vec<_> = build(&a).rules.iter().map(|r| r.id.clone()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    // ─── Lockout guard ───────────────────────────────────────────────────

    fn listener(name: &str, port: u16, bind: &str) -> ListeningSocket {
        ListeningSocket {
            pid: 1,
            process_name: name.into(),
            port,
            protocol: Protocol::Tcp,
            bind_address: ip(bind),
            exe_path: None,
            cmdline: None,
        }
    }

    fn eth0() -> Vec<HostInterface> {
        vec![HostInterface {
            name: "eth0".into(),
            addrs: vec![ip("192.168.1.5")],
        }]
    }

    #[test]
    fn lockout_wildcard_sshd_without_grant_is_a_risk() {
        let risks =
            check_protect_host(&Snapshot::default(), &[listener("sshd", 22, "::")], &eth0())
                .unwrap_err();
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].port, 22);
    }

    #[test]
    fn lockout_detects_rdp_by_port_and_name() {
        let ls = [
            listener("svchost", 3389, "0.0.0.0"),
            listener("xrdp", 5000, "::"),
            listener("TermService.exe", 5001, "::"),
            listener("nginx", 80, "::"),
        ];
        let risks = check_protect_host(&Snapshot::default(), &ls, &eth0()).unwrap_err();
        assert_eq!(risks.len(), 3);
    }

    #[test]
    fn lockout_ignores_loopback_and_other_interfaces() {
        let ls = [
            listener("sshd", 22, "127.0.0.1"),
            listener("sshd", 22, "::1"),
            listener("sshd", 2222, "10.9.9.9"),
            listener("sshd", 22, "10.9.9.9"),
        ];
        assert!(check_protect_host(&Snapshot::default(), &ls, &eth0()).is_ok());
        // Bound to an address of the protected interface: at risk.
        let ls = [listener("sshd", 22, "192.168.1.5")];
        assert!(check_protect_host(&Snapshot::default(), &ls, &eth0()).is_err());
    }

    #[test]
    fn lockout_cleared_by_a_rule_for_the_listener() {
        // The managed address lives on `lo` here, so protect `lo`.
        let lo = [HostInterface {
            name: "lo".into(),
            addrs: vec![],
        }];
        let mut s = ula_snap(Policy::Open);
        s.sockets[0].socket.port = 22;
        s.sockets[0].socket.process_name = "sshd".into();
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &lo).is_ok());
        // A closed socket without ACL has no rule: still a risk.
        let s = {
            let mut s = s;
            s.sockets[0].socket.addresses[0].policy = Policy::Closed;
            s
        };
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &lo).is_err());
    }

    #[test]
    fn lockout_rule_for_an_address_on_another_interface_does_not_help() {
        // sshd is open on a ULA on `lo`, but the host scope on eth0 still drops SSH to
        // eth0's own addresses.
        let mut s = ula_snap(Policy::Open);
        s.sockets[0].socket.port = 22;
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &eth0()).is_err());
        // A managed address on eth0 itself does help.
        s.sockets[0].socket.addresses[0].interface = "eth0".into();
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &eth0()).is_ok());
    }

    #[test]
    fn lockout_rule_bound_to_another_interface_does_not_help() {
        let mut s = ygg_snap();
        s.sockets[0].socket.port = 22;
        // The only rule for port 22 is the ygg0-bound one plus a plain one; remove plain.
        s.sockets[0].acl = vec![acl("w", "ygg", "200:1::5")];
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &eth0()).is_err());
    }

    #[test]
    fn lockout_empty_interfaces_is_ok() {
        assert!(
            check_protect_host(&Snapshot::default(), &[listener("sshd", 22, "::")], &[]).is_ok()
        );
    }
}
