//! The ruleset producer (ADR 0029): a pure function from a [`Snapshot`] of the daemon's
//! state to the [`DesiredRuleset`] that every platform backend renders and applies whole.
//! It is the only place that turns grants into rules.
//!
//! The lockout guard for whole-host protection (ADR 0026) lives here too, since it asks
//! "would the ruleset built with this setting still let remote admin in".

use crate::firewall::{DesiredRuleset, Families, Rule, Scope, ScopeKind, ScopeMatch, Sources};
use ipnet::IpNet;
use socketguard_core::{
    app_identity, credential_source, valid_interface_name, App, Credential, Grant, ListeningSocket,
    Network, NetworkKind, Peer, PeerGroup, PortRef, PortSet, Protocol, Subject,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use tracing::warn;

/// Everything the producer needs, gathered from the DB and the active networks.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Apps with their ports and addresses.
    pub apps: Vec<App>,
    pub networks: Vec<Network>,
    pub peers: Vec<Peer>,
    pub groups: Vec<PeerGroup>,
    pub grants: Vec<Grant>,
    /// Interfaces under whole-host protection.
    pub protect_host: Vec<String>,
    /// Addresses the daemon owns on interfaces, whether or not an app still has them
    /// (retiring ones included): denied until they are really gone.
    pub owned: Vec<IpAddr>,
}

fn sorted_unique<T: Ord>(v: impl IntoIterator<Item = T>) -> Vec<T> {
    v.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

/// The ports an address serves: its `Only` list, or for `All` every app port that no
/// `Only` address on the same network claims.
pub(crate) fn served_ports(app: &App, address: &socketguard_core::Address) -> BTreeSet<PortRef> {
    match &address.ports {
        PortSet::Only(list) => list.iter().copied().collect(),
        PortSet::All => {
            let claimed: BTreeSet<PortRef> = app
                .addresses
                .iter()
                .filter(|a| a.network_id == address.network_id)
                .filter_map(|a| match &a.ports {
                    PortSet::Only(list) => Some(list.iter().copied()),
                    PortSet::All => None,
                })
                .flatten()
                .collect();
            app.ports
                .iter()
                .map(|p| PortRef {
                    port: p.port,
                    proto: p.proto,
                })
                .filter(|p| !claimed.contains(p))
                .collect()
        }
    }
}

/// The credentials of a grant's peers (all members of a group); empty for Anyone.
pub(crate) fn subject_credentials<'a>(
    snap: &'a Snapshot,
    peers: &HashMap<&'a str, &'a Peer>,
    subject: &Subject,
) -> Vec<&'a Credential> {
    match subject {
        Subject::Anyone => Vec::new(),
        Subject::Peer(id) => peers
            .get(id.as_str())
            .map(|p| p.credentials.iter().collect())
            .unwrap_or_default(),
        Subject::Group(id) => snap
            .groups
            .iter()
            .find(|g| &g.id == id)
            .map(|g| {
                g.members
                    .iter()
                    .filter_map(|m| peers.get(m.as_str()))
                    .flat_map(|p| p.credentials.iter())
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Build the desired ruleset, also returning warnings the caller may want to log.
///
/// - Managed scope: every IP locator of every app, so an address is denied from the
///   moment it exists.
/// - An overlay scope per Yggdrasil network, a whole-host scope per protected interface
///   (IPv6 only: no grant can name an IPv4 address yet, so an IPv4 whole-host scope would
///   be unremediable).
/// - Rules: for each IP address, each port it serves, each grant that applies, the
///   sources of the subject's credentials that are reachable on the address's network,
///   aggregated so that no source network overlaps another (nft rejects overlapping set
///   elements). Every rule is bound to its network's interface, not only Yggdrasil ones,
///   so a forged source on another interface is refused (ADR 0028). Anyone gives
///   `Sources::Any`, bound the same way.
///
/// Rule ids are `a:<address>:<port>:<proto>:<grant>`, plus `:<interface>` for the rule
/// bound to an interface. Unique, and stable while the grant and address live.
pub fn build_with_warnings(snap: &Snapshot) -> (DesiredRuleset, Vec<String>) {
    let networks: HashMap<&str, &Network> =
        snap.networks.iter().map(|n| (n.id.as_str(), n)).collect();
    let peers: HashMap<&str, &Peer> = snap.peers.iter().map(|p| (p.id.as_str(), p)).collect();
    let ygg_ifaces = sorted_unique(
        snap.networks
            .iter()
            .filter(|n| n.kind == NetworkKind::Yggdrasil)
            .filter_map(|n| n.interface.clone())
            .filter(|i| valid_interface_name(i)),
    );

    let mut rules: BTreeMap<String, Rule> = BTreeMap::new();
    let mut warnings: BTreeSet<String> = BTreeSet::new();
    let mut managed: BTreeSet<IpAddr> = snap.owned.iter().copied().collect();

    for app in &snap.apps {
        for address in &app.addresses {
            let Some(addr) = address.locator.ipv6() else {
                continue; // not an IP locator: enforced elsewhere (ADR 0037)
            };
            let dst = IpAddr::V6(addr);
            managed.insert(dst);
            let Some(network) = networks.get(address.network_id.as_str()) else {
                continue;
            };
            if !network.grants_apply {
                continue;
            }
            let iif = match &network.interface {
                Some(i) if valid_interface_name(i) => Some(i.clone()),
                Some(i) => {
                    warnings.insert(format!(
                        "Network {} has the invalid interface name {i:?}; it gets no grant rules",
                        network.id
                    ));
                    continue;
                }
                None => None,
            };
            let served = served_ports(app, address);
            for grant in snap.grants.iter().filter(|g| {
                g.app_id == app.id
                    && g.network_id
                        .as_deref()
                        .is_none_or(|n| n == address.network_id)
            }) {
                let creds = subject_credentials(snap, &peers, &grant.subject);
                // Sources per interface binding; the same for every port of this grant.
                let mut bound: BTreeMap<Option<String>, Vec<IpNet>> = BTreeMap::new();
                if grant.subject != Subject::Anyone {
                    for c in creds {
                        let Some(net) = credential_source(c, network) else {
                            continue;
                        };
                        if network.kind == NetworkKind::Yggdrasil && iif.is_none() {
                            warnings.insert(format!(
                                "Network {} has no interface; skipping its Yggdrasil sources",
                                network.id
                            ));
                            continue;
                        }
                        bound.entry(iif.clone()).or_default().push(net);
                    }
                }
                for port in served
                    .iter()
                    .filter(|p| grant.port.is_none_or(|gp| gp == **p))
                {
                    let base =
                        format!("a:{}:{}:{}:{}", address.id, port.port, port.proto, grant.id);
                    let mut push = |id: String, iif: Option<String>, sources: Sources| {
                        rules.insert(
                            id.clone(),
                            Rule {
                                id,
                                iif,
                                dst,
                                port: port.port,
                                proto: port.proto,
                                sources,
                            },
                        );
                    };
                    if grant.subject == Subject::Anyone {
                        let id = match &iif {
                            Some(i) => format!("{base}:{i}"),
                            None => base,
                        };
                        push(id, iif.clone(), Sources::Any);
                        continue;
                    }
                    for (bound_iif, nets) in &bound {
                        let id = match bound_iif {
                            Some(i) => format!("{base}:{i}"),
                            None => base.clone(),
                        };
                        push(id, bound_iif.clone(), Sources::Nets(IpNet::aggregate(nets)));
                    }
                }
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
    for iface in sorted_unique(
        snap.protect_host
            .iter()
            .filter(|s| !s.is_empty())
            .filter(|s| {
                let ok = valid_interface_name(s);
                if !ok {
                    warnings.insert(format!(
                        "Ignoring the invalid protected interface name {s:?}"
                    ));
                }
                ok
            })
            .cloned(),
    ) {
        scopes.push(Scope {
            id: format!("host:{iface}"),
            kind: ScopeKind::WholeHost,
            matcher: ScopeMatch::Interface {
                name: iface,
                families: Families::V6,
            },
        });
    }

    (
        DesiredRuleset {
            scopes,
            rules: rules.into_values().collect(),
        },
        warnings.into_iter().collect(),
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
    /// The app the listener belongs to.
    pub app_id: String,
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
/// interfaces and no rule in the would-be ruleset admits any source to its app on them:
/// that is, no grant reaches it from a reachable credential, or from Anyone, through an
/// address on a protected interface.
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
    let mut app_of_dst: HashMap<IpAddr, &str> = HashMap::new();
    for app in &snap.apps {
        for a in &app.addresses {
            let Some(addr) = a.locator.ipv6() else {
                continue;
            };
            app_of_dst.insert(IpAddr::V6(addr), app.id.as_str());
            let on_names = snap
                .networks
                .iter()
                .find(|n| n.id == a.network_id)
                .and_then(|n| n.interface.as_deref())
                .is_some_and(|i| names.contains(i));
            if on_names {
                on_iface.insert(IpAddr::V6(addr));
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
        let app_id = app_identity(l).id;
        let allowed = ruleset.rules.iter().any(|r| {
            r.port == l.port
                && r.proto == l.protocol
                && (ip.is_unspecified() || r.dst == ip)
                && on_iface.contains(&r.dst)
                && on_protected(&r.iif)
                && app_of_dst.get(&r.dst) == Some(&app_id.as_str())
        });
        if !allowed {
            risks.insert((
                l.port,
                l.protocol.to_string(),
                l.process_name.clone(),
                ip,
                app_id,
            ));
        }
    }
    if risks.is_empty() {
        Ok(())
    } else {
        Err(risks
            .into_iter()
            .map(
                |(port, proto, process_name, bind_address, app_id)| LockoutRisk {
                    app_id,
                    process_name,
                    port,
                    protocol: proto.parse().expect("round-trips Display"),
                    bind_address,
                },
            )
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use socketguard_core::{Address, AppPort, CredentialKind, Locator, NetworkStatus, Reach};

    const KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";
    const KEY_ADDR: &str = "200:8af8:ba35:56ae:bef0:6284:981f:5972/128";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn tcp(port: u16) -> PortRef {
        PortRef {
            port,
            proto: Protocol::Tcp,
        }
    }

    fn network(id: &str, kind: NetworkKind, iface: &str, prefix: Option<&str>) -> Network {
        Network {
            id: id.into(),
            kind,
            name: id.into(),
            interface: Some(iface.into()),
            grants_apply: kind != NetworkKind::Local,
            status: NetworkStatus::Up,
            prefix: prefix.map(|p| p.parse().unwrap()),
        }
    }

    fn local() -> Network {
        network("local", NetworkKind::Local, "lo", None)
    }
    fn lan() -> Network {
        network("lan", NetworkKind::Lan, "eth0", Some("2001:db8:1:2::"))
    }
    fn ygg() -> Network {
        network("ygg", NetworkKind::Yggdrasil, "ygg0", Some("300:1:2:3::"))
    }

    fn address(id: &str, app: &str, net: &str, addr: &str, ports: PortSet) -> Address {
        Address {
            id: id.into(),
            app_id: app.into(),
            network_id: net.into(),
            ports,
            locator: Locator::Ipv6 {
                addr: addr.parse().unwrap(),
            },
            created_at: Utc::now(),
        }
    }

    fn app(id: &str, ports: &[u16], addresses: Vec<Address>) -> App {
        App {
            id: id.into(),
            name: id.into(),
            process_name: id.into(),
            exe_path: None,
            interpreter_arg: None,
            identity_note: None,
            reviewed: true,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            ports: ports
                .iter()
                .map(|p| AppPort {
                    port: *p,
                    proto: Protocol::Tcp,
                    listening: true,
                    last_seen: Utc::now(),
                })
                .collect(),
            addresses,
        }
    }

    fn peer(id: &str, creds: &[(CredentialKind, &str)]) -> Peer {
        Peer {
            id: id.into(),
            label: id.into(),
            credentials: creds
                .iter()
                .enumerate()
                .map(|(i, (k, v))| Credential {
                    id: format!("{id}-c{i}"),
                    kind: *k,
                    value: (*v).into(),
                    label: None,
                })
                .collect(),
            groups: vec![],
            created_at: Utc::now(),
        }
    }

    fn grant(id: &str, app: &str, subject: Subject) -> Grant {
        Grant {
            id: id.into(),
            app_id: app.into(),
            port: None,
            network_id: None,
            subject,
            created_at: Utc::now(),
        }
    }

    /// One app "web" on 8080 with an address on every network; no grants yet.
    fn base() -> Snapshot {
        Snapshot {
            apps: vec![app(
                "web",
                &[8080],
                vec![
                    address("al", "web", "local", "fd00::1", PortSet::All),
                    address("an", "web", "lan", "2001:db8:1:2::100", PortSet::All),
                    address("ay", "web", "ygg", "300:1:2:3::100", PortSet::All),
                ],
            )],
            networks: vec![local(), lan(), ygg()],
            ..Snapshot::default()
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

    fn ids(rs: &DesiredRuleset) -> Vec<&str> {
        rs.rules.iter().map(|r| r.id.as_str()).collect()
    }

    #[test]
    fn no_grants_means_no_rules_but_every_address_is_managed() {
        let rs = build(&base());
        assert!(rs.rules.is_empty());
        assert_eq!(
            managed(&rs),
            vec![ip("fd00::1"), ip("2001:db8:1:2::100"), ip("300:1:2:3::100")]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
        let scope_ids: Vec<_> = rs.scopes.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(scope_ids, ["managed", "overlay:ygg0"]);
    }

    #[test]
    fn anyone_is_open_on_every_network_that_takes_grants() {
        let mut s = base();
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let rs = build(&s);
        assert_eq!(ids(&rs), ["a:an:8080:tcp:g:eth0", "a:ay:8080:tcp:g:ygg0"]);
        // Anyone is bound to the network's interface like any other rule.
        assert!(rs.rules.iter().all(|r| r.sources == Sources::Any));
        assert_eq!(rs.rules[0].iif.as_deref(), Some("eth0"));
        assert_eq!(rs.rules[1].iif.as_deref(), Some("ygg0"));
        // Local is this machine only: no rule for it, though its address is managed.
        assert!(managed(&rs).contains(&ip("fd00::1")));
    }

    #[test]
    fn ygg_key_peer_gets_an_interface_bound_rule() {
        let mut s = base();
        s.peers = vec![peer("b", &[(CredentialKind::YggKey, KEY)])];
        s.grants = vec![grant("g", "web", Subject::Peer("b".into()))];
        let rs = build(&s);
        // Not reachable on the LAN, verified on Yggdrasil.
        assert_eq!(ids(&rs), ["a:ay:8080:tcp:g:ygg0"]);
        let r = &rs.rules[0];
        assert_eq!(r.iif.as_deref(), Some("ygg0"));
        assert_eq!(r.dst, ip("300:1:2:3::100"));
        assert_eq!(r.sources, Sources::Nets(vec![KEY_ADDR.parse().unwrap()]));
    }

    #[test]
    fn lan_ip_peer_gets_an_interface_bound_rule_only_on_the_lan() {
        let mut s = base();
        s.peers = vec![peer("p", &[(CredentialKind::Ip, "fd00:5a::2/128")])];
        s.grants = vec![grant("g", "web", Subject::Peer("p".into()))];
        let rs = build(&s);
        assert_eq!(ids(&rs), ["a:an:8080:tcp:g:eth0"]);
        assert_eq!(rs.rules[0].iif.as_deref(), Some("eth0"));
        assert_eq!(rs.rules[0].dst, ip("2001:db8:1:2::100"));
    }

    #[test]
    fn credentials_merge_per_binding_and_split_across_bindings() {
        let mut s = base();
        s.grants = vec![grant("g", "web", Subject::Group("grp".into()))];
        s.peers = vec![
            peer(
                "b",
                &[
                    (CredentialKind::YggKey, KEY),
                    (CredentialKind::YggSubnet, "300:7:7:7::/64"),
                    (CredentialKind::Ip, "fd00::9/128"),
                ],
            ),
            peer("c", &[(CredentialKind::YggAddr, "200:1::5")]),
        ];
        s.groups = vec![PeerGroup {
            id: "grp".into(),
            label: "grp".into(),
            members: vec!["c".into(), "b".into()],
            created_at: Utc::now(),
        }];
        let rs = build(&s);
        assert_eq!(ids(&rs), ["a:an:8080:tcp:g:eth0", "a:ay:8080:tcp:g:ygg0"]);
        let ygg_rule = &rs.rules[1];
        assert_eq!(
            ygg_rule.sources,
            Sources::Nets(vec![
                "200:1::5/128".parse().unwrap(),
                KEY_ADDR.parse().unwrap(),
                "300:7:7:7::/64".parse().unwrap(),
            ])
        );
        let lan_rule = &rs.rules[0];
        assert_eq!(
            lan_rule.sources,
            Sources::Nets(vec!["fd00::9/128".parse().unwrap()])
        );
        let unique: BTreeSet<_> = ids(&rs).into_iter().collect();
        assert_eq!(unique.len(), rs.rules.len());
    }

    #[test]
    fn ip_suffix_follows_the_networks_prefix() {
        let mut s = base();
        s.peers = vec![peer("p", &[(CredentialKind::IpSuffix, "::a:b:c:d")])];
        s.grants = vec![grant("g", "web", Subject::Peer("p".into()))];
        let rs = build(&s);
        assert_eq!(
            rs.rules[0].sources,
            Sources::Nets(vec!["2001:db8:1:2:a:b:c:d/128".parse().unwrap()])
        );
        s.networks[1].prefix = Some("2001:db8:9:9::".parse().unwrap());
        let rs = build(&s);
        assert_eq!(
            rs.rules[0].sources,
            Sources::Nets(vec!["2001:db8:9:9:a:b:c:d/128".parse().unwrap()])
        );
        // Without a /64 (DHCPv6) the suffix reaches nothing.
        s.networks[1].prefix = None;
        assert!(build(&s).rules.is_empty());
    }

    #[test]
    fn not_reachable_credentials_produce_no_rule() {
        let mut s = base();
        s.peers = vec![peer(
            "p",
            &[
                (CredentialKind::WgKey, "AAAA"),
                (CredentialKind::TlsSpki, "AAAA"),
                (CredentialKind::TorClientKey, "AAAA"),
            ],
        )];
        s.grants = vec![grant("g", "web", Subject::Peer("p".into()))];
        assert!(build(&s).rules.is_empty());
        // A dangling subject grants nothing.
        s.grants = vec![grant("g", "web", Subject::Peer("gone".into()))];
        assert!(build(&s).rules.is_empty());
    }

    #[test]
    fn grant_port_and_network_narrow_the_rules() {
        let mut s = base();
        s.apps[0].ports = vec![
            app("x", &[8080, 9090], vec![]).ports[0].clone(),
            app("x", &[9090], vec![]).ports[0].clone(),
        ];
        s.grants = vec![
            Grant {
                port: Some(tcp(9090)),
                network_id: Some("ygg".into()),
                ..grant("narrow", "web", Subject::Anyone)
            },
            grant("other-app", "nope", Subject::Anyone),
        ];
        let rs = build(&s);
        assert_eq!(ids(&rs), ["a:ay:9090:tcp:narrow:ygg0"]);
        // A grant for a port the address does not serve gives no rule.
        s.grants[0].port = Some(tcp(1));
        assert!(build(&s).rules.is_empty());
    }

    #[test]
    fn all_excludes_ports_claimed_by_an_only_address() {
        let mut s = base();
        s.apps[0].ports = vec![
            app("x", &[80], vec![]).ports[0].clone(),
            app("x", &[443], vec![]).ports[0].clone(),
        ];
        s.apps[0].addresses.push(address(
            "ay2",
            "web",
            "ygg",
            "300:1:2:3::200",
            PortSet::Only(vec![tcp(443)]),
        ));
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let rs = build(&s);
        let mut ygg_rules: Vec<_> = rs
            .rules
            .iter()
            .filter(|r| r.dst == ip("300:1:2:3::100") || r.dst == ip("300:1:2:3::200"))
            .map(|r| (r.dst.to_string(), r.port))
            .collect();
        ygg_rules.sort();
        assert_eq!(
            ygg_rules,
            [
                ("300:1:2:3::100".to_string(), 80),
                ("300:1:2:3::200".to_string(), 443)
            ]
        );
        // The Only address serves its port even before the app listens on it.
        s.apps[0].ports.clear();
        let rs = build(&s);
        assert!(rs.rules.iter().any(|r| r.id == "a:ay2:443:tcp:g:ygg0"));
    }

    #[test]
    fn unlistening_ports_stay_in_the_ruleset() {
        let mut s = base();
        s.apps[0].ports[0].listening = false;
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        assert_eq!(build(&s).rules.len(), 2);
    }

    #[test]
    fn address_of_an_unknown_network_is_denied_without_rules() {
        let mut s = base();
        s.networks.retain(|n| n.id != "ygg");
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let rs = build(&s);
        assert_eq!(ids(&rs), ["a:an:8080:tcp:g:eth0"]);
        assert!(managed(&rs).contains(&ip("300:1:2:3::100")));
        assert!(!rs.scopes.iter().any(|s| s.id.starts_with("overlay")));
    }

    #[test]
    fn onion_locators_are_not_ip_rules() {
        let mut s = base();
        s.apps[0].addresses.push(Address {
            locator: Locator::Onion {
                hostname: "x.onion".into(),
            },
            ..address("ao", "web", "tor", "::1", PortSet::All)
        });
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        assert_eq!(build(&s).rules.len(), 2);
    }

    #[test]
    fn overlay_scope_exists_without_any_app() {
        let s = Snapshot {
            networks: vec![ygg()],
            ..Snapshot::default()
        };
        let rs = build(&s);
        assert_eq!(rs.scopes.len(), 1);
        assert_eq!(rs.scopes[0].id, "overlay:ygg0");
        assert_eq!(rs.scopes[0].kind, ScopeKind::Overlay);
        assert_eq!(
            rs.scopes[0].matcher,
            ScopeMatch::Interface {
                name: "ygg0".into(),
                families: Families::Both
            }
        );
        assert!(rs.rules.is_empty());
    }

    #[test]
    fn whole_host_scope_per_interface() {
        let mut s = base();
        s.protect_host = vec!["eth1".into(), "eth0".into(), "eth0".into(), "".into()];
        let rs = build(&s);
        let scope_ids: Vec<_> = rs.scopes.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            scope_ids,
            ["managed", "overlay:ygg0", "host:eth0", "host:eth1"]
        );
        assert_eq!(rs.scopes[2].kind, ScopeKind::WholeHost);
        assert!(matches!(
            rs.scopes[2].matcher,
            ScopeMatch::Interface {
                families: Families::V6,
                ..
            }
        ));
    }

    #[test]
    fn output_is_deterministic() {
        let mut a = base();
        a.peers = vec![
            peer(
                "b",
                &[
                    (CredentialKind::YggKey, KEY),
                    (CredentialKind::Ip, "fd00::9/128"),
                ],
            ),
            peer("c", &[(CredentialKind::YggAddr, "200:1::5")]),
        ];
        a.groups = vec![PeerGroup {
            id: "grp".into(),
            label: "grp".into(),
            members: vec!["b".into(), "c".into()],
            created_at: Utc::now(),
        }];
        a.grants = vec![
            grant("g1", "web", Subject::Group("grp".into())),
            grant("g2", "web", Subject::Anyone),
        ];
        a.protect_host = vec!["eth0".into(), "eth1".into()];
        let mut b = a.clone();
        b.apps[0].addresses.reverse();
        b.apps[0].ports.reverse();
        b.peers.reverse();
        b.grants.reverse();
        b.groups[0].members.reverse();
        b.networks.reverse();
        b.protect_host.reverse();
        assert_eq!(build(&a), build(&b));
        let got = ids(&build(&a))
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let mut sorted = got.clone();
        sorted.sort();
        assert_eq!(got, sorted);
        let unique: BTreeSet<_> = got.iter().collect();
        assert_eq!(unique.len(), got.len(), "rule ids are unique");
    }

    #[test]
    fn golden_v1_snapshot() {
        let mut s = base();
        s.peers = vec![
            peer("laptop", &[(CredentialKind::YggKey, KEY)]),
            peer("nas", &[(CredentialKind::Ip, "fd00:5a::2/128")]),
        ];
        s.grants = vec![
            grant("g1", "web", Subject::Peer("laptop".into())),
            grant("g2", "web", Subject::Peer("nas".into())),
        ];
        s.protect_host = vec!["eth0".into()];
        insta::assert_debug_snapshot!(build(&s));
        // Reach is what the table says, for the record.
        assert_eq!(
            socketguard_core::best_reach(&s.peers[0].credentials, &ygg()),
            Reach::Verified
        );
    }

    #[test]
    fn overlapping_sources_are_aggregated() {
        let mut s = base();
        s.peers = vec![
            peer(
                "p",
                &[
                    (CredentialKind::Ip, "fd00::/8"),
                    (CredentialKind::Ip, "fd00::5/128"),
                    (CredentialKind::Ip, "2001:db8::/64"),
                    (CredentialKind::Ip, "2001:db8::7/128"),
                ],
            ),
            peer("q", &[(CredentialKind::Ip, "fd00:1::/32")]),
        ];
        s.groups = vec![PeerGroup {
            id: "grp".into(),
            label: "grp".into(),
            members: vec!["p".into(), "q".into()],
            created_at: Utc::now(),
        }];
        s.grants = vec![grant("g", "web", Subject::Group("grp".into()))];
        let rs = build(&s);
        assert_eq!(
            rs.rules[0].sources,
            Sources::Nets(vec![
                "2001:db8::/64".parse().unwrap(),
                "fd00::/8".parse().unwrap()
            ])
        );
    }

    #[test]
    fn hostile_interface_names_never_reach_the_ruleset() {
        let mut s = base();
        let evil = format!("eth0{} accept #", '"');
        s.protect_host = vec![evil.clone(), "eth1".into()];
        s.networks[1].interface = Some(evil.clone());
        s.networks[2].interface = Some(format!("ygg0{}x", char::from(10u8)));
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let (rs, warnings) = build_with_warnings(&s);
        assert!(!warnings.is_empty());
        assert!(rs.validate().is_ok());
        assert!(rs.rules.is_empty());
        let scope_ids: Vec<_> = rs.scopes.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(scope_ids, ["managed", "host:eth1"]);
    }

    #[test]
    fn owned_addresses_stay_in_the_managed_scope_without_an_app() {
        let s = Snapshot {
            owned: vec![ip("300:1:2:3::dead")],
            ..Snapshot::default()
        };
        let rs = build(&s);
        assert!(rs.scopes.iter().any(|sc| matches!(
            &sc.matcher,
            ScopeMatch::Destinations(d) if d == &vec![ip("300:1:2:3::dead")]
        )));
        assert!(rs.rules.is_empty());
    }

    // ─── Lockout guard ───────────────────────────────────────────────────

    fn listener(name: &str, port: u16, bind: &str) -> ListeningSocket {
        ListeningSocket {
            pid: 1,
            process_name: name.into(),
            port,
            protocol: Protocol::Tcp,
            bind_address: ip(bind),
            exe_path: Some(format!("/usr/sbin/{name}")),
            cmdline: None,
            uid: Some("0".into()),
            foreign_mntns: false,
            cwd: None,
        }
    }

    fn eth0() -> Vec<HostInterface> {
        vec![HostInterface {
            name: "eth0".into(),
            addrs: vec![ip("192.168.1.5")],
        }]
    }

    /// An sshd app, as the guard identifies it, with an address on the LAN network.
    fn sshd_snap(grants: Vec<Grant>) -> Snapshot {
        let id = app_identity(&listener("sshd", 22, "::")).id;
        let mut a = app(&id, &[22], vec![]);
        a.addresses = vec![address("ad", &id, "lan", "2001:db8:1:2::22", PortSet::All)];
        Snapshot {
            apps: vec![a],
            networks: vec![lan()],
            grants: grants
                .into_iter()
                .map(|g| Grant {
                    app_id: id.clone(),
                    ..g
                })
                .collect(),
            peers: vec![peer("admin", &[(CredentialKind::Ip, "fd00:5a::2/128")])],
            ..Snapshot::default()
        }
    }

    #[test]
    fn lockout_wildcard_sshd_without_grant_is_a_risk() {
        let risks =
            check_protect_host(&Snapshot::default(), &[listener("sshd", 22, "::")], &eth0())
                .unwrap_err();
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].port, 22);
        // An app with an address but no grant is still a risk.
        assert!(
            check_protect_host(&sshd_snap(vec![]), &[listener("sshd", 22, "::")], &eth0()).is_err()
        );
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
        let ls = [listener("sshd", 22, "192.168.1.5")];
        assert!(check_protect_host(&Snapshot::default(), &ls, &eth0()).is_err());
    }

    #[test]
    fn lockout_cleared_by_a_grant_that_reaches() {
        let by_peer = sshd_snap(vec![grant("g", "", Subject::Peer("admin".into()))]);
        assert!(check_protect_host(&by_peer, &[listener("sshd", 22, "::")], &eth0()).is_ok());
        let anyone = sshd_snap(vec![grant("g", "", Subject::Anyone)]);
        assert!(check_protect_host(&anyone, &[listener("sshd", 22, "::")], &eth0()).is_ok());
    }

    #[test]
    fn lockout_not_cleared_by_an_unreachable_credential() {
        let mut s = sshd_snap(vec![grant("g", "", Subject::Peer("admin".into()))]);
        // A key credential does not identify anyone on a LAN.
        s.peers = vec![peer("admin", &[(CredentialKind::YggKey, KEY)])];
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &eth0()).is_err());
    }

    #[test]
    fn lockout_grant_for_another_app_or_interface_does_not_help() {
        // A grant on another app's port 22 address.
        let mut s = sshd_snap(vec![grant("g", "", Subject::Anyone)]);
        s.apps[0].id = "someone-else".into();
        s.apps[0].addresses[0].app_id = "someone-else".into();
        s.grants[0].app_id = "someone-else".into();
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &eth0()).is_err());
        // The address is on a network whose interface is not the protected one.
        let mut s = sshd_snap(vec![grant("g", "", Subject::Anyone)]);
        s.networks[0].interface = Some("eth1".into());
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &eth0()).is_err());
    }

    #[test]
    fn lockout_rule_bound_to_another_interface_does_not_help() {
        let id = app_identity(&listener("sshd", 22, "::")).id;
        let mut a = app(&id, &[22], vec![]);
        a.addresses = vec![address("ad", &id, "ygg", "300:1:2:3::22", PortSet::All)];
        let s = Snapshot {
            apps: vec![a],
            networks: vec![ygg()],
            peers: vec![peer("admin", &[(CredentialKind::YggKey, KEY)])],
            grants: vec![Grant {
                app_id: id,
                ..grant("g", "", Subject::Peer("admin".into()))
            }],
            ..Snapshot::default()
        };
        // The only rule is bound to ygg0 and sits on a different interface than eth0.
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &eth0()).is_err());
    }

    #[test]
    fn lockout_empty_interfaces_is_ok() {
        assert!(
            check_protect_host(&Snapshot::default(), &[listener("sshd", 22, "::")], &[]).is_ok()
        );
    }
}
