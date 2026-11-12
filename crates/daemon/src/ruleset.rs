//! The ruleset producer (ADR 0029): a pure function from a [`Snapshot`] of the daemon's
//! state to the [`DesiredRuleset`] that every platform backend renders and applies whole.
//! It is the only place that turns grants into rules.
//!
//! The lockout guard for whole-host protection (ADR 0026) lives here too, since it asks
//! "would the ruleset built with this setting still let remote admin in".

use crate::firewall::{DesiredRuleset, Dst, Families, Rule, Scope, ScopeKind, ScopeMatch, Sources};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use socketguard_core::{
    app_identity, credential_source, valid_interface_name, Address, App, AppPort, Credential,
    Grant, ListeningSocket, Model, Network, NetworkKind, Peer, PeerGroup, PortGroup, PortRange,
    PortRef, Protocol, Reservation, ScopePorts, Subject, Tag, World,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use tracing::warn;

/// The addresses of a managed Yggdrasil node: its own `200::/7` address and its routed
/// `300::/64` subnet. SocketGuard denies exactly these as destinations on any interface
/// (ADR 0051), so a node it does not manage is left alone. Remembered once known, so the
/// block outlives the node being stopped or its adapter missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OverlayNode {
    pub address: std::net::Ipv6Addr,
    pub subnet: Ipv6Net,
}

/// The id of the scope denying the node address of Yggdrasil network `network_id`.
pub fn overlay_addr_scope_id(network_id: &str) -> String {
    format!("overlay:{network_id}:addr")
}

/// The id of the scope denying the routed subnet of Yggdrasil network `network_id`.
pub fn overlay_subnet_scope_id(network_id: &str) -> String {
    format!("overlay:{network_id}:subnet")
}

/// The id of the scope denying the whole Yggdrasil range (`200::/7`) for the network
/// `network_id`, an existing node (ADR 0051, amendment).
pub fn overlay_range_scope_id(network_id: &str) -> String {
    format!("overlay:{network_id}:range")
}

/// The Yggdrasil address range, `200::/7`.
pub fn yggdrasil_range() -> Ipv6Net {
    Ipv6Net::new(std::net::Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 0), 7).expect("valid prefix")
}

/// Everything the producer needs, gathered from the DB and the active networks.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Apps with their ports.
    pub apps: Vec<App>,
    /// Every address, automatic and reserved. Which are up is decided by [`Model`].
    pub addresses: Vec<Address>,
    pub reservations: Vec<Reservation>,
    pub networks: Vec<Network>,
    pub peers: Vec<Peer>,
    pub groups: Vec<PeerGroup>,
    pub grants: Vec<Grant>,
    /// Tags, to expand the grants that target them (ADR 0043).
    pub tags: Vec<Tag>,
    /// Port groups, for the ports of the scopes that name them (ADR 0047).
    pub port_groups: Vec<PortGroup>,
    /// The known node addresses of the Yggdrasil networks, by network id (live, else the
    /// last ones remembered).
    pub ygg_nodes: BTreeMap<String, OverlayNode>,
    /// Yggdrasil networks on a node the user runs (not managed): blocked by the whole
    /// range `200::/7`, whether or not their node's address is known.
    pub ygg_existing: BTreeSet<String>,
    /// Interfaces under whole-host protection.
    pub protect_host: Vec<String>,
    /// The IPv4 subnets of the protected interfaces that carry IPv4 (others are absent).
    pub v4_subnets: BTreeMap<String, Vec<Ipv4Net>>,
    /// Addresses the daemon owns on interfaces, whether or not an app still has them
    /// (retiring ones included): denied until they are really gone.
    pub owned: Vec<IpAddr>,
}

fn sorted_unique<T: Ord>(v: impl IntoIterator<Item = T>) -> Vec<T> {
    v.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

impl Snapshot {
    /// The state as the address model reads it.
    pub fn world(&self) -> World<'_> {
        World {
            apps: &self.apps,
            networks: &self.networks,
            grants: &self.grants,
            tags: &self.tags,
            reservations: &self.reservations,
            port_groups: &self.port_groups,
            addresses: &self.addresses,
        }
    }
}

/// The destination ports to write rules for: every detected or explicit port on its own
/// (stable rule ids, one rule per port) and every group range as one range.
pub(crate) fn rule_ranges(ports: &ScopePorts) -> Vec<PortRange> {
    ports
        .fixed
        .ports()
        .map(PortRange::single)
        .chain(ports.ranged.ranges())
        .collect()
}

/// The credentials of a grant's peers (all members of a group); empty for Anyone.
pub(crate) fn subject_credentials<'a>(
    groups: &'a [PeerGroup],
    peers: &HashMap<&'a str, &'a Peer>,
    subject: &Subject,
) -> Vec<&'a Credential> {
    match subject {
        Subject::Anyone => Vec::new(),
        Subject::Peer(id) => peers
            .get(id.as_str())
            .map(|p| p.credentials.iter().collect())
            .unwrap_or_default(),
        Subject::Group(id) => groups
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

/// Whether `grant` is a segment grant: Anyone, scoped to a LAN or Local network.
fn is_segment(grant: &Grant, network: &Network) -> bool {
    grant.subject == Subject::Anyone
        && grant.network_id.is_some()
        && matches!(network.kind, NetworkKind::Lan | NetworkKind::Local)
}

/// The IPv6 sources on the link of `network`: its live /64 and link-local.
fn on_link_v6(network: &Network) -> Vec<IpNet> {
    let mut nets: Vec<IpNet> = vec!["fe80::/10".parse().expect("valid net")];
    if let Some(p) = network.prefix.and_then(|p| Ipv6Net::new(p, 64).ok()) {
        nets.push(IpNet::V6(p.trunc()));
    }
    nets
}

/// The IPv4 networks among `creds` (kind `ip`).
fn v4_sources(creds: &[&Credential]) -> Vec<IpNet> {
    creds
        .iter()
        .filter(|c| c.kind == socketguard_core::CredentialKind::Ip)
        .filter_map(|c| c.value.parse::<IpNet>().ok())
        .filter(|n| n.addr().is_ipv4())
        .collect()
}

/// Rules for IPv4 (ADR 0044): per protected interface that carries IPv4, each grant allows
/// its IPv4 peers (or everyone, or the interface's subnet for a segment) to the app's IPv4
/// ports on any of the host's IPv4 addresses. Ids are
/// `v4:<port>:<proto>:<grant>:<interface>:<app>`.
fn host_ipv4_rules(
    snap: &Snapshot,
    model: &Model,
    networks: &HashMap<&str, &Network>,
    peers: &HashMap<&str, &Peer>,
    rules: &mut BTreeMap<String, Rule>,
) {
    for app in &snap.apps {
        let v4_ports: BTreeSet<PortRef> = app
            .ports
            .iter()
            .filter(|p| p.family.has_v4())
            .map(AppPort::port_ref)
            .collect();
        if v4_ports.is_empty() {
            continue;
        }
        for ag in model.app_grants(app).iter() {
            let grant = &ag.grant;
            let scoped = grant
                .network_id
                .as_deref()
                .map(|id| networks.get(id).copied());
            let creds = subject_credentials(&snap.groups, peers, &grant.subject);
            let peer_nets = v4_sources(&creds);
            for (iface, subnets) in &snap.v4_subnets {
                if !snap.protect_host.contains(iface) {
                    continue;
                }
                // A network-scoped grant applies only where that network's interface is.
                let network = match scoped {
                    None => None,
                    Some(Some(n))
                        if n.grants_apply
                            && n.interface.as_deref() == Some(iface.as_str())
                            && matches!(n.kind, NetworkKind::Lan | NetworkKind::Local) =>
                    {
                        Some(n)
                    }
                    Some(_) => continue,
                };
                let sources = match (&grant.subject, network) {
                    (Subject::Anyone, None) => Sources::Any,
                    (Subject::Anyone, Some(_)) => {
                        Sources::Nets(subnets.iter().copied().map(IpNet::V4).collect())
                    }
                    _ if peer_nets.is_empty() => continue,
                    _ => Sources::Nets(IpNet::aggregate(&peer_nets)),
                };
                for port in v4_ports.iter().filter(|p| ag.ports.contains(**p)) {
                    let id = format!(
                        "v4:{}:{}:{}:{iface}:{}",
                        port.port, port.proto, grant.id, app.id
                    );
                    rules.insert(
                        id.clone(),
                        Rule {
                            id,
                            iif: Some(iface.clone()),
                            dst: Dst::HostV4,
                            ports: PortRange::single(*port),
                            sources: sources.clone(),
                        },
                    );
                }
            }
        }
    }
}

/// Build the desired ruleset, also returning warnings the caller may want to log.
///
/// - Managed scope: every IP locator that is up (see [`Model`]) and every address still on
///   an interface (`owned`), so an address is denied from the moment it exists and until
///   it is gone.
/// - Per Yggdrasil network an overlay scope for each of the node's known addresses (its
///   `/128` and its `/64`), and one for its interface when that is known, a whole-host scope per protected interface
///   (both families: IPv4 grants allow the way in, see [`host_ipv4_rules`]).
/// - A grant to Anyone scoped to a LAN or Local network ("everyone on <network>") admits
///   only that network's prefix and link-local sources, not every source on the interface.
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

    let model = Model::new(snap.world());
    let info = model.address_info();
    let apps: HashMap<&str, &App> = snap.apps.iter().map(|a| (a.id.as_str(), a)).collect();
    for address in &snap.addresses {
        let Some(state) = info.get(&address.id).filter(|s| s.up) else {
            continue; // dormant: not on the interface, no rules
        };
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
        for (app_id, served) in &state.served {
            let Some(app) = apps.get(app_id.as_str()) else {
                continue;
            };
            let app_grants = model.app_grants(app);
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
            for app_grant in app_grants.iter().filter(|g| {
                g.grant
                    .network_id
                    .as_deref()
                    .is_none_or(|n| n == address.network_id)
            }) {
                let grant = &app_grant.grant;
                let creds = subject_credentials(&snap.groups, &peers, &grant.subject);
                // Sources per interface binding; the same for every port of this grant.
                let mut bound: BTreeMap<Option<String>, Vec<IpNet>> = BTreeMap::new();
                if grant.subject != Subject::Anyone {
                    for c in creds {
                        let Some(net) = credential_source(c, network) else {
                            continue;
                        };
                        // IPv4 credentials get their own rules (below), not one on a v6 address.
                        if net.addr().is_ipv4() {
                            continue;
                        }
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
                for ports in rule_ranges(&served.intersect(&app_grant.ports)) {
                    let base = format!(
                        "a:{}:{}:{}:{}",
                        address.id,
                        ports.port_text(),
                        ports.proto,
                        grant.id
                    );
                    let mut push = |id: String, iif: Option<String>, sources: Sources| {
                        rules.insert(
                            id.clone(),
                            Rule {
                                id,
                                iif,
                                dst: Dst::Addr(dst),
                                ports,
                                sources,
                            },
                        );
                    };
                    if grant.subject == Subject::Anyone {
                        let id = match &iif {
                            Some(i) => format!("{base}:{i}"),
                            None => base,
                        };
                        // "Everyone on <network>": the interface alone would also pass a
                        // router's traffic from other segments, so the sources are the
                        // network's own prefix and link-local (ADR 0044).
                        let sources = if is_segment(grant, network) {
                            Sources::Nets(on_link_v6(network))
                        } else {
                            Sources::Any
                        };
                        push(id, iif.clone(), sources);
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

    host_ipv4_rules(snap, &model, &networks, &peers, &mut rules);

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
    // Closed whatever happens to the adapter (ADR 0051): an interface rule cannot exist
    // while the adapter does not, so a node that restarts or a renamed adapter would leave
    // the host open. Rules still admit granted peers, as they do for the interface scope.
    // An existing node is closed by the whole range, known address or not. SocketGuard's
    // own node keeps the narrow block of its address and subnet, which leaves a node it
    // does not manage alone; a node that was never seen has no addresses to name yet.
    for network in snap
        .networks
        .iter()
        .filter(|n| n.kind == NetworkKind::Yggdrasil)
    {
        if snap.ygg_existing.contains(&network.id) {
            scopes.push(Scope {
                id: overlay_range_scope_id(&network.id),
                kind: ScopeKind::Overlay,
                matcher: ScopeMatch::DestinationNet(IpNet::V6(yggdrasil_range())),
            });
            continue;
        }
        let Some(node) = snap.ygg_nodes.get(&network.id) else {
            continue;
        };
        scopes.push(Scope {
            id: overlay_addr_scope_id(&network.id),
            kind: ScopeKind::Overlay,
            matcher: ScopeMatch::DestinationNet(IpNet::V6(
                Ipv6Net::new(node.address, 128).expect("full prefix"),
            )),
        });
        scopes.push(Scope {
            id: overlay_subnet_scope_id(&network.id),
            kind: ScopeKind::Overlay,
            matcher: ScopeMatch::DestinationNet(IpNet::V6(node.subnet)),
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
                families: Families::Both,
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
    socketguard_core::REMOTE_ADMIN_PORTS.contains(&l.port)
        || matches!(name, "sshd" | "xrdp" | "termservice")
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
    let mut app_of_dst: HashMap<IpAddr, Vec<&str>> = HashMap::new();
    let info = Model::new(snap.world()).address_info();
    for a in &snap.addresses {
        let Some(state) = info.get(&a.id).filter(|s| s.up) else {
            continue;
        };
        let Some(addr) = a.locator.ipv6() else {
            continue;
        };
        app_of_dst.insert(
            IpAddr::V6(addr),
            state.served.keys().map(String::as_str).collect(),
        );
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
            r.ports.contains(PortRef {
                port: l.port,
                proto: l.protocol,
            }) && on_protected(&r.iif)
                && match r.dst {
                    Dst::Addr(dst) => {
                        (ip.is_unspecified() || dst == ip)
                            && on_iface.contains(&dst)
                            && app_of_dst
                                .get(&dst)
                                .is_some_and(|apps| apps.contains(&app_id.as_str()))
                    }
                    // An IPv4 rule, named after its app (see `host_ipv4_rules`).
                    Dst::HostV4 => {
                        (ip.is_unspecified() || ip.is_ipv4())
                            && r.id.splitn(6, ':').nth(5) == Some(app_id.as_str())
                    }
                }
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
    use socketguard_core::{
        Address, AppPort, CredentialKind, Locator, NetworkStatus, PortGroup, Reach, Scope, Target,
    };

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
            vlan_id: None,
            managed: None,
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

    fn address(id: &str, app: &str, net: &str, addr: &str, scope: Scope) -> Address {
        Address {
            id: id.into(),
            ..Address::automatic(
                app,
                scope,
                net,
                Locator::Ipv6 {
                    addr: addr.parse().unwrap(),
                },
            )
        }
    }

    fn app(id: &str, ports: &[u16]) -> App {
        App {
            id: id.into(),
            name: id.into(),
            process_name: id.into(),
            exe_path: None,
            interpreter_arg: None,
            identity_note: None,
            exe_missing: false,
            system: false,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            ports: ports
                .iter()
                .map(|p| AppPort {
                    port: *p,
                    proto: Protocol::Tcp,
                    listening: true,
                    last_seen: Utc::now(),
                    family: Default::default(),
                })
                .collect(),
            addresses: vec![],
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
            target: Target::App(app.into()),
            scope: Scope::All,
            network_id: None,
            subject,
            created_at: Utc::now(),
        }
    }

    /// A grant to a peer that does not exist: it names a row (so gives the row an address)
    /// without letting anyone in.
    fn names(id: &str, scope: Scope) -> Grant {
        Grant {
            scope,
            ..grant(id, "web", Subject::Peer("nobody".into()))
        }
    }

    /// One app "web" on 8080 with an address on every network; no grants yet.
    fn base() -> Snapshot {
        Snapshot {
            apps: vec![app("web", &[8080])],
            addresses: vec![
                address("al", "web", "local", "fd00::1", Scope::All),
                address("an", "web", "lan", "2001:db8:1:2::100", Scope::All),
                address("ay", "web", "ygg", "300:1:2:3::100", Scope::All),
            ],
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
    fn without_grants_only_loopback_is_managed_and_dormant_addresses_stay_out() {
        let rs = build(&base());
        assert!(rs.rules.is_empty());
        // Local on loopback is always up; the others are remembered but dormant.
        assert_eq!(managed(&rs), vec![ip("fd00::1")]);
        // Until one is still on its interface: it stays denied until it is gone.
        let mut s = base();
        s.owned = vec![ip("300:1:2:3::100")];
        assert_eq!(
            managed(&build(&s)),
            vec![ip("300:1:2:3::100"), ip("fd00::1")]
        );
        // A grant names the row: the addresses on networks that take grants are managed.
        s.owned.clear();
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        assert_eq!(managed(&build(&s)).len(), 3);
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
            app("x", &[8080, 9090]).ports[0].clone(),
            app("x", &[9090]).ports[0].clone(),
        ];
        s.grants = vec![
            Grant {
                scope: Scope::port(tcp(9090)),
                network_id: Some("ygg".into()),
                ..grant("narrow", "web", Subject::Anyone)
            },
            grant("other-app", "nope", Subject::Anyone),
            // The address of "All ports" exists because a grant names it.
            names("names", Scope::All),
        ];
        let rs = build(&s);
        assert_eq!(ids(&rs), ["a:ay:9090:tcp:narrow:ygg0"]);
        // A grant for a port the address does not serve gives no rule.
        s.grants[0].scope = Scope::port(tcp(1));
        assert!(build(&s).rules.is_empty());
    }

    #[test]
    fn an_all_address_also_serves_the_ports_that_have_their_own_address() {
        let mut s = base();
        s.apps[0].ports = vec![
            app("x", &[80]).ports[0].clone(),
            app("x", &[443]).ports[0].clone(),
        ];
        s.addresses.push(address(
            "ay2",
            "web",
            "ygg",
            "300:1:2:3::200",
            Scope::port(tcp(443)),
        ));
        s.grants = vec![
            grant("g", "web", Subject::Anyone),
            names("n443", Scope::port(tcp(443))),
        ];
        let rs = build(&s);
        let mut ygg_rules: Vec<_> = rs
            .rules
            .iter()
            .filter(|r| r.dst == ip("300:1:2:3::100") || r.dst == ip("300:1:2:3::200"))
            .map(|r| (r.dst.addr().unwrap().to_string(), r.ports.start))
            .collect();
        ygg_rules.sort();
        assert_eq!(
            ygg_rules,
            [
                ("300:1:2:3::100".to_string(), 80),
                ("300:1:2:3::100".to_string(), 443),
                ("300:1:2:3::200".to_string(), 443)
            ]
        );
        // A port address serves its port even before the app listens on it, and a grant
        // for that port covers it.
        s.apps[0].ports.clear();
        s.grants = vec![Grant {
            scope: Scope::port(tcp(443)),
            ..grant("g", "web", Subject::Anyone)
        }];
        let rs = build(&s);
        assert!(rs.rules.iter().any(|r| r.id == "a:ay2:443:tcp:g:ygg0"));
    }

    fn group(id: &str, ranges: &[&str], apps: &[&str]) -> PortGroup {
        PortGroup {
            id: id.into(),
            label: id.into(),
            ports: socketguard_core::parse_ranges(ranges).unwrap(),
            apps: apps.iter().map(|a| a.to_string()).collect(),
            created_at: Utc::now(),
        }
    }

    fn rule_ports(rs: &DesiredRuleset, address: &str) -> Vec<String> {
        let prefix = format!("a:{address}:");
        let mut v: Vec<String> = rs
            .rules
            .iter()
            .filter(|r| r.id.starts_with(&prefix))
            .map(|r| r.ports.to_string())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_port_group_range_is_a_range_rule_before_anything_listens() {
        let mut s = base();
        s.apps[0].ports.clear();
        s.port_groups = vec![group("passive", &["50000-51000/tcp", "21/tcp"], &["web"])];
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let rs = build(&s);
        assert_eq!(rule_ports(&rs, "ay"), ["21/tcp", "50000-51000/tcp"]);
        assert!(rs
            .rules
            .iter()
            .any(|r| r.id == "a:ay:50000-51000:tcp:g:ygg0"
                && r.ports == "50000-51000/tcp".parse().unwrap()));
        // A single-port range keeps the id of a plain port.
        assert!(rs.rules.iter().any(|r| r.id == "a:ay:21:tcp:g:ygg0"));
        // Not attached to the app: no ports from it.
        s.port_groups[0].apps.clear();
        assert!(build(&s).rules.is_empty());
    }

    #[test]
    fn ranges_leave_out_ports_another_app_listens_on() {
        let mut s = base();
        s.apps[0].ports = app("x", &[50005]).ports;
        s.apps.push(app("other", &[50003]));
        s.port_groups = vec![group("passive", &["50000-50010/tcp"], &["web"])];
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let rs = build(&s);
        // 50003 is the other app's; 50005 is web's own and stays (as a port of its own).
        assert_eq!(
            rule_ports(&rs, "ay"),
            [
                "50000-50002/tcp",
                "50004/tcp",
                "50005/tcp",
                "50006-50010/tcp"
            ]
        );
        // The one exclusion rule holds for a named port too: 50003 is the other app's.
        s.addresses.push(address(
            "ap",
            "web",
            "ygg",
            "300:1:2:3::400",
            Scope::port(tcp(50003)),
        ));
        let mut explicit = s.clone();
        explicit.grants = vec![Grant {
            id: "gp".into(),
            scope: Scope::port(tcp(50003)),
            ..grant("gp", "web", Subject::Anyone)
        }];
        assert!(rule_ports(&build(&explicit), "ap").is_empty());
        assert!(rule_ports(&build(&explicit), "ay").is_empty());
        // Once the other app lets go of it, the port address serves it again.
        explicit.apps[1].ports[0].listening = false;
        assert_eq!(rule_ports(&build(&explicit), "ap"), ["50003/tcp"]);
        // The other app's port going quiet frees the range again.
        s.apps[1].ports[0].listening = false;
        assert_eq!(
            rule_ports(&build(&s), "ay"),
            ["50000-50004/tcp", "50005/tcp", "50006-50010/tcp"]
        );
    }

    #[test]
    fn a_port_address_stops_serving_a_port_another_app_took_over() {
        // A had an address and a grant for 9000; it stopped listening there and B started.
        let mut s = base();
        s.apps[0].ports = app("x", &[8080]).ports;
        s.addresses = vec![address(
            "ap",
            "web",
            "ygg",
            "300:1:2:3::500",
            Scope::port(tcp(9000)),
        )];
        s.grants = vec![Grant {
            scope: Scope::port(tcp(9000)),
            ..grant("g", "web", Subject::Anyone)
        }];
        assert_eq!(
            rule_ports(&build(&s), "ap"),
            ["9000/tcp"],
            "nobody else has it"
        );
        s.apps.push(app("other", &[9000]));
        assert!(rule_ports(&build(&s), "ap").is_empty());
        // Detected on its own app too, it stays.
        s.apps[0].ports.push(app("x", &[9000]).ports[0].clone());
        assert_eq!(rule_ports(&build(&s), "ap"), ["9000/tcp"]);
        // A stale record (seen once, no longer listening) does not keep it.
        s.apps[0].ports.last_mut().expect("port").listening = false;
        assert!(rule_ports(&build(&s), "ap").is_empty());
    }

    #[test]
    fn a_group_address_serves_only_its_group_and_a_group_grant_only_its_ranges() {
        let mut s = base();
        s.apps[0].ports = app("x", &[8080]).ports;
        s.port_groups = vec![group("passive", &["50000-50010/tcp"], &["web"])];
        s.addresses = vec![address(
            "ag",
            "web",
            "ygg",
            "300:1:2:3::300",
            Scope::group("passive"),
        )];
        s.grants = vec![
            grant("g", "web", Subject::Anyone),
            names("ng", Scope::group("passive")),
        ];
        // The group address serves the group's range, not the detected 8080.
        assert_eq!(rule_ports(&build(&s), "ag"), ["50000-50010/tcp"]);
        // A grant for the group on an All address covers the range only.
        s.addresses = vec![address("ay", "web", "ygg", "300:1:2:3::100", Scope::All)];
        s.grants = vec![
            Grant {
                scope: Scope::group("passive"),
                ..grant("g", "web", Subject::Anyone)
            },
            names("n", Scope::All),
        ];
        assert_eq!(rule_ports(&build(&s), "ay"), ["50000-50010/tcp"]);
    }

    #[test]
    fn a_tag_grant_by_group_meets_the_members_scope() {
        let mut s = base();
        s.apps[0].ports = app("x", &[8080]).ports;
        s.port_groups = vec![
            group("passive", &["50000-50010/tcp"], &["web"]),
            group("wide", &["50005-60000/tcp"], &[]),
        ];
        s.tags = vec![socketguard_core::Tag {
            id: "t".into(),
            label: "t".into(),
            patterns: vec![],
            members: vec![socketguard_core::TagMember {
                app_id: "web".into(),
                scope: Scope::group("passive"),
            }],
            excluded: vec![],
            created_at: Utc::now(),
        }];
        s.grants = vec![
            Grant {
                target: Target::Tag("t".into()),
                scope: Scope::group("wide"),
                ..grant("g", "web", Subject::Anyone)
            },
            names("n", Scope::All),
        ];
        // The member's range narrowed to the grant's group.
        assert_eq!(rule_ports(&build(&s), "ay"), ["50005-50010/tcp"]);
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
        s.owned = vec![ip("300:1:2:3::100")];
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let rs = build(&s);
        assert_eq!(ids(&rs), ["a:an:8080:tcp:g:eth0"]);
        assert!(managed(&rs).contains(&ip("300:1:2:3::100")));
        assert!(!rs.scopes.iter().any(|s| s.id.starts_with("overlay")));
    }

    #[test]
    fn onion_locators_are_not_ip_rules() {
        let mut s = base();
        s.addresses.push(Address {
            locator: Locator::Onion {
                hostname: "x.onion".into(),
            },
            ..address("ao", "web", "tor", "::1", Scope::All)
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

    fn node() -> OverlayNode {
        OverlayNode {
            address: "200:1:2:3::5".parse().unwrap(),
            subnet: "300:1:2:3::/64".parse().unwrap(),
        }
    }

    fn net_scopes(rs: &DesiredRuleset) -> Vec<(&str, String)> {
        rs.scopes
            .iter()
            .filter_map(|s| match &s.matcher {
                ScopeMatch::DestinationNet(n) => Some((s.id.as_str(), n.to_string())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_node_addresses_are_denied_whatever_happens_to_the_adapter() {
        // The node was seen once: no interface (down, adapter missing) changes nothing.
        let mut no_iface = ygg();
        no_iface.interface = None;
        no_iface.status = NetworkStatus::Down {
            reason: "the Yggdrasil node is not running".into(),
        };
        for networks in [vec![ygg()], vec![no_iface]] {
            let s = Snapshot {
                networks,
                ygg_nodes: [("ygg".to_string(), node())].into(),
                ..Snapshot::default()
            };
            let rs = build(&s);
            assert_eq!(
                net_scopes(&rs),
                [
                    ("overlay:ygg:addr", "200:1:2:3::5/128".to_string()),
                    ("overlay:ygg:subnet", "300:1:2:3::/64".to_string())
                ]
            );
            assert!(rs.scopes.iter().all(|s| s.kind == ScopeKind::Overlay));
            assert!(rs.rules.is_empty(), "before any app or address");
        }
    }

    #[test]
    fn the_interface_scope_stays_beside_the_address_scopes() {
        let s = Snapshot {
            networks: vec![ygg()],
            ygg_nodes: [("ygg".to_string(), node())].into(),
            ..Snapshot::default()
        };
        let ids: Vec<_> = build(&s).scopes.into_iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            ["overlay:ygg0", "overlay:ygg:addr", "overlay:ygg:subnet"]
        );
    }

    #[test]
    fn a_node_never_seen_has_no_address_to_deny_and_nothing_else_is_touched() {
        // No interface and no address: SocketGuard has put nothing on the node yet.
        let mut no_iface = ygg();
        no_iface.interface = None;
        let s = Snapshot {
            networks: vec![no_iface],
            ..Snapshot::default()
        };
        assert!(build(&s).scopes.is_empty());
        // With a configured interface that one is closed.
        let s = Snapshot {
            networks: vec![ygg()],
            ..Snapshot::default()
        };
        assert_eq!(build(&s).scopes.len(), 1);
    }

    #[test]
    fn an_address_of_a_node_socketguard_does_not_manage_is_left_alone() {
        let s = Snapshot {
            networks: vec![ygg()],
            ygg_nodes: [("ygg".to_string(), node())].into(),
            ..Snapshot::default()
        };
        let rs = build(&s);
        let other: std::net::Ipv6Addr = "200:9:9:9::7".parse().unwrap();
        let other_subnet: std::net::Ipv6Addr = "300:9:9:9::1".parse().unwrap();
        for sc in &rs.scopes {
            if let ScopeMatch::DestinationNet(n) = &sc.matcher {
                assert!(!n.contains(&IpAddr::V6(other)), "{}", sc.id);
                assert!(!n.contains(&IpAddr::V6(other_subnet)), "{}", sc.id);
            }
        }
        assert!(rs.rules.is_empty());
    }

    fn existing() -> BTreeSet<String> {
        ["ygg".to_string()].into()
    }

    #[test]
    fn an_existing_node_is_denied_by_the_whole_range_whatever_is_known() {
        let mut no_iface = ygg();
        no_iface.interface = None;
        no_iface.status = NetworkStatus::Down {
            reason: "the Yggdrasil node is not running".into(),
        };
        // Node never seen, seen once, and adapter missing: the same single range scope.
        for (networks, nodes) in [
            (vec![ygg()], BTreeMap::new()),
            (vec![ygg()], [("ygg".to_string(), node())].into()),
            (vec![no_iface], BTreeMap::new()),
        ] {
            let s = Snapshot {
                networks,
                ygg_nodes: nodes,
                ygg_existing: existing(),
                ..Snapshot::default()
            };
            let rs = build(&s);
            assert_eq!(
                net_scopes(&rs),
                [("overlay:ygg:range", "200::/7".to_string())]
            );
            assert!(rs.scopes.iter().all(|s| s.kind == ScopeKind::Overlay));
        }
    }

    #[test]
    fn an_existing_node_keeps_its_interface_scope_beside_the_range() {
        let s = Snapshot {
            networks: vec![ygg()],
            ygg_existing: existing(),
            ..Snapshot::default()
        };
        let ids: Vec<_> = build(&s).scopes.into_iter().map(|s| s.id).collect();
        assert_eq!(ids, ["overlay:ygg0", "overlay:ygg:range"]);
    }

    #[test]
    fn a_managed_node_keeps_the_narrow_scopes_and_a_foreign_address_is_untouched() {
        // Not in `ygg_existing`: managed. Another node's 200::/7 address matches nothing.
        let s = Snapshot {
            networks: vec![ygg()],
            ygg_nodes: [("ygg".to_string(), node())].into(),
            ..Snapshot::default()
        };
        let rs = build(&s);
        assert!(!rs.scopes.iter().any(|s| s.id.ends_with(":range")));
        let foreign: IpAddr = "200:9:9:9::7".parse().unwrap();
        for sc in &rs.scopes {
            if let ScopeMatch::DestinationNet(n) = &sc.matcher {
                assert!(!n.contains(&foreign), "{}", sc.id);
            }
        }
        // Whereas the range covers it, and the SocketGuard addresses in 300::/64.
        let range = IpNet::V6(yggdrasil_range());
        assert!(range.contains(&foreign));
        assert!(range.contains(&"300:1:2:3::100".parse::<IpAddr>().unwrap()));
        assert!(!range.contains(&"fd00::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn a_granted_port_is_admitted_beside_the_range_scope() {
        let mut s = base();
        s.ygg_existing = existing();
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let rs = build(&s);
        // The SocketGuard address 300:1:2:3::100 lies inside the range; the rule for it
        // is emitted, and backends place rules before scope drops.
        let rule = rs
            .rules
            .iter()
            .find(|r| r.id == "a:ay:8080:tcp:g:ygg0")
            .expect("the granted port has a rule");
        let Dst::Addr(a) = rule.dst else { panic!() };
        assert!(IpNet::V6(yggdrasil_range()).contains(&a));
        assert!(rs.scopes.iter().any(|s| s.id == "overlay:ygg:range"));
    }

    #[test]
    fn granted_ports_are_still_admitted_beside_the_address_scopes() {
        let mut s = base();
        s.ygg_nodes = [("ygg".to_string(), node())].into();
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let rs = build(&s);
        assert!(rs.rules.iter().any(|r| r.id == "a:ay:8080:tcp:g:ygg0"));
        assert!(rs.scopes.iter().any(|s| s.id == "overlay:ygg:addr"));
    }

    #[test]
    fn removing_the_yggdrasil_network_removes_its_scopes() {
        let mut s = base();
        s.ygg_nodes = [("ygg".to_string(), node())].into();
        assert!(!net_scopes(&build(&s)).is_empty());
        s.networks.retain(|n| n.id != "ygg");
        assert!(net_scopes(&build(&s)).is_empty());
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
                families: Families::Both,
                ..
            }
        ));
    }

    // ---- IPv4 and segments (ADR 0044) ----

    /// "web" on 8080 (dual-stack) with a LAN address, eth0 protected with an IPv4 subnet.
    fn protected_lan() -> Snapshot {
        let mut s = base();
        s.protect_host = vec!["eth0".into()];
        s.v4_subnets = BTreeMap::from([("eth0".into(), vec!["192.168.1.0/24".parse().unwrap()])]);
        s
    }

    fn v4_rules(rs: &DesiredRuleset) -> Vec<&Rule> {
        rs.rules.iter().filter(|r| r.dst == Dst::HostV4).collect()
    }

    #[test]
    fn ipv4_peer_is_allowed_on_a_protected_interface() {
        let mut s = protected_lan();
        s.peers = vec![peer(
            "p",
            &[
                (CredentialKind::Ip, "192.168.1.5/32"),
                (CredentialKind::Ip, "10.0.20.0/24"),
                (CredentialKind::Ip, "fd00::7/128"),
            ],
        )];
        s.grants = vec![grant("g", "web", Subject::Peer("p".into()))];
        let rs = build(&s);
        let v4 = v4_rules(&rs);
        assert_eq!(v4.len(), 1);
        assert_eq!(v4[0].id, "v4:8080:tcp:g:eth0:web");
        assert_eq!(v4[0].iif.as_deref(), Some("eth0"));
        assert_eq!(
            v4[0].sources,
            Sources::Nets(vec![
                "10.0.20.0/24".parse().unwrap(),
                "192.168.1.5/32".parse().unwrap()
            ])
        );
        // The IPv4 sources never end up on a rule for a per-app IPv6 address.
        for r in rs.rules.iter().filter(|r| r.dst != Dst::HostV4) {
            if let Sources::Nets(n) = &r.sources {
                assert!(n.iter().all(|n| n.addr().is_ipv6()), "{r:?}");
            }
        }
        // IPv4 is in scope, so an unknown IPv4 source is dropped.
        assert!(rs.scopes.iter().any(|sc| sc.id == "host:eth0"));
    }

    #[test]
    fn ipv4_rules_follow_the_listener_family_and_the_grant_port() {
        let mut s = protected_lan();
        s.apps[0].ports = vec![
            AppPort {
                port: 8080,
                proto: Protocol::Tcp,
                listening: true,
                last_seen: Utc::now(),
                family: socketguard_core::AddrFamily::V6,
            },
            AppPort {
                port: 9090,
                proto: Protocol::Tcp,
                listening: true,
                last_seen: Utc::now(),
                family: socketguard_core::AddrFamily::Dual,
            },
        ];
        s.peers = vec![peer("p", &[(CredentialKind::Ip, "192.168.1.5/32")])];
        s.grants = vec![grant("g", "web", Subject::Peer("p".into()))];
        let rs = build(&s);
        let ports: Vec<_> = v4_rules(&rs).iter().map(|r| r.ports.start).collect();
        assert_eq!(ports, [9090], "an IPv6-only port gets no IPv4 rule");
        s.grants[0].scope = Scope::port(tcp(8080));
        assert!(v4_rules(&build(&s)).is_empty());
    }

    #[test]
    fn ipv4_needs_a_protected_interface_with_ipv4() {
        let mut s = protected_lan();
        s.peers = vec![peer("p", &[(CredentialKind::Ip, "192.168.1.5/32")])];
        s.grants = vec![grant("g", "web", Subject::Peer("p".into()))];
        // Protected but no IPv4 subnet on it: nothing to allow.
        s.v4_subnets.clear();
        assert!(v4_rules(&build(&s)).is_empty());
        // Not protected: no rule, the interface is not filtered at all.
        let mut s = protected_lan();
        s.protect_host.clear();
        s.peers = vec![peer("p", &[(CredentialKind::Ip, "192.168.1.5/32")])];
        s.grants = vec![grant("g", "web", Subject::Peer("p".into()))];
        assert!(v4_rules(&build(&s)).is_empty());
    }

    #[test]
    fn a_network_scoped_ipv4_grant_applies_only_on_that_networks_interface() {
        let mut s = protected_lan();
        s.protect_host.push("eth1".into());
        s.v4_subnets
            .insert("eth1".into(), vec!["10.9.0.0/24".parse().unwrap()]);
        s.networks.push(network(
            "lan2",
            NetworkKind::Lan,
            "eth1",
            Some("2001:db8:9::"),
        ));
        s.peers = vec![peer("p", &[(CredentialKind::Ip, "192.168.1.5/32")])];
        let mut g = grant("g", "web", Subject::Peer("p".into()));
        let ifaces = |s: &Snapshot| -> Vec<String> {
            v4_rules(&build(s))
                .iter()
                .filter_map(|r| r.iif.clone())
                .collect()
        };
        s.grants = vec![g.clone()];
        assert_eq!(ifaces(&s), ["eth0", "eth1"]);
        g.network_id = Some("lan2".into());
        s.grants = vec![g.clone()];
        assert_eq!(ifaces(&s), ["eth1"]);
        // Yggdrasil has no IPv4.
        g.network_id = Some("ygg".into());
        s.grants = vec![g];
        assert!(ifaces(&s).is_empty());
    }

    #[test]
    fn anyone_is_open_over_ipv4_on_protected_interfaces() {
        let mut s = protected_lan();
        s.grants = vec![grant("g", "web", Subject::Anyone)];
        let rs = build(&s);
        let v4 = v4_rules(&rs);
        assert_eq!(v4.len(), 1);
        assert_eq!(v4[0].sources, Sources::Any);
    }

    #[test]
    fn a_segment_grant_admits_only_the_networks_own_sources() {
        let mut s = protected_lan();
        let mut g = grant("g", "web", Subject::Anyone);
        g.network_id = Some("lan".into());
        s.grants = vec![g];
        let rs = build(&s);
        let lan_rule = rs
            .rules
            .iter()
            .find(|r| r.dst == ip("2001:db8:1:2::100"))
            .unwrap();
        assert_eq!(lan_rule.iif.as_deref(), Some("eth0"));
        assert_eq!(
            lan_rule.sources,
            Sources::Nets(vec![
                "fe80::/10".parse().unwrap(),
                "2001:db8:1:2::/64".parse().unwrap()
            ])
        );
        // The IPv4 side is the interface's subnet, and only that network's address gets a rule.
        let v4 = v4_rules(&rs);
        assert_eq!(v4.len(), 1);
        assert_eq!(
            v4[0].sources,
            Sources::Nets(vec!["192.168.1.0/24".parse().unwrap()])
        );
        assert_eq!(rs.rules.len(), 2);
    }

    #[test]
    fn segment_sources_follow_the_prefix_and_other_anyone_grants_stay_open() {
        let mut s = base();
        let mut g = grant("g", "web", Subject::Anyone);
        g.network_id = Some("lan".into());
        s.grants = vec![g];
        s.networks[1].prefix = Some("2001:db8:7:7::".parse().unwrap());
        let rs = build(&s);
        let Sources::Nets(n) = &rs.rules[0].sources else {
            panic!("a segment grant lists sources")
        };
        assert!(n.contains(&"2001:db8:7:7::/64".parse().unwrap()));
        // Scoped to Yggdrasil, or to nothing, Anyone has no source restriction.
        for scope in [Some("ygg"), None] {
            s.grants[0].network_id = scope.map(String::from);
            let rs = build(&s);
            assert!(
                rs.rules.iter().all(|r| r.sources == Sources::Any),
                "{scope:?}"
            );
        }
    }

    #[test]
    fn lockout_check_counts_ipv4_rules() {
        let mut s = protected_lan();
        s.peers = vec![peer("p", &[(CredentialKind::Ip, "192.168.1.5/32")])];
        let l = ListeningSocket::new(1, 22, Protocol::Tcp, ip("0.0.0.0")).with_process_name("sshd");
        let iface = HostInterface {
            name: "eth0".into(),
            addrs: vec![ip("192.168.1.10")],
        };
        // The listener's app is identified by its socket, so grant the app that matches it.
        let app_id = app_identity(&l).id;
        s.apps[0].id = app_id.clone();
        s.apps[0].ports = vec![AppPort {
            port: 22,
            proto: Protocol::Tcp,
            listening: true,
            last_seen: Utc::now(),
            family: Default::default(),
        }];
        s.addresses.clear();
        assert!(
            check_protect_host(&s, std::slice::from_ref(&l), std::slice::from_ref(&iface)).is_err()
        );
        s.grants = vec![grant("g", &app_id, Subject::Peer("p".into()))];
        assert!(check_protect_host(&s, &[l], &[iface]).is_ok());
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
        b.addresses.reverse();
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
            unidentified: false,
            in_service_unit: false,
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
        let a = app(&id, &[22]);
        Snapshot {
            apps: vec![a],
            addresses: vec![address("ad", &id, "lan", "2001:db8:1:2::22", Scope::All)],
            networks: vec![lan()],
            grants: grants
                .into_iter()
                .map(|g| Grant {
                    target: Target::App(id.clone()),
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
        s.addresses[0].app_id = Some("someone-else".into());
        s.grants[0].target = Target::App("someone-else".into());
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &eth0()).is_err());
        // The address is on a network whose interface is not the protected one.
        let mut s = sshd_snap(vec![grant("g", "", Subject::Anyone)]);
        s.networks[0].interface = Some("eth1".into());
        assert!(check_protect_host(&s, &[listener("sshd", 22, "::")], &eth0()).is_err());
    }

    #[test]
    fn lockout_rule_bound_to_another_interface_does_not_help() {
        let id = app_identity(&listener("sshd", 22, "::")).id;
        let a = app(&id, &[22]);
        let s = Snapshot {
            apps: vec![a],
            addresses: vec![address("ad", &id, "ygg", "300:1:2:3::22", Scope::All)],
            networks: vec![ygg()],
            peers: vec![peer("admin", &[(CredentialKind::YggKey, KEY)])],
            grants: vec![Grant {
                target: Target::App(id),
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
