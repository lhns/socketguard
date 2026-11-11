//! Which addresses exist and are up (ADR 0047), and what each serves. One pure model over
//! the daemon's state, used by the ruleset producer, the Tor enforcement, the interface
//! pass and the API, so they cannot disagree.
//!
//! - A **row** is (app, scope): "All sockets", one socket or an attached socket group.
//! - A grant **names** a row: a grant on an app names (app, its scope); a grant on a tag
//!   names each member's row. A grant on a reservation names no row.
//! - An **automatic address** belongs to a row and is up while a grant that applies on its
//!   network names it. A row bound to a reservation has none.
//! - A **reservation address** (one per reservation and network) is created once a grant
//!   covers something the reservation serves there and is up while one does. On Tor only
//!   a grant on the reservation itself counts (Tor authorizes per address, so a grant on a
//!   single bound row cannot be told apart there).
//! - Networks where grants do not apply (Local on loopback) give every app an All address,
//!   always up.

use crate::model::{
    Address, AddressId, App, AppId, Binding, BindingId, Grant, Network, NetworkId,
    NetworkKind, PortConflict, PortRef, Reservation, ReservationId, Target,
};
use crate::scope::{
    foreign_listening, scope_ports, PortRange, PortRangeSet, Scope, ScopePorts, SocketGroup,
};
use crate::tags::{grant_targets, grants_for_app, reservation_members, AppGrant, Tag, TagMember};
use crate::types::Protocol;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A row of an app.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Row {
    pub app_id: AppId,
    pub scope: Scope,
}

impl From<&TagMember> for Row {
    fn from(m: &TagMember) -> Self {
        Row {
            app_id: m.app_id.clone(),
            scope: m.scope.clone(),
        }
    }
}

/// Whether the firewall enforces the network (IP locators). Tor authorizes per address.
/// Mirrors `Capabilities::ip_locators` of the daemon.
pub fn firewall_enforced(network: &Network) -> bool {
    network.kind != NetworkKind::Tor
}

/// Whether UDP ports can be served on the network. Mirrors `Capabilities::udp`.
pub fn serves_udp(network: &Network) -> bool {
    network.kind != NetworkKind::Tor
}

/// Whether `grant` applies on `network`.
pub fn grant_applies(grant: &Grant, network: &Network) -> bool {
    network.grants_apply
        && grant
            .network_id
            .as_deref()
            .is_none_or(|n| n == network.id)
}

/// The state the models reads.
#[derive(Clone, Copy)]
pub struct World<'a> {
    pub apps: &'a [App],
    pub networks: &'a [Network],
    pub grants: &'a [Grant],
    pub tags: &'a [Tag],
    pub reservations: &'a [Reservation],
    pub socket_groups: &'a [SocketGroup],
    pub addresses: &'a [Address],
}

/// What one address serves, whether it is up, and what it leaves out.
#[derive(Debug, Clone, Default)]
pub struct AddressInfo {
    pub up: bool,
    /// The ports served for each app (an automatic address: its app only).
    pub served: BTreeMap<AppId, ScopePorts>,
    /// Ports of its scope(s) left out because another app listens on them.
    pub excluded: PortRangeSet,
}

/// What a reservation serves, independent of any network.
#[derive(Debug, Clone, Default)]
pub struct Serving {
    pub served: BTreeMap<AppId, ScopePorts>,
    pub conflicts: Vec<PortConflict>,
    pub excluded: PortRangeSet,
}

/// The model over a [`World`], with what it computes once.
pub struct Model<'a> {
    pub w: World<'a>,
    /// Tags and, standing in for tags, reservations (see [`grant_targets`]).
    pub targets: Vec<Tag>,
    apps: HashMap<&'a str, &'a App>,
    foreign: HashMap<&'a str, PortRangeSet>,
}

fn listening(app: &App) -> PortRangeSet {
    PortRangeSet::from_ports(app.ports.iter().filter(|p| p.listening).map(|p| p.port_ref()))
}

impl<'a> Model<'a> {
    pub fn new(w: World<'a>) -> Self {
        Model {
            w,
            targets: grant_targets(w.tags, w.reservations),
            apps: w.apps.iter().map(|a| (a.id.as_str(), a)).collect(),
            foreign: w
                .apps
                .iter()
                .map(|a| (a.id.as_str(), foreign_listening(w.apps, &a.id)))
                .collect(),
        }
    }

    pub fn network(&self, id: &str) -> Option<&'a Network> {
        self.w.networks.iter().find(|n| n.id == id)
    }

    fn foreign_of(&self, app_id: &str) -> PortRangeSet {
        self.foreign.get(app_id).cloned().unwrap_or_default()
    }

    /// The grants that apply to `app` (tag and reservation grants expanded), with the
    /// ports they cover on it.
    pub fn app_grants(&self, app: &App) -> Vec<AppGrant> {
        grants_for_app(
            self.w.grants,
            &self.targets,
            app,
            self.w.socket_groups,
            &self.foreign_of(&app.id),
        )
    }

    fn usable(&self, row: &Row, network: &Network) -> bool {
        let Some(app) = self.apps.get(row.app_id.as_str()) else {
            return false;
        };
        if let Scope::Group { id } = &row.scope {
            if !self
                .w
                .socket_groups
                .iter()
                .any(|g| &g.id == id && g.is_attached_to(&app.id))
            {
                return false;
            }
        }
        !(row.scope.as_port().is_some_and(|p| p.proto == Protocol::Udp) && !serves_udp(network))
    }

    /// The rows a grant that applies on `network` names.
    pub fn named_rows(&self, network: &Network) -> BTreeSet<Row> {
        let mut out = BTreeSet::new();
        for g in self.w.grants.iter().filter(|g| grant_applies(g, network)) {
            let rows: Vec<Row> = match &g.target {
                Target::App(a) => vec![Row {
                    app_id: a.clone(),
                    scope: g.scope.clone(),
                }],
                Target::Tag(t) => self
                    .w
                    .tags
                    .iter()
                    .find(|x| &x.id == t)
                    .map(|t| t.members.iter().map(Row::from).collect())
                    .unwrap_or_default(),
                Target::Reservation(_) => vec![],
            };
            out.extend(rows.into_iter().filter(|r| self.usable(r, network)));
        }
        out
    }

    /// The rows bound to a reservation.
    pub fn bound_rows(&self) -> BTreeSet<Row> {
        self.w
            .reservations
            .iter()
            .flat_map(|r| reservation_members(r, self.w.tags))
            .map(|m| Row::from(&m))
            .collect()
    }

    /// The rows that have an automatic address on `network`, up.
    pub fn automatic_rows(&self, network: &Network) -> BTreeSet<Row> {
        if !network.grants_apply {
            return self
                .w
                .apps
                .iter()
                .map(|a| Row {
                    app_id: a.id.clone(),
                    scope: Scope::All,
                })
                .collect();
        }
        let bound = self.bound_rows();
        self.named_rows(network)
            .into_iter()
            .filter(|r| !bound.contains(r))
            .collect()
    }

    /// The reservation a row is bound to, if any.
    pub fn reservation_of(&self, row: &Row) -> Option<&'a Reservation> {
        self.w.reservations.iter().find(|r| {
            reservation_members(r, self.w.tags)
                .iter()
                .any(|m| Row::from(m) == *row)
        })
    }

    /// What a reservation serves: for each bound row `scope_ports` with the exclusion rule;
    /// a port that rows of several apps still claim after it goes to the app that listens
    /// on it, and is closed when none or several do (ADR 0047). Conflicts are reported from
    /// the plain claims, so a resolved one still shows.
    pub fn reservation_serving(&self, res: &Reservation) -> Serving {
        let none = PortRangeSet::new();
        let groups = self.w.socket_groups;
        // Rows, with the bindings that produce them.
        let mut rows: Vec<(Row, Vec<BindingId>)> = Vec::new();
        for b in &res.bindings {
            let members: Vec<TagMember> =
                reservation_members(&single(res, b), self.w.tags);
            for m in members {
                let row = Row::from(&m);
                match rows.iter_mut().find(|(r, _)| *r == row) {
                    Some((_, ids)) => ids.push(b.id.clone()),
                    None => rows.push((row, vec![b.id.clone()])),
                }
            }
        }
        let mut trimmed: BTreeMap<AppId, ScopePorts> = BTreeMap::new();
        let mut raw: BTreeMap<AppId, PortRangeSet> = BTreeMap::new();
        let mut claims: Vec<RowClaim> = Vec::new();
        for (row, ids) in &rows {
            let Some(app) = self.apps.get(row.app_id.as_str()) else {
                continue;
            };
            let all = scope_ports(app, &row.scope, groups, &none).total();
            let t = scope_ports(app, &row.scope, groups, &self.foreign_of(&app.id));
            trimmed
                .entry(app.id.clone())
                .and_modify(|x| *x = x.union(&t))
                .or_insert(t);
            raw.entry(app.id.clone())
                .and_modify(|x| *x = x.union(&all))
                .or_insert_with(|| all.clone());
            claims.push(RowClaim {
                app_id: app.id.clone(),
                bindings: ids.clone(),
                raw: all,
            });
        }
        let totals: BTreeMap<&AppId, PortRangeSet> =
            trimmed.iter().map(|(a, t)| (a, t.total())).collect();
        let ids: Vec<&AppId> = trimmed.keys().collect();
        let mut contested = PortRangeSet::new();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                contested = contested.union(&totals[a].intersect(&totals[b]));
            }
        }
        let listens: BTreeMap<&AppId, PortRangeSet> = ids
            .iter()
            .map(|a| {
                let l = self.apps.get(a.as_str()).map(|x| listening(x)).unwrap_or_default();
                (*a, totals[a].intersect(&l))
            })
            .collect();
        let mut served: BTreeMap<AppId, ScopePorts> = BTreeMap::new();
        for a in &ids {
            let others = ids
                .iter()
                .filter(|b| b != &a)
                .fold(PortRangeSet::new(), |acc, b| acc.union(&listens[b]));
            let wins = contested.intersect(&listens[a]).subtract(&others);
            served.insert(
                (*a).clone(),
                trimmed[*a].subtract(&contested.subtract(&wins)),
            );
        }
        let excluded = raw.iter().fold(PortRangeSet::new(), |acc, (a, r)| {
            acc.union(&r.subtract(&totals[a]))
        });
        let conflicts = conflicts_of(&claims, &served);
        Serving {
            served,
            conflicts,
            excluded,
        }
    }

    /// Whether a grant that applies on `network` covers something `served` has. For a
    /// reservation on a network that authorizes per address (Tor), only a grant on the
    /// reservation itself counts: a grant on one bound row has no effect there.
    fn covered_on(
        &self,
        network: &Network,
        served: &BTreeMap<AppId, ScopePorts>,
        res: Option<&Reservation>,
    ) -> bool {
        let counts = |g: &AppGrant| match res {
            Some(r) if !firewall_enforced(network) => self
                .w
                .grants
                .iter()
                .any(|x| x.id == g.grant.id && x.target == Target::Reservation(r.id.clone())),
            _ => true,
        };
        served.iter().any(|(app_id, sp)| {
            let Some(app) = self.apps.get(app_id.as_str()) else {
                return false;
            };
            let mut ports = sp.total();
            if !serves_udp(network) {
                ports = ports.intersect(&all_tcp());
            }
            !ports.is_empty()
                && self
                    .app_grants(app)
                    .iter()
                    .filter(|g| grant_applies(&g.grant, network) && counts(g))
                    .any(|g| !g.ports.total().intersect(&ports).is_empty())
        })
    }

    /// The networks on which a grant covers something the reservation serves: where it
    /// has (or gets) an address.
    pub fn reservation_networks(&self, res: &Reservation) -> Vec<NetworkId> {
        let serving = self.reservation_serving(res);
        self.w
            .networks
            .iter()
            .filter(|n| n.grants_apply && self.covered_on(n, &serving.served, Some(res)))
            .map(|n| n.id.clone())
            .collect()
    }

    /// Every address with its state.
    pub fn address_info(&self) -> HashMap<AddressId, AddressInfo> {
        let none = PortRangeSet::new();
        let groups = self.w.socket_groups;
        let mut servings: HashMap<&str, Serving> = HashMap::new();
        let mut out = HashMap::new();
        for a in self.w.addresses {
            let network = self.network(&a.network_id);
            let info = if let Some(rid) = &a.reservation_id {
                let Some(res) = self.w.reservations.iter().find(|r| &r.id == rid) else {
                    out.insert(a.id.clone(), AddressInfo::default());
                    continue;
                };
                let s = servings
                    .entry(rid.as_str())
                    .or_insert_with(|| self.reservation_serving(res));
                let up = network
                    .is_some_and(|n| n.grants_apply && self.covered_on(n, &s.served, Some(res)));
                AddressInfo {
                    up,
                    served: s.served.clone(),
                    excluded: s.excluded.clone(),
                }
            } else if let (Some(app_id), Some(app)) = (
                &a.app_id,
                a.app_id.as_deref().and_then(|id| self.apps.get(id)),
            ) {
                let served = scope_ports(app, &a.scope, groups, &self.foreign_of(&app.id));
                let raw = scope_ports(app, &a.scope, groups, &none).total();
                let up = network.is_some_and(|n| {
                    self.automatic_rows(n).contains(&Row {
                        app_id: app_id.clone(),
                        scope: a.scope.clone(),
                    })
                });
                AddressInfo {
                    up,
                    excluded: raw.subtract(&served.total()),
                    served: BTreeMap::from([(app_id.clone(), served)]),
                }
            } else {
                AddressInfo::default()
            };
            out.insert(a.id.clone(), info);
        }
        out
    }

    /// The automatic addresses that are missing: a row and a network.
    pub fn missing_automatic(&self) -> Vec<(NetworkId, Row)> {
        let mut out = Vec::new();
        for n in self.w.networks {
            for row in self.automatic_rows(n) {
                let has = self.w.addresses.iter().any(|a| {
                    a.network_id == n.id
                        && a.app_id.as_deref() == Some(row.app_id.as_str())
                        && a.scope == row.scope
                });
                if !has {
                    out.push((n.id.clone(), row));
                }
            }
        }
        out
    }

    /// The reservation addresses that are missing: a reservation and a network.
    pub fn missing_reserved(&self) -> Vec<(ReservationId, NetworkId)> {
        let mut out = Vec::new();
        for res in self.w.reservations {
            for n in self.reservation_networks(res) {
                let has = self
                    .w
                    .addresses
                    .iter()
                    .any(|a| a.network_id == n && a.reservation_id.as_ref() == Some(&res.id));
                if !has {
                    out.push((res.id.clone(), n));
                }
            }
        }
        out
    }
}

/// A reservation holding only `binding`, to expand it.
fn single(res: &Reservation, binding: &Binding) -> Reservation {
    Reservation {
        bindings: vec![binding.clone()],
        ..res.clone()
    }
}

fn all_tcp() -> PortRangeSet {
    PortRangeSet::from_ranges([PortRange {
        start: 1,
        end: u16::MAX,
        proto: Protocol::Tcp,
    }])
}

struct RowClaim {
    app_id: AppId,
    bindings: Vec<BindingId>,
    raw: PortRangeSet,
}

/// The ports that rows of several apps claim, in stretches where the claiming bindings and
/// the app served stay the same.
fn conflicts_of(claims: &[RowClaim], served: &BTreeMap<AppId, ScopePorts>) -> Vec<PortConflict> {
    let totals: Vec<(&AppId, PortRangeSet)> = served.iter().map(|(a, s)| (a, s.total())).collect();
    let mut out: Vec<PortConflict> = Vec::new();
    for proto in [Protocol::Tcp, Protocol::Udp] {
        let mut cuts: BTreeSet<u32> = BTreeSet::new();
        let sets = claims
            .iter()
            .map(|c| &c.raw)
            .chain(totals.iter().map(|(_, t)| t));
        for set in sets {
            for r in set.ranges().into_iter().filter(|r| r.proto == proto) {
                cuts.insert(u32::from(r.start));
                cuts.insert(u32::from(r.end) + 1);
            }
        }
        let cuts: Vec<u32> = cuts.into_iter().collect();
        let mut stretch: Vec<(u32, u32, PortConflict)> = Vec::new();
        for pair in cuts.windows(2) {
            let (from, to) = (pair[0], pair[1] - 1);
            let at = PortRef {
                port: from as u16,
                proto,
            };
            let claiming: Vec<&RowClaim> = claims.iter().filter(|c| c.raw.contains(at)).collect();
            let apps: BTreeSet<&AppId> = claiming.iter().map(|c| &c.app_id).collect();
            if apps.len() < 2 {
                continue;
            }
            let bindings: Vec<BindingId> = claiming
                .iter()
                .flat_map(|c| c.bindings.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let served_app = totals
                .iter()
                .find(|(_, t)| t.contains(at))
                .map(|(a, _)| (*a).clone());
            let range = PortRange {
                start: from as u16,
                end: to as u16,
                proto,
            };
            match stretch.last_mut() {
                Some((_, end, c))
                    if *end + 1 == from && c.bindings == bindings && c.served_app == served_app =>
                {
                    *end = to;
                    c.ports.end = to as u16;
                }
                _ => stretch.push((
                    from,
                    to,
                    PortConflict {
                        ports: range,
                        bindings,
                        served_app,
                    },
                )),
            }
        }
        out.extend(stretch.into_iter().map(|(_, _, c)| c));
    }
    out
}

/// What the v7 -> v8 migration makes of an address that has an app and a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyClass {
    /// Stays the automatic address of its row (up when named, else dormant).
    Automatic,
    /// A grant covers what it serves without naming its row: it becomes the address of a
    /// new reservation with this label and one binding to the row.
    Reservation { label: String },
}

/// Classify the addresses of `w` (all automatic, as the schema migration leaves them).
pub fn classify_legacy(w: World<'_>) -> Vec<(AddressId, LegacyClass)> {
    let m = Model::new(w);
    let mut labels: BTreeSet<String> = w.reservations.iter().map(|r| r.label.clone()).collect();
    let mut out = Vec::new();
    for a in w.addresses {
        let (Some(app_id), Some(network)) = (&a.app_id, m.network(&a.network_id)) else {
            out.push((a.id.clone(), LegacyClass::Automatic));
            continue;
        };
        let Some(app) = m.apps.get(app_id.as_str()) else {
            out.push((a.id.clone(), LegacyClass::Automatic));
            continue;
        };
        if !network.grants_apply {
            out.push((a.id.clone(), LegacyClass::Automatic));
            continue;
        }
        let row = Row {
            app_id: app_id.clone(),
            scope: a.scope.clone(),
        };
        if m.named_rows(network).contains(&row) {
            out.push((a.id.clone(), LegacyClass::Automatic));
            continue;
        }
        let served = BTreeMap::from([(
            app_id.clone(),
            scope_ports(app, &a.scope, w.socket_groups, &m.foreign_of(app_id)),
        )]);
        if m.covered_on(network, &served, None) {
            let base = format!("{} {}", app.name, a.scope.describe(w.socket_groups));
            let mut label = base.clone();
            let mut n = 2;
            while labels.contains(&label) {
                label = format!("{base} ({n})");
                n += 1;
            }
            labels.insert(label.clone());
            out.push((a.id.clone(), LegacyClass::Reservation { label }));
        } else {
            out.push((a.id.clone(), LegacyClass::Automatic));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BindingTarget, Locator, NetworkStatus, Subject};
    use crate::scope::tests::{app_with, group};
    use chrono::Utc;

    fn net(id: &str, kind: NetworkKind, grants_apply: bool) -> Network {
        Network {
            id: id.into(),
            kind,
            name: id.into(),
            interface: Some("if0".into()),
            grants_apply,
            status: NetworkStatus::Up,
            prefix: None,
            vlan_id: None,
        }
    }

    fn grant(id: &str, target: Target, scope: Scope, network: Option<&str>) -> Grant {
        Grant {
            id: id.into(),
            target,
            scope,
            network_id: network.map(String::from),
            subject: Subject::Anyone,
            created_at: Utc::now(),
        }
    }

    fn tcp(port: u16) -> Scope {
        Scope::port(PortRef {
            port,
            proto: Protocol::Tcp,
        })
    }

    fn reservation(id: &str, bindings: &[BindingTarget]) -> Reservation {
        Reservation {
            id: id.into(),
            label: id.into(),
            bindings: bindings
                .iter()
                .enumerate()
                .map(|(i, t)| Binding {
                    id: format!("{id}-b{i}"),
                    reservation_id: id.into(),
                    target: t.clone(),
                })
                .collect(),
            created_at: Utc::now(),
        }
    }

    fn bind(app: &str, scope: Scope) -> BindingTarget {
        BindingTarget::App {
            app_id: app.into(),
            scope,
        }
    }

    fn texts(s: &PortRangeSet) -> Vec<String> {
        s.ranges().iter().map(|r| r.to_string()).collect()
    }

    fn loc() -> Locator {
        Locator::Ipv6 {
            addr: "fd00::1".parse().unwrap(),
        }
    }

    #[test]
    fn a_grant_names_its_row_and_a_tag_grant_each_members_row() {
        let apps = [app_with("a", &[(22, true)]), app_with("b", &[(443, true)])];
        let nets = [net("lan", NetworkKind::Lan, true)];
        let tags = [Tag {
            id: "t".into(),
            label: "t".into(),
            patterns: vec![],
            members: vec![
                TagMember {
                    app_id: "a".into(),
                    scope: Scope::All,
                },
                TagMember {
                    app_id: "b".into(),
                    scope: tcp(443),
                },
            ],
            excluded: vec![],
            created_at: Utc::now(),
        }];
        // The tag grant's own scope limits ports and names no other row.
        let grants = [
            grant("g1", Target::App("a".into()), tcp(22), None),
            grant("g2", Target::Tag("t".into()), tcp(80), None),
        ];
        let w = World {
            apps: &apps,
            networks: &nets,
            grants: &grants,
            tags: &tags,
            reservations: &[],
            socket_groups: &[],
            addresses: &[],
        };
        let rows = Model::new(w).named_rows(&nets[0]);
        let names: Vec<String> = rows
            .iter()
            .map(|r| format!("{}:{:?}", r.app_id, r.scope.as_port().map(|p| p.port)))
            .collect();
        assert_eq!(names, ["a:None", "a:Some(22)", "b:Some(443)"]);
    }

    #[test]
    fn a_bound_row_has_no_automatic_address_and_on_tor_only_reservation_grants_count() {
        let apps = [app_with("a", &[(22, true)])];
        let nets = [
            net("lan", NetworkKind::Lan, true),
            net("tor", NetworkKind::Tor, true),
        ];
        let res = [reservation("r", &[bind("a", Scope::All)])];
        let grants = [grant("g", Target::App("a".into()), Scope::All, None)];
        let w = World {
            apps: &apps,
            networks: &nets,
            grants: &grants,
            tags: &[],
            reservations: &res,
            socket_groups: &[],
            addresses: &[],
        };
        let m = Model::new(w);
        assert!(m.automatic_rows(&nets[0]).is_empty());
        assert!(m.automatic_rows(&nets[1]).is_empty());
        // The grant on the row covers what the reservation serves on IP only.
        assert_eq!(m.reservation_networks(&res[0]), ["lan"]);
        // A grant on the reservation covers it everywhere.
        let grants = [grant("g", Target::Reservation("r".into()), Scope::All, None)];
        let w = World { grants: &grants, ..w };
        assert_eq!(Model::new(w).reservation_networks(&res[0]), ["lan", "tor"]);
    }

    #[test]
    fn a_shared_reservation_gives_each_port_to_the_app_listening_on_it() {
        let apps = [app_with("a", &[(80, true)]), app_with("b", &[(443, true)])];
        let groups = [group("web", &["80/tcp", "443/tcp"], &["a", "b"])];
        let res = reservation(
            "r",
            &[
                bind("a", Scope::group("web")),
                bind("b", Scope::group("web")),
            ],
        );
        let w = World {
            apps: &apps,
            networks: &[],
            grants: &[],
            tags: &[],
            reservations: std::slice::from_ref(&res),
            socket_groups: &groups,
            addresses: &[],
        };
        let s = Model::new(w).reservation_serving(&res);
        assert_eq!(texts(&s.served["a"].total()), ["80/tcp"]);
        assert_eq!(texts(&s.served["b"].total()), ["443/tcp"]);
        // Both bindings claim both ports; each is served for the app listening on it.
        assert_eq!(s.conflicts.len(), 2);
        assert_eq!(s.conflicts[0].ports.to_string(), "80/tcp");
        assert_eq!(s.conflicts[0].served_app.as_deref(), Some("a"));
        assert_eq!(s.conflicts[1].served_app.as_deref(), Some("b"));
        assert_eq!(s.conflicts[0].bindings.len(), 2);
    }

    #[test]
    fn an_undetected_port_claimed_twice_is_closed_and_claimed_once_follows() {
        let apps = [app_with("a", &[]), app_with("b", &[])];
        let groups = [group("g1", &["9000-9001/tcp"], &["a", "b"])];
        let res = reservation(
            "r",
            &[bind("a", Scope::group("g1")), bind("b", Scope::group("g1"))],
        );
        let w = World {
            apps: &apps,
            networks: &[],
            grants: &[],
            tags: &[],
            reservations: std::slice::from_ref(&res),
            socket_groups: &groups,
            addresses: &[],
        };
        let s = Model::new(w).reservation_serving(&res);
        assert!(s.served["a"].is_empty() && s.served["b"].is_empty());
        assert_eq!(s.conflicts.len(), 1);
        assert_eq!(s.conflicts[0].ports.to_string(), "9000-9001/tcp");
        assert_eq!(s.conflicts[0].served_app, None);
        // Only one binding claims 9005: it follows that binding.
        let res2 = reservation(
            "r2",
            &[bind("a", Scope::group("g1")), bind("b", tcp(9005))],
        );
        let w2 = World {
            reservations: std::slice::from_ref(&res2),
            ..w
        };
        let s2 = Model::new(w2).reservation_serving(&res2);
        assert_eq!(texts(&s2.served["b"].total()), ["9005/tcp"]);
        assert_eq!(texts(&s2.served["a"].total()), ["9000-9001/tcp"]);
        assert!(s2.conflicts.is_empty());
    }

    #[test]
    fn excluded_ports_are_reported() {
        // b listens on 80; a's range covers it and a does not listen: left out of a's row.
        let apps = [app_with("a", &[]), app_with("b", &[(80, true)])];
        let groups = [group("web", &["80-81/tcp"], &["a"])];
        let nets = [net("lan", NetworkKind::Lan, true)];
        let a = Address::automatic("a", Scope::group("web"), "lan", loc());
        let grants = [grant("g", Target::App("a".into()), Scope::group("web"), None)];
        let addrs = [a.clone()];
        let w = World {
            apps: &apps,
            networks: &nets,
            grants: &grants,
            tags: &[],
            reservations: &[],
            socket_groups: &groups,
            addresses: &addrs,
        };
        let info = &Model::new(w).address_info()[&a.id];
        assert!(info.up);
        assert_eq!(texts(&info.excluded), ["80/tcp"]);
        assert_eq!(texts(&info.served["a"].total()), ["81/tcp"]);
    }

    #[test]
    fn legacy_classification_has_three_cases_and_spares_loopback() {
        let apps = [app_with("a", &[(80, true), (81, true)])];
        let nets = [
            net("ygg", NetworkKind::Yggdrasil, true),
            net("lo", NetworkKind::Local, false),
        ];
        let grants = [grant("g", Target::App("a".into()), tcp(80), None)];
        let named = Address::automatic("a", tcp(80), "ygg", loc());
        let covered = Address::automatic("a", Scope::All, "ygg", loc());
        let nothing = Address::automatic("a", tcp(81), "ygg", loc());
        let local = Address::automatic("a", Scope::All, "lo", loc());
        let addrs = [named.clone(), covered.clone(), nothing.clone(), local.clone()];
        let w = World {
            apps: &apps,
            networks: &nets,
            grants: &grants,
            tags: &[],
            reservations: &[],
            socket_groups: &[],
            addresses: &addrs,
        };
        let c: HashMap<_, _> = classify_legacy(w).into_iter().collect();
        assert_eq!(c[&named.id], LegacyClass::Automatic);
        assert_eq!(
            c[&covered.id],
            LegacyClass::Reservation {
                label: "a All sockets".into()
            }
        );
        assert_eq!(c[&nothing.id], LegacyClass::Automatic);
        assert_eq!(c[&local.id], LegacyClass::Automatic);
    }
}
