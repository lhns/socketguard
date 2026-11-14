//! Read-only queries. Each loads the state once ([`Engine::address_views`]) and works from
//! that copy.

use super::mutations::grant_change_name;
use super::*;
use crate::networks;
use crate::ruleset;
use crate::AppState;
use socketguard_core::api_types::{BatchChange, Change, ChangeItem, ChangeKind, NetworkAddPreview};
use socketguard_core::{
    covered_ports, effective_access, grant_reach, grant_targets, reservation_members,
    ActivityQuery, ActivityRecord, Address, App, AppDetail, Credential, CredentialKind, Grant,
    GrantReach, GrantView, Model, Network, NetworkKind, Peer, PeerGroup, PortGroup, PortRangeSet,
    Reach, Reservation, Row, Settings, Subject, Tag, Target, V4Context,
};
use std::collections::{HashMap, HashSet};

/// What the reach of a grant is worked out from, built once per request.
pub(super) struct ReachCtx<'a> {
    apps: HashMap<&'a str, &'a App>,
    peers: HashMap<&'a str, &'a Peer>,
    groups: &'a [PeerGroup],
    tags: &'a [Tag],
    port_groups: &'a [PortGroup],
    /// Tags and, standing in for tags, reservations (see [`grant_targets`]).
    pub(super) targets: Vec<Tag>,
    /// The label of the reservation each bound row belongs to.
    bound: HashMap<Row, &'a str>,
    /// App ports whose IPv4 listeners are all on loopback (see `Snapshot::v4_local_only`).
    v4_local_only: std::collections::BTreeSet<(String, PortRef)>,
}

impl<'a> ReachCtx<'a> {
    pub(super) fn new(
        apps: &'a [App],
        peers: &'a [Peer],
        groups: &'a [PeerGroup],
        tags: &'a [Tag],
        port_groups: &'a [PortGroup],
        reservations: &'a [Reservation],
    ) -> Self {
        let mut bound: HashMap<Row, &str> = HashMap::new();
        for r in reservations {
            for m in reservation_members(r, tags) {
                bound.entry(Row::from(&m)).or_insert(r.label.as_str());
            }
        }
        Self {
            apps: apps.iter().map(|a| (a.id.as_str(), a)).collect(),
            peers: peers.iter().map(|p| (p.id.as_str(), p)).collect(),
            groups,
            tags,
            port_groups,
            targets: grant_targets(tags, reservations),
            bound,
            v4_local_only: Default::default(),
        }
    }

    pub(super) fn with_v4_local_only(
        mut self,
        local: &std::collections::BTreeSet<(String, PortRef)>,
    ) -> Self {
        self.v4_local_only = local.clone();
        self
    }

    /// The apps a grant can concern: the one it targets, or the members of its tag or
    /// reservation.
    fn apps_of(&self, grant: &Grant) -> Vec<&'a App> {
        match &grant.target {
            Target::App(a) => self.apps.get(a.as_str()).copied().into_iter().collect(),
            Target::Tag(id) | Target::Reservation(id) => self
                .targets
                .iter()
                .find(|t| &t.id == id)
                .into_iter()
                .flat_map(|t| t.members.iter())
                .filter_map(|m| self.apps.get(m.app_id.as_str()).copied())
                .collect(),
        }
    }

    /// How well the subject of `grant` is identified on each network the grant applies to.
    pub(super) fn reach_of(
        &self,
        grant: &Grant,
        networks: &[Network],
        protected: &[String],
    ) -> Vec<GrantReach> {
        let creds: Vec<Credential> =
            ruleset::subject_credentials(self.groups, &self.peers, &grant.subject)
                .into_iter()
                .cloned()
                .collect();
        // IPv4 credentials depend on whether the granted ports listen on IPv4 and on
        // whether protect-host filters the interface (ADR 0044).
        let none = PortRangeSet::new();
        // A listener bound to loopback only is not reachable over IPv4 from the network.
        let v4_ports = |exposed: bool| {
            self.apps_of(grant).into_iter().any(|a| {
                covered_ports(grant, &self.targets, a, self.port_groups, &none).is_some_and(
                    |covered| {
                        a.ports
                            .iter()
                            .filter(|p| covered.contains(p.port_ref()))
                            .filter(|p| p.listening && p.family.has_v4())
                            .any(|p| {
                                self.v4_local_only.contains(&(a.id.clone(), p.port_ref()))
                                    != exposed
                            })
                    },
                )
            })
        };
        let app_listens_v4 = v4_ports(true);
        let local_only = !app_listens_v4 && v4_ports(false);
        let mut reach = grant_reach(
            &grant.subject,
            &creds,
            grant.network_id.as_deref(),
            networks,
            &V4Context {
                app_listens_v4,
                protected,
            },
        );
        if local_only && creds.iter().any(|c| c.kind == CredentialKind::Ip) {
            for r in reach.iter_mut().filter(|r| {
                r.reach == Reach::NotReachable
                    && r.note.is_none()
                    && networks.iter().any(|n| {
                        n.id == r.network_id
                            && n.grants_apply
                            && matches!(n.kind, NetworkKind::Lan | NetworkKind::Local)
                    })
            }) {
                r.note = Some("it listens on this machine only (IPv4 loopback)".into());
            }
        }
        self.bound_rows_on_tor(&mut reach, grant, networks);
        reach
    }

    /// The rows a grant names: its own row, or the rows of the members of its tag. A grant on
    /// a reservation names none (it covers whatever is bound).
    fn grant_rows(&self, grant: &Grant) -> Vec<Row> {
        match &grant.target {
            Target::App(a) => vec![Row {
                app_id: a.clone(),
                scope: grant.scope.clone(),
            }],
            Target::Tag(t) => self
                .tags
                .iter()
                .find(|x| &x.id == t)
                .map(|t| t.members.iter().map(Row::from).collect())
                .unwrap_or_default(),
            Target::Reservation(_) => vec![],
        }
    }

    /// Among `grants`, those that name a row in `freed` (bound before a change, not any more)
    /// and now let their subject in on a Tor network: a row is inert there while bound
    /// (`bound_rows_on_tor`), so freeing it publishes its own onion address. Compared per
    /// row, not per grant: a tag grant that was live through its other members gains this
    /// member's service too.
    pub(super) fn freed_live_on_tor<'g>(
        &self,
        grants: &'g [Grant],
        freed: &HashSet<Row>,
        networks: &[Network],
        protected: &[String],
    ) -> Vec<&'g Grant> {
        grants
            .iter()
            .filter(|g| self.grant_rows(g).iter().any(|r| freed.contains(r)))
            .filter(|g| {
                self.reach_of(g, networks, protected).iter().any(|r| {
                    r.reach != Reach::NotReachable
                        && networks
                            .iter()
                            .any(|n| n.id == r.network_id && n.kind == NetworkKind::Tor)
                })
            })
            .collect()
    }

    /// On Tor a reservation is opened as a whole (ADR 0047): a grant on a row that is bound
    /// to a reservation has no effect there. Say so in the reach, with the reason.
    fn bound_rows_on_tor(&self, reach: &mut [GrantReach], grant: &Grant, networks: &[Network]) {
        let rows = self.grant_rows(grant);
        let bound: Vec<(&Row, &str)> = rows
            .iter()
            .filter_map(|row| Some((row, *self.bound.get(row)?)))
            .collect();
        if bound.is_empty() {
            return;
        }
        let notes: Vec<String> = bound
            .iter()
            .map(|(row, label)| {
                let what = match &grant.target {
                    Target::Tag(_) => format!(
                        "{} ",
                        self.apps
                            .get(row.app_id.as_str())
                            .map_or(row.app_id.clone(), |a| a.name.clone())
                    ),
                    _ => String::new(),
                };
                format!(
                    "{what}bound to reservation {label}: on Tor grant the reservation as a whole"
                )
            })
            .collect();
        for r in reach.iter_mut() {
            let tor = networks
                .iter()
                .any(|n| n.id == r.network_id && n.kind == NetworkKind::Tor);
            if tor {
                if bound.len() == rows.len() {
                    r.reach = Reach::NotReachable;
                }
                r.note = Some(notes.join("; "));
            }
        }
    }
}

impl GrantFilter {
    fn matches(&self, grant: &Grant, groups: &[PeerGroup]) -> bool {
        if self
            .app_id
            .as_ref()
            .is_some_and(|a| grant.target != Target::App(a.clone()))
            || self
                .tag_id
                .as_ref()
                .is_some_and(|t| grant.target != Target::Tag(t.clone()))
            || self
                .reservation_id
                .as_ref()
                .is_some_and(|r| grant.target != Target::Reservation(r.clone()))
        {
            return false;
        }
        if let Some(pid) = &self.peer_id {
            let hit = match &grant.subject {
                Subject::Peer(p) => p == pid,
                Subject::Group(g) => groups
                    .iter()
                    .find(|x| &x.id == g)
                    .is_some_and(|g| g.members.contains(pid)),
                Subject::Anyone => false,
            };
            if !hit {
                return false;
            }
        }
        self.group_id
            .as_ref()
            .is_none_or(|gid| grant.subject == Subject::Group(gid.clone()))
    }
}

impl Engine {
    /// Every address with what is computed for the API: `up` (really on the interface, or
    /// really published), `excluded` and the Tor `notes`.
    pub(super) async fn address_views(
        &self,
        state: &AppState,
    ) -> Result<(Vec<Address>, crate::ruleset::Snapshot), EngineError> {
        let snap = self.gather_snapshot(state).await?;
        let model = Model::new(snap.world());
        let info = model.address_info();
        let on_interface: HashSet<std::net::IpAddr> = state
            .db
            .list_owned_addresses()
            .await?
            .into_iter()
            .filter(|o| !o.retiring)
            .map(|o| std::net::IpAddr::V6(o.addr))
            .collect();
        let secrets = state.db.onion_keys().await?;
        let binds = self.binds.lock().unwrap().clone();
        let mut plans: HashMap<String, networks::tor::Plan> = HashMap::new();
        for net in snap
            .networks
            .iter()
            .filter(|n| n.kind == socketguard_core::NetworkKind::Tor)
        {
            for ea in
                networks::enforcement_for(net, &snap, &model, &info, &secrets, &binds).addresses
            {
                plans.insert(ea.id.clone(), networks::tor::plan(&ea));
            }
        }
        let mut out = Vec::new();
        for a in &snap.catalog.addresses {
            let mut a = a.clone();
            let i = info.get(&a.id);
            a.excluded = i.map(|i| i.excluded.ranges()).unwrap_or_default();
            let wanted = i.is_some_and(|i| i.up);
            a.up = match (&a.locator, plans.get(&a.id)) {
                (socketguard_core::Locator::Ipv6 { addr }, _) => {
                    wanted && on_interface.contains(&std::net::IpAddr::V6(*addr))
                }
                (_, Some(plan)) => wanted && plan.spec.is_some(),
                (_, None) => false,
            };
            if let Some(plan) = plans.get(&a.id) {
                a.notes = plan.notes.clone();
            }
            if a.reservation_id.is_some() && plans.contains_key(&a.id) {
                a.notes.push(
                    "on Tor only grants on the reservation itself admit clients; grants on \
                     single bound ports have no effect"
                        .to_string(),
                );
            }
            out.push(a);
        }
        Ok((out, snap))
    }

    pub async fn list_addresses(&self, state: &AppState) -> Result<Vec<Address>, EngineError> {
        Ok(self.address_views(state).await?.0)
    }

    pub async fn list_apps(&self, state: &AppState) -> Result<Vec<App>, EngineError> {
        let (views, snap) = self.address_views(state).await?;
        let index = AddressIndex::new(&views, &snap.catalog.reservations, &snap.catalog.tags);
        let mut apps = snap.catalog.apps.clone();
        for app in &mut apps {
            app.addresses = index.of_app(&app.id);
            app.exe_missing = super::discovery::exe_missing(app);
        }
        Ok(apps)
    }

    /// An app with its addresses, ports and grants (with reach), from one load of the state.
    pub async fn get_app(&self, state: &AppState, id: &str) -> Result<AppDetail, EngineError> {
        let (views, snap) = self.address_views(state).await?;
        let mut app = snap
            .catalog
            .apps
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or_else(|| EngineError::NotFound(format!("app {id}")))?;
        app.addresses =
            AddressIndex::new(&views, &snap.catalog.reservations, &snap.catalog.tags).of_app(id);
        app.exe_missing = super::discovery::exe_missing(&app);
        let ctx = Self::reach_ctx(&snap);
        let protected: Vec<String> = snap.v4_subnets.keys().cloned().collect();
        let grants = snap
            .catalog
            .grants
            .iter()
            .filter(|g| g.target == Target::App(id.to_string()))
            .map(|g| GrantView {
                reach: ctx.reach_of(g, &snap.networks, &protected),
                grant: g.clone(),
            })
            .collect();
        Ok(AppDetail {
            counters: self.metrics.app_counters(&app.id),
            access: effective_access(
                &snap.catalog.grants,
                &ctx.targets,
                &app,
                &snap.catalog.port_groups,
            ),
            port_groups: snap
                .catalog
                .port_groups
                .iter()
                .filter(|g| g.is_attached_to(&app.id))
                .cloned()
                .collect(),
            tags: snap
                .catalog
                .tags
                .iter()
                .filter(|t| t.members.iter().any(|m| m.app_id == app.id))
                .map(|t| t.id.clone())
                .collect(),
            app,
            grants,
        })
    }

    pub(super) fn reach_ctx(snap: &ruleset::Snapshot) -> ReachCtx<'_> {
        ReachCtx::new(
            &snap.catalog.apps,
            &snap.catalog.peers,
            &snap.catalog.groups,
            &snap.catalog.tags,
            &snap.catalog.port_groups,
            &snap.catalog.reservations,
        )
        .with_v4_local_only(&snap.v4_local_only)
    }

    pub async fn list_peers(&self, state: &AppState) -> Result<Vec<Peer>, EngineError> {
        Ok(state.db.list_peers().await?)
    }

    pub async fn get_peer(&self, state: &AppState, id: &str) -> Result<Peer, EngineError> {
        state
            .db
            .get_peer(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("peer {id}")))
    }

    pub async fn list_groups(&self, state: &AppState) -> Result<Vec<PeerGroup>, EngineError> {
        Ok(state.db.list_groups().await?)
    }

    pub async fn get_group(&self, state: &AppState, id: &str) -> Result<PeerGroup, EngineError> {
        state
            .db
            .get_group(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("peer group {id}")))
    }

    /// Grants with the reach the daemon computes for each network they apply to. The reach
    /// is worked out only for the grants the filter keeps.
    pub async fn list_grants(
        &self,
        state: &AppState,
        filter: GrantFilter,
    ) -> Result<Vec<GrantView>, EngineError> {
        let snap = self.gather_snapshot(state).await?;
        let ctx = Self::reach_ctx(&snap);
        let protected: Vec<String> = snap.v4_subnets.keys().cloned().collect();
        Ok(snap
            .catalog
            .grants
            .iter()
            .filter(|g| filter.matches(g, &snap.catalog.groups))
            .map(|g| GrantView {
                reach: ctx.reach_of(g, &snap.networks, &protected),
                grant: g.clone(),
            })
            .collect())
    }

    /// The grants that let someone in on `network` once `inst` is added (ADR 0066): those
    /// whose reach there, worked out by the same code as every other listing, is not
    /// `NotReachable`. A grant without a network applies to every network on which grants
    /// apply; a grant row that names the id applies to it, whatever network it was made for
    /// (removing a network deletes its grants, but a row may name an id nothing serves).
    /// Local on loopback takes no grants, so it never has gains.
    pub(super) async fn grants_taking_effect_on(
        &self,
        state: &AppState,
        inst: &socketguard_core::config::BackendInstanceConfig,
        network: &Arc<dyn networks::Network>,
    ) -> Result<NetworkAddPreview, EngineError> {
        let kind = network.kind();
        let grants_apply = network.capabilities().grants_apply;
        let new_net = Network {
            id: inst.id.clone(),
            kind,
            name: inst.id.clone(),
            interface: inst.backend.interface().map(str::to_string),
            grants_apply,
            status: socketguard_core::NetworkStatus::Down {
                reason: "being added".into(),
            },
            // A /64 network gets its prefix only once it is up; a peer identified by an
            // address suffix would then be let in, so count it as let in now.
            prefix: (grants_apply && network.capabilities().ip_locators)
                .then_some(Ipv6Addr::UNSPECIFIED),
            vlan_id: None,
            child: None,
        };
        let cat = crate::catalog::Catalog::load(state).await?;
        let protected = self.protected_interfaces(state).await?;
        let v4_local_only = self.v4_local_only.lock().unwrap().clone();
        let ctx = ReachCtx::new(
            &cat.apps,
            &cat.peers,
            &cat.groups,
            &cat.tags,
            &cat.port_groups,
            &cat.reservations,
        )
        .with_v4_local_only(&v4_local_only);
        let mut gains = Vec::new();
        for g in &cat.grants {
            let reach: Vec<GrantReach> = ctx
                .reach_of(g, std::slice::from_ref(&new_net), &protected)
                .into_iter()
                .filter(|r| r.reach != Reach::NotReachable)
                .collect();
            if reach.is_empty() {
                continue;
            }
            gains.push(BatchChange {
                change: Change {
                    kind: ChangeKind::Update,
                    item: ChangeItem::Grant,
                    name: grant_change_name(
                        &cat.subject_label(&g.subject),
                        &cat.target_label(&g.target),
                        &g.scope,
                        &cat.port_groups,
                    ),
                    detail: Some(match &g.network_id {
                        Some(n) => format!("on {n}"),
                        None => "on every network".to_string(),
                    }),
                    opens_to_anyone: g.subject == Subject::Anyone,
                },
                id: Some(g.id.clone()),
                reach,
            });
        }
        Ok(NetworkAddPreview {
            confirm_open_required: gains.iter().any(|g| g.change.opens_to_anyone),
            gains,
        })
    }

    /// The interfaces under protect-host that carry IPv4 (what decides IPv4 reach).
    pub(super) async fn protected_interfaces(
        &self,
        state: &AppState,
    ) -> Result<Vec<String>, EngineError> {
        Ok(self
            .protected_v4_subnets(&state.db.protect_host().await?)
            .into_keys()
            .collect())
    }

    pub async fn get_grant(&self, state: &AppState, id: &str) -> Result<GrantView, EngineError> {
        let grant = state
            .db
            .get_grant(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("grant {id}")))?;
        self.list_grants(
            state,
            GrantFilter {
                app_id: match &grant.target {
                    Target::App(id) => Some(id.clone()),
                    _ => None,
                },
                tag_id: match &grant.target {
                    Target::Tag(id) => Some(id.clone()),
                    _ => None,
                },
                reservation_id: match &grant.target {
                    Target::Reservation(id) => Some(id.clone()),
                    _ => None,
                },
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .find(|g| g.grant.id == id)
        .ok_or_else(|| EngineError::NotFound(format!("grant {id}")))
    }

    pub async fn settings(&self, state: &AppState) -> Result<Settings, EngineError> {
        Ok(state.db.settings().await?)
    }

    pub async fn activity(
        &self,
        state: &AppState,
        query: &ActivityQuery,
    ) -> Result<Vec<ActivityRecord>, EngineError> {
        Ok(state.db.list_activity(query).await?)
    }
}

/// The addresses that serve the rows of an app: its automatic ones and those of the
/// reservations it has a row bound in.
pub(super) struct AddressIndex<'a> {
    views: &'a [Address],
    /// The reservations each app has a row bound in.
    bound: HashMap<String, HashSet<&'a str>>,
}

impl<'a> AddressIndex<'a> {
    pub(super) fn new(
        views: &'a [Address],
        reservations: &'a [Reservation],
        tags: &[socketguard_core::Tag],
    ) -> Self {
        let mut bound: HashMap<String, HashSet<&str>> = HashMap::new();
        for r in reservations {
            for m in reservation_members(r, tags) {
                bound.entry(m.app_id).or_default().insert(r.id.as_str());
            }
        }
        Self { views, bound }
    }

    pub(super) fn of_app(&self, app_id: &str) -> Vec<Address> {
        let bound = self.bound.get(app_id);
        self.views
            .iter()
            .filter(|a| {
                a.app_id.as_deref() == Some(app_id)
                    || a.reservation_id
                        .as_deref()
                        .is_some_and(|r| bound.is_some_and(|b| b.contains(r)))
            })
            .cloned()
            .collect()
    }
}
