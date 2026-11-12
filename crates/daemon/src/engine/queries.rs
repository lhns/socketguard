//! Read-only queries. Each loads the state once ([`Engine::address_views`]) and works from
//! that copy.

use super::reservations::AddressIndex;
use super::*;
use crate::ruleset;
use crate::AppState;
use socketguard_core::{
    covered_ports, effective_access, grant_reach, grant_targets, reservation_members,
    ActivityQuery, ActivityRecord, App, AppDetail, Credential, Grant, GrantReach, GrantView,
    Network, NetworkKind, Peer, PeerGroup, PortGroup, PortRangeSet, Reach, Reservation, Row,
    Settings, Subject, Tag, Target, V4Context,
};
use std::collections::HashMap;

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
        }
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
        let app_listens_v4 = self.apps_of(grant).into_iter().any(|a| {
            covered_ports(grant, &self.targets, a, self.port_groups, &none).is_some_and(|covered| {
                a.ports
                    .iter()
                    .filter(|p| covered.contains(p.port_ref()))
                    .any(|p| p.listening && p.family.has_v4())
            })
        });
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
        self.bound_rows_on_tor(&mut reach, grant, networks);
        reach
    }

    /// On Tor a reservation is opened as a whole (ADR 0047): a grant on a row that is bound
    /// to a reservation has no effect there. Say so in the reach, with the reason.
    fn bound_rows_on_tor(&self, reach: &mut [GrantReach], grant: &Grant, networks: &[Network]) {
        let rows: Vec<Row> = match &grant.target {
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
        };
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
