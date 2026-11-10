//! Read-only queries.

use super::*;
use crate::ruleset;
use crate::AppState;
use socketguard_core::{
    covered_ports, effective_access, grant_reach, ActivityQuery, ActivityRecord, App, AppDetail,
    Credential, GrantView, Peer, PeerGroup, Settings, Subject, Target, V4Context,
};
use std::collections::HashMap;

impl Engine {
    pub async fn list_apps(
        &self,
        state: &AppState,
        pending_only: bool,
    ) -> Result<Vec<App>, EngineError> {
        let mut apps = state.db.list_apps().await?;
        if pending_only {
            apps.retain(|a| !a.reviewed);
        }
        Ok(apps)
    }

    /// An app with its addresses, ports and grants (with reach).
    pub async fn get_app(&self, state: &AppState, id: &str) -> Result<AppDetail, EngineError> {
        let app = state
            .db
            .get_app(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("app {id}")))?;
        let grants = self
            .list_grants(
                state,
                GrantFilter {
                    app_id: Some(id.to_string()),
                    ..Default::default()
                },
            )
            .await?;
        let all_grants = state.db.list_grants().await?;
        let tags = state.db.list_tags().await?;
        Ok(AppDetail {
            counters: self.metrics.app_counters(&app.id),
            access: effective_access(&all_grants, &tags, &app.id),
            tags: tags
                .iter()
                .filter(|t| t.members.iter().any(|m| m.app_id == app.id))
                .map(|t| t.id.clone())
                .collect(),
            app,
            grants,
        })
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

    /// Grants with the reach the daemon computes for each network they apply to.
    pub async fn list_grants(
        &self,
        state: &AppState,
        filter: GrantFilter,
    ) -> Result<Vec<GrantView>, EngineError> {
        let cat = super::mutations::Catalog::load(state).await?;
        let groups: HashMap<&str, &PeerGroup> =
            cat.groups.iter().map(|g| (g.id.as_str(), g)).collect();
        let networks = self.networks();
        let protected = self.protected_interfaces(state).await?;
        let mut out = Vec::new();
        for grant in cat.grants.iter().cloned() {
            if filter
                .app_id
                .as_ref()
                .is_some_and(|a| grant.target != Target::App(a.clone()))
            {
                continue;
            }
            if filter
                .tag_id
                .as_ref()
                .is_some_and(|t| grant.target != Target::Tag(t.clone()))
            {
                continue;
            }
            if let Some(pid) = &filter.peer_id {
                let hit = match &grant.subject {
                    Subject::Peer(p) => p == pid,
                    Subject::Group(g) => groups
                        .get(g.as_str())
                        .is_some_and(|g| g.members.contains(pid)),
                    Subject::Anyone => false,
                };
                if !hit {
                    continue;
                }
            }
            if let Some(gid) = &filter.group_id {
                if grant.subject != Subject::Group(gid.clone()) {
                    continue;
                }
            }
            let reach = Self::reach_of(&grant, &cat, &networks, &protected);
            out.push(GrantView { grant, reach });
        }
        Ok(out)
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

    /// How well the subject of `grant` is identified on each network the grant applies to.
    pub(super) fn reach_of(
        grant: &socketguard_core::Grant,
        cat: &super::mutations::Catalog,
        networks: &[socketguard_core::Network],
        protected: &[String],
    ) -> Vec<socketguard_core::GrantReach> {
        let peers: HashMap<&str, &Peer> = cat.peers.iter().map(|p| (p.id.as_str(), p)).collect();
        let creds: Vec<Credential> =
            ruleset::subject_credentials(&cat.groups, &peers, &grant.subject)
                .into_iter()
                .cloned()
                .collect();
        // IPv4 credentials depend on whether the granted ports listen on IPv4 and on
        // whether protect-host filters the interface (ADR 0044).
        let app_listens_v4 = cat.apps.iter().any(|a| {
            let covered = covered_ports(grant, &cat.tags, &a.id);
            a.ports
                .iter()
                .filter(|p| covered.iter().any(|c| c.is_none_or(|c| c == p.port_ref())))
                .any(|p| p.listening && p.family.has_v4())
        });
        grant_reach(
            &grant.subject,
            &creds,
            grant.network_id.as_deref(),
            networks,
            &V4Context {
                app_listens_v4,
                protected,
            },
        )
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
                    Target::Tag(_) => None,
                },
                tag_id: match &grant.target {
                    Target::Tag(id) => Some(id.clone()),
                    Target::App(_) => None,
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
