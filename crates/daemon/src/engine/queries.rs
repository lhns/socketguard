//! Read-only queries.

use super::*;
use crate::ruleset;
use crate::AppState;
use socketguard_core::{
    grant_reach, ActivityQuery, ActivityRecord, App, AppDetail, Credential, GrantView, Peer,
    PeerGroup, Settings, Subject,
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
        Ok(AppDetail {
            counters: self.metrics.app_counters(&app.id),
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
        let db = &state.db;
        let peer_list = db.list_peers().await?;
        let group_list = db.list_groups().await?;
        let peers: HashMap<&str, &Peer> = peer_list.iter().map(|p| (p.id.as_str(), p)).collect();
        let groups: HashMap<&str, &PeerGroup> =
            group_list.iter().map(|g| (g.id.as_str(), g)).collect();
        let networks = self.networks();
        let mut out = Vec::new();
        for grant in db.list_grants().await? {
            if filter.app_id.as_ref().is_some_and(|a| *a != grant.app_id) {
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
            let creds: Vec<Credential> =
                ruleset::subject_credentials(&group_list, &peers, &grant.subject)
                    .into_iter()
                    .cloned()
                    .collect();
            let reach = grant_reach(
                &grant.subject,
                &creds,
                grant.network_id.as_deref(),
                &networks,
            );
            out.push(GrantView { grant, reach });
        }
        Ok(out)
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
                app_id: Some(grant.app_id.clone()),
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
