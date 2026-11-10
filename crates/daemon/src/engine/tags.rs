//! Tags (ADR 0043): their lifecycle and membership. Grants on tags are ordinary grants
//! (`mutations`); the ruleset expands them.

use super::*;
use crate::api::DaemonEvent;
use crate::state::{NewActivity, Write};
use crate::AppState;
use chrono::Utc;
use socketguard_core::{new_id, ActivityKind, App, PortRef, Tag, TagMember};

/// The patterns as stored: trimmed, no blanks, no duplicates.
pub(super) fn clean_patterns(patterns: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in patterns.iter().map(|p| p.trim()).filter(|p| !p.is_empty()) {
        if !out.iter().any(|o| o == p) {
            out.push(p.to_string());
        }
    }
    out
}

impl Engine {
    pub async fn list_tags(&self, state: &AppState) -> Result<Vec<Tag>, EngineError> {
        Ok(state.db.list_tags().await?)
    }

    pub async fn get_tag(&self, state: &AppState, id: &str) -> Result<Tag, EngineError> {
        state
            .db
            .get_tag(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("tag {id}")))
    }

    /// Create a tag. Apps that already match its patterns join it.
    pub async fn create_tag(
        &self,
        state: &AppState,
        label: &str,
        patterns: &[String],
        members: &[TagMember],
    ) -> Result<Tag, EngineError> {
        let apps = state.db.list_apps().await?;
        let tag = Self::plan_tag(new_id(), label, patterns, members, &apps)?;
        state
            .db
            .apply_writes(&[Write::InsertTag(tag.clone())])
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("tag {}", tag.label)))?;
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(ActivityKind::TagAdded, format!("Added tag {}", tag.label));
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::TagsChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        self.get_tag(state, &tag.id).await
    }

    /// A new tag with `members` and the apps among `apps` its patterns match; checks the
    /// label and that the members' apps exist.
    pub(super) fn plan_tag(
        id: String,
        label: &str,
        patterns: &[String],
        members: &[TagMember],
        apps: &[App],
    ) -> Result<Tag, EngineError> {
        let label = Self::clean_label(label, "tag")?;
        if let Some(m) = members
            .iter()
            .find(|m| !apps.iter().any(|a| a.id == m.app_id))
        {
            return Err(EngineError::NotFound(format!("app {}", m.app_id)));
        }
        let mut tag = Tag {
            id,
            label,
            patterns: clean_patterns(patterns),
            members: members.to_vec(),
            excluded: vec![],
            created_at: Utc::now(),
        };
        let matched: Vec<TagMember> = tag
            .pattern_candidates(apps)
            .into_iter()
            .map(|a| TagMember {
                app_id: a.id.clone(),
                port: None,
            })
            .collect();
        for m in matched {
            if !tag.members.contains(&m) {
                tag.members.push(m);
            }
        }
        Ok(tag)
    }

    /// Rename a tag and/or change its patterns. Apps matching new patterns join it (apps
    /// that were removed by hand stay out); nobody leaves because a pattern went away.
    pub async fn update_tag(
        &self,
        state: &AppState,
        id: &str,
        label: Option<&str>,
        patterns: Option<&[String]>,
    ) -> Result<Tag, EngineError> {
        let mut tag = self.get_tag(state, id).await?;
        let label = label.map(|l| Self::clean_label(l, "tag")).transpose()?;
        let patterns = patterns.map(clean_patterns);
        if !state
            .db
            .update_tag(id, label.as_deref(), patterns.as_deref())
            .await
            .map_err(|e| Self::conflict_or_internal(e, "this tag label"))?
        {
            return Err(EngineError::NotFound(format!("tag {id}")));
        }
        if let Some(p) = patterns {
            tag.patterns = p;
            let apps = state.db.list_apps().await?;
            let writes: Vec<Write> = tag
                .pattern_candidates(&apps)
                .into_iter()
                .map(|a| Write::AddTagMember {
                    tag_id: id.to_string(),
                    app_id: a.id.clone(),
                    port: None,
                })
                .collect();
            state.db.apply_writes(&writes).await?;
        }
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::TagChanged,
            format!("Changed tag {}", label.as_deref().unwrap_or(&tag.label)),
        );
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::TagsChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        self.get_tag(state, id).await
    }

    /// Delete a tag; the grants on it go with it, and with them their rules.
    pub async fn delete_tag(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let tag = self.get_tag(state, id).await?;
        state.db.delete_tag(id).await?;
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::TagRemoved,
            format!("Removed tag {}", tag.label),
        );
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::TagsChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        Ok(())
    }

    /// Add an app (or one port of it) to a tag.
    pub async fn add_tag_member(
        &self,
        state: &AppState,
        tag_id: &str,
        app_id: &str,
        port: Option<PortRef>,
    ) -> Result<Tag, EngineError> {
        let tag = self.get_tag(state, tag_id).await?;
        let app = state
            .db
            .get_app(app_id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?;
        if let Some(p) = port {
            if !app.has_port(p) {
                return Err(EngineError::Invalid(format!(
                    "{} has no port {p}",
                    app.name
                )));
            }
        }
        state
            .db
            .apply_writes(&[Write::AddTagMember {
                tag_id: tag_id.to_string(),
                app_id: app_id.to_string(),
                port,
            }])
            .await?;
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::TagChanged,
            format!("Added {} to tag {}", app.name, tag.label),
        )
        .app(app_id);
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::TagsChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        self.get_tag(state, tag_id).await
    }

    /// Remove an app (or one port of it) from a tag. Removing a whole app that the tag's
    /// patterns match is remembered, so discovery does not add it back.
    pub async fn remove_tag_member(
        &self,
        state: &AppState,
        tag_id: &str,
        app_id: &str,
        port: Option<PortRef>,
    ) -> Result<Tag, EngineError> {
        let tag = self.get_tag(state, tag_id).await?;
        if !tag
            .members
            .iter()
            .any(|m| m.app_id == app_id && m.port == port)
        {
            return Err(EngineError::NotFound(format!(
                "membership of app {app_id} in tag {}",
                tag.label
            )));
        }
        let exclude = Self::removal_excludes(state, &tag, app_id, port).await?;
        state
            .db
            .apply_writes(&[Write::RemoveTagMember {
                tag_id: tag_id.to_string(),
                app_id: app_id.to_string(),
                port,
                exclude,
            }])
            .await?;
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::TagChanged,
            format!("Removed an app from tag {}", tag.label),
        )
        .app(app_id);
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::TagsChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        self.get_tag(state, tag_id).await
    }

    /// Whether removing this membership should be remembered as an exclusion: a whole app
    /// that the tag's patterns match.
    pub(super) async fn removal_excludes(
        state: &AppState,
        tag: &Tag,
        app_id: &str,
        port: Option<PortRef>,
    ) -> Result<bool, EngineError> {
        if port.is_some() || tag.patterns.is_empty() {
            return Ok(false);
        }
        Ok(state
            .db
            .get_app(app_id)
            .await?
            .is_some_and(|a| tag.matches(&a)))
    }

    /// Put a newly discovered app into the tags whose patterns match it. The caller applies
    /// the ruleset (the reconcile pass does, right after).
    pub(super) async fn tag_new_app(&self, state: &AppState, app: &App) {
        match state.db.auto_tag_app(app).await {
            Ok(joined) if !joined.is_empty() => {
                self.emit(state, DaemonEvent::TagsChanged);
            }
            Ok(_) => {}
            Err(e) => warn!("Could not tag the new app {}: {e:#}", app.name),
        }
    }
}
