//! Tags (ADR 0043): their lifecycle and membership. Grants on tags are ordinary grants
//! (`mutations`); the ruleset expands them.

use super::batch::{lets_in, Plan};
use super::mutations::{any_to_anyone, ensure_confirmed};
use super::*;
use crate::api::DaemonEvent;
use crate::state::{NewActivity, Write};
use crate::AppState;
use chrono::Utc;
use socketguard_core::api_types::{BatchChange, Change, ChangeItem, ChangeKind, ChangeOp};
use socketguard_core::{
    new_id, ActivityKind, App, BindingTarget, GrantReach, Scope, Tag, TagMember, Target,
};

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
        let applied = self.apply_and_ensure(state).await;
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
                scope: Scope::All,
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
        confirm_open: bool,
    ) -> Result<Tag, EngineError> {
        let mut tag = self.get_tag(state, id).await?;
        let label = label.map(|l| Self::clean_label(l, "tag")).transpose()?;
        let patterns = patterns.map(clean_patterns);
        if patterns
            .as_ref()
            .is_some_and(|p| !p.is_empty() && *p != tag.patterns)
        {
            // Setting patterns on a tag that Anyone can reach opens every app that matches
            // later, whether or not one matches today (ADR 0059).
            let cat = crate::catalog::Catalog::load(state).await?;
            ensure_confirmed(any_to_anyone(&cat.grants_through_tag(id)), confirm_open)?;
        }
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
                    scope: Scope::All,
                })
                .collect();
            state.db.apply_writes(&writes).await?;
        }
        let applied = self.apply_and_ensure(state).await;
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
    /// A reservation that binds the tag loses those bindings (they cascade), which frees the
    /// rows: refused without `confirm_open` where that makes a grant to Anyone live on Tor.
    pub async fn delete_tag(
        &self,
        state: &AppState,
        id: &str,
        confirm_open: bool,
    ) -> Result<(), EngineError> {
        let tag = self.get_tag(state, id).await?;
        let mut cat = crate::catalog::Catalog::load(state).await?;
        let bound_before = cat.bound_rows();
        cat.tags.retain(|t| t.id != id);
        for r in cat.reservations.iter_mut() {
            r.bindings
                .retain(|b| !matches!(&b.target, BindingTarget::Tag { tag_id } if tag_id == id));
        }
        cat.grants
            .retain(|g| g.target != Target::Tag(id.to_string()));
        let freed = cat.freed_grants(
            &bound_before,
            &self.networks(),
            &self.protected_interfaces(state).await?,
        );
        ensure_confirmed(any_to_anyone(&freed), confirm_open)?;
        state.db.delete_tag(id).await?;
        let applied = self.apply_and_ensure(state).await;
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

    /// Add an app (or a port or port group of it) to a tag.
    pub async fn add_tag_member(
        &self,
        state: &AppState,
        tag_id: &str,
        app_id: &str,
        scope: Scope,
        confirm_open: bool,
    ) -> Result<Tag, EngineError> {
        self.run_one(
            state,
            ChangeOp::AddTagMember {
                tag_id: tag_id.to_string(),
                app_id: app_id.to_string(),
                scope,
                confirm_open,
            },
        )
        .await?;
        self.get_tag(state, tag_id).await
    }

    /// Remove an app (or a port or port group of it) from a tag. Removing a whole app that
    /// the tag's patterns match is remembered, so discovery does not add it back.
    pub async fn remove_tag_member(
        &self,
        state: &AppState,
        tag_id: &str,
        app_id: &str,
        scope: Scope,
        confirm_open: bool,
    ) -> Result<Tag, EngineError> {
        self.run_one(
            state,
            ChangeOp::RemoveTagMember {
                tag_id: tag_id.to_string(),
                app_id: app_id.to_string(),
                scope,
                confirm_open,
            },
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
        scope: &Scope,
    ) -> Result<bool, EngineError> {
        if !scope.is_all() || tag.patterns.is_empty() {
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
                // A tag that Anyone can reach opens the app by its pattern: say so.
                if let Ok(cat) = crate::catalog::Catalog::load(state).await {
                    for tag_id in &joined {
                        let Some(tag) = cat.tag(tag_id) else { continue };
                        if any_to_anyone(&cat.grants_through_tag(tag_id)) {
                            self.record(
                                state,
                                NewActivity::new(
                                    ActivityKind::TagChanged,
                                    format!(
                                        "{} was opened to Anyone through the pattern of tag {}",
                                        app.name, tag.label
                                    ),
                                )
                                .app(&app.id),
                            )
                            .await;
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(e) => warn!("Could not tag the new app {}: {e:#}", app.name),
        }
    }
}

impl Engine {
    // Batch planning: one method per operation of `ChangeOp` (see `batch`).
    pub(super) fn plan_op_create_tag(
        &self,
        plan: &mut Plan,
        ref_: &Option<String>,
        label: &str,
        patterns: &[String],
    ) -> Result<(), EngineError> {
        let tag = Self::plan_tag(new_id(), label, patterns, &[], &plan.cat.apps)?;
        if plan.cat.tags.iter().any(|t| t.label == tag.label) {
            return Err(EngineError::Conflict(format!(
                "tag {} already exists",
                tag.label
            )));
        }
        plan.define_ref(ref_, &tag.id)?;
        plan.activities.push(NewActivity::new(
            ActivityKind::TagAdded,
            format!("Added tag {}", tag.label),
        ));
        plan.change(
            ChangeKind::Create,
            ChangeItem::Tag,
            tag.label.clone(),
            Some(tag.id.clone()),
        );
        plan.cat.tags.push(tag.clone());
        plan.writes.push(Write::InsertTag(tag));
        plan.event(DaemonEvent::TagsChanged);
        Ok(())
    }

    pub(super) fn plan_op_add_tag_member(
        &self,
        plan: &mut Plan,
        tag_id: &str,
        app_id: &str,
        scope: &Scope,
        confirm_open: bool,
    ) -> Result<(), EngineError> {
        let scope = plan.resolve_scope(scope)?;
        let tag_id = plan.resolve(tag_id)?;
        let app = plan
            .cat
            .app(app_id)
            .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?
            .clone();
        Self::check_scope_on_app(&plan.cat, &app, &scope)?;
        let member = TagMember {
            app_id: app.id.clone(),
            scope: scope.clone(),
        };
        let tag = plan
            .cat
            .tags
            .iter()
            .find(|t| t.id == tag_id)
            .ok_or_else(|| EngineError::NotFound(format!("tag {tag_id}")))?;
        let is_new = !tag.members.contains(&member);
        let tag_label = tag.label.clone();
        // What the tag's grants, and those of a reservation that binds the tag, let in
        // on this app.
        let grants = plan.cat.grants_through_tag(&tag_id);
        let opens = any_to_anyone(&grants);
        ensure_confirmed(is_new && opens, confirm_open)?;
        let tag = plan
            .cat
            .tags
            .iter_mut()
            .find(|t| t.id == tag_id)
            .ok_or_else(|| EngineError::NotFound(format!("tag {tag_id}")))?;
        tag.excluded.retain(|a| *a != app.id);
        if is_new {
            tag.members.push(member);
            // The reach depends on the covered ports, so it is read once the
            // member is in the catalog.
            let reach: Vec<GrantReach> = grants.iter().flat_map(|g| plan.grant_reach(g)).collect();
            let who = plan.who(&grants);
            plan.activities.push(
                NewActivity::new(
                    ActivityKind::TagChanged,
                    format!("Added {} to tag {tag_label}", app.name),
                )
                .app(&app.id),
            );
            plan.changes_reach |= lets_in(&reach);
            plan.changes.push(BatchChange {
                change: Change {
                    kind: ChangeKind::Create,
                    item: ChangeItem::TagMember,
                    name: format!("{} in tag {tag_label}", app.name),
                    detail: (!who.is_empty()).then(|| format!("reachable by {}", who.join(", "))),
                    opens_to_anyone: opens,
                },
                id: None,
                reach,
            });
        }
        plan.writes.push(Write::AddTagMember {
            tag_id,
            app_id: app.id,
            scope,
        });
        plan.event(DaemonEvent::TagsChanged);
        plan.event(DaemonEvent::GrantsChanged);
        Ok(())
    }

    pub(super) async fn plan_op_remove_tag_member(
        &self,
        state: &AppState,
        plan: &mut Plan,
        tag_id: &str,
        app_id: &str,
        scope: &Scope,
    ) -> Result<(), EngineError> {
        let scope = plan.resolve_scope(scope)?;
        let tag_id = plan.resolve(tag_id)?;
        let tag = plan
            .cat
            .tags
            .iter()
            .find(|t| t.id == tag_id)
            .ok_or_else(|| EngineError::NotFound(format!("tag {tag_id}")))?
            .clone();
        if !tag
            .members
            .iter()
            .any(|m| m.app_id == *app_id && m.scope == scope)
        {
            return Err(EngineError::NotFound(format!(
                "membership of app {app_id} in tag {}",
                tag.label
            )));
        }
        let exclude = Self::removal_excludes(state, &tag, app_id, &scope).await?;
        let live = plan.cat.tags.iter_mut().find(|t| t.id == tag_id);
        if let Some(live) = live {
            live.members
                .retain(|m| !(m.app_id == *app_id && m.scope == scope));
            if exclude {
                live.excluded.push(app_id.to_string());
            }
        }
        plan.activities.push(
            NewActivity::new(
                ActivityKind::TagChanged,
                format!("Removed an app from tag {}", tag.label),
            )
            .app(app_id),
        );
        plan.change(
            ChangeKind::Delete,
            ChangeItem::TagMember,
            format!("{app_id} from tag {}", tag.label),
            None,
        );
        plan.writes.push(Write::RemoveTagMember {
            tag_id,
            app_id: app_id.to_string(),
            scope,
            exclude,
        });
        plan.event(DaemonEvent::TagsChanged);
        plan.event(DaemonEvent::GrantsChanged);
        Ok(())
    }
}
