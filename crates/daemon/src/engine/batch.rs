//! Batch changes (ADR 0045): many operations, one transaction, one firewall update.
//!
//! The operations are planned in order against an in-memory copy of the state
//! ([`Catalog`]), so later ones see earlier ones, including what a `ref` stands for. The
//! plan is a list of database writes, applied in one transaction; a dry run applies them
//! against the real constraints and rolls back.

use super::mutations::Catalog;
use super::socket_groups::GroupPlan;
use super::*;
use crate::api::DaemonEvent;
use crate::state::{NewActivity, Write};
use crate::AppState;
use chrono::Utc;
use socketguard_core::api_types::{
    BatchChange, Change, ChangeItem, ChangeKind, ChangeOp, ChangesRequest, ChangesResponse,
};
use socketguard_core::{
    new_id, ActivityKind, Address, Credential, Grant, GrantReach, NewGrant, Peer, Reach, Scope,
    SocketGroup, Subject, TagMember, Target,
};
use std::collections::BTreeMap;

/// The state of planning a batch.
struct Plan {
    cat: Catalog,
    refs: BTreeMap<String, String>,
    writes: Vec<Write>,
    changes: Vec<BatchChange>,
    activities: Vec<NewActivity>,
    events: Vec<DaemonEvent>,
    networks: Vec<socketguard_core::Network>,
    protected: Vec<String>,
    /// Some operation gives someone access they did not have.
    changes_reach: bool,
    /// Addresses that go with a socket group the batch detaches or deletes.
    removed: Vec<Address>,
}

impl Plan {
    fn event(&mut self, ev: DaemonEvent) {
        if !self.events.contains(&ev) {
            self.events.push(ev);
        }
    }

    fn change(&mut self, kind: ChangeKind, item: ChangeItem, name: String, id: Option<String>) {
        self.changes.push(BatchChange {
            change: Change {
                kind,
                item,
                name,
                detail: None,
                opens_to_anyone: false,
            },
            id,
            reach: vec![],
        });
    }

    /// An id or a `ref` of an earlier create operation.
    fn resolve(&self, id: &str) -> Result<String, EngineError> {
        if id.starts_with('$') {
            self.refs
                .get(id)
                .cloned()
                .ok_or_else(|| EngineError::Invalid(format!("unknown reference {id}")))
        } else {
            Ok(id.to_string())
        }
    }

    fn define_ref(&mut self, name: &Option<String>, id: &str) -> Result<(), EngineError> {
        let Some(name) = name else {
            return Ok(());
        };
        if !name.starts_with('$') || name.len() < 2 {
            return Err(EngineError::Invalid(format!(
                "a ref starts with $ and has a name, like $new0 (got {name:?})"
            )));
        }
        if self.refs.insert(name.clone(), id.to_string()).is_some() {
            return Err(EngineError::Invalid(format!("ref {name} is used twice")));
        }
        Ok(())
    }

    fn grant_reach(&self, grant: &Grant) -> Vec<GrantReach> {
        Engine::reach_of(grant, &self.cat, &self.networks, &self.protected)
    }

    /// A scope whose socket group may be a `ref` of an earlier operation.
    fn resolve_scope(&self, scope: &Scope) -> Result<Scope, EngineError> {
        Ok(match scope {
            Scope::Group { id } => Scope::Group {
                id: self.resolve(id)?,
            },
            other => other.clone(),
        })
    }

    /// Add the outcome of a socket group operation: its writes, the addresses that leave, and
    /// who can now reach more (the grants that cover more ports than before).
    fn push_group_plan(
        &mut self,
        gp: GroupPlan,
        kind: ChangeKind,
        name: String,
        group: &SocketGroup,
        activity: NewActivity,
    ) {
        let reach: Vec<GrantReach> = gp.widened.iter().flat_map(|g| self.grant_reach(g)).collect();
        self.changes_reach |= lets_in(&reach);
        let who: Vec<String> = gp
            .widened
            .iter()
            .map(|g| match &g.subject {
                Subject::Anyone => "Anyone".to_string(),
                Subject::Peer(id) => self
                    .cat
                    .peer(id)
                    .map_or_else(|| id.clone(), |p| p.label.clone()),
                Subject::Group(id) => self
                    .cat
                    .group(id)
                    .map_or_else(|| id.clone(), |g| format!("group {}", g.label)),
            })
            .collect();
        self.changes.push(BatchChange {
            change: Change {
                kind,
                item: ChangeItem::SocketGroup,
                name,
                detail: (!who.is_empty()).then(|| format!("reachable by {}", who.join(", "))),
                opens_to_anyone: gp.opens_to_anyone(),
            },
            id: Some(group.id.clone()),
            reach,
        });
        self.activities.push(activity);
        self.writes.extend(gp.writes);
        self.removed.extend(gp.removed);
        self.event(DaemonEvent::SocketGroupsChanged);
        self.event(DaemonEvent::GrantsChanged);
        self.event(DaemonEvent::AppsChanged);
    }
}

/// Does any network let the subject in? ("not reachable" everywhere opens nothing.)
fn lets_in(reach: &[GrantReach]) -> bool {
    reach.iter().any(|r| r.reach != Reach::NotReachable)
}

impl Engine {
    /// Apply (or, with `dry_run`, only check) a batch of changes. All or nothing: the first
    /// operation that fails refuses the whole batch and nothing is saved.
    pub async fn apply_changes(
        &self,
        state: &AppState,
        req: &ChangesRequest,
    ) -> Result<ChangesResponse, EngineError> {
        // The confirmation is the first thing every frontend must handle, so it comes
        // before any other complaint.
        for op in &req.ops {
            if let ChangeOp::AddGrant {
                subject: Subject::Anyone,
                confirm_open: false,
                ..
            } = op
            {
                return Err(EngineError::ConfirmationRequired);
            }
        }
        let mut plan = Plan {
            cat: Catalog::load(state).await?,
            refs: BTreeMap::new(),
            writes: Vec::new(),
            changes: Vec::new(),
            activities: Vec::new(),
            events: Vec::new(),
            networks: self.networks(),
            protected: self.protected_interfaces(state).await?,
            changes_reach: false,
            removed: Vec::new(),
        };
        for (i, op) in req.ops.iter().enumerate() {
            self.plan_op(state, &mut plan, op)
                .await
                .map_err(|e| in_operation(i, e))?;
        }

        let response = |plan: &Plan| ChangesResponse {
            dry_run: req.dry_run,
            refs: plan.refs.clone(),
            changes: plan.changes.clone(),
            changes_reach: plan.changes_reach,
        };
        if req.dry_run {
            // The real constraints decide, but nothing stays.
            state
                .db
                .try_writes(&plan.writes)
                .await
                .map_err(|e| Self::conflict_or_internal(e, "a change of this batch"))?;
            return Ok(response(&plan));
        }
        if plan.writes.is_empty() {
            return Ok(response(&plan));
        }
        // Addresses of a socket group that goes or is detached leave their interfaces and
        // networks first (retiring, so they stay denied until really gone).
        if !plan.removed.is_empty() {
            self.retire_addresses(state, &plan.removed).await?;
            self.remove_app_locators(state, &plan.removed).await;
        }
        state
            .db
            .apply_writes(&plan.writes)
            .await
            .map_err(|e| Self::conflict_or_internal(e, "a change of this batch"))?;
        let applied = if plan.removed.is_empty() {
            self.apply_firewall(state).await
        } else {
            self.apply_and_ensure(state).await
        };
        if let Err(e) = state.db.insert_activity(&plan.activities).await {
            warn!("Could not record activity: {e}");
        }
        plan.event(DaemonEvent::Activity);
        let events = std::mem::take(&mut plan.events);
        self.commit(state, applied, None, &events).await?;
        Ok(response(&plan))
    }

    async fn plan_op(
        &self,
        state: &AppState,
        plan: &mut Plan,
        op: &ChangeOp,
    ) -> Result<(), EngineError> {
        match op {
            ChangeOp::CreatePeer {
                ref_,
                label,
                credentials,
            } => {
                let label = Self::clean_label(label, "peer")?;
                if plan.cat.peers.iter().any(|p| p.label == label) {
                    return Err(EngineError::Conflict(format!(
                        "peer {label} already exists"
                    )));
                }
                let mut creds: Vec<Credential> = Vec::new();
                for input in credentials {
                    let c = self.new_credential(state, input).await?;
                    let taken = plan
                        .cat
                        .peers
                        .iter()
                        .flat_map(|p| p.credentials.iter().map(move |x| (&p.label, x)))
                        .find(|(_, x)| x.kind == c.kind && x.value == c.value);
                    if let Some((owner, _)) = taken {
                        return Err(EngineError::Conflict(format!(
                            "{} {} already belongs to peer {owner}",
                            c.kind, c.value
                        )));
                    }
                    if creds.iter().any(|x| x.kind == c.kind && x.value == c.value) {
                        return Err(EngineError::Invalid(format!(
                            "{} {} is listed twice",
                            c.kind, c.value
                        )));
                    }
                    creds.push(c);
                }
                let peer = Peer {
                    id: new_id(),
                    label: label.clone(),
                    credentials: creds,
                    groups: vec![],
                    created_at: Utc::now(),
                };
                plan.define_ref(ref_, &peer.id)?;
                plan.activities.push(
                    NewActivity::new(ActivityKind::PeerAdded, format!("Added peer {label}"))
                        .peer(&peer.id),
                );
                plan.change(
                    ChangeKind::Create,
                    ChangeItem::Peer,
                    label,
                    Some(peer.id.clone()),
                );
                plan.cat.peers.push(peer.clone());
                plan.writes.push(Write::InsertPeer(peer));
                plan.event(DaemonEvent::PeersChanged);
            }
            ChangeOp::CreateTag {
                ref_,
                label,
                patterns,
            } => {
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
            }
            ChangeOp::CreateSocketGroup {
                ref_,
                label,
                ports,
                apps,
                confirm_open,
            } => {
                let (group, gp) = self.plan_create_group(
                    &mut plan.cat,
                    new_id(),
                    label,
                    ports,
                    apps,
                    *confirm_open,
                )?;
                plan.define_ref(ref_, &group.id)?;
                let activity = NewActivity::new(
                    ActivityKind::SocketGroupAdded,
                    format!("Added socket group {}", group.label),
                );
                plan.push_group_plan(gp, ChangeKind::Create, group.label.clone(), &group, activity);
            }
            ChangeOp::UpdateSocketGroup {
                group_id,
                label,
                ports,
                confirm_open,
            } => {
                let id = plan.resolve(group_id)?;
                let (group, gp) = self.plan_update_group(
                    &mut plan.cat,
                    &id,
                    label.as_deref(),
                    ports.as_deref(),
                    *confirm_open,
                )?;
                let activity = NewActivity::new(
                    ActivityKind::SocketGroupChanged,
                    format!("Changed socket group {}", group.label),
                );
                plan.push_group_plan(gp, ChangeKind::Update, group.label.clone(), &group, activity);
            }
            ChangeOp::DeleteSocketGroup { group_id } => {
                let id = plan.resolve(group_id)?;
                let (group, gp) = self.plan_delete_group(&mut plan.cat, &id)?;
                let activity = NewActivity::new(
                    ActivityKind::SocketGroupRemoved,
                    format!("Removed socket group {}", group.label),
                );
                plan.push_group_plan(gp, ChangeKind::Delete, group.label.clone(), &group, activity);
            }
            ChangeOp::AttachSocketGroup {
                group_id,
                app_id,
                confirm_open,
            } => {
                let id = plan.resolve(group_id)?;
                let (group, gp) =
                    self.plan_attach_group(&mut plan.cat, &id, app_id, *confirm_open)?;
                if !gp.writes.is_empty() {
                    let app = plan.cat.app(app_id).map_or(app_id.clone(), |a| a.name.clone());
                    let activity = NewActivity::new(
                        ActivityKind::SocketGroupChanged,
                        format!("Attached socket group {} to {app}", group.label),
                    )
                    .app(app_id);
                    plan.push_group_plan(
                        gp,
                        ChangeKind::Update,
                        format!("{} attached to {app}", group.label),
                        &group,
                        activity,
                    );
                }
            }
            ChangeOp::DetachSocketGroup { group_id, app_id } => {
                let id = plan.resolve(group_id)?;
                let (group, gp) = self.plan_detach_group(&mut plan.cat, &id, app_id)?;
                let app = plan.cat.app(app_id).map_or(app_id.clone(), |a| a.name.clone());
                let activity = NewActivity::new(
                    ActivityKind::SocketGroupChanged,
                    format!("Detached socket group {} from {app}", group.label),
                )
                .app(app_id);
                plan.push_group_plan(
                    gp,
                    ChangeKind::Update,
                    format!("{} detached from {app}", group.label),
                    &group,
                    activity,
                );
            }
            ChangeOp::AddGrant {
                target,
                scope,
                network_id,
                subject,
                confirm_open,
            } => {
                let target = match target {
                    Target::App(id) => Target::App(id.clone()),
                    Target::Tag(id) => Target::Tag(plan.resolve(id)?),
                };
                let subject = match subject {
                    Subject::Peer(id) => Subject::Peer(plan.resolve(id)?),
                    Subject::Group(id) => Subject::Group(plan.resolve(id)?),
                    Subject::Anyone => Subject::Anyone,
                };
                let req = NewGrant {
                    target,
                    scope: plan.resolve_scope(scope)?,
                    network_id: network_id.clone(),
                    subject,
                    confirm_open: *confirm_open,
                };
                let info = self.check_new_grant(&plan.cat, &req)?;
                let grant = Grant {
                    id: new_id(),
                    target: req.target,
                    scope: req.scope,
                    network_id: req.network_id,
                    subject: req.subject,
                    created_at: Utc::now(),
                };
                plan.activities
                    .push(Self::grant_added_activity(&grant, &info));
                let reach = plan.grant_reach(&grant);
                plan.changes_reach |= lets_in(&reach);
                plan.changes.push(BatchChange {
                    change: Change {
                        kind: ChangeKind::Create,
                        item: ChangeItem::Grant,
                        name: format!(
                            "{} to {}{}",
                            info.subject_label,
                            info.target_name,
                            if grant.scope.is_all() {
                                String::new()
                            } else {
                                format!(" {}", grant.scope.describe(&plan.cat.socket_groups))
                            }
                        ),
                        detail: grant.network_id.as_ref().map(|n| format!("on {n}")),
                        opens_to_anyone: grant.subject == Subject::Anyone,
                    },
                    id: Some(grant.id.clone()),
                    reach,
                });
                plan.cat.grants.push(grant.clone());
                plan.writes.push(Write::InsertGrant(grant));
                plan.event(DaemonEvent::GrantsChanged);
            }
            ChangeOp::RemoveGrant { grant_id } => {
                let id = plan.resolve(grant_id)?;
                let at = plan
                    .cat
                    .grants
                    .iter()
                    .position(|g| g.id == id)
                    .ok_or_else(|| EngineError::NotFound(format!("grant {id}")))?;
                let grant = plan.cat.grants.remove(at);
                let reach = plan.grant_reach(&grant);
                plan.activities
                    .push(self.grant_removed_activity(state, &grant).await);
                plan.changes.push(BatchChange {
                    change: Change {
                        kind: ChangeKind::Delete,
                        item: ChangeItem::Grant,
                        name: format!("grant {}", &id[..id.len().min(8)]),
                        detail: None,
                        opens_to_anyone: false,
                    },
                    id: Some(id.clone()),
                    reach,
                });
                plan.writes.push(Write::DeleteGrant(id));
                plan.event(DaemonEvent::GrantsChanged);
            }
            ChangeOp::AddTagMember {
                tag_id,
                app_id,
                scope,
                confirm_open,
            } => {
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
                // What the tag's grants let in on this app.
                let grants: Vec<Grant> = plan
                    .cat
                    .grants
                    .iter()
                    .filter(|g| matches!(&g.target, Target::Tag(t) if *t == tag_id))
                    .cloned()
                    .collect();
                let opens = grants.iter().any(|g| g.subject == Subject::Anyone);
                if is_new && opens && !confirm_open {
                    return Err(EngineError::ConfirmationRequired);
                }
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
                    let reach: Vec<GrantReach> =
                        grants.iter().flat_map(|g| plan.grant_reach(g)).collect();
                    let who: Vec<String> = grants
                        .iter()
                        .map(|g| match &g.subject {
                            Subject::Anyone => "Anyone".to_string(),
                            Subject::Peer(id) => plan
                                .cat
                                .peer(id)
                                .map_or_else(|| id.clone(), |p| p.label.clone()),
                            Subject::Group(id) => plan
                                .cat
                                .group(id)
                                .map_or_else(|| id.clone(), |g| format!("group {}", g.label)),
                        })
                        .collect();
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
                            detail: (!who.is_empty())
                                .then(|| format!("reachable by {}", who.join(", "))),
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
            }
            ChangeOp::RemoveTagMember {
                tag_id,
                app_id,
                scope,
            } => {
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
                        live.excluded.push(app_id.clone());
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
                    app_id: app_id.clone(),
                    scope,
                    exclude,
                });
                plan.event(DaemonEvent::TagsChanged);
                plan.event(DaemonEvent::GrantsChanged);
            }
            ChangeOp::Review { app_id, reviewed } => {
                let app = plan
                    .cat
                    .apps
                    .iter_mut()
                    .find(|a| a.id == *app_id)
                    .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?;
                app.reviewed = *reviewed;
                let name = app.name.clone();
                plan.change(
                    ChangeKind::Update,
                    ChangeItem::App,
                    name,
                    Some(app_id.clone()),
                );
                plan.writes.push(Write::SetReviewed {
                    app_id: app_id.clone(),
                    reviewed: *reviewed,
                });
                plan.event(DaemonEvent::AppsChanged);
            }
        }
        Ok(())
    }
}

/// Name the operation a refusal came from.
fn in_operation(i: usize, e: EngineError) -> EngineError {
    match e {
        EngineError::NotFound(m) => EngineError::NotFound(format!("{m} (operation {i})")),
        EngineError::Invalid(m) => EngineError::Invalid(format!("operation {i}: {m}")),
        EngineError::Conflict(m) => EngineError::Conflict(format!("operation {i}: {m}")),
        other => other,
    }
}
