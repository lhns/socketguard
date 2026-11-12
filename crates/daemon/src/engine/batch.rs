//! Batch changes (ADR 0045): many operations, one transaction, one firewall update.
//!
//! The operations are planned in order against an in-memory copy of the state
//! ([`Catalog`]), so later ones see earlier ones, including what a `ref` stands for. The
//! plan is a list of database writes, applied in one transaction; a dry run applies them
//! against the real constraints and rolls back.

use super::port_groups::GroupPlan;
use super::reservations::ResPlan;
use super::*;
use crate::api::DaemonEvent;
use crate::catalog::Catalog;
use crate::state::{NewActivity, Write};
use crate::AppState;
use socketguard_core::api_types::{
    BatchChange, Change, ChangeItem, ChangeKind, ChangeOp, ChangesRequest, ChangesResponse,
};
use socketguard_core::{
    Address, BindingTarget, Grant, GrantReach, PortGroup, Reach, Scope, Subject,
};
use std::collections::BTreeMap;

/// The state of planning a batch.
pub(super) struct Plan {
    pub(super) cat: Catalog,
    pub(super) refs: BTreeMap<String, String>,
    pub(super) writes: Vec<Write>,
    pub(super) changes: Vec<BatchChange>,
    pub(super) activities: Vec<NewActivity>,
    pub(super) events: Vec<DaemonEvent>,
    pub(super) networks: Vec<socketguard_core::Network>,
    pub(super) protected: Vec<String>,
    /// Some operation gives someone access they did not have.
    pub(super) changes_reach: bool,
    /// Addresses that go with a port group the batch detaches or deletes.
    pub(super) removed: Vec<Address>,
}

impl Plan {
    pub(super) fn event(&mut self, ev: DaemonEvent) {
        if !self.events.contains(&ev) {
            self.events.push(ev);
        }
    }

    pub(super) fn change(
        &mut self,
        kind: ChangeKind,
        item: ChangeItem,
        name: String,
        id: Option<String>,
    ) {
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
    pub(super) fn resolve(&self, id: &str) -> Result<String, EngineError> {
        if id.starts_with('$') {
            self.refs
                .get(id)
                .cloned()
                .ok_or_else(|| EngineError::Invalid(format!("unknown reference {id}")))
        } else {
            Ok(id.to_string())
        }
    }

    pub(super) fn define_ref(
        &mut self,
        name: &Option<String>,
        id: &str,
    ) -> Result<(), EngineError> {
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

    pub(super) fn grant_reach(&self, grant: &Grant) -> Vec<GrantReach> {
        let c = &self.cat;
        super::queries::ReachCtx::new(
            &c.apps,
            &c.peers,
            &c.groups,
            &c.tags,
            &c.port_groups,
            &c.reservations,
        )
        .reach_of(grant, &self.networks, &self.protected)
    }

    /// A scope whose port group may be a `ref` of an earlier operation.
    pub(super) fn resolve_scope(&self, scope: &Scope) -> Result<Scope, EngineError> {
        Ok(match scope {
            Scope::Group { id } => Scope::Group {
                id: self.resolve(id)?,
            },
            other => other.clone(),
        })
    }

    /// A binding target whose tag or port group may be a `ref` of an earlier operation.
    pub(super) fn resolve_binding(&self, t: &BindingTarget) -> Result<BindingTarget, EngineError> {
        Ok(match t {
            BindingTarget::App { app_id, scope } => BindingTarget::App {
                app_id: app_id.clone(),
                scope: self.resolve_scope(scope)?,
            },
            BindingTarget::Tag { tag_id } => BindingTarget::Tag {
                tag_id: self.resolve(tag_id)?,
            },
        })
    }

    /// Who is reachable through `grants`, for the detail of a change.
    pub(super) fn who(&self, grants: &[Grant]) -> Vec<String> {
        grants
            .iter()
            .map(|g| self.cat.subject_label(&g.subject))
            .collect()
    }

    /// Add the outcome of a reservation operation or `move_app`: its writes, the addresses
    /// that leave, and who can now reach more.
    pub(super) fn push_res_plan(
        &mut self,
        rp: ResPlan,
        (kind, item): (ChangeKind, ChangeItem),
        name: String,
        id: Option<String>,
        activity: NewActivity,
    ) {
        let reach: Vec<GrantReach> = rp
            .widened
            .iter()
            .flat_map(|g| self.grant_reach(g))
            .collect();
        self.changes_reach |= lets_in(&reach);
        let who = self.who(&rp.widened);
        self.changes.push(BatchChange {
            change: Change {
                kind,
                item,
                name,
                detail: (!who.is_empty()).then(|| format!("reachable by {}", who.join(", "))),
                opens_to_anyone: rp.opens_to_anyone(),
            },
            id,
            reach,
        });
        self.activities.push(activity);
        self.writes.extend(rp.writes);
        self.removed.extend(rp.removed);
        self.event(DaemonEvent::ReservationsChanged);
        self.event(DaemonEvent::AddressesChanged);
        self.event(DaemonEvent::GrantsChanged);
        self.event(DaemonEvent::AppsChanged);
    }

    /// Add the outcome of a port group operation: its writes, the addresses that leave, and
    /// who can now reach more (the grants that cover more ports than before).
    pub(super) fn push_group_plan(
        &mut self,
        gp: GroupPlan,
        kind: ChangeKind,
        name: String,
        group: &PortGroup,
        activity: NewActivity,
    ) {
        let reach: Vec<GrantReach> = gp
            .widened
            .iter()
            .flat_map(|g| self.grant_reach(g))
            .collect();
        self.changes_reach |= lets_in(&reach);
        let who = self.who(&gp.widened);
        self.changes.push(BatchChange {
            change: Change {
                kind,
                item: ChangeItem::PortGroup,
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
        self.event(DaemonEvent::PortGroupsChanged);
        self.event(DaemonEvent::GrantsChanged);
        self.event(DaemonEvent::AppsChanged);
    }
}

/// Does any network let the subject in? ("not reachable" everywhere opens nothing.)
pub(super) fn lets_in(reach: &[GrantReach]) -> bool {
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
        // Addresses of a port group that goes or is detached leave their interfaces and
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
        let applied = self.apply_and_ensure(state).await;
        if let Err(e) = state.db.insert_activity(&plan.activities).await {
            warn!("Could not record activity: {e}");
        }
        plan.event(DaemonEvent::Activity);
        let events = std::mem::take(&mut plan.events);
        self.commit(state, applied, None, &events).await?;
        Ok(response(&plan))
    }

    pub(super) async fn run_one(
        &self,
        state: &AppState,
        op: ChangeOp,
    ) -> Result<ChangesResponse, EngineError> {
        self.apply_changes(
            state,
            &ChangesRequest {
                ops: vec![op],
                dry_run: false,
            },
        )
        .await
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
                self.plan_op_create_peer(state, plan, ref_, label, credentials)
                    .await?
            }
            ChangeOp::CreateGroup {
                ref_,
                label,
                members,
            } => self.plan_op_create_peer_group(plan, ref_, label, members)?,
            ChangeOp::CreateTag {
                ref_,
                label,
                patterns,
            } => self.plan_op_create_tag(plan, ref_, label, patterns)?,
            ChangeOp::CreatePortGroup {
                ref_,
                label,
                ports,
                apps,
                confirm_open,
            } => self.plan_op_create_port_group(plan, ref_, label, ports, apps, *confirm_open)?,
            ChangeOp::UpdatePortGroup {
                group_id,
                label,
                ports,
                confirm_open,
            } => self.plan_op_update_port_group(plan, group_id, label, ports, *confirm_open)?,
            ChangeOp::DeletePortGroup { group_id } => {
                self.plan_op_delete_port_group(plan, group_id)?
            }
            ChangeOp::AttachPortGroup {
                group_id,
                app_id,
                confirm_open,
            } => self.plan_op_attach_port_group(plan, group_id, app_id, *confirm_open)?,
            ChangeOp::DetachPortGroup { group_id, app_id } => {
                self.plan_op_detach_port_group(plan, group_id, app_id)?
            }
            ChangeOp::AddGrant {
                target,
                scope,
                network_id,
                subject,
                confirm_open,
            } => self.plan_op_add_grant(plan, target, scope, network_id, subject, *confirm_open)?,
            ChangeOp::RemoveGrant { grant_id } => {
                self.plan_op_remove_grant(state, plan, grant_id).await?
            }
            ChangeOp::AddTagMember {
                tag_id,
                app_id,
                scope,
                confirm_open,
            } => self.plan_op_add_tag_member(plan, tag_id, app_id, scope, *confirm_open)?,
            ChangeOp::RemoveTagMember {
                tag_id,
                app_id,
                scope,
            } => {
                self.plan_op_remove_tag_member(state, plan, tag_id, app_id, scope)
                    .await?
            }
            ChangeOp::CreateReservation {
                ref_,
                label,
                bindings,
                confirm_open,
            } => self.plan_op_create_reservation(plan, ref_, label, bindings, *confirm_open)?,
            ChangeOp::ReserveAddress {
                ref_,
                address_id,
                label,
            } => self.plan_op_reserve_address(plan, ref_, address_id, label)?,
            ChangeOp::RenameReservation {
                reservation_id,
                label,
            } => self.plan_op_rename_reservation(plan, reservation_id, label)?,
            ChangeOp::AddBinding {
                reservation_id,
                target,
                confirm_open,
            } => self.plan_op_add_binding(plan, reservation_id, target, *confirm_open)?,
            ChangeOp::RemoveBinding {
                reservation_id,
                binding_id,
            } => self.plan_op_remove_binding(plan, reservation_id, binding_id)?,
            ChangeOp::ReleaseReservation { reservation_id } => {
                self.plan_op_release_reservation(plan, reservation_id)?
            }
            ChangeOp::MoveApp {
                from,
                to,
                confirm_open,
            } => self.plan_op_move_app(plan, from, to, *confirm_open)?,
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
