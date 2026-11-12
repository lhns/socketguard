//! Moving everything of one app to another (ADR 0047): planned like the other changes
//! (`reservations`, `port_groups`) and run as a one-operation batch.

use super::batch::Plan;
use super::mutations::ensure_confirmed;
use super::reservations::ResPlan;
use super::*;
use crate::catalog::Catalog;
use crate::state::{NewActivity, Write};
use socketguard_core::api_types::{ChangeItem, ChangeKind, ChangeOp};
use socketguard_core::{
    reservation_members, ActivityKind, Address, Binding, BindingTarget, Grant, Row, Scope, Subject,
    Target,
};

impl Engine {
    pub(super) fn plan_op_move_app(
        &self,
        plan: &mut Plan,
        from: &str,
        to: &str,
        confirm_open: bool,
    ) -> Result<(), EngineError> {
        let rp = self.plan_move_app(&mut plan.cat, from, to, confirm_open)?;
        let name = |id: &str| plan.cat.app(id).map_or(id.to_string(), |a| a.name.clone());
        let (a, b) = (name(from), name(to));
        let activity = NewActivity::new(
            ActivityKind::AppMoved,
            format!("Moved the grants, tags and addresses of {a} to {b}"),
        )
        .app(to);
        plan.push_res_plan(
            rp,
            (ChangeKind::Update, ChangeItem::App),
            format!("{a} moved to {b}"),
            Some(to.to_string()),
            activity,
        );
        Ok(())
    }

    /// Plan moving everything of app `from` to app `to`: direct grants, tag memberships,
    /// automatic addresses and reservation bindings. What `to` already has is skipped
    /// (a grant, a membership, a binding) or, for an address, replaced by the moving one.
    /// Port groups used by what moves are attached to `to`.
    pub(super) fn plan_move_app(
        &self,
        cat: &mut Catalog,
        from: &str,
        to: &str,
        confirm_open: bool,
    ) -> Result<ResPlan, EngineError> {
        if from == to {
            return Err(EngineError::Invalid(
                "an app cannot be moved onto itself".into(),
            ));
        }
        if cat.app(from).is_none() {
            return Err(EngineError::NotFound(format!("app {from}")));
        }
        let to_app = cat
            .app(to)
            .ok_or_else(|| EngineError::NotFound(format!("app {to}")))?
            .clone();
        let before = cat.clone();
        let mut plan = ResPlan::default();
        let mut groups: Vec<String> = Vec::new();
        let note_group = |scope: &Scope, groups: &mut Vec<String>| {
            if let Some(g) = scope.group_id() {
                if !groups.contains(&g.to_string()) {
                    groups.push(g.to_string());
                }
            }
        };

        // Direct grants.
        let mine: Vec<Grant> = cat
            .grants
            .iter()
            .filter(|g| g.target == Target::App(from.to_string()))
            .cloned()
            .collect();
        for g in mine {
            let dup = cat.grants.iter().any(|x| {
                x.target == Target::App(to.to_string())
                    && x.scope == g.scope
                    && x.network_id == g.network_id
                    && x.subject == g.subject
            });
            if dup {
                plan.writes.push(Write::DeleteGrant(g.id.clone()));
                cat.grants.retain(|x| x.id != g.id);
                continue;
            }
            plan.moves_anyone_grant |= g.subject == Subject::Anyone;
            note_group(&g.scope, &mut groups);
            plan.writes.push(Write::MoveGrant {
                grant_id: g.id.clone(),
                to_app: to.to_string(),
            });
            if let Some(x) = cat.grants.iter_mut().find(|x| x.id == g.id) {
                x.target = Target::App(to.to_string());
            }
        }

        // Tag memberships.
        for tag in cat.tags.iter_mut() {
            let mine: Vec<_> = tag
                .members
                .iter()
                .filter(|m| m.app_id == from)
                .cloned()
                .collect();
            for m in mine {
                note_group(&m.scope, &mut groups);
                plan.writes.push(Write::RemoveTagMember {
                    tag_id: tag.id.clone(),
                    app_id: from.to_string(),
                    scope: m.scope.clone(),
                    exclude: false,
                });
                plan.writes.push(Write::AddTagMember {
                    tag_id: tag.id.clone(),
                    app_id: to.to_string(),
                    scope: m.scope.clone(),
                });
                tag.members.retain(|x| x != &m);
                let moved = socketguard_core::TagMember {
                    app_id: to.to_string(),
                    scope: m.scope,
                };
                if !tag.members.contains(&moved) {
                    tag.members.push(moved);
                }
            }
        }

        // Automatic addresses: the moving one replaces the target's for the same row.
        let mine: Vec<Address> = cat
            .addresses
            .iter()
            .filter(|a| a.app_id.as_deref() == Some(from))
            .cloned()
            .collect();
        for a in mine {
            note_group(&a.scope, &mut groups);
            if let Some(old) = cat
                .addresses
                .iter()
                .find(|x| {
                    x.app_id.as_deref() == Some(to)
                        && x.network_id == a.network_id
                        && x.scope == a.scope
                })
                .cloned()
            {
                plan.writes.push(Write::DeleteAddress(old.id.clone()));
                cat.addresses.retain(|x| x.id != old.id);
                plan.removed.push(old);
            }
            plan.writes.push(Write::MoveAddress {
                address_id: a.id.clone(),
                to_app: to.to_string(),
            });
            if let Some(x) = cat.addresses.iter_mut().find(|x| x.id == a.id) {
                x.app_id = Some(to.to_string());
            }
        }

        // Reservation bindings.
        let others: Vec<Row> = cat
            .reservations
            .iter()
            .flat_map(|r| {
                reservation_members(r, &cat.tags)
                    .iter()
                    .map(|m| (r.id.clone(), Row::from(m)))
                    .collect::<Vec<_>>()
            })
            .filter(|(_, row)| row.app_id == to)
            .map(|(_, row)| row)
            .collect();
        for r in cat.reservations.iter_mut() {
            let mine: Vec<Binding> = r
                .bindings
                .iter()
                .filter(
                    |b| matches!(&b.target, BindingTarget::App { app_id, .. } if app_id == from),
                )
                .cloned()
                .collect();
            for b in mine {
                let BindingTarget::App { scope, .. } = &b.target else {
                    continue;
                };
                let moved = BindingTarget::App {
                    app_id: to.to_string(),
                    scope: scope.clone(),
                };
                let row = Row {
                    app_id: to.to_string(),
                    scope: scope.clone(),
                };
                if r.bindings.iter().any(|x| x.target == moved) {
                    plan.writes.push(Write::DeleteBinding(b.id.clone()));
                    r.bindings.retain(|x| x.id != b.id);
                    continue;
                }
                if others.contains(&row) {
                    return Err(EngineError::Conflict(format!(
                        "{} {} is already bound to another reservation",
                        to_app.name,
                        row.scope.describe(&before.port_groups)
                    )));
                }
                note_group(scope, &mut groups);
                plan.writes.push(Write::MoveBinding {
                    binding_id: b.id.clone(),
                    to_app: to.to_string(),
                });
                if let Some(x) = r.bindings.iter_mut().find(|x| x.id == b.id) {
                    x.target = moved;
                }
            }
        }

        // The port groups that moved things use must be attached to the target.
        for g in groups {
            let attached = cat
                .port_group(&g)
                .ok_or_else(|| EngineError::NotFound(format!("port group {g}")))?
                .is_attached_to(to);
            if !attached {
                if to_app.identity_note.as_deref() == Some("unidentified") {
                    return Err(EngineError::Invalid(format!(
                        "{} is an unidentified socket and takes no port groups",
                        to_app.name
                    )));
                }
                plan.writes.push(Write::AttachPortGroup {
                    group_id: g.clone(),
                    app_id: to.to_string(),
                });
                if let Some(x) = cat.port_groups.iter_mut().find(|x| x.id == g) {
                    x.apps.push(to.to_string());
                }
            }
        }
        plan.widened = cat.widened_since(&before, &[to.to_string()]);
        ensure_confirmed(plan.opens_to_anyone(), confirm_open)?;
        Ok(plan)
    }

    pub async fn move_app(
        &self,
        state: &AppState,
        from: &str,
        to: &str,
        confirm_open: bool,
    ) -> Result<(), EngineError> {
        self.run_one(
            state,
            ChangeOp::MoveApp {
                from: from.to_string(),
                to: to.to_string(),
                confirm_open,
            },
        )
        .await?;
        Ok(())
    }
}
