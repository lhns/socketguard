//! Reservations (ADR 0047).
//!
//! Like port groups, every change is planned against a [`Catalog`] first; the REST
//! methods run the plan as a one-operation batch (`batch`), so a single call and a batch
//! check and apply the same things. A reservation needs no locator when it is created: its
//! addresses are created by [`Engine::ensure_addresses`] once a grant covers it.

use super::batch::Plan;
use super::mutations::{any_to_anyone, ensure_confirmed};
use super::*;
use crate::catalog::Catalog;
use crate::state::{NewActivity, Write};
use crate::AppState;
use chrono::Utc;
use socketguard_core::api_types::{ChangeItem, ChangeKind, ChangeOp};
use socketguard_core::{
    new_id, reservation_members, ActivityKind, Address, Binding, BindingTarget, Grant, Model,
    Reservation, ReservationView, Row, Scope, Target,
};
use std::collections::HashSet;

/// What a planned change of reservations (or `move_app`) comes to.
#[derive(Default)]
pub(super) struct ResPlan {
    pub writes: Vec<Write>,
    /// Addresses that leave with it; they go off their interfaces and networks first.
    pub removed: Vec<Address>,
    /// Grants that cover more than before, with the catalog as it is after.
    pub widened: Vec<Grant>,
    /// `move_app`: a grant to Anyone moves.
    pub moves_anyone_grant: bool,
}

impl ResPlan {
    pub fn opens_to_anyone(&self) -> bool {
        self.moves_anyone_grant || any_to_anyone(&self.widened)
    }
}

impl Catalog {
    /// The rows bound to a reservation, directly or through a tag.
    pub(super) fn bound_rows(&self) -> HashSet<Row> {
        self.reservations
            .iter()
            .flat_map(|r| reservation_members(r, &self.tags))
            .map(|m| Row::from(&m))
            .collect()
    }

    /// The grants that name a row that was bound in `before` and is not any more, and now
    /// let their subject in on a Tor network (a bound row is inert there, ADR 0047). A change
    /// that frees rows reports these like other changes of reach, and needs `confirm_open`
    /// when Anyone is among them.
    pub(super) fn freed_grants(
        &self,
        before: &HashSet<Row>,
        networks: &[socketguard_core::Network],
        protected: &[String],
    ) -> Vec<Grant> {
        let after = self.bound_rows();
        let freed: HashSet<Row> = before.difference(&after).cloned().collect();
        if freed.is_empty() {
            return vec![];
        }
        let ctx = super::queries::ReachCtx::new(
            &self.apps,
            &self.peers,
            &self.groups,
            &self.tags,
            &self.port_groups,
            &self.reservations,
        );
        ctx.freed_live_on_tor(&self.grants, &freed, networks, protected)
            .into_iter()
            .cloned()
            .collect()
    }
}

fn row_text(cat: &Catalog, row: &Row) -> String {
    let app = cat
        .app(&row.app_id)
        .map_or(row.app_id.clone(), |a| a.name.clone());
    format!("{app} {}", row.scope.describe(&cat.port_groups))
}

impl Engine {
    // ─── Planning ────────────────────────────────────────────────────────────

    /// Check that `target` can be bound to reservation `reservation_id` and return the
    /// rows it stands for. A row is bound to at most one reservation, once.
    fn check_binding_target(
        &self,
        cat: &Catalog,
        reservation_id: &str,
        target: &BindingTarget,
    ) -> Result<Vec<Row>, EngineError> {
        let rows: Vec<Row> = match target {
            BindingTarget::App { app_id, scope } => {
                let app = cat
                    .app(app_id)
                    .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?;
                Self::check_scope_on_app(cat, app, scope)?;
                vec![Row {
                    app_id: app_id.clone(),
                    scope: scope.clone(),
                }]
            }
            BindingTarget::Tag { tag_id } => cat
                .tag(tag_id)
                .ok_or_else(|| EngineError::NotFound(format!("tag {tag_id}")))?
                .members
                .iter()
                .map(Row::from)
                .collect(),
        };
        for row in &rows {
            for r in &cat.reservations {
                if reservation_members(r, &cat.tags)
                    .iter()
                    .any(|m| Row::from(m) == *row)
                {
                    return Err(EngineError::Conflict(format!(
                        "{} is already bound to {}reservation {}",
                        row_text(cat, row),
                        if r.id == reservation_id { "this " } else { "" },
                        r.label
                    )));
                }
            }
        }
        Ok(rows)
    }

    fn unique_label(
        cat: &Catalog,
        label: &str,
        except: Option<&str>,
    ) -> Result<String, EngineError> {
        let label = Self::clean_label(label, "reservation")?;
        if cat
            .reservations
            .iter()
            .any(|r| r.label == label && Some(r.id.as_str()) != except)
        {
            return Err(EngineError::Conflict(format!(
                "reservation {label} already exists"
            )));
        }
        Ok(label)
    }

    /// Plan a new reservation with its first bindings.
    pub(super) fn plan_create_reservation(
        &self,
        cat: &mut Catalog,
        id: String,
        label: &str,
        bindings: &[BindingTarget],
        confirm_open: bool,
    ) -> Result<(Reservation, ResPlan), EngineError> {
        let label = Self::unique_label(cat, label, None)?;
        let res = Reservation {
            id: id.clone(),
            label,
            bindings: vec![],
            created_at: Utc::now(),
        };
        cat.reservations.push(res.clone());
        let mut plan = ResPlan {
            writes: vec![Write::InsertReservation(res)],
            ..Default::default()
        };
        for t in bindings {
            let (_, p) = self.plan_add_binding(cat, &id, t, confirm_open)?;
            plan.writes.extend(p.writes);
            plan.widened.extend(p.widened);
        }
        let created = cat.reservation(&id).expect("just added").clone();
        Ok((created, plan))
    }

    pub(super) fn plan_rename_reservation(
        &self,
        cat: &mut Catalog,
        id: &str,
        label: &str,
    ) -> Result<(Reservation, ResPlan), EngineError> {
        let label = Self::unique_label(cat, label, Some(id))?;
        let res = cat
            .reservations
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| EngineError::NotFound(format!("reservation {id}")))?;
        res.label = label.clone();
        Ok((
            res.clone(),
            ResPlan {
                writes: vec![Write::RenameReservation {
                    id: id.to_string(),
                    label,
                }],
                ..Default::default()
            },
        ))
    }

    /// Plan adding a binding. The grants on the reservation then cover the new rows: that is
    /// a change of reach, and needs `confirm_open` when Anyone is among them.
    pub(super) fn plan_add_binding(
        &self,
        cat: &mut Catalog,
        reservation_id: &str,
        target: &BindingTarget,
        confirm_open: bool,
    ) -> Result<(Binding, ResPlan), EngineError> {
        if cat.reservation(reservation_id).is_none() {
            return Err(EngineError::NotFound(format!(
                "reservation {reservation_id}"
            )));
        }
        let rows = self.check_binding_target(cat, reservation_id, target)?;
        let before = cat.clone();
        let binding = Binding {
            id: new_id(),
            reservation_id: reservation_id.to_string(),
            target: target.clone(),
        };
        cat.reservations
            .iter_mut()
            .find(|r| r.id == reservation_id)
            .expect("checked above")
            .bindings
            .push(binding.clone());
        let apps: Vec<String> = rows
            .iter()
            .map(|r| r.app_id.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let plan = ResPlan {
            writes: vec![Write::InsertBinding(binding.clone())],
            widened: cat.widened_since(&before, &apps),
            ..Default::default()
        };
        ensure_confirmed(plan.opens_to_anyone(), confirm_open)?;
        Ok((binding, plan))
    }

    pub(super) fn plan_remove_binding(
        &self,
        cat: &mut Catalog,
        reservation_id: &str,
        binding_id: &str,
    ) -> Result<(Binding, ResPlan), EngineError> {
        let res = cat
            .reservations
            .iter_mut()
            .find(|r| r.id == reservation_id)
            .ok_or_else(|| EngineError::NotFound(format!("reservation {reservation_id}")))?;
        let at = res
            .bindings
            .iter()
            .position(|b| b.id == binding_id)
            .ok_or_else(|| EngineError::NotFound(format!("binding {binding_id}")))?;
        let binding = res.bindings.remove(at);
        Ok((
            binding,
            ResPlan {
                writes: vec![Write::DeleteBinding(binding_id.to_string())],
                ..Default::default()
            },
        ))
    }

    /// Plan deleting a reservation: its addresses leave their networks, the grants on it
    /// and its bindings go. The rows it held get automatic addresses where grants name them.
    pub(super) fn plan_release_reservation(
        &self,
        cat: &mut Catalog,
        id: &str,
    ) -> Result<(Reservation, ResPlan), EngineError> {
        let at = cat
            .reservations
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| EngineError::NotFound(format!("reservation {id}")))?;
        let res = cat.reservations.remove(at);
        let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut cat.addresses)
            .into_iter()
            .partition(|a| a.reservation_id.as_deref() == Some(id));
        cat.addresses = kept;
        cat.grants
            .retain(|g| g.target != Target::Reservation(id.to_string()));
        Ok((
            res,
            ResPlan {
                writes: vec![Write::DeleteReservation(id.to_string())],
                removed: gone,
                ..Default::default()
            },
        ))
    }

    /// Plan turning an automatic address into a reservation with that row bound, the
    /// address (locator kept) becoming its address on that network.
    pub(super) fn plan_reserve_address(
        &self,
        cat: &mut Catalog,
        address_id: &str,
        label: &str,
    ) -> Result<(Reservation, ResPlan), EngineError> {
        let label = Self::unique_label(cat, label, None)?;
        let addr = cat
            .addresses
            .iter()
            .find(|a| a.id == address_id)
            .ok_or_else(|| EngineError::NotFound(format!("address {address_id}")))?
            .clone();
        let Some(app_id) = addr.app_id.clone() else {
            return Err(EngineError::Invalid(
                "this address already belongs to a reservation".into(),
            ));
        };
        let on_grant_network = self
            .networks()
            .iter()
            .any(|n| n.id == addr.network_id && n.grants_apply);
        if !on_grant_network {
            return Err(EngineError::Invalid(
                "this address is on a network where grants have no effect".into(),
            ));
        }
        let target = BindingTarget::App {
            app_id,
            scope: addr.scope.clone(),
        };
        let id = new_id();
        self.check_binding_target(cat, &id, &target)?;
        let res = Reservation {
            id: id.clone(),
            label,
            bindings: vec![Binding {
                id: new_id(),
                reservation_id: id.clone(),
                target,
            }],
            created_at: Utc::now(),
        };
        cat.reservations.push(res.clone());
        if let Some(a) = cat.addresses.iter_mut().find(|a| a.id == address_id) {
            a.app_id = None;
            a.scope = Scope::All;
            a.reservation_id = Some(id.clone());
        }
        Ok((
            res.clone(),
            ResPlan {
                writes: vec![
                    Write::InsertReservation(res),
                    Write::AssignAddress {
                        address_id: address_id.to_string(),
                        reservation_id: id,
                    },
                ],
                ..Default::default()
            },
        ))
    }

    // ─── Views ───────────────────────────────────────────────────────────────

    pub async fn list_reservations(
        &self,
        state: &AppState,
    ) -> Result<Vec<ReservationView>, EngineError> {
        let (views, snap) = self.address_views(state).await?;
        let model = Model::new(snap.world());
        let ctx = Self::reach_ctx(&snap);
        let protected: Vec<String> = snap.v4_subnets.keys().cloned().collect();
        let mut out = Vec::new();
        for res in &snap.catalog.reservations {
            let grants = snap
                .catalog
                .grants
                .iter()
                .filter(|g| g.target == Target::Reservation(res.id.clone()))
                .map(|g| socketguard_core::GrantView {
                    reach: ctx.reach_of(g, &snap.networks, &protected),
                    grant: g.clone(),
                })
                .collect();
            out.push(ReservationView {
                reservation: res.clone(),
                addresses: views
                    .iter()
                    .filter(|a| a.reservation_id.as_deref() == Some(res.id.as_str()))
                    .cloned()
                    .collect(),
                conflicts: model.reservation_serving(res).conflicts,
                grants,
            });
        }
        Ok(out)
    }

    pub async fn get_reservation(
        &self,
        state: &AppState,
        id: &str,
    ) -> Result<ReservationView, EngineError> {
        self.list_reservations(state)
            .await?
            .into_iter()
            .find(|r| r.reservation.id == id)
            .ok_or_else(|| EngineError::NotFound(format!("reservation {id}")))
    }

    // ─── REST operations: one-operation batches ──────────────────────────────

    pub async fn create_reservation(
        &self,
        state: &AppState,
        label: &str,
        bindings: Vec<BindingTarget>,
        confirm_open: bool,
    ) -> Result<ReservationView, EngineError> {
        let r = self
            .run_one(
                state,
                ChangeOp::CreateReservation {
                    ref_: None,
                    label: label.to_string(),
                    bindings,
                    confirm_open,
                },
            )
            .await?;
        let id = r
            .changes
            .first()
            .and_then(|c| c.id.clone())
            .unwrap_or_default();
        self.get_reservation(state, &id).await
    }

    pub async fn rename_reservation(
        &self,
        state: &AppState,
        id: &str,
        label: &str,
    ) -> Result<ReservationView, EngineError> {
        self.run_one(
            state,
            ChangeOp::RenameReservation {
                reservation_id: id.to_string(),
                label: label.to_string(),
            },
        )
        .await?;
        self.get_reservation(state, id).await
    }

    pub async fn add_binding(
        &self,
        state: &AppState,
        id: &str,
        target: BindingTarget,
        confirm_open: bool,
    ) -> Result<ReservationView, EngineError> {
        self.run_one(
            state,
            ChangeOp::AddBinding {
                reservation_id: id.to_string(),
                target,
                confirm_open,
            },
        )
        .await?;
        self.get_reservation(state, id).await
    }

    pub async fn remove_binding(
        &self,
        state: &AppState,
        id: &str,
        binding_id: &str,
        confirm_open: bool,
    ) -> Result<ReservationView, EngineError> {
        self.run_one(
            state,
            ChangeOp::RemoveBinding {
                reservation_id: id.to_string(),
                binding_id: binding_id.to_string(),
                confirm_open,
            },
        )
        .await?;
        self.get_reservation(state, id).await
    }

    pub async fn release_reservation(
        &self,
        state: &AppState,
        id: &str,
        confirm_open: bool,
    ) -> Result<(), EngineError> {
        self.run_one(
            state,
            ChangeOp::ReleaseReservation {
                reservation_id: id.to_string(),
                confirm_open,
            },
        )
        .await?;
        Ok(())
    }

    pub async fn reserve_address(
        &self,
        state: &AppState,
        address_id: &str,
        label: &str,
    ) -> Result<ReservationView, EngineError> {
        let r = self
            .run_one(
                state,
                ChangeOp::ReserveAddress {
                    ref_: None,
                    address_id: address_id.to_string(),
                    label: label.to_string(),
                },
            )
            .await?;
        let id = r
            .changes
            .first()
            .and_then(|c| c.id.clone())
            .unwrap_or_default();
        self.get_reservation(state, &id).await
    }
}

impl Engine {
    // Batch planning: one method per operation of `ChangeOp` (see `batch`).
    pub(super) fn plan_op_create_reservation(
        &self,
        plan: &mut Plan,
        ref_: &Option<String>,
        label: &str,
        bindings: &[BindingTarget],
        confirm_open: bool,
    ) -> Result<(), EngineError> {
        let bindings: Vec<BindingTarget> = bindings
            .iter()
            .map(|b| plan.resolve_binding(b))
            .collect::<Result<_, _>>()?;
        let (res, rp) =
            self.plan_create_reservation(&mut plan.cat, new_id(), label, &bindings, confirm_open)?;
        plan.define_ref(ref_, &res.id)?;
        let activity = NewActivity::new(
            ActivityKind::ReservationAdded,
            format!("Added reservation {}", res.label),
        );
        plan.push_res_plan(
            rp,
            (ChangeKind::Create, ChangeItem::Reservation),
            res.label.clone(),
            Some(res.id.clone()),
            activity,
        );
        Ok(())
    }

    pub(super) fn plan_op_reserve_address(
        &self,
        plan: &mut Plan,
        ref_: &Option<String>,
        address_id: &str,
        label: &str,
    ) -> Result<(), EngineError> {
        let address_id = plan.resolve(address_id)?;
        let (res, rp) = self.plan_reserve_address(&mut plan.cat, &address_id, label)?;
        plan.define_ref(ref_, &res.id)?;
        let activity = NewActivity::new(
            ActivityKind::ReservationAdded,
            format!("Reserved an address as {}", res.label),
        );
        plan.push_res_plan(
            rp,
            (ChangeKind::Create, ChangeItem::Reservation),
            res.label.clone(),
            Some(res.id.clone()),
            activity,
        );
        Ok(())
    }

    pub(super) fn plan_op_rename_reservation(
        &self,
        plan: &mut Plan,
        reservation_id: &str,
        label: &str,
    ) -> Result<(), EngineError> {
        let id = plan.resolve(reservation_id)?;
        let (res, rp) = self.plan_rename_reservation(&mut plan.cat, &id, label)?;
        let activity = NewActivity::new(
            ActivityKind::ReservationChanged,
            format!("Renamed a reservation to {}", res.label),
        );
        plan.push_res_plan(
            rp,
            (ChangeKind::Update, ChangeItem::Reservation),
            res.label.clone(),
            Some(res.id.clone()),
            activity,
        );
        Ok(())
    }

    pub(super) fn plan_op_add_binding(
        &self,
        plan: &mut Plan,
        reservation_id: &str,
        target: &BindingTarget,
        confirm_open: bool,
    ) -> Result<(), EngineError> {
        let id = plan.resolve(reservation_id)?;
        let target = plan.resolve_binding(target)?;
        let (binding, rp) = self.plan_add_binding(&mut plan.cat, &id, &target, confirm_open)?;
        let label = plan
            .cat
            .reservation(&id)
            .map_or(id.clone(), |r| r.label.clone());
        let activity = NewActivity::new(
            ActivityKind::ReservationChanged,
            format!("Bound something to reservation {label}"),
        );
        plan.push_res_plan(
            rp,
            (ChangeKind::Create, ChangeItem::Binding),
            format!("binding of reservation {label}"),
            Some(binding.id),
            activity,
        );
        Ok(())
    }

    pub(super) fn plan_op_remove_binding(
        &self,
        plan: &mut Plan,
        reservation_id: &str,
        binding_id: &str,
    ) -> Result<(), EngineError> {
        let id = plan.resolve(reservation_id)?;
        let (binding, rp) = self.plan_remove_binding(&mut plan.cat, &id, binding_id)?;
        let label = plan
            .cat
            .reservation(&id)
            .map_or(id.clone(), |r| r.label.clone());
        let activity = NewActivity::new(
            ActivityKind::ReservationChanged,
            format!("Unbound something from reservation {label}"),
        );
        plan.push_res_plan(
            rp,
            (ChangeKind::Delete, ChangeItem::Binding),
            format!("binding of reservation {label}"),
            Some(binding.id),
            activity,
        );
        Ok(())
    }

    pub(super) fn plan_op_release_reservation(
        &self,
        plan: &mut Plan,
        reservation_id: &str,
    ) -> Result<(), EngineError> {
        let id = plan.resolve(reservation_id)?;
        let (res, rp) = self.plan_release_reservation(&mut plan.cat, &id)?;
        let activity = NewActivity::new(
            ActivityKind::ReservationRemoved,
            format!("Released reservation {}", res.label),
        );
        plan.push_res_plan(
            rp,
            (ChangeKind::Delete, ChangeItem::Reservation),
            res.label.clone(),
            Some(res.id.clone()),
            activity,
        );
        Ok(())
    }
}
