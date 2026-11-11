//! Reservations and moving an app (ADR 0047), and the views of addresses.
//!
//! Like socket groups, every change is planned against a [`Catalog`] first; the REST
//! methods run the plan as a one-operation batch (`batch`), so a single call and a batch
//! check and apply the same things. A reservation needs no locator when it is created: its
//! addresses are created by [`Engine::ensure_addresses`] once a grant covers it.

use super::mutations::Catalog;
use super::*;
use crate::networks;
use crate::state::Write;
use crate::AppState;
use chrono::Utc;
use socketguard_core::api_types::{ChangeOp, ChangesRequest, ChangesResponse};
use socketguard_core::{
    grant_targets, new_id, reservation_members, Address, App, Binding, BindingTarget, Grant, Model,
    Reservation, ReservationView, Row, Scope, Subject, Target,
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
        self.moves_anyone_grant || self.widened.iter().any(|g| g.subject == Subject::Anyone)
    }
}

fn row_text(cat: &Catalog, row: &Row) -> String {
    let app = cat
        .app(&row.app_id)
        .map_or(row.app_id.clone(), |a| a.name.clone());
    format!("{app} {}", row.scope.describe(&cat.socket_groups))
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
        if plan.opens_to_anyone() && !confirm_open {
            return Err(EngineError::ConfirmationRequired);
        }
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

    /// Plan moving everything of app `from` to app `to`: direct grants, tag memberships,
    /// automatic addresses and reservation bindings. What `to` already has is skipped
    /// (a grant, a membership, a binding) or, for an address, replaced by the moving one.
    /// Socket groups used by what moves are attached to `to`.
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
        let from_app = cat
            .app(from)
            .ok_or_else(|| EngineError::NotFound(format!("app {from}")))?
            .clone();
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
                        row.scope.describe(&before.socket_groups)
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

        // The socket groups that moved things use must be attached to the target.
        for g in groups {
            let attached = cat
                .socket_group(&g)
                .ok_or_else(|| EngineError::NotFound(format!("port group {g}")))?
                .is_attached_to(to);
            if !attached {
                if to_app.identity_note.as_deref() == Some("unidentified") {
                    return Err(EngineError::Invalid(format!(
                        "{} is an unidentified socket and takes no port groups",
                        to_app.name
                    )));
                }
                plan.writes.push(Write::AttachSocketGroup {
                    group_id: g.clone(),
                    app_id: to.to_string(),
                });
                if let Some(x) = cat.socket_groups.iter_mut().find(|x| x.id == g) {
                    x.apps.push(to.to_string());
                }
            }
        }
        let _ = from_app;
        plan.widened = cat.widened_since(&before, &[to.to_string()]);
        if plan.opens_to_anyone() && !confirm_open {
            return Err(EngineError::ConfirmationRequired);
        }
        Ok(plan)
    }

    // ─── Views ───────────────────────────────────────────────────────────────

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
            for ea in networks::enforcement_for(net, &snap, &secrets, &binds).addresses {
                plans.insert(ea.id.clone(), networks::tor::plan(&ea));
            }
        }
        let mut out = Vec::new();
        for a in &snap.addresses {
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

    /// The addresses that serve the rows of `app`: its automatic ones and the reservations
    /// it has a row bound in.
    pub(super) fn addresses_of_app(
        app: &App,
        views: &[Address],
        reservations: &[Reservation],
        tags: &[socketguard_core::Tag],
    ) -> Vec<Address> {
        let bound: HashSet<&str> = reservations
            .iter()
            .filter(|r| {
                reservation_members(r, tags)
                    .iter()
                    .any(|m| m.app_id == app.id)
            })
            .map(|r| r.id.as_str())
            .collect();
        views
            .iter()
            .filter(|a| {
                a.app_id.as_deref() == Some(app.id.as_str())
                    || a.reservation_id
                        .as_deref()
                        .is_some_and(|r| bound.contains(r))
            })
            .cloned()
            .collect()
    }

    pub async fn list_addresses(&self, state: &AppState) -> Result<Vec<Address>, EngineError> {
        Ok(self.address_views(state).await?.0)
    }

    pub async fn list_reservations(
        &self,
        state: &AppState,
    ) -> Result<Vec<ReservationView>, EngineError> {
        let (views, snap) = self.address_views(state).await?;
        let model = Model::new(snap.world());
        let cat = Catalog::load(state).await?;
        let targets = grant_targets(&snap.tags, &snap.reservations);
        let _ = targets;
        let networks = self.networks();
        let protected = self.protected_interfaces(state).await?;
        let mut out = Vec::new();
        for res in &snap.reservations {
            let grants = cat
                .grants
                .iter()
                .filter(|g| g.target == Target::Reservation(res.id.clone()))
                .map(|g| socketguard_core::GrantView {
                    reach: Self::reach_of(g, &cat, &networks, &protected),
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

    async fn run_one(
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
    ) -> Result<ReservationView, EngineError> {
        self.run_one(
            state,
            ChangeOp::RemoveBinding {
                reservation_id: id.to_string(),
                binding_id: binding_id.to_string(),
            },
        )
        .await?;
        self.get_reservation(state, id).await
    }

    pub async fn release_reservation(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        self.run_one(
            state,
            ChangeOp::ReleaseReservation {
                reservation_id: id.to_string(),
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
