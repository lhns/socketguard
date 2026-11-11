//! Port groups (ADR 0047): their lifecycle and attachment to apps.
//!
//! Every change is planned against a [`Catalog`] first ([`Engine::plan_create_group`] and
//! friends), which yields the database writes, the addresses that have to leave and the
//! grants that now cover more. The REST methods run one plan; a batch (`batch`) chains
//! several on its own copy of the catalog. So both check the same things: names, the
//! refusal while a group is used, and the confirmation when a change opens an app to Anyone.

use super::mutations::Catalog;
use super::*;
use crate::api::DaemonEvent;
use crate::state::{NewActivity, Write};
use crate::AppState;
use chrono::Utc;
use socketguard_core::{
    covered_ports, new_id, normalize_ranges, ActivityKind, Address, AppId, Grant, PortGroup,
    PortRange, PortRangeSet, Scope, Subject, Target,
};

/// What a planned change of port groups comes to.
#[derive(Default)]
pub(super) struct GroupPlan {
    pub writes: Vec<Write>,
    /// Addresses that served the group on an app and leave with it; they go off their
    /// interfaces (and networks) before the writes.
    pub removed: Vec<Address>,
    /// Grants that cover more ports than before the change, with the catalog as it is after.
    pub widened: Vec<Grant>,
}

impl GroupPlan {
    /// A grant to Anyone now covers ports it did not.
    pub fn opens_to_anyone(&self) -> bool {
        self.widened.iter().any(|g| g.subject == Subject::Anyone)
    }
}

impl Catalog {
    /// The grants that cover more on one of `app_ids` than they did in `before`.
    pub(super) fn widened_since(&self, before: &Catalog, app_ids: &[AppId]) -> Vec<Grant> {
        let none = PortRangeSet::new();
        let (targets, targets_before) = (self.targets(), before.targets());
        let total = |targets: &[socketguard_core::Tag],
                     cat: &Catalog,
                     grant: &Grant,
                     app: &socketguard_core::App| {
            covered_ports(grant, targets, app, &cat.port_groups, &none)
                .map(|c| c.total())
                .unwrap_or_default()
        };
        let mut out: Vec<Grant> = Vec::new();
        for grant in &self.grants {
            let widened = app_ids.iter().any(|id| {
                let (Some(app), Some(was)) = (self.app(id), before.app(id)) else {
                    return false;
                };
                // The grant as it was (it may have been moved to another target).
                let was_total = before
                    .grants
                    .iter()
                    .find(|g| g.id == grant.id)
                    .map(|g| total(&targets_before, before, g, was))
                    .unwrap_or_default();
                !total(&targets, self, grant, app)
                    .subtract(&was_total)
                    .is_empty()
            });
            if widened {
                out.push(grant.clone());
            }
        }
        out
    }

    fn peer_or_group_label(&self, s: &Subject) -> String {
        match s {
            Subject::Anyone => "Anyone".to_string(),
            Subject::Peer(id) => self
                .peer(id)
                .map_or_else(|| id.clone(), |p| p.label.clone()),
            Subject::Group(id) => self
                .group(id)
                .map_or_else(|| id.clone(), |g| format!("group {}", g.label)),
        }
    }

    /// What uses port group `group_id`, for a refusal: grants with that scope on `app_id`
    /// (or, with None, on any app and any tag) and tag members with that scope.
    fn group_users(&self, group_id: &str, app_id: Option<&str>) -> Vec<String> {
        let scope = Scope::group(group_id);
        let mut out = Vec::new();
        for g in self.grants.iter().filter(|g| g.scope == scope) {
            let on = match (&g.target, app_id) {
                (Target::App(a), Some(want)) if a != want => continue,
                (Target::Tag(_) | Target::Reservation(_), Some(_)) => continue,
                (Target::App(a), _) => self.app(a).map_or_else(|| a.clone(), |a| a.name.clone()),
                (Target::Tag(t), None) => format!(
                    "tag {}",
                    self.tag(t).map_or_else(|| t.clone(), |t| t.label.clone())
                ),
                (Target::Reservation(r), None) => format!(
                    "reservation {}",
                    self.reservation(r)
                        .map_or_else(|| r.clone(), |r| r.label.clone())
                ),
            };
            out.push(format!(
                "the grant to {} on {on}",
                self.peer_or_group_label(&g.subject)
            ));
        }
        for t in &self.tags {
            for m in t.members.iter().filter(|m| m.scope == scope) {
                if app_id.is_some_and(|want| m.app_id != want) {
                    continue;
                }
                let app = self
                    .app(&m.app_id)
                    .map_or_else(|| m.app_id.clone(), |a| a.name.clone());
                out.push(format!("{app} in tag {}", t.label));
            }
        }
        for r in &self.reservations {
            for b in &r.bindings {
                if let socketguard_core::BindingTarget::App { app_id: a, scope } = &b.target {
                    if *scope != Scope::group(group_id) || app_id.is_some_and(|want| a != want) {
                        continue;
                    }
                    let app = self.app(a).map_or_else(|| a.clone(), |a| a.name.clone());
                    out.push(format!("{app} bound to reservation {}", r.label));
                }
            }
        }
        out
    }

    /// Take the automatic addresses with group `group_id` out of the catalog (of `app_id`
    /// only, or of every app) and return them.
    fn take_group_addresses(&mut self, group_id: &str, app_id: Option<&str>) -> Vec<Address> {
        let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.addresses)
            .into_iter()
            .partition(|a| {
                a.scope.group_id() == Some(group_id)
                    && a.app_id
                        .as_deref()
                        .is_some_and(|id| app_id.is_none_or(|want| id == want))
            });
        self.addresses = kept;
        gone
    }
}

/// Validate and normalize the ports of a group: at least one, each a valid range.
pub fn clean_ranges(ports: &[PortRange]) -> Result<Vec<PortRange>, EngineError> {
    if ports.is_empty() {
        return Err(EngineError::Invalid(
            "a port group needs at least one port or port range".into(),
        ));
    }
    for r in ports {
        r.validate().map_err(EngineError::Invalid)?;
    }
    Ok(normalize_ranges(ports))
}

/// The name an unnamed port group gets: its normalized ports (`80/tcp, 443/tcp`), made
/// unique among the existing labels by a ` (2)`, ` (3)`... suffix.
fn default_group_label(ranges: &[PortRange], taken: impl Fn(&str) -> bool) -> String {
    let base = ranges
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut label = base.clone();
    let mut n = 2;
    while taken(&label) {
        label = format!("{base} ({n})");
        n += 1;
    }
    label
}

/// An unidentified app is one port (ADR 0046); it takes no port groups.
fn check_takes_groups(app: &socketguard_core::App) -> Result<(), EngineError> {
    if app.identity_note.as_deref() == Some("unidentified") {
        return Err(EngineError::Invalid(format!(
            "{} is an unidentified socket and takes no port groups",
            app.name
        )));
    }
    Ok(())
}

fn join(items: &[String]) -> String {
    items.join("; ")
}

impl Engine {
    pub async fn list_port_groups(&self, state: &AppState) -> Result<Vec<PortGroup>, EngineError> {
        Ok(state.db.list_port_groups().await?)
    }

    pub async fn get_port_group(
        &self,
        state: &AppState,
        id: &str,
    ) -> Result<PortGroup, EngineError> {
        state
            .db
            .get_port_group(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("port group {id}")))
    }

    // ─── Planning ────────────────────────────────────────────────────────────

    /// Plan a new group, attached to `apps` right away.
    pub(super) fn plan_create_group(
        &self,
        cat: &mut Catalog,
        id: String,
        label: Option<&str>,
        ports: &[PortRange],
        apps: &[AppId],
        confirm_open: bool,
    ) -> Result<(PortGroup, GroupPlan), EngineError> {
        let ranges = clean_ranges(ports)?;
        let taken = |l: &str| cat.port_groups.iter().any(|g| g.label == l);
        let label = match label.map(str::trim) {
            None | Some("") => default_group_label(&ranges, taken),
            Some(l) => {
                let l = Self::clean_label(l, "port group")?;
                if taken(&l) {
                    return Err(EngineError::Conflict(format!(
                        "port group {l} already exists"
                    )));
                }
                l
            }
        };
        let mut attached: Vec<AppId> = Vec::new();
        for a in apps {
            check_takes_groups(
                cat.app(a)
                    .ok_or_else(|| EngineError::NotFound(format!("app {a}")))?,
            )?;
            if !attached.contains(a) {
                attached.push(a.clone());
            }
        }
        let group = PortGroup {
            id,
            label,
            ports: ranges,
            apps: attached.clone(),
            created_at: Utc::now(),
        };
        let before = cat.clone();
        cat.port_groups.push(group.clone());
        let plan = GroupPlan {
            writes: vec![Write::InsertPortGroup(group.clone())],
            widened: cat.widened_since(&before, &attached),
            removed: vec![],
        };
        if plan.opens_to_anyone() && !confirm_open {
            return Err(EngineError::ConfirmationRequired);
        }
        Ok((group, plan))
    }

    /// Plan a new label and/or new ports. New ports take effect everywhere the group is
    /// used, so a grant to Anyone that gains ports needs `confirm_open`.
    pub(super) fn plan_update_group(
        &self,
        cat: &mut Catalog,
        id: &str,
        label: Option<&str>,
        ports: Option<&[PortRange]>,
        confirm_open: bool,
    ) -> Result<(PortGroup, GroupPlan), EngineError> {
        let current = cat
            .port_group(id)
            .ok_or_else(|| EngineError::NotFound(format!("port group {id}")))?
            .clone();
        let label = label
            .map(|l| Self::clean_label(l, "port group"))
            .transpose()?;
        if let Some(l) = &label {
            if cat.port_groups.iter().any(|g| g.label == *l && g.id != id) {
                return Err(EngineError::Conflict(format!(
                    "port group {l} already exists"
                )));
            }
        }
        let ports = ports.map(clean_ranges).transpose()?;
        let before = cat.clone();
        let live = cat
            .port_groups
            .iter_mut()
            .find(|g| g.id == id)
            .expect("checked above");
        if let Some(l) = &label {
            live.label = l.clone();
        }
        if let Some(p) = &ports {
            live.ports = p.clone();
        }
        let updated = live.clone();
        let plan = GroupPlan {
            writes: vec![Write::UpdatePortGroup {
                id: id.to_string(),
                label,
                ports,
            }],
            widened: cat.widened_since(&before, &current.apps),
            removed: vec![],
        };
        if plan.opens_to_anyone() && !confirm_open {
            return Err(EngineError::ConfirmationRequired);
        }
        Ok((updated, plan))
    }

    /// Plan the deletion of a group. Refused while a grant or a tag member uses it; the
    /// addresses that served it go with it.
    pub(super) fn plan_delete_group(
        &self,
        cat: &mut Catalog,
        id: &str,
    ) -> Result<(PortGroup, GroupPlan), EngineError> {
        let group = cat
            .port_group(id)
            .ok_or_else(|| EngineError::NotFound(format!("port group {id}")))?
            .clone();
        let users = cat.group_users(id, None);
        if !users.is_empty() {
            return Err(EngineError::Conflict(format!(
                "port group {} is still used by {}",
                group.label,
                join(&users)
            )));
        }
        let removed = cat.take_group_addresses(id, None);
        cat.port_groups.retain(|g| g.id != id);
        let mut writes: Vec<Write> = removed
            .iter()
            .map(|a| Write::DeleteAddress(a.id.clone()))
            .collect();
        writes.push(Write::DeletePortGroup(id.to_string()));
        Ok((
            group,
            GroupPlan {
                writes,
                removed,
                widened: vec![],
            },
        ))
    }

    /// Plan attaching a group to an app. Attaching again changes nothing.
    pub(super) fn plan_attach_group(
        &self,
        cat: &mut Catalog,
        group_id: &str,
        app_id: &str,
        confirm_open: bool,
    ) -> Result<(PortGroup, GroupPlan), EngineError> {
        let group = cat
            .port_group(group_id)
            .ok_or_else(|| EngineError::NotFound(format!("port group {group_id}")))?
            .clone();
        check_takes_groups(
            cat.app(app_id)
                .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?,
        )?;
        if group.is_attached_to(app_id) {
            return Ok((group, GroupPlan::default()));
        }
        let before = cat.clone();
        let live = cat
            .port_groups
            .iter_mut()
            .find(|g| g.id == group_id)
            .expect("checked above");
        live.apps.push(app_id.to_string());
        let attached = live.clone();
        let plan = GroupPlan {
            writes: vec![Write::AttachPortGroup {
                group_id: group_id.to_string(),
                app_id: app_id.to_string(),
            }],
            widened: cat.widened_since(&before, &[app_id.to_string()]),
            removed: vec![],
        };
        if plan.opens_to_anyone() && !confirm_open {
            return Err(EngineError::ConfirmationRequired);
        }
        Ok((attached, plan))
    }

    /// Plan detaching a group from an app. Refused while a grant or a tag member uses it
    /// there; the app's addresses that served the group go.
    pub(super) fn plan_detach_group(
        &self,
        cat: &mut Catalog,
        group_id: &str,
        app_id: &str,
    ) -> Result<(PortGroup, GroupPlan), EngineError> {
        let group = cat
            .port_group(group_id)
            .ok_or_else(|| EngineError::NotFound(format!("port group {group_id}")))?
            .clone();
        let app_name = cat
            .app(app_id)
            .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?
            .name
            .clone();
        if !group.is_attached_to(app_id) {
            return Err(EngineError::NotFound(format!(
                "port group {} on app {app_name}",
                group.label
            )));
        }
        let users = cat.group_users(group_id, Some(app_id));
        if !users.is_empty() {
            return Err(EngineError::Conflict(format!(
                "port group {} is still used on {app_name} by {}",
                group.label,
                join(&users)
            )));
        }
        let removed = cat.take_group_addresses(group_id, Some(app_id));
        let live = cat
            .port_groups
            .iter_mut()
            .find(|g| g.id == group_id)
            .expect("checked above");
        live.apps.retain(|a| a != app_id);
        let detached = live.clone();
        let mut writes: Vec<Write> = removed
            .iter()
            .map(|a| Write::DeleteAddress(a.id.clone()))
            .collect();
        writes.push(Write::DetachPortGroup {
            group_id: group_id.to_string(),
            app_id: app_id.to_string(),
        });
        Ok((
            detached,
            GroupPlan {
                writes,
                removed,
                widened: vec![],
            },
        ))
    }

    // ─── Running a plan ──────────────────────────────────────────────────────

    /// Save a plan and make it take effect: the addresses it removes leave their interfaces
    /// and networks first (retiring, so they stay denied), then the writes, then the
    /// ruleset.
    async fn run_group_plan(
        &self,
        state: &AppState,
        plan: GroupPlan,
        activity: NewActivity,
    ) -> Result<(), EngineError> {
        if !plan.removed.is_empty() {
            self.retire_addresses(state, &plan.removed).await?;
            self.remove_app_locators(state, &plan.removed).await;
        }
        state
            .db
            .apply_writes(&plan.writes)
            .await
            .map_err(|e| Self::conflict_or_internal(e, "this port group"))?;
        let applied = self.apply_and_ensure(state).await;
        self.commit(
            state,
            applied,
            Some(activity),
            &[
                DaemonEvent::PortGroupsChanged,
                DaemonEvent::GrantsChanged,
                DaemonEvent::AppsChanged,
            ],
        )
        .await?;
        Ok(())
    }

    // ─── REST operations ─────────────────────────────────────────────────────

    pub async fn create_port_group(
        &self,
        state: &AppState,
        label: Option<&str>,
        ports: &[PortRange],
        apps: &[AppId],
        confirm_open: bool,
    ) -> Result<PortGroup, EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) =
            self.plan_create_group(&mut cat, new_id(), label, ports, apps, confirm_open)?;
        let activity = NewActivity::new(
            ActivityKind::PortGroupAdded,
            format!("Added port group {}", group.label),
        );
        self.run_group_plan(state, plan, activity).await?;
        self.get_port_group(state, &group.id).await
    }

    pub async fn update_port_group(
        &self,
        state: &AppState,
        id: &str,
        label: Option<&str>,
        ports: Option<&[PortRange]>,
        confirm_open: bool,
    ) -> Result<PortGroup, EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) = self.plan_update_group(&mut cat, id, label, ports, confirm_open)?;
        let activity = NewActivity::new(
            ActivityKind::PortGroupChanged,
            format!("Changed port group {}", group.label),
        );
        self.run_group_plan(state, plan, activity).await?;
        self.get_port_group(state, id).await
    }

    pub async fn delete_port_group(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) = self.plan_delete_group(&mut cat, id)?;
        let activity = NewActivity::new(
            ActivityKind::PortGroupRemoved,
            format!("Removed port group {}", group.label),
        );
        self.run_group_plan(state, plan, activity).await
    }

    pub async fn attach_port_group(
        &self,
        state: &AppState,
        group_id: &str,
        app_id: &str,
        confirm_open: bool,
    ) -> Result<PortGroup, EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) = self.plan_attach_group(&mut cat, group_id, app_id, confirm_open)?;
        if plan.writes.is_empty() {
            return Ok(group);
        }
        let activity = NewActivity::new(
            ActivityKind::PortGroupChanged,
            format!("Attached port group {}", group.label),
        )
        .app(app_id);
        self.run_group_plan(state, plan, activity).await?;
        self.get_port_group(state, group_id).await
    }

    pub async fn detach_port_group(
        &self,
        state: &AppState,
        group_id: &str,
        app_id: &str,
    ) -> Result<PortGroup, EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) = self.plan_detach_group(&mut cat, group_id, app_id)?;
        let activity = NewActivity::new(
            ActivityKind::PortGroupChanged,
            format!("Detached port group {}", group.label),
        )
        .app(app_id);
        self.run_group_plan(state, plan, activity).await?;
        self.get_port_group(state, group_id).await
    }
}
