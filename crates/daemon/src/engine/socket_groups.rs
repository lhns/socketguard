//! Socket groups (ADR 0047): their lifecycle and attachment to apps.
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
    covered_ports, new_id, normalize_ranges, ActivityKind, Address, AppId, Grant, PortRange,
    PortRangeSet, Scope, SocketGroup, Subject, Target,
};

/// What a planned change of socket groups comes to.
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
        let total = |cat: &Catalog, grant: &Grant, app: &socketguard_core::App| {
            covered_ports(grant, &cat.tags, app, &cat.socket_groups, &none)
                .map(|c| c.total())
                .unwrap_or_default()
        };
        let mut out: Vec<Grant> = Vec::new();
        for grant in &self.grants {
            let widened = app_ids.iter().any(|id| {
                let (Some(app), Some(was)) = (self.app(id), before.app(id)) else {
                    return false;
                };
                !total(self, grant, app)
                    .subtract(&total(before, grant, was))
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
            Subject::Peer(id) => self.peer(id).map_or_else(|| id.clone(), |p| p.label.clone()),
            Subject::Group(id) => self
                .group(id)
                .map_or_else(|| id.clone(), |g| format!("group {}", g.label)),
        }
    }

    /// What uses socket group `group_id`, for a refusal: grants with that scope on `app_id`
    /// (or, with None, on any app and any tag) and tag members with that scope.
    fn group_users(&self, group_id: &str, app_id: Option<&str>) -> Vec<String> {
        let scope = Scope::group(group_id);
        let mut out = Vec::new();
        for g in self.grants.iter().filter(|g| g.scope == scope) {
            let on = match (&g.target, app_id) {
                (Target::App(a), Some(want)) if a != want => continue,
                (Target::Tag(_), Some(_)) => continue,
                (Target::App(a), _) => self.app(a).map_or_else(|| a.clone(), |a| a.name.clone()),
                (Target::Tag(t), None) => format!(
                    "tag {}",
                    self.tag(t).map_or_else(|| t.clone(), |t| t.label.clone())
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
        out
    }

    /// Take the addresses with group `group_id` out of the catalog (of `app_id` only, or of
    /// every app) and return them.
    fn take_group_addresses(&mut self, group_id: &str, app_id: Option<&str>) -> Vec<Address> {
        let mut taken = Vec::new();
        for app in &mut self.apps {
            if app_id.is_some_and(|want| app.id != want) {
                continue;
            }
            let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut app.addresses)
                .into_iter()
                .partition(|a| a.scope.group_id() == Some(group_id));
            app.addresses = kept;
            taken.extend(gone);
        }
        taken
    }
}

/// Validate and normalize the ports of a group: at least one, each a valid range.
pub fn clean_ranges(ports: &[PortRange]) -> Result<Vec<PortRange>, EngineError> {
    if ports.is_empty() {
        return Err(EngineError::Invalid(
            "a socket group needs at least one port or port range".into(),
        ));
    }
    for r in ports {
        r.validate().map_err(EngineError::Invalid)?;
    }
    Ok(normalize_ranges(ports))
}

fn join(items: &[String]) -> String {
    items.join("; ")
}

impl Engine {
    pub async fn list_socket_groups(&self, state: &AppState) -> Result<Vec<SocketGroup>, EngineError> {
        Ok(state.db.list_socket_groups().await?)
    }

    pub async fn get_socket_group(
        &self,
        state: &AppState,
        id: &str,
    ) -> Result<SocketGroup, EngineError> {
        state
            .db
            .get_socket_group(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("socket group {id}")))
    }

    // ─── Planning ────────────────────────────────────────────────────────────

    /// Plan a new group, attached to `apps` right away.
    pub(super) fn plan_create_group(
        &self,
        cat: &mut Catalog,
        id: String,
        label: &str,
        ports: &[PortRange],
        apps: &[AppId],
        confirm_open: bool,
    ) -> Result<(SocketGroup, GroupPlan), EngineError> {
        let label = Self::clean_label(label, "socket group")?;
        if cat.socket_groups.iter().any(|g| g.label == label) {
            return Err(EngineError::Conflict(format!(
                "socket group {label} already exists"
            )));
        }
        let mut attached: Vec<AppId> = Vec::new();
        for a in apps {
            cat.app(a)
                .ok_or_else(|| EngineError::NotFound(format!("app {a}")))?;
            if !attached.contains(a) {
                attached.push(a.clone());
            }
        }
        let group = SocketGroup {
            id,
            label,
            ports: clean_ranges(ports)?,
            apps: attached.clone(),
            created_at: Utc::now(),
        };
        let before = cat.clone();
        cat.socket_groups.push(group.clone());
        let plan = GroupPlan {
            writes: vec![Write::InsertSocketGroup(group.clone())],
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
    ) -> Result<(SocketGroup, GroupPlan), EngineError> {
        let current = cat
            .socket_group(id)
            .ok_or_else(|| EngineError::NotFound(format!("socket group {id}")))?
            .clone();
        let label = label
            .map(|l| Self::clean_label(l, "socket group"))
            .transpose()?;
        if let Some(l) = &label {
            if cat
                .socket_groups
                .iter()
                .any(|g| g.label == *l && g.id != id)
            {
                return Err(EngineError::Conflict(format!(
                    "socket group {l} already exists"
                )));
            }
        }
        let ports = ports.map(clean_ranges).transpose()?;
        let before = cat.clone();
        let live = cat
            .socket_groups
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
            writes: vec![Write::UpdateSocketGroup {
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
    ) -> Result<(SocketGroup, GroupPlan), EngineError> {
        let group = cat
            .socket_group(id)
            .ok_or_else(|| EngineError::NotFound(format!("socket group {id}")))?
            .clone();
        let users = cat.group_users(id, None);
        if !users.is_empty() {
            return Err(EngineError::Conflict(format!(
                "socket group {} is still used by {}",
                group.label,
                join(&users)
            )));
        }
        let removed = cat.take_group_addresses(id, None);
        cat.socket_groups.retain(|g| g.id != id);
        let mut writes: Vec<Write> = removed
            .iter()
            .map(|a| Write::DeleteAddress(a.id.clone()))
            .collect();
        writes.push(Write::DeleteSocketGroup(id.to_string()));
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
    ) -> Result<(SocketGroup, GroupPlan), EngineError> {
        let group = cat
            .socket_group(group_id)
            .ok_or_else(|| EngineError::NotFound(format!("socket group {group_id}")))?
            .clone();
        cat.app(app_id)
            .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?;
        if group.is_attached_to(app_id) {
            return Ok((group, GroupPlan::default()));
        }
        let before = cat.clone();
        let live = cat
            .socket_groups
            .iter_mut()
            .find(|g| g.id == group_id)
            .expect("checked above");
        live.apps.push(app_id.to_string());
        let attached = live.clone();
        let plan = GroupPlan {
            writes: vec![Write::AttachSocketGroup {
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
    ) -> Result<(SocketGroup, GroupPlan), EngineError> {
        let group = cat
            .socket_group(group_id)
            .ok_or_else(|| EngineError::NotFound(format!("socket group {group_id}")))?
            .clone();
        let app_name = cat
            .app(app_id)
            .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?
            .name
            .clone();
        if !group.is_attached_to(app_id) {
            return Err(EngineError::NotFound(format!(
                "socket group {} on app {app_name}",
                group.label
            )));
        }
        let users = cat.group_users(group_id, Some(app_id));
        if !users.is_empty() {
            return Err(EngineError::Conflict(format!(
                "socket group {} is still used on {app_name} by {}",
                group.label,
                join(&users)
            )));
        }
        let removed = cat.take_group_addresses(group_id, Some(app_id));
        let live = cat
            .socket_groups
            .iter_mut()
            .find(|g| g.id == group_id)
            .expect("checked above");
        live.apps.retain(|a| a != app_id);
        let detached = live.clone();
        let mut writes: Vec<Write> = removed
            .iter()
            .map(|a| Write::DeleteAddress(a.id.clone()))
            .collect();
        writes.push(Write::DetachSocketGroup {
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
            .map_err(|e| Self::conflict_or_internal(e, "this socket group"))?;
        let applied = self.apply_and_ensure(state).await;
        self.commit(
            state,
            applied,
            Some(activity),
            &[
                DaemonEvent::SocketGroupsChanged,
                DaemonEvent::GrantsChanged,
                DaemonEvent::AppsChanged,
            ],
        )
        .await?;
        Ok(())
    }

    // ─── REST operations ─────────────────────────────────────────────────────

    pub async fn create_socket_group(
        &self,
        state: &AppState,
        label: &str,
        ports: &[PortRange],
        apps: &[AppId],
        confirm_open: bool,
    ) -> Result<SocketGroup, EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) =
            self.plan_create_group(&mut cat, new_id(), label, ports, apps, confirm_open)?;
        let activity = NewActivity::new(
            ActivityKind::SocketGroupAdded,
            format!("Added socket group {}", group.label),
        );
        self.run_group_plan(state, plan, activity).await?;
        self.get_socket_group(state, &group.id).await
    }

    pub async fn update_socket_group(
        &self,
        state: &AppState,
        id: &str,
        label: Option<&str>,
        ports: Option<&[PortRange]>,
        confirm_open: bool,
    ) -> Result<SocketGroup, EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) = self.plan_update_group(&mut cat, id, label, ports, confirm_open)?;
        let activity = NewActivity::new(
            ActivityKind::SocketGroupChanged,
            format!("Changed socket group {}", group.label),
        );
        self.run_group_plan(state, plan, activity).await?;
        self.get_socket_group(state, id).await
    }

    pub async fn delete_socket_group(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) = self.plan_delete_group(&mut cat, id)?;
        let activity = NewActivity::new(
            ActivityKind::SocketGroupRemoved,
            format!("Removed socket group {}", group.label),
        );
        self.run_group_plan(state, plan, activity).await
    }

    pub async fn attach_socket_group(
        &self,
        state: &AppState,
        group_id: &str,
        app_id: &str,
        confirm_open: bool,
    ) -> Result<SocketGroup, EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) = self.plan_attach_group(&mut cat, group_id, app_id, confirm_open)?;
        if plan.writes.is_empty() {
            return Ok(group);
        }
        let activity = NewActivity::new(
            ActivityKind::SocketGroupChanged,
            format!("Attached socket group {}", group.label),
        )
        .app(app_id);
        self.run_group_plan(state, plan, activity).await?;
        self.get_socket_group(state, group_id).await
    }

    pub async fn detach_socket_group(
        &self,
        state: &AppState,
        group_id: &str,
        app_id: &str,
    ) -> Result<SocketGroup, EngineError> {
        let mut cat = Catalog::load(state).await?;
        let (group, plan) = self.plan_detach_group(&mut cat, group_id, app_id)?;
        let activity = NewActivity::new(
            ActivityKind::SocketGroupChanged,
            format!("Detached socket group {}", group.label),
        )
        .app(app_id);
        self.run_group_plan(state, plan, activity).await?;
        self.get_socket_group(state, group_id).await
    }
}
