//! Export and apply (`GET /api/export`, `POST /api/apply`): the settings, peers, groups,
//! port groups, grants and reservations (with their bindings and the grants on them) as a
//! portable document, and a diff-then-apply of such a
//! document over the current state. Peers, groups and port groups match by label, grants
//! by (app id, scope, network, subject); a grant names its port group by label. Everything
//! the document lacks is deleted, so the document is the whole truth. Tags are not part of
//! it (yet).
//!
//! Applying is not transactional: the document is validated up front, but a failure
//! midway (e.g. the lockout guard refusing whole-host protection) leaves the earlier
//! steps applied. Run a dry run first.

use crate::engine::{Engine, EngineError, GrantFilter, ProtectHostError};
use crate::AppState;
use socketguard_core::api_types::{
    ApplyRequest, ApplyResponse, Change, ChangeItem, ChangeKind, ExportAppRef, ExportBinding,
    ExportCredential, ExportDocument, ExportGrant, ExportGroup, ExportPeer, ExportPortGroup,
    ExportReservation, ExportReservationGrant, ExportScope, ExportSubject, EXPORT_VERSION,
};
use socketguard_core::{
    normalize_credential, ranges_text, BindingTarget, NewCredential, NewGrant, Peer, PeerGroup,
    PortGroup, PortRef, Scope, Subject, Tag, Target,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The current state as a document.
pub async fn export(engine: &Engine, state: &AppState) -> Result<ExportDocument, EngineError> {
    let peers = engine.list_peers(state).await?;
    let groups = engine.list_groups(state).await?;
    let peer_label: HashMap<&str, &str> = peers
        .iter()
        .map(|p| (p.id.as_str(), p.label.as_str()))
        .collect();

    let mut out_peers: Vec<ExportPeer> = peers
        .iter()
        .map(|p| {
            let mut credentials: Vec<ExportCredential> = p
                .credentials
                .iter()
                .map(|c| ExportCredential {
                    kind: c.kind,
                    value: c.value.clone(),
                    label: c.label.clone(),
                })
                .collect();
            credentials.sort_by(|a, b| {
                (a.kind.to_string(), &a.value).cmp(&(b.kind.to_string(), &b.value))
            });
            ExportPeer {
                label: p.label.clone(),
                credentials,
            }
        })
        .collect();
    out_peers.sort_by(|a, b| a.label.cmp(&b.label));

    let mut out_groups: Vec<ExportGroup> = groups
        .iter()
        .map(|g| {
            let mut members: Vec<String> = g
                .members
                .iter()
                .filter_map(|m| peer_label.get(m.as_str()).map(|l| l.to_string()))
                .collect();
            members.sort();
            ExportGroup {
                label: g.label.clone(),
                members,
            }
        })
        .collect();
    out_groups.sort_by(|a, b| a.label.cmp(&b.label));

    let apps: HashMap<String, String> = state
        .db
        .list_apps()
        .await?
        .into_iter()
        .map(|a| (a.id, a.name))
        .collect();
    let port_groups = engine.list_port_groups(state).await?;
    let mut out_port_groups: Vec<ExportPortGroup> = port_groups
        .iter()
        .map(|g| {
            let mut attached: Vec<ExportAppRef> = g
                .apps
                .iter()
                .filter_map(|id| {
                    Some(ExportAppRef {
                        id: id.clone(),
                        name: apps.get(id)?.clone(),
                    })
                })
                .collect();
            attached.sort_by(|a, b| a.id.cmp(&b.id));
            ExportPortGroup {
                label: g.label.clone(),
                ports: g.ports.clone(),
                apps: attached,
            }
        })
        .collect();
    out_port_groups.sort_by(|a, b| a.label.cmp(&b.label));
    let mut out_grants: Vec<ExportGrant> = Vec::new();
    for g in engine.list_grants(state, GrantFilter::default()).await? {
        let g = g.grant;
        // Tags are not part of the document (yet): grants on tags are left out.
        let Target::App(app_id) = &g.target else {
            continue;
        };
        let Some(name) = apps.get(app_id) else {
            continue;
        };
        let Some(subject) = export_subject(&g.subject, &peers, &groups) else {
            continue;
        };
        let Some(scope) = export_scope(&g.scope, &port_groups) else {
            continue;
        };
        out_grants.push(ExportGrant {
            app: ExportAppRef {
                id: app_id.clone(),
                name: name.clone(),
            },
            scope,
            network: g.network_id.clone(),
            subject,
        });
    }
    out_grants.sort_by_key(grant_key);

    let tags = state.db.list_tags().await?;
    let mut out_reservations: Vec<ExportReservation> = Vec::new();
    for r in engine.list_reservations(state).await? {
        let mut bindings: Vec<ExportBinding> = r
            .reservation
            .bindings
            .iter()
            .filter_map(|b| export_binding(&b.target, &apps, &tags, &port_groups))
            .collect();
        bindings.sort();
        let mut grants: Vec<ExportReservationGrant> = r
            .grants
            .iter()
            .filter_map(|g| {
                Some(ExportReservationGrant {
                    network: g.grant.network_id.clone(),
                    subject: export_subject(&g.grant.subject, &peers, &groups)?,
                })
            })
            .collect();
        grants.sort_by_key(res_grant_key);
        out_reservations.push(ExportReservation {
            label: r.reservation.label.clone(),
            bindings,
            grants,
        });
    }
    out_reservations.sort_by(|a, b| a.label.cmp(&b.label));

    Ok(ExportDocument {
        version: EXPORT_VERSION,
        settings: engine.settings(state).await?,
        peers: out_peers,
        groups: out_groups,
        port_groups: out_port_groups,
        grants: out_grants,
        reservations: out_reservations,
    })
}

/// A binding as the document names it; None when what it names is gone.
fn export_binding(
    t: &BindingTarget,
    apps: &HashMap<String, String>,
    tags: &[Tag],
    groups: &[PortGroup],
) -> Option<ExportBinding> {
    Some(match t {
        BindingTarget::App { app_id, scope } => ExportBinding::App {
            app: ExportAppRef {
                id: app_id.clone(),
                name: apps.get(app_id)?.clone(),
            },
            scope: export_scope(scope, groups)?,
        },
        BindingTarget::Tag { tag_id } => ExportBinding::Tag {
            label: tags.iter().find(|t| &t.id == tag_id)?.label.clone(),
        },
    })
}

type ResGrantKey = (Option<String>, (u8, String));

fn res_grant_key(g: &ExportReservationGrant) -> ResGrantKey {
    (g.network.clone(), subject_key(&g.subject))
}

type GrantKey = (String, ExportScope, Option<String>, (u8, String));

/// A grant's scope as the document names it (a port group by label); None when the group
/// is gone.
fn export_scope(s: &Scope, groups: &[PortGroup]) -> Option<ExportScope> {
    Some(match s {
        Scope::All => ExportScope::All,
        Scope::Port { port, proto } => ExportScope::Port {
            port: *port,
            proto: *proto,
        },
        Scope::Group { id } => ExportScope::Group {
            label: groups.iter().find(|g| g.id == *id)?.label.clone(),
        },
    })
}

/// A document scope as a scope (a port group by label); an error when the group is gone.
fn export_to_scope(s: &ExportScope, groups: &[PortGroup]) -> Result<Scope, EngineError> {
    Ok(match s {
        ExportScope::All => Scope::All,
        ExportScope::Port { port, proto } => Scope::Port {
            port: *port,
            proto: *proto,
        },
        ExportScope::Group { label } => Scope::Group {
            id: groups
                .iter()
                .find(|x| x.label == *label)
                .map(|x| x.id.clone())
                .ok_or_else(|| EngineError::NotFound(format!("port group {label}")))?,
        },
    })
}

fn describe_scope(s: &ExportScope) -> Option<String> {
    match s {
        ExportScope::All => None,
        ExportScope::Port { port, proto } => Some(format!("{port}/{proto}")),
        ExportScope::Group { label } => Some(format!("group {label}")),
    }
}

/// A grant's subject as the document names it (by label); None when its peer or group is
/// gone.
fn export_subject(s: &Subject, peers: &[Peer], groups: &[PeerGroup]) -> Option<ExportSubject> {
    Some(match s {
        Subject::Anyone => ExportSubject::Anyone,
        Subject::Peer(id) => ExportSubject::Peer(peers.iter().find(|p| p.id == *id)?.label.clone()),
        Subject::Group(id) => {
            ExportSubject::Group(groups.iter().find(|g| g.id == *id)?.label.clone())
        }
    })
}

fn subject_key(s: &ExportSubject) -> (u8, String) {
    match s {
        ExportSubject::Anyone => (0, String::new()),
        ExportSubject::Peer(l) => (1, l.clone()),
        ExportSubject::Group(l) => (2, l.clone()),
    }
}

fn grant_key(g: &ExportGrant) -> GrantKey {
    (
        g.app.id.clone(),
        g.scope.clone(),
        g.network.clone(),
        subject_key(&g.subject),
    )
}

fn cred_key(c: &ExportCredential) -> (String, String) {
    (c.kind.to_string(), c.value.clone())
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, EngineError> {
    Err(EngineError::Invalid(msg.into()))
}

/// Check the document and put its credentials in normal form.
async fn validate(
    engine: &Engine,
    state: &AppState,
    doc: &ExportDocument,
) -> Result<ExportDocument, EngineError> {
    if doc.version != EXPORT_VERSION {
        return invalid(format!(
            "unsupported document version {} (this daemon reads version {EXPORT_VERSION})",
            doc.version
        ));
    }
    if let Some(bad) = doc
        .settings
        .protect_host_interfaces
        .iter()
        .find(|i| !i.trim().is_empty() && !socketguard_core::valid_interface_name(i))
    {
        return invalid(format!("invalid interface name {bad:?}"));
    }
    let mut doc = doc.clone();
    let mut peer_labels = BTreeSet::new();
    let mut seen_creds = BTreeSet::new();
    for p in &mut doc.peers {
        p.label = Engine::clean_label(&p.label, "peer")?;
        if !peer_labels.insert(p.label.clone()) {
            return invalid(format!("peer {} is listed twice", p.label));
        }
        for c in &mut p.credentials {
            let (kind, value) = normalize_credential(c.kind, &c.value)?;
            c.kind = kind;
            c.value = value;
            c.label = c.label.take().filter(|l| !l.trim().is_empty());
            if !seen_creds.insert(cred_key(c)) {
                return invalid(format!("{} {} is listed twice", c.kind, c.value));
            }
        }
    }
    let mut group_labels = BTreeSet::new();
    for g in &mut doc.groups {
        g.label = Engine::clean_label(&g.label, "group")?;
        if !group_labels.insert(g.label.clone()) {
            return invalid(format!("group {} is listed twice", g.label));
        }
        g.members.sort();
        g.members.dedup();
        if let Some(m) = g.members.iter().find(|m| !peer_labels.contains(*m)) {
            return invalid(format!("group {} names unknown peer {m}", g.label));
        }
    }
    let apps: HashMap<String, socketguard_core::App> = state
        .db
        .list_apps()
        .await?
        .into_iter()
        .map(|a| (a.id.clone(), a))
        .collect();
    // Port groups: valid ports, attached to apps that exist.
    let mut port_group_apps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for g in &mut doc.port_groups {
        g.label = Engine::clean_label(&g.label, "port group")?;
        g.ports = crate::engine::clean_ranges(&g.ports)?;
        g.apps.sort_by(|a, b| a.id.cmp(&b.id));
        g.apps.dedup_by(|a, b| a.id == b.id);
        if port_group_apps
            .insert(
                g.label.clone(),
                g.apps.iter().map(|a| a.id.clone()).collect(),
            )
            .is_some()
        {
            return invalid(format!("port group {} is listed twice", g.label));
        }
        if let Some(a) = g.apps.iter().find(|a| !apps.contains_key(&a.id)) {
            return invalid(format!(
                "port group {} names unknown app {} ({})",
                g.label, a.id, a.name
            ));
        }
    }
    doc.port_groups.sort_by(|a, b| a.label.cmp(&b.label));
    let networks = engine.networks();
    let mut seen_grants = BTreeSet::new();
    for g in &doc.grants {
        let Some(app) = apps.get(&g.app.id) else {
            return invalid(format!(
                "grant names unknown app {} ({})",
                g.app.id, g.app.name
            ));
        };
        match &g.scope {
            ExportScope::All => {}
            ExportScope::Port { port, proto } => {
                let p = PortRef {
                    port: *port,
                    proto: *proto,
                };
                let in_group = doc
                    .port_groups
                    .iter()
                    .filter(|sg| sg.apps.iter().any(|a| a.id == app.id))
                    .any(|sg| sg.ports.iter().any(|r| r.contains(p)));
                if !app.has_port(p) && !in_group {
                    return invalid(format!("{} has no port {p}", app.name));
                }
            }
            ExportScope::Group { label } => {
                if !port_group_apps
                    .get(label)
                    .is_some_and(|attached| attached.contains(&app.id))
                {
                    return invalid(format!(
                        "grant for {} names port group {label}, which the document does not attach to it",
                        app.name
                    ));
                }
            }
        }
        if let Some(n) = &g.network {
            match networks.iter().find(|x| x.id == *n) {
                None => return invalid(format!("grant names unknown network {n}")),
                Some(net) if !net.grants_apply => {
                    return Err(EngineError::LocalNetwork);
                }
                Some(_) => {}
            }
        }
        match &g.subject {
            ExportSubject::Peer(l) if !peer_labels.contains(l) => {
                return invalid(format!("grant names unknown peer {l}"));
            }
            ExportSubject::Group(l) if !group_labels.contains(l) => {
                return invalid(format!("grant names unknown group {l}"));
            }
            _ => {}
        }
        if !seen_grants.insert(grant_key(g)) {
            return invalid(format!("grant for {} is listed twice", app.name));
        }
    }
    doc.grants.sort_by_key(grant_key);

    let tags = state.db.list_tags().await?;
    let mut res_labels = BTreeSet::new();
    let mut bound_rows = BTreeSet::new();
    for r in &mut doc.reservations {
        r.label = Engine::clean_label(&r.label, "reservation")?;
        if !res_labels.insert(r.label.clone()) {
            return invalid(format!("reservation {} is listed twice", r.label));
        }
        r.bindings.sort();
        r.bindings.dedup();
        for b in &r.bindings {
            match b {
                ExportBinding::App { app, scope } => {
                    let Some(a) = apps.get(&app.id) else {
                        return invalid(format!(
                            "reservation {} names unknown app {} ({})",
                            r.label, app.id, app.name
                        ));
                    };
                    if let ExportScope::Group { label } = scope {
                        if !port_group_apps
                            .get(label)
                            .is_some_and(|attached| attached.contains(&a.id))
                        {
                            return invalid(format!(
                                "reservation {} binds {} to port group {label}, which the document does not attach to it",
                                r.label, a.name
                            ));
                        }
                    }
                    if !bound_rows.insert((app.id.clone(), scope.clone())) {
                        return invalid(format!(
                            "{} is bound to more than one reservation",
                            a.name
                        ));
                    }
                }
                ExportBinding::Tag { label } => {
                    if !tags.iter().any(|t| t.label == *label) {
                        return invalid(format!(
                            "reservation {} names unknown tag {label}",
                            r.label
                        ));
                    }
                }
            }
        }
        let mut seen = BTreeSet::new();
        for g in &r.grants {
            if let Some(n) = &g.network {
                match networks.iter().find(|x| x.id == *n) {
                    None => return invalid(format!("grant names unknown network {n}")),
                    Some(net) if !net.grants_apply => return Err(EngineError::LocalNetwork),
                    Some(_) => {}
                }
            }
            match &g.subject {
                ExportSubject::Peer(l) if !peer_labels.contains(l) => {
                    return invalid(format!("grant names unknown peer {l}"));
                }
                ExportSubject::Group(l) if !group_labels.contains(l) => {
                    return invalid(format!("grant names unknown group {l}"));
                }
                _ => {}
            }
            if !seen.insert(res_grant_key(g)) {
                return invalid(format!(
                    "a grant on reservation {} is listed twice",
                    r.label
                ));
            }
        }
    }
    doc.reservations.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(doc)
}

/// What to do, in the order of the phases the executor runs them.
#[derive(Debug, Default)]
struct Plan {
    delete_grants: Vec<ExportGrant>,
    delete_port_groups: Vec<String>,
    /// Groups to create, and the groups to change with what they are now.
    create_port_groups: Vec<ExportPortGroup>,
    update_port_groups: Vec<(ExportPortGroup, ExportPortGroup)>,
    remove_credentials: Vec<(String, ExportCredential)>,
    delete_groups: Vec<String>,
    delete_peers: Vec<String>,
    create_peers: Vec<ExportPeer>,
    add_credentials: Vec<(String, ExportCredential)>,
    create_groups: Vec<ExportGroup>,
    set_members: Vec<ExportGroup>,
    create_grants: Vec<ExportGrant>,
    /// Reservations: grants and bindings that go, reservations that go, then what is new.
    remove_reservation_grants: Vec<(String, ExportReservationGrant)>,
    remove_bindings: Vec<(String, ExportBinding)>,
    delete_reservations: Vec<String>,
    create_reservations: Vec<ExportReservation>,
    add_bindings: Vec<(String, ExportBinding)>,
    add_reservation_grants: Vec<(String, ExportReservationGrant)>,
    protect_host: Option<Vec<String>>,
    changes: Vec<Change>,
}

fn change(
    kind: ChangeKind,
    item: ChangeItem,
    name: impl Into<String>,
    detail: Option<String>,
) -> Change {
    Change {
        kind,
        item,
        name: name.into(),
        detail,
        opens_to_anyone: false,
    }
}

fn describe_grant(g: &ExportGrant) -> String {
    let mut s = g.app.name.clone();
    if let Some(p) = describe_scope(&g.scope) {
        s.push_str(&format!(" {p}"));
    }
    if let Some(n) = &g.network {
        s.push_str(&format!(" on {n}"));
    }
    match &g.subject {
        ExportSubject::Anyone => s.push_str(" to Anyone"),
        ExportSubject::Peer(l) => s.push_str(&format!(" to peer {l}")),
        ExportSubject::Group(l) => s.push_str(&format!(" to group {l}")),
    }
    s
}

fn plan(current: &ExportDocument, desired: &ExportDocument) -> Plan {
    let mut p = Plan::default();
    let mut sorted_changes: Vec<Change> = Vec::new();

    // Settings.
    let norm = |v: &[String]| -> Vec<String> {
        let mut v: Vec<String> = v.iter().filter(|s| !s.trim().is_empty()).cloned().collect();
        v.sort();
        v.dedup();
        v
    };
    let (cur_ph, want_ph) = (
        norm(&current.settings.protect_host_interfaces),
        norm(&desired.settings.protect_host_interfaces),
    );
    if cur_ph != want_ph {
        sorted_changes.push(change(
            ChangeKind::Update,
            ChangeItem::Setting,
            "protect_host_interfaces",
            Some(format!(
                "[{}] -> [{}]",
                cur_ph.join(", "),
                want_ph.join(", ")
            )),
        ));
        p.protect_host = Some(want_ph);
    }

    // Peers.
    let cur: BTreeMap<&str, &ExportPeer> = current
        .peers
        .iter()
        .map(|x| (x.label.as_str(), x))
        .collect();
    let want: BTreeMap<&str, &ExportPeer> = desired
        .peers
        .iter()
        .map(|x| (x.label.as_str(), x))
        .collect();
    for (label, w) in &want {
        match cur.get(label) {
            None => {
                sorted_changes.push(change(
                    ChangeKind::Create,
                    ChangeItem::Peer,
                    *label,
                    Some(format!("{} credentials", w.credentials.len())),
                ));
                p.create_peers.push((*w).clone());
            }
            Some(c) => {
                let full =
                    |x: &ExportCredential| (x.kind.to_string(), x.value.clone(), x.label.clone());
                let have: BTreeSet<_> = c.credentials.iter().map(full).collect();
                let need: BTreeSet<_> = w.credentials.iter().map(full).collect();
                let mut parts = Vec::new();
                for cr in c.credentials.iter().filter(|x| !need.contains(&full(x))) {
                    parts.push(format!("-{} {}", cr.kind, cr.value));
                    p.remove_credentials.push((label.to_string(), cr.clone()));
                }
                for cr in w.credentials.iter().filter(|x| !have.contains(&full(x))) {
                    parts.push(format!("+{} {}", cr.kind, cr.value));
                    p.add_credentials.push((label.to_string(), cr.clone()));
                }
                if !parts.is_empty() {
                    sorted_changes.push(change(
                        ChangeKind::Update,
                        ChangeItem::Peer,
                        *label,
                        Some(parts.join(", ")),
                    ));
                }
            }
        }
    }
    for label in cur.keys().filter(|l| !want.contains_key(*l)) {
        sorted_changes.push(change(ChangeKind::Delete, ChangeItem::Peer, *label, None));
        p.delete_peers.push(label.to_string());
    }

    // Groups.
    let cur: BTreeMap<&str, &ExportGroup> = current
        .groups
        .iter()
        .map(|x| (x.label.as_str(), x))
        .collect();
    let want: BTreeMap<&str, &ExportGroup> = desired
        .groups
        .iter()
        .map(|x| (x.label.as_str(), x))
        .collect();
    for (label, w) in &want {
        match cur.get(label) {
            None => {
                sorted_changes.push(change(
                    ChangeKind::Create,
                    ChangeItem::Group,
                    *label,
                    Some(format!("members: {}", w.members.join(", "))),
                ));
                p.create_groups.push((*w).clone());
            }
            Some(c) if c.members != w.members => {
                let old: BTreeSet<&String> = c.members.iter().collect();
                let new: BTreeSet<&String> = w.members.iter().collect();
                let mut parts: Vec<String> =
                    old.difference(&new).map(|m| format!("-{m}")).collect();
                parts.extend(new.difference(&old).map(|m| format!("+{m}")));
                sorted_changes.push(change(
                    ChangeKind::Update,
                    ChangeItem::Group,
                    *label,
                    Some(parts.join(", ")),
                ));
                p.set_members.push((*w).clone());
            }
            Some(_) => {}
        }
    }
    for label in cur.keys().filter(|l| !want.contains_key(*l)) {
        sorted_changes.push(change(ChangeKind::Delete, ChangeItem::Group, *label, None));
        p.delete_groups.push(label.to_string());
    }

    // Port groups.
    let cur: BTreeMap<&str, &ExportPortGroup> = current
        .port_groups
        .iter()
        .map(|x| (x.label.as_str(), x))
        .collect();
    let want: BTreeMap<&str, &ExportPortGroup> = desired
        .port_groups
        .iter()
        .map(|x| (x.label.as_str(), x))
        .collect();
    let app_ids =
        |g: &ExportPortGroup| -> BTreeSet<String> { g.apps.iter().map(|a| a.id.clone()).collect() };
    for (label, w) in &want {
        match cur.get(label) {
            None => {
                sorted_changes.push(change(
                    ChangeKind::Create,
                    ChangeItem::PortGroup,
                    *label,
                    Some(format!("{}; {} apps", ranges_text(&w.ports), w.apps.len())),
                ));
                p.create_port_groups.push((*w).clone());
            }
            Some(c) if c.ports != w.ports || app_ids(c) != app_ids(w) => {
                let mut parts = Vec::new();
                if c.ports != w.ports {
                    parts.push(format!("ports {}", ranges_text(&w.ports)));
                }
                let (old, new) = (app_ids(c), app_ids(w));
                parts.extend(old.difference(&new).map(|a| format!("detach {a}")));
                parts.extend(new.difference(&old).map(|a| format!("attach {a}")));
                sorted_changes.push(change(
                    ChangeKind::Update,
                    ChangeItem::PortGroup,
                    *label,
                    Some(parts.join(", ")),
                ));
                p.update_port_groups.push(((*w).clone(), (*c).clone()));
            }
            Some(_) => {}
        }
    }
    for label in cur.keys().filter(|l| !want.contains_key(*l)) {
        sorted_changes.push(change(
            ChangeKind::Delete,
            ChangeItem::PortGroup,
            *label,
            None,
        ));
        p.delete_port_groups.push(label.to_string());
    }

    // Grants: no field to update, so only creates and deletes.
    let cur: BTreeMap<GrantKey, &ExportGrant> =
        current.grants.iter().map(|g| (grant_key(g), g)).collect();
    let want: BTreeMap<GrantKey, &ExportGrant> =
        desired.grants.iter().map(|g| (grant_key(g), g)).collect();
    for (k, g) in &want {
        if !cur.contains_key(k) {
            let mut c = change(
                ChangeKind::Create,
                ChangeItem::Grant,
                describe_grant(g),
                None,
            );
            c.opens_to_anyone = g.subject == ExportSubject::Anyone;
            sorted_changes.push(c);
            p.create_grants.push((*g).clone());
        }
    }
    for (k, g) in &cur {
        if !want.contains_key(k) {
            let mut c = change(
                ChangeKind::Delete,
                ChangeItem::Grant,
                describe_grant(g),
                None,
            );
            c.opens_to_anyone = g.subject == ExportSubject::Anyone;
            sorted_changes.push(c);
            p.delete_grants.push((*g).clone());
        }
    }

    // Reservations: by label.
    let cur: BTreeMap<&str, &ExportReservation> = current
        .reservations
        .iter()
        .map(|x| (x.label.as_str(), x))
        .collect();
    let want: BTreeMap<&str, &ExportReservation> = desired
        .reservations
        .iter()
        .map(|x| (x.label.as_str(), x))
        .collect();
    for (label, w) in &want {
        match cur.get(label) {
            None => {
                sorted_changes.push(change(
                    ChangeKind::Create,
                    ChangeItem::Reservation,
                    *label,
                    Some(format!(
                        "{} bindings, {} grants",
                        w.bindings.len(),
                        w.grants.len()
                    )),
                ));
                p.create_reservations.push((*w).clone());
            }
            Some(c) => {
                let (old_b, new_b): (BTreeSet<&ExportBinding>, BTreeSet<&ExportBinding>) =
                    (c.bindings.iter().collect(), w.bindings.iter().collect());
                for b in old_b.difference(&new_b) {
                    sorted_changes.push(change(
                        ChangeKind::Delete,
                        ChangeItem::Binding,
                        format!("binding of reservation {label}"),
                        None,
                    ));
                    p.remove_bindings.push((label.to_string(), (*b).clone()));
                }
                for b in new_b.difference(&old_b) {
                    sorted_changes.push(change(
                        ChangeKind::Create,
                        ChangeItem::Binding,
                        format!("binding of reservation {label}"),
                        None,
                    ));
                    p.add_bindings.push((label.to_string(), (*b).clone()));
                }
                let (old_g, new_g): (
                    BTreeMap<ResGrantKey, &ExportReservationGrant>,
                    BTreeMap<ResGrantKey, &ExportReservationGrant>,
                ) = (
                    c.grants.iter().map(|g| (res_grant_key(g), g)).collect(),
                    w.grants.iter().map(|g| (res_grant_key(g), g)).collect(),
                );
                for (k, g) in &old_g {
                    if !new_g.contains_key(k) {
                        sorted_changes.push(change(
                            ChangeKind::Delete,
                            ChangeItem::Grant,
                            format!("grant on reservation {label}"),
                            None,
                        ));
                        p.remove_reservation_grants
                            .push((label.to_string(), (*g).clone()));
                    }
                }
                for (k, g) in &new_g {
                    if !old_g.contains_key(k) {
                        let mut c = change(
                            ChangeKind::Create,
                            ChangeItem::Grant,
                            format!("grant on reservation {label}"),
                            None,
                        );
                        c.opens_to_anyone = g.subject == ExportSubject::Anyone;
                        sorted_changes.push(c);
                        p.add_reservation_grants
                            .push((label.to_string(), (*g).clone()));
                    }
                }
            }
        }
    }
    for label in cur.keys().filter(|l| !want.contains_key(*l)) {
        sorted_changes.push(change(
            ChangeKind::Delete,
            ChangeItem::Reservation,
            *label,
            None,
        ));
        p.delete_reservations.push(label.to_string());
    }
    p.changes = sorted_changes;
    p
}

fn new_credential(c: &ExportCredential) -> NewCredential {
    NewCredential {
        kind: c.kind,
        value: c.value.clone(),
        label: c.label.clone(),
    }
}

/// Diff `req.document` against the current state and, unless `dry_run`, apply it.
pub async fn apply(
    engine: &Engine,
    state: &AppState,
    req: ApplyRequest,
) -> Result<ApplyResponse, EngineError> {
    let desired = validate(engine, state, &req.document).await?;
    let current = export(engine, state).await?;
    let plan = plan(&current, &desired);
    if req.dry_run || plan.changes.is_empty() {
        return Ok(ApplyResponse {
            dry_run: req.dry_run,
            changes: plan.changes,
        });
    }
    execute(engine, state, &plan).await?;
    Ok(ApplyResponse {
        dry_run: false,
        changes: plan.changes,
    })
}

async fn execute(engine: &Engine, state: &AppState, p: &Plan) -> Result<(), EngineError> {
    // Phase 1: grants that go. Their rules leave before the subjects do.
    let current_grants = engine.list_grants(state, GrantFilter::default()).await?;
    let peers = engine.list_peers(state).await?;
    let groups = engine.list_groups(state).await?;
    let port_groups = engine.list_port_groups(state).await?;
    for g in &p.delete_grants {
        let key = grant_key(g);
        let found = current_grants.iter().find(|v| {
            let (Some(subject), Some(scope)) = (
                export_subject(&v.grant.subject, &peers, &groups),
                export_scope(&v.grant.scope, &port_groups),
            ) else {
                return false;
            };
            (
                match &v.grant.target {
                    Target::App(id) => id.clone(),
                    Target::Tag(_) | Target::Reservation(_) => return false,
                },
                scope,
                v.grant.network_id.clone(),
                subject_key(&subject),
            ) == key
        });
        if let Some(v) = found {
            engine.delete_grant(state, &v.grant.id).await?;
        }
    }

    // Phase 1a: reservations. Grants on them and bindings go first, then reservations that
    // go (their addresses leave); what a port group is bound to blocks detaching it.
    let reservations = engine.list_reservations(state).await?;
    let tags = state.db.list_tags().await?;
    let res_id = |label: &str, rs: &[socketguard_core::ReservationView]| {
        rs.iter()
            .find(|r| r.reservation.label == label)
            .map(|r| r.reservation.id.clone())
            .ok_or_else(|| EngineError::NotFound(format!("reservation {label}")))
    };
    for (label, g) in &p.remove_reservation_grants {
        let Some(view) = reservations.iter().find(|r| r.reservation.label == *label) else {
            continue;
        };
        let found = view.grants.iter().find(|v| {
            export_subject(&v.grant.subject, &peers, &groups)
                .is_some_and(|s| (v.grant.network_id.clone(), subject_key(&s)) == res_grant_key(g))
        });
        if let Some(v) = found {
            engine.delete_grant(state, &v.grant.id).await?;
        }
    }
    for (label, b) in &p.remove_bindings {
        let Some(view) = reservations.iter().find(|r| r.reservation.label == *label) else {
            continue;
        };
        let apps_by_id: HashMap<String, String> = state
            .db
            .list_apps()
            .await?
            .into_iter()
            .map(|a| (a.id, a.name))
            .collect();
        let found = view.reservation.bindings.iter().find(|x| {
            export_binding(&x.target, &apps_by_id, &tags, &port_groups).as_ref() == Some(b)
        });
        if let Some(x) = found {
            engine
                .remove_binding(state, &view.reservation.id, &x.id)
                .await?;
        }
    }
    for label in &p.delete_reservations {
        if let Ok(id) = res_id(label, &reservations) {
            engine.release_reservation(state, &id).await?;
        }
    }

    // Phase 1b: port groups. What goes (a detached or deleted group, once no grant uses
    // it) first, then what is new or wider, before any grant refers to it. The document
    // states the Anyone grants explicitly, so a group that widens them counts as confirmed.
    for (want, was) in &p.update_port_groups {
        let Some(group) = port_groups.iter().find(|g| g.label == want.label) else {
            continue;
        };
        let wanted: BTreeSet<&String> = want.apps.iter().map(|a| &a.id).collect();
        for gone in was.apps.iter().filter(|a| !wanted.contains(&a.id)) {
            engine.detach_port_group(state, &group.id, &gone.id).await?;
        }
    }
    for label in &p.delete_port_groups {
        if let Some(group) = port_groups.iter().find(|g| g.label == *label) {
            engine.delete_port_group(state, &group.id).await?;
        }
    }
    for g in &p.create_port_groups {
        let apps: Vec<String> = g.apps.iter().map(|a| a.id.clone()).collect();
        engine
            .create_port_group(state, &g.label, &g.ports, &apps, true)
            .await?;
    }
    for (want, was) in &p.update_port_groups {
        let Some(group) = port_groups.iter().find(|g| g.label == want.label) else {
            continue;
        };
        if want.ports != was.ports {
            engine
                .update_port_group(state, &group.id, None, Some(&want.ports), true)
                .await?;
        }
        let had: BTreeSet<&String> = was.apps.iter().map(|a| &a.id).collect();
        for added in want.apps.iter().filter(|a| !had.contains(&a.id)) {
            engine
                .attach_port_group(state, &group.id, &added.id, true)
                .await?;
        }
    }
    let port_groups = engine.list_port_groups(state).await?;

    // Phase 2: take away what no longer belongs, so a credential can move between peers.
    for (label, c) in &p.remove_credentials {
        let Some(peer) = peers.iter().find(|x| x.label == *label) else {
            continue;
        };
        if let Some(cred) = peer
            .credentials
            .iter()
            .find(|x| x.kind == c.kind && x.value == c.value)
        {
            engine.remove_credential(state, &peer.id, &cred.id).await?;
        }
    }
    for label in &p.delete_groups {
        if let Some(g) = groups.iter().find(|x| x.label == *label) {
            engine.delete_group(state, &g.id).await?;
        }
    }
    for label in &p.delete_peers {
        if let Some(peer) = peers.iter().find(|x| x.label == *label) {
            engine.delete_peer(state, &peer.id).await?;
        }
    }

    // Phase 3: peers and their credentials.
    for peer in &p.create_peers {
        let creds: Vec<NewCredential> = peer.credentials.iter().map(new_credential).collect();
        engine.create_peer(state, &peer.label, &creds).await?;
    }
    let peers = engine.list_peers(state).await?;
    let peer_id = |label: &str| -> Result<String, EngineError> {
        peers
            .iter()
            .find(|x| x.label == label)
            .map(|x| x.id.clone())
            .ok_or_else(|| EngineError::NotFound(format!("peer {label}")))
    };
    for (label, c) in &p.add_credentials {
        engine
            .add_credential(state, &peer_id(label)?, &new_credential(c))
            .await?;
    }

    // Phase 4: groups.
    for g in &p.create_groups {
        let members = g
            .members
            .iter()
            .map(|m| peer_id(m))
            .collect::<Result<Vec<_>, _>>()?;
        engine.create_group(state, &g.label, &members).await?;
    }
    let groups = engine.list_groups(state).await?;
    for g in &p.set_members {
        let Some(group) = groups.iter().find(|x| x.label == g.label) else {
            continue;
        };
        let members = g
            .members
            .iter()
            .map(|m| peer_id(m))
            .collect::<Result<Vec<_>, _>>()?;
        engine.set_group_members(state, &group.id, &members).await?;
    }

    // Phase 5: grants. Anyone is explicit in the document, so it counts as confirmed.
    for g in &p.create_grants {
        let subject = match &g.subject {
            ExportSubject::Anyone => Subject::Anyone,
            ExportSubject::Peer(l) => Subject::Peer(peer_id(l)?),
            ExportSubject::Group(l) => Subject::Group(
                groups
                    .iter()
                    .find(|x| x.label == *l)
                    .map(|x| x.id.clone())
                    .ok_or_else(|| EngineError::NotFound(format!("peer group {l}")))?,
            ),
        };
        engine
            .create_grant(
                state,
                &NewGrant {
                    target: Target::App(g.app.id.clone()),
                    scope: match &g.scope {
                        ExportScope::All => Scope::All,
                        ExportScope::Port { port, proto } => Scope::Port {
                            port: *port,
                            proto: *proto,
                        },
                        ExportScope::Group { label } => Scope::Group {
                            id: port_groups
                                .iter()
                                .find(|x| x.label == *label)
                                .map(|x| x.id.clone())
                                .ok_or_else(|| {
                                    EngineError::NotFound(format!("port group {label}"))
                                })?,
                        },
                    },
                    network_id: g.network.clone(),
                    subject,
                    confirm_open: true,
                },
            )
            .await?;
    }

    // Phase 5b: reservations, their bindings and the grants on them. The document is
    // explicit about Anyone, so it counts as confirmed.
    let to_target = |b: &ExportBinding| -> Result<BindingTarget, EngineError> {
        Ok(match b {
            ExportBinding::App { app, scope } => BindingTarget::App {
                app_id: app.id.clone(),
                scope: export_to_scope(scope, &port_groups)?,
            },
            ExportBinding::Tag { label } => BindingTarget::Tag {
                tag_id: tags
                    .iter()
                    .find(|t| t.label == *label)
                    .map(|t| t.id.clone())
                    .ok_or_else(|| EngineError::NotFound(format!("tag {label}")))?,
            },
        })
    };
    for r in &p.create_reservations {
        let bindings = r
            .bindings
            .iter()
            .map(&to_target)
            .collect::<Result<Vec<_>, _>>()?;
        engine
            .create_reservation(state, &r.label, bindings, true)
            .await?;
    }
    let reservations = engine.list_reservations(state).await?;
    for (label, b) in &p.add_bindings {
        engine
            .add_binding(state, &res_id(label, &reservations)?, to_target(b)?, true)
            .await?;
    }
    let subject_of = |s: &ExportSubject| -> Result<Subject, EngineError> {
        Ok(match s {
            ExportSubject::Anyone => Subject::Anyone,
            ExportSubject::Peer(l) => Subject::Peer(peer_id(l)?),
            ExportSubject::Group(l) => Subject::Group(
                groups
                    .iter()
                    .find(|x| x.label == *l)
                    .map(|x| x.id.clone())
                    .ok_or_else(|| EngineError::NotFound(format!("peer group {l}")))?,
            ),
        })
    };
    let wanted_grants: Vec<(String, ExportReservationGrant)> = p
        .create_reservations
        .iter()
        .flat_map(|r| r.grants.iter().map(|g| (r.label.clone(), g.clone())))
        .chain(p.add_reservation_grants.iter().cloned())
        .collect();
    for (label, g) in &wanted_grants {
        engine
            .create_grant(
                state,
                &NewGrant {
                    target: Target::Reservation(res_id(label, &reservations)?),
                    scope: Scope::All,
                    network_id: g.network.clone(),
                    subject: subject_of(&g.subject)?,
                    confirm_open: true,
                },
            )
            .await?;
    }

    // Phase 6: settings. Whole-host protection last: the lockout guard looks at the grants.
    if let Some(interfaces) = &p.protect_host {
        match engine
            .set_protect_host(state, interfaces.clone(), false)
            .await
        {
            Ok(_) => {}
            Err(e @ ProtectHostError::Lockout(_)) => {
                return Err(EngineError::Conflict(format!(
                    "applied everything except whole-host protection: {e}"
                )));
            }
            Err(ProtectHostError::Invalid(msg)) => return Err(EngineError::Invalid(msg)),
            Err(ProtectHostError::Other(e)) => return Err(EngineError::Internal(e)),
        }
    }
    Ok(())
}
