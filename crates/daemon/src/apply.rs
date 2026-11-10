//! Export and apply (`GET /api/export`, `POST /api/apply`): the settings, peers, groups and
//! grants as a portable document, and a diff-then-apply of such a document over the
//! current state. Peers and groups match by label, grants by (app id, port, network,
//! subject); everything the document lacks is deleted, so the document is the whole truth.
//!
//! Applying is not transactional: the document is validated up front, but a failure
//! midway (e.g. the lockout guard refusing whole-host protection) leaves the earlier
//! steps applied. Run a dry run first.

use crate::engine::{Engine, EngineError, GrantFilter, ProtectHostError};
use crate::AppState;
use socketguard_core::api_types::{
    ApplyRequest, ApplyResponse, Change, ChangeItem, ChangeKind, ExportAppRef, ExportCredential,
    ExportDocument, ExportGrant, ExportGroup, ExportPeer, ExportSubject, EXPORT_VERSION,
};
use socketguard_core::{
    normalize_credential, AddressMode, NewCredential, NewGrant, Peer, PeerGroup, PortRef, Subject,
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
    let mut out_grants: Vec<ExportGrant> = Vec::new();
    for g in engine.list_grants(state, GrantFilter::default()).await? {
        let g = g.grant;
        let Some(name) = apps.get(&g.app_id) else {
            continue;
        };
        let Some(subject) = export_subject(&g.subject, &peers, &groups) else {
            continue;
        };
        out_grants.push(ExportGrant {
            app: ExportAppRef {
                id: g.app_id.clone(),
                name: name.clone(),
            },
            port: g.port,
            network: g.network_id.clone(),
            subject,
        });
    }
    out_grants.sort_by_key(grant_key);

    Ok(ExportDocument {
        version: EXPORT_VERSION,
        settings: engine.settings(state).await?,
        peers: out_peers,
        groups: out_groups,
        grants: out_grants,
    })
}

type GrantKey = (String, Option<PortRef>, Option<String>, (u8, String));

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
        g.port,
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
    let networks = engine.networks();
    let mut seen_grants = BTreeSet::new();
    for g in &doc.grants {
        let Some(app) = apps.get(&g.app.id) else {
            return invalid(format!(
                "grant names unknown app {} ({})",
                g.app.id, g.app.name
            ));
        };
        if let Some(p) = g.port {
            if !app.has_port(p) {
                return invalid(format!("{} has no port {p}", app.name));
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
    Ok(doc)
}

/// What to do, in the order of the phases the executor runs them.
#[derive(Debug, Default)]
struct Plan {
    delete_grants: Vec<ExportGrant>,
    remove_credentials: Vec<(String, ExportCredential)>,
    delete_groups: Vec<String>,
    delete_peers: Vec<String>,
    create_peers: Vec<ExportPeer>,
    add_credentials: Vec<(String, ExportCredential)>,
    create_groups: Vec<ExportGroup>,
    set_members: Vec<ExportGroup>,
    create_grants: Vec<ExportGrant>,
    address_mode: Option<AddressMode>,
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
    if let Some(p) = g.port {
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
    if current.settings.address_mode != desired.settings.address_mode {
        p.address_mode = Some(desired.settings.address_mode);
        sorted_changes.push(change(
            ChangeKind::Update,
            ChangeItem::Setting,
            "address_mode",
            Some(format!(
                "{} -> {}",
                current.settings.address_mode.as_str(),
                desired.settings.address_mode.as_str()
            )),
        ));
    }
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
    for g in &p.delete_grants {
        let key = grant_key(g);
        let found = current_grants.iter().find(|v| {
            export_subject(&v.grant.subject, &peers, &groups).is_some_and(|subject| {
                (
                    v.grant.app_id.clone(),
                    v.grant.port,
                    v.grant.network_id.clone(),
                    subject_key(&subject),
                ) == key
            })
        });
        if let Some(v) = found {
            engine.delete_grant(state, &v.grant.id).await?;
        }
    }

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
                    app_id: g.app.id.clone(),
                    port: g.port,
                    network_id: g.network.clone(),
                    subject,
                    confirm_open: true,
                },
            )
            .await?;
    }

    // Phase 6: settings. Whole-host protection last: the lockout guard looks at the grants.
    if let Some(mode) = p.address_mode {
        engine.set_address_mode(state, mode).await?;
    }
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
