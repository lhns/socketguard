//! Mutations: apps, peers, groups and grants. Each saves, applies the firewall, and
//! records and announces the change.

use super::*;
use crate::api::DaemonEvent;
use crate::state::{self, NewActivity};
use crate::AppState;
use chrono::Utc;
use socketguard_core::{
    new_id, normalize_credential, ActivityKind, AddressMode, App, Credential, CredentialKind,
    Grant, GrantView, NewCredential, NewGrant, Peer, PeerGroup, SocketGroup, Subject, Tag, Target,
};
use std::collections::{BTreeSet, HashSet};

impl Engine {
    /// Choose how new apps and ports get addresses; existing layouts are untouched.
    pub async fn set_address_mode(
        &self,
        state: &AppState,
        mode: AddressMode,
    ) -> Result<(), EngineError> {
        state.db.set_address_mode(mode).await?;
        self.commit(state, Ok(()), None, &[DaemonEvent::SettingsChanged])
            .await?;
        Ok(())
    }

    /// Mark an app reviewed (or pending again). It stays closed until granted.
    pub async fn review_app(
        &self,
        state: &AppState,
        id: &str,
        reviewed: bool,
    ) -> Result<(), EngineError> {
        if !state.db.set_reviewed(id, reviewed).await? {
            return Err(EngineError::NotFound(format!("app {id}")));
        }
        self.commit(state, Ok(()), None, &[DaemonEvent::AppsChanged])
            .await?;
        Ok(())
    }

    /// Forget an app: its addresses leave the interfaces, then it and its grants go. It
    /// reappears as pending the next time it listens.
    pub async fn delete_app(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let app = state
            .db
            .get_app(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("app {id}")))?;
        self.retire_addresses(state, &app.addresses).await?;
        self.remove_app_locators(state, &app.addresses).await;
        state.db.delete_app(id).await?;
        let applied = self.apply_firewall(state).await;
        self.sweep_owned(state).await;
        let activity = NewActivity::new(
            ActivityKind::AppRemoved,
            format!("Removed app {}", app.name),
        )
        .app(id);
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::AppsChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        Ok(())
    }

    pub(crate) fn clean_label(label: &str, what: &str) -> Result<String, EngineError> {
        let label = label.trim();
        if label.is_empty() {
            return Err(EngineError::Invalid(format!(
                "{what} label must not be empty"
            )));
        }
        Ok(label.to_string())
    }

    /// The name an unnamed peer gets: its first credential, without a /32 or /128 and
    /// with keys shortened, made unique among `taken` by a ` (2)`, ` (3)`… suffix.
    pub(super) fn default_peer_label(
        first: Option<&Credential>,
        taken: impl Fn(&str) -> bool,
    ) -> Result<String, EngineError> {
        let Some(c) = first else {
            return Err(EngineError::Invalid(
                "a peer needs a name or a credential".into(),
            ));
        };
        let base = match c.kind {
            CredentialKind::YggKey
            | CredentialKind::TorClientKey
            | CredentialKind::WgKey
            | CredentialKind::TlsSpki => match c.value.char_indices().nth(12) {
                Some((at, _)) => format!("{}…", &c.value[..at]),
                None => c.value.clone(),
            },
            _ => c
                .value
                .strip_suffix("/32")
                .or_else(|| c.value.strip_suffix("/128"))
                .unwrap_or(&c.value)
                .to_string(),
        };
        let mut name = base.clone();
        let mut n = 2;
        while taken(&name) {
            name = format!("{base} ({n})");
            n += 1;
        }
        Ok(name)
    }

    pub(super) async fn new_credential(
        &self,
        state: &AppState,
        input: &NewCredential,
    ) -> Result<Credential, EngineError> {
        let (kind, value) = normalize_credential(input.kind, &input.value)?;
        if let Some(owner) = state.db.find_credential_owner(kind, &value).await? {
            let label = state
                .db
                .get_peer(&owner)
                .await?
                .map(|p| p.label)
                .unwrap_or(owner);
            return Err(EngineError::Conflict(format!(
                "{kind} {value} already belongs to peer {label}"
            )));
        }
        Ok(Credential {
            id: new_id(),
            kind,
            value,
            label: input.label.clone().filter(|l| !l.trim().is_empty()),
        })
    }

    pub(super) fn conflict_or_internal(e: anyhow::Error, what: &str) -> EngineError {
        if state::is_unique_violation(&e) {
            EngineError::Conflict(format!("{what} already exists"))
        } else {
            EngineError::Internal(e)
        }
    }

    pub async fn create_peer(
        &self,
        state: &AppState,
        label: &str,
        credentials: &[NewCredential],
    ) -> Result<Peer, EngineError> {
        let mut creds: Vec<Credential> = Vec::new();
        for input in credentials {
            let c = self.new_credential(state, input).await?;
            if creds.iter().any(|x| x.kind == c.kind && x.value == c.value) {
                return Err(EngineError::Invalid(format!(
                    "{} {} is listed twice",
                    c.kind, c.value
                )));
            }
            creds.push(c);
        }
        let label = if label.trim().is_empty() {
            let taken: Vec<String> = state
                .db
                .list_peers()
                .await?
                .into_iter()
                .map(|p| p.label)
                .collect();
            Self::default_peer_label(creds.first(), |n| taken.iter().any(|t| t == n))?
        } else {
            Self::clean_label(label, "peer")?
        };
        let peer = Peer {
            id: new_id(),
            label: label.clone(),
            credentials: creds,
            groups: vec![],
            created_at: Utc::now(),
        };
        state
            .db
            .insert_peer(&peer)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("peer {label}")))?;
        let activity =
            NewActivity::new(ActivityKind::PeerAdded, format!("Added peer {label}")).peer(&peer.id);
        self.commit(state, Ok(()), Some(activity), &[DaemonEvent::PeersChanged])
            .await?;
        Ok(peer)
    }

    pub async fn update_peer_label(
        &self,
        state: &AppState,
        id: &str,
        label: &str,
    ) -> Result<Peer, EngineError> {
        let label = Self::clean_label(label, "peer")?;
        if !state
            .db
            .rename_peer(id, &label)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("peer {label}")))?
        {
            return Err(EngineError::NotFound(format!("peer {id}")));
        }
        let activity = NewActivity::new(
            ActivityKind::PeerChanged,
            format!("Renamed peer to {label}"),
        )
        .peer(id);
        self.commit(state, Ok(()), Some(activity), &[DaemonEvent::PeersChanged])
            .await?;
        self.get_peer(state, id).await
    }

    /// Delete a peer; the grants that name it go with it, and with them their rules.
    pub async fn delete_peer(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let peer = self.get_peer(state, id).await?;
        state.db.delete_peer(id).await?;
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::PeerRemoved,
            format!("Removed peer {}", peer.label),
        )
        .peer(id);
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::PeersChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        Ok(())
    }

    pub async fn add_credential(
        &self,
        state: &AppState,
        peer_id: &str,
        input: &NewCredential,
    ) -> Result<Credential, EngineError> {
        let peer = self.get_peer(state, peer_id).await?;
        let c = self.new_credential(state, input).await?;
        state
            .db
            .add_credential(peer_id, &c)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("{} {}", c.kind, c.value)))?;
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::PeerChanged,
            format!("Added {} to peer {}", c.kind, peer.label),
        )
        .peer(peer_id);
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::PeersChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        Ok(c)
    }

    pub async fn remove_credential(
        &self,
        state: &AppState,
        peer_id: &str,
        cred_id: &str,
    ) -> Result<(), EngineError> {
        let peer = self.get_peer(state, peer_id).await?;
        if !state.db.remove_credential(peer_id, cred_id).await? {
            return Err(EngineError::NotFound(format!("credential {cred_id}")));
        }
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::PeerChanged,
            format!("Removed a credential from peer {}", peer.label),
        )
        .peer(peer_id);
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::PeersChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        Ok(())
    }

    pub async fn create_group(
        &self,
        state: &AppState,
        label: &str,
        members: &[String],
    ) -> Result<PeerGroup, EngineError> {
        let label = Self::clean_label(label, "group")?;
        self.check_peers_exist(state, members).await?;
        let group = PeerGroup {
            id: new_id(),
            label: label.clone(),
            members: members
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            created_at: Utc::now(),
        };
        state
            .db
            .insert_group(&group)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("group {label}")))?;
        let activity = NewActivity::new(ActivityKind::GroupAdded, format!("Added group {label}"));
        self.commit(state, Ok(()), Some(activity), &[DaemonEvent::PeersChanged])
            .await?;
        Ok(group)
    }

    pub async fn rename_group(
        &self,
        state: &AppState,
        id: &str,
        label: &str,
    ) -> Result<PeerGroup, EngineError> {
        let label = Self::clean_label(label, "group")?;
        if !state
            .db
            .rename_group(id, &label)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("group {label}")))?
        {
            return Err(EngineError::NotFound(format!("peer group {id}")));
        }
        let activity = NewActivity::new(
            ActivityKind::GroupChanged,
            format!("Renamed group to {label}"),
        );
        self.commit(state, Ok(()), Some(activity), &[DaemonEvent::PeersChanged])
            .await?;
        self.get_group(state, id).await
    }

    pub async fn delete_group(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let group = self.get_group(state, id).await?;
        state.db.delete_group(id).await?;
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::GroupRemoved,
            format!("Removed group {}", group.label),
        );
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::PeersChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        Ok(())
    }

    /// Replace a group's members.
    pub async fn set_group_members(
        &self,
        state: &AppState,
        id: &str,
        peer_ids: &[String],
    ) -> Result<PeerGroup, EngineError> {
        let group = self.get_group(state, id).await?;
        self.check_peers_exist(state, peer_ids).await?;
        state.db.set_group_members(id, peer_ids).await?;
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::GroupChanged,
            format!("Changed the members of group {}", group.label),
        );
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::PeersChanged, DaemonEvent::GrantsChanged],
        )
        .await?;
        self.get_group(state, id).await
    }

    pub(super) async fn check_peers_exist(
        &self,
        state: &AppState,
        ids: &[String],
    ) -> Result<(), EngineError> {
        let known: HashSet<String> = state
            .db
            .list_peers()
            .await?
            .into_iter()
            .map(|p| p.id)
            .collect();
        match ids.iter().find(|i| !known.contains(*i)) {
            Some(missing) => Err(EngineError::NotFound(format!("peer {missing}"))),
            None => Ok(()),
        }
    }

    /// Create a grant. Rejected: a grant on Local ([`EngineError::LocalNetwork`]), a grant
    /// to Anyone without `confirm_open`, and unknown apps, tags, ports, networks or
    /// subjects.
    pub async fn create_grant(
        &self,
        state: &AppState,
        req: &NewGrant,
    ) -> Result<GrantView, EngineError> {
        let cat = Catalog::load(state).await?;
        let info = self.check_new_grant(&cat, req)?;
        let grant = Grant {
            id: new_id(),
            target: req.target.clone(),
            scope: req.scope.clone(),
            network_id: req.network_id.clone(),
            subject: req.subject.clone(),
            created_at: Utc::now(),
        };
        // The unique index settles a race with an identical request.
        state
            .db
            .insert_grant(&grant)
            .await
            .map_err(|e| Self::conflict_or_internal(e, "this grant"))?;
        let applied = self.apply_firewall(state).await;
        let act = Self::grant_added_activity(&grant, &info);
        self.commit(state, applied, Some(act), &[DaemonEvent::GrantsChanged])
            .await?;
        self.get_grant(state, &grant.id).await
    }

    pub(super) fn grant_added_activity(grant: &Grant, info: &GrantInfo) -> NewActivity {
        let mut act = NewActivity::new(
            ActivityKind::GrantAdded,
            format!(
                "Granted {} access to {}",
                info.subject_label, info.target_name
            ),
        );
        if let Target::App(id) = &grant.target {
            act = act.app(id);
        }
        if let Subject::Peer(id) = &grant.subject {
            act.peer_id = Some(id.clone());
        }
        act.network_id = grant.network_id.clone();
        act
    }

    /// Whether `scope` can be used on `app`: a port the app has (or that one of its attached
    /// socket groups covers), or a socket group attached to it.
    pub(super) fn check_scope_on_app(
        cat: &Catalog,
        app: &App,
        scope: &socketguard_core::Scope,
    ) -> Result<(), EngineError> {
        use socketguard_core::Scope;
        match scope {
            Scope::All => Ok(()),
            Scope::Port { port, proto } => {
                let p = socketguard_core::PortRef {
                    port: *port,
                    proto: *proto,
                };
                let in_group = cat
                    .socket_groups
                    .iter()
                    .filter(|g| g.is_attached_to(&app.id))
                    .any(|g| g.ports.iter().any(|r| r.contains(p)));
                if app.has_port(p) || in_group {
                    Ok(())
                } else {
                    Err(EngineError::Invalid(format!("{} has no port {p}", app.name)))
                }
            }
            Scope::Group { id } => {
                let group = cat
                    .socket_group(id)
                    .ok_or_else(|| EngineError::NotFound(format!("socket group {id}")))?;
                if group.is_attached_to(&app.id) {
                    Ok(())
                } else {
                    Err(EngineError::Invalid(format!(
                        "socket group {} is not attached to {}",
                        group.label, app.name
                    )))
                }
            }
        }
    }

    /// Check a new grant against `cat`; the labels for the activity record.
    pub(super) fn check_new_grant(
        &self,
        cat: &Catalog,
        req: &NewGrant,
    ) -> Result<GrantInfo, EngineError> {
        let target_name = match &req.target {
            Target::App(id) => {
                let app = cat
                    .app(id)
                    .ok_or_else(|| EngineError::NotFound(format!("app {id}")))?;
                Self::check_scope_on_app(cat, app, &req.scope)?;
                app.name.clone()
            }
            Target::Tag(id) => {
                let tag = cat
                    .tag(id)
                    .ok_or_else(|| EngineError::NotFound(format!("tag {id}")))?;
                // The grant's own scope needs no attachment, but the group must exist.
                if let Some(gid) = req.scope.group_id() {
                    cat.socket_group(gid)
                        .ok_or_else(|| EngineError::NotFound(format!("socket group {gid}")))?;
                }
                format!("tag {}", tag.label)
            }
        };
        if let Some(nid) = &req.network_id {
            let net = self
                .networks()
                .into_iter()
                .find(|n| n.id == *nid)
                .ok_or_else(|| EngineError::NotFound(format!("network {nid}")))?;
            if !net.grants_apply {
                return Err(EngineError::LocalNetwork);
            }
        }
        let subject_label = match &req.subject {
            Subject::Anyone => {
                if !req.confirm_open {
                    return Err(EngineError::ConfirmationRequired);
                }
                "Anyone".to_string()
            }
            Subject::Peer(id) => cat
                .peer(id)
                .ok_or_else(|| EngineError::NotFound(format!("peer {id}")))?
                .label
                .clone(),
            Subject::Group(id) => cat
                .group(id)
                .ok_or_else(|| EngineError::NotFound(format!("peer group {id}")))?
                .label
                .clone(),
        };
        if cat.grants.iter().any(|g| {
            g.target == req.target
                && g.scope == req.scope
                && g.network_id == req.network_id
                && g.subject == req.subject
        }) {
            return Err(EngineError::Conflict("this grant already exists".into()));
        }
        Ok(GrantInfo {
            target_name,
            subject_label,
        })
    }

    pub async fn delete_grant(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let grant = state
            .db
            .get_grant(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("grant {id}")))?;
        state.db.delete_grant(id).await?;
        let applied = self.apply_firewall(state).await;
        let act = self.grant_removed_activity(state, &grant).await;
        self.commit(state, applied, Some(act), &[DaemonEvent::GrantsChanged])
            .await?;
        Ok(())
    }

    pub(super) async fn grant_removed_activity(
        &self,
        state: &AppState,
        grant: &Grant,
    ) -> NewActivity {
        let name = match &grant.target {
            Target::App(id) => state
                .db
                .get_app(id)
                .await
                .ok()
                .flatten()
                .map(|a| a.name)
                .unwrap_or_else(|| id.clone()),
            Target::Tag(id) => state
                .db
                .get_tag(id)
                .await
                .ok()
                .flatten()
                .map(|t| format!("tag {}", t.label))
                .unwrap_or_else(|| format!("tag {id}")),
        };
        let mut act = NewActivity::new(
            ActivityKind::GrantRemoved,
            format!("Removed a grant for {name}"),
        );
        if let Target::App(id) = &grant.target {
            act = act.app(id);
        }
        if let Subject::Peer(p) = &grant.subject {
            act.peer_id = Some(p.clone());
        }
        act.network_id = grant.network_id.clone();
        act
    }
}

/// Labels for the activity record of a new grant.
pub(super) struct GrantInfo {
    pub target_name: String,
    pub subject_label: String,
}

/// The apps, peers, groups, tags and grants a change is checked against. A batch edits its
/// own copy as it goes, so later operations see earlier ones (including created refs).
#[derive(Default, Clone)]
pub(super) struct Catalog {
    pub apps: Vec<App>,
    pub peers: Vec<Peer>,
    pub groups: Vec<PeerGroup>,
    pub tags: Vec<Tag>,
    pub socket_groups: Vec<SocketGroup>,
    pub grants: Vec<Grant>,
}

impl Catalog {
    pub async fn load(state: &AppState) -> anyhow::Result<Self> {
        let db = &state.db;
        Ok(Self {
            apps: db.list_apps().await?,
            peers: db.list_peers().await?,
            groups: db.list_groups().await?,
            tags: db.list_tags().await?,
            socket_groups: db.list_socket_groups().await?,
            grants: db.list_grants().await?,
        })
    }

    pub fn app(&self, id: &str) -> Option<&App> {
        self.apps.iter().find(|a| a.id == id)
    }

    pub fn peer(&self, id: &str) -> Option<&Peer> {
        self.peers.iter().find(|p| p.id == id)
    }

    pub fn group(&self, id: &str) -> Option<&PeerGroup> {
        self.groups.iter().find(|g| g.id == id)
    }

    pub fn tag(&self, id: &str) -> Option<&Tag> {
        self.tags.iter().find(|t| t.id == id)
    }

    pub fn socket_group(&self, id: &str) -> Option<&SocketGroup> {
        self.socket_groups.iter().find(|g| g.id == id)
    }
}
