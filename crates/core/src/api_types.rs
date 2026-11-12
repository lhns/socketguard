//! Request and response bodies of the local API (ADR 0032, docs/api.md). The domain types
//! they carry live in [`crate::model`]. With the `ts` feature each type also derives its
//! TypeScript binding (ADR 0033).

use crate::config::BackendConfig;
use crate::model::{
    AppId, BindingId, BindingTarget, Credential, CredentialKind, GrantId, Network, NetworkId,
    NewCredential, PeerId, ReservationId, Settings, Subject, TagId, Target,
};
use crate::reach::GrantReach;
use crate::scope::{PortGroupId, PortRange, Scope};
use crate::tags::TagMember;
use crate::types::Protocol;
use serde::{Deserialize, Serialize};

/// Machine-readable error codes in [`ApiError::code`].
pub mod error_code {
    pub const NOT_FOUND: &str = "not_found";
    pub const INVALID: &str = "invalid";
    pub const CONFLICT: &str = "conflict";
    pub const LOCAL_NETWORK: &str = "local_network";
    pub const CONFIRMATION_REQUIRED: &str = "confirmation_required";
    pub const PROTECT_HOST_REFUSED: &str = "protect_host_refused";
    pub const INTERNAL: &str = "internal";
}

/// Body of every error response.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    /// Extra data: for `protect_host_refused`, a list of [`LockoutRiskInfo`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional, type = "unknown"))]
    pub details: Option<serde_json::Value>,
}

/// Whether a change has taken effect on the networks (`enforcement.status`).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementStatus {
    /// Saved, but a network could not enforce it yet (e.g. Tor is down); the daemon keeps
    /// retrying.
    Pending,
    /// The firewall rules could not be applied (ADR 0051): the change is saved, and a
    /// network added with it is not closed yet.
    Failed,
}

/// The `enforcement` field of an HTTP 202 response: the change is saved but not yet
/// enforced everywhere. Absent on a plain success.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enforcement {
    pub status: EnforcementStatus,
    pub message: String,
}

/// Body of a 202 response to a request that otherwise has no body (deletes).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementNotice {
    pub enforcement: Enforcement,
}

/// A remote-admin listener that whole-host protection would cut off.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockoutRiskInfo {
    pub process_name: String,
    pub port: u16,
    pub protocol: Protocol,
    pub bind_address: String,
    /// Human-readable form: "sshd on :::22/tcp has no grant".
    pub message: String,
}

// ─── Status ──────────────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub apps: u32,
    pub addresses: u32,
    pub peers: u32,
    pub groups: u32,
    pub grants: u32,
}

/// Response of `GET /api/status`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub version: String,
    pub networks: Vec<Network>,
    /// Interfaces under whole-host protection.
    pub protect_host_interfaces: Vec<String>,
    /// Enforcement is switched off (`disable`): no rules, no addresses, until `enable`.
    pub disabled: bool,
    /// A SocketGuard ruleset was found with an empty database and left in place: nothing is
    /// applied or added until `enable` (adopt) or `disable` (remove).
    #[serde(default)]
    pub unadopted: bool,
    pub counts: Counts,
    /// The config file the daemon loaded (or would create) (ADR 0050).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub config_path: Option<String>,
    /// The database in use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub db_path: Option<String>,
    /// The Unix socket or Windows pipe the API listens on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub socket: Option<String>,
    /// Whether SocketGuard is registered as a system service (None: could not be told).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub service_installed: Option<bool>,
    /// The third-party files this build ships (ADR 0052); no `dir` when it has none.
    #[serde(default)]
    pub bundled: crate::setup::BundledInfo,
    /// Portable mode (ADR 0054): everything is in the program's folder and the rules and
    /// addresses end with the daemon's process.
    #[serde(default)]
    pub portable: bool,
    /// The database file is restricted to SYSTEM and Administrators. False only in portable
    /// mode on a volume without access control lists.
    #[serde(default = "yes")]
    pub db_protected: bool,
    /// Blocked connections are being logged. False in portable mode when the system's
    /// net-event option is off (portable mode does not change it).
    #[serde(default = "yes")]
    pub drop_events: bool,
}

fn yes() -> bool {
    true
}

// ─── Apps ────────────────────────────────────────────────────────────────────

/// Body of `POST /api/credentials/parse`: pasted text with any number of values.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseCredentialsRequest {
    pub text: String,
}

/// Body of `POST /api/apps/{id}/move`: move grants, tag memberships, addresses and
/// reservation bindings from the app in the path to `to` (ADR 0047).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveAppRequest {
    pub to: AppId,
    /// Needed when a moved grant is to Anyone, or the target gains access for Anyone.
    #[serde(default)]
    pub confirm_open: bool,
}

// ─── Peers and groups ────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewPeer {
    /// Without a name (or with a blank one) the daemon names the peer after its first
    /// credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub label: Option<String>,
    #[serde(default)]
    pub credentials: Vec<crate::model::NewCredential>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateLabel {
    pub label: String,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewGroup {
    pub label: String,
    #[serde(default)]
    pub members: Vec<PeerId>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetMembers {
    pub peer_ids: Vec<PeerId>,
}

// ─── Networks, settings, maintenance ─────────────────────────────────────────

/// Body of `POST /api/networks`: a backend instance. `id` defaults to the backend's
/// default id (`yggdrasil`, `slaac-eth0`, ...).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewNetwork {
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub id: Option<String>,
    #[serde(flatten)]
    pub backend: BackendConfig,
}

/// Body of `PUT /api/networks/{id}/peers`: the peers of a managed Yggdrasil network (the
/// node restarts to use them).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetPeers {
    pub peers: Vec<String>,
}

/// Body of `PUT /api/networks/{id}/bridges`: the obfs4 bridge lines of a managed Tor network
/// (Tor restarts to use them). Empty turns bridges off. Lines are checked by
/// `bridge::parse_bridge_line` and stored in canonical form.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetBridges {
    pub bridges: Vec<String>,
}

/// Body of `PUT /api/settings/protect-host`. An empty list turns protection off.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectHostRequest {
    pub interfaces: Vec<String>,
    /// Enable despite lockout risks.
    #[serde(default)]
    pub force: bool,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectHostResponse {
    pub settings: Settings,
    /// Lockout risks that `force` overrode.
    pub overridden: Vec<LockoutRiskInfo>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisableRequest {
    pub confirm: bool,
}

/// Query of `GET /api/exposure`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExposureQuery {
    /// A network id, or `all` (the default): what becomes reachable without that block.
    pub without: Option<String>,
}

// ─── Exposure (ADR 0051) ─────────────────────────────────────────────────────

/// A program listening on all addresses, so reachable over a network once SocketGuard's
/// block on it is gone.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposedListener {
    /// The app's name.
    pub app: String,
    pub port: u16,
    pub proto: Protocol,
}

/// What stays reachable over one network when SocketGuard stops blocking it.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkExposure {
    /// The network's id.
    pub network: String,
    pub kind: crate::model::NetworkKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub interface: Option<String>,
    /// The software behind the network keeps running when the block goes.
    pub node_running: bool,
    /// The programs listening on all addresses (what the block keeps off the network).
    pub listeners: Vec<ExposedListener>,
}

impl NetworkExposure {
    /// What stays reachable without the block, in plain words; None when the node does not
    /// run (nothing is reachable over it).
    pub fn sentence(&self) -> Option<String> {
        if !self.node_running {
            return None;
        }
        let programs = match self.listeners.len() {
            0 => "no program listens on all addresses now".to_string(),
            1 => "1 program on this PC is reachable over it".to_string(),
            k => format!("{k} programs on this PC are reachable over it"),
        };
        let mut s = format!(
            "{} keeps running. Without SocketGuard, {programs}",
            self.network
        );
        if !self.listeners.is_empty() {
            let list: Vec<String> = self
                .listeners
                .iter()
                .map(|l| format!("{} (port {}/{})", l.app, l.port, l.proto))
                .collect();
            s.push_str(&format!(": {}", list.join(", ")));
        }
        s.push('.');
        s.push_str(" Stop its service yourself to close it.");
        Some(s)
    }
}

impl ExposureResponse {
    /// One sentence per network whose node keeps running.
    pub fn sentences(&self) -> Vec<String> {
        self.networks.iter().filter_map(|n| n.sentence()).collect()
    }
}

/// Response of `GET /api/exposure` and the body of a `confirmation_required` answer to
/// removing a network that stays reachable.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureResponse {
    /// Only the networks that are affected and whose node runs or has listeners.
    pub networks: Vec<NetworkExposure>,
}

// ─── Export and apply ────────────────────────────────────────────────────────

/// Version of [`ExportDocument`].
pub const EXPORT_VERSION: u32 = 1;

/// The portable form of settings, peers, groups and grants (`GET /api/export`). It names
/// things by label (and apps by id), never by internal id, so it can move between hosts.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportDocument {
    pub version: u32,
    pub settings: Settings,
    pub peers: Vec<ExportPeer>,
    pub groups: Vec<ExportGroup>,
    #[serde(default)]
    pub port_groups: Vec<ExportPortGroup>,
    pub grants: Vec<ExportGrant>,
    #[serde(default)]
    pub reservations: Vec<ExportReservation>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPeer {
    pub label: String,
    pub credentials: Vec<ExportCredential>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportCredential {
    pub kind: CredentialKind,
    pub value: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportGroup {
    pub label: String,
    /// Peer labels.
    pub members: Vec<String>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExportAppRef {
    pub id: String,
    /// For humans; ignored on apply.
    pub name: String,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPortGroup {
    pub label: String,
    pub ports: Vec<PortRange>,
    /// The apps it is attached to; an app that does not exist here makes the document invalid.
    pub apps: Vec<ExportAppRef>,
}

/// A scope by label, as the document names a port group.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExportScope {
    #[default]
    All,
    Port {
        port: u16,
        proto: Protocol,
    },
    Group {
        label: String,
    },
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportGrant {
    pub app: ExportAppRef,
    #[serde(default)]
    pub scope: ExportScope,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub network: Option<String>,
    pub subject: ExportSubject,
}

/// `{"peer": "label"}`, `{"group": "label"}` or `"anyone"`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportSubject {
    Peer(String),
    Group(String),
    Anyone,
}

/// What a reservation binding names in a document: an app (by identity) with a scope, or a
/// tag by label.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExportBinding {
    App {
        app: ExportAppRef,
        #[serde(default)]
        scope: ExportScope,
    },
    Tag {
        label: String,
    },
}

/// A grant on a reservation: always on all of its rows.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReservationGrant {
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub network: Option<String>,
    pub subject: ExportSubject,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReservation {
    pub label: String,
    #[serde(default)]
    pub bindings: Vec<ExportBinding>,
    #[serde(default)]
    pub grants: Vec<ExportReservationGrant>,
}

/// Body of `POST /api/apply`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyRequest {
    pub document: ExportDocument,
    #[serde(default)]
    pub dry_run: bool,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Create,
    Update,
    Delete,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeItem {
    Setting,
    Peer,
    Group,
    Grant,
    Tag,
    TagMember,
    PortGroup,
    App,
    Reservation,
    Binding,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub kind: ChangeKind,
    pub item: ChangeItem,
    /// Setting name, peer or group label, or a description of the grant.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub detail: Option<String>,
    /// A grant to Anyone, which the document confirms by being explicit.
    #[serde(default)]
    pub opens_to_anyone: bool,
}

/// Result of `POST /api/apply`: what changes (or changed).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyResponse {
    pub dry_run: bool,
    pub changes: Vec<Change>,
}

impl ApplyResponse {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

// ─── Tags ────────────────────────────────────────────────────────────────────

/// Body of `POST /api/tags`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewTag {
    pub label: String,
    /// Globs on the process name or the executable path (ADR 0043).
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub members: Vec<TagMember>,
}

/// Body of `PATCH /api/tags/{id}`. Absent fields stay as they are.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateTag {
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub label: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub patterns: Option<Vec<String>>,
    /// Needed when new patterns add existing apps to a tag that has a grant to Anyone
    /// (ADR 0043); without it the daemon answers `confirmation_required`.
    #[serde(default)]
    pub confirm_open: bool,
}

/// Body of `POST /api/tags/{id}/members`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewTagMember {
    pub app_id: AppId,
    #[serde(default)]
    pub scope: Scope,
    /// Needed when the tag has a grant to Anyone, which would open the app.
    #[serde(default)]
    pub confirm_open: bool,
}

/// Query of `DELETE /api/tags/{id}/members/{app_id}`: without `port` and `group` the
/// All-sockets membership goes, with `port` (and `proto`) the membership of that port, with
/// `group` (a port group id) the membership by that group.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub proto: Option<Protocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub group: Option<PortGroupId>,
}

impl MemberQuery {
    /// The scope the query names.
    pub fn scope(&self) -> Result<Scope, String> {
        match (self.port, self.proto, &self.group) {
            (None, None, None) => Ok(Scope::All),
            (Some(port), proto, None) => Ok(Scope::Port {
                port,
                proto: proto.unwrap_or(Protocol::Tcp),
            }),
            (None, None, Some(id)) => Ok(Scope::Group { id: id.clone() }),
            _ => Err("give a port with its proto, or a group, not both".to_string()),
        }
    }
}

// ─── Port groups ───────────────────────────────────────────────────────────

/// Body of `POST /api/port-groups`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewPortGroup {
    /// Without a name (or with a blank one) the daemon names the group after its ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub label: Option<String>,
    pub ports: Vec<PortRange>,
    /// Apps to attach it to right away.
    #[serde(default)]
    pub apps: Vec<AppId>,
    /// Needed when attaching would open an app to Anyone.
    #[serde(default)]
    pub confirm_open: bool,
}

/// Body of `PUT /api/port-groups/{id}`. Absent fields stay as they are. New ports take
/// effect everywhere the group is used.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePortGroup {
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub label: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub ports: Option<Vec<PortRange>>,
    /// Needed when new ports would open an app to Anyone.
    #[serde(default)]
    pub confirm_open: bool,
}

/// Body of `PUT /api/port-groups/{id}/apps/{app_id}`. Attaching a group to an app widens
/// what the grants covering the app's All ports cover; where that reaches Anyone it needs `confirm_open`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachPortGroup {
    #[serde(default)]
    pub confirm_open: bool,
}

// ─── Reservations ────────────────────────────────────────────────────────────

/// Body of `POST /api/reservations`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewReservation {
    pub label: String,
    #[serde(default)]
    pub bindings: Vec<BindingTarget>,
    /// Needed when the first bindings put rows under a grant to Anyone (none exist for a
    /// new reservation, so this only matters for symmetry with `NewBinding`).
    #[serde(default)]
    pub confirm_open: bool,
}

/// Body of `POST /api/reservations/{id}/bindings`. Binding a row to a reservation that has
/// a grant to Anyone opens the row, so it needs `confirm_open`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewBinding {
    pub target: BindingTarget,
    #[serde(default)]
    pub confirm_open: bool,
}

/// Body of `POST /api/addresses/{id}/reserve`: turn an automatic address into a
/// reservation with this label, keeping the address.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveRequest {
    pub label: String,
}

// ─── Batch changes ───────────────────────────────────────────────────────────

/// One operation of `POST /api/changes` (ADR 0045). Wherever an id goes, a `ref` of an
/// earlier create operation may stand in for it.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ChangeOp {
    CreatePeer {
        /// A client-chosen name starting with `$`, e.g. `$new0`.
        #[serde(rename = "ref", default)]
        #[cfg_attr(feature = "ts", ts(optional, rename = "ref"))]
        ref_: Option<String>,
        /// Optional, as in `NewPeer`.
        #[serde(default)]
        #[cfg_attr(feature = "ts", ts(optional))]
        label: Option<String>,
        #[serde(default)]
        credentials: Vec<NewCredential>,
    },
    /// A group of existing peers or `ref`s of peers created earlier in the batch.
    CreateGroup {
        #[serde(rename = "ref", default)]
        #[cfg_attr(feature = "ts", ts(optional, rename = "ref"))]
        ref_: Option<String>,
        label: String,
        #[serde(default)]
        members: Vec<PeerId>,
    },
    CreateTag {
        #[serde(rename = "ref", default)]
        #[cfg_attr(feature = "ts", ts(optional, rename = "ref"))]
        ref_: Option<String>,
        label: String,
        #[serde(default)]
        patterns: Vec<String>,
    },
    CreatePortGroup {
        #[serde(rename = "ref", default)]
        #[cfg_attr(feature = "ts", ts(optional, rename = "ref"))]
        ref_: Option<String>,
        /// Optional, as in `NewPortGroup`.
        #[serde(default)]
        #[cfg_attr(feature = "ts", ts(optional))]
        label: Option<String>,
        ports: Vec<PortRange>,
        /// Apps to attach it to right away.
        #[serde(default)]
        apps: Vec<AppId>,
        /// Needed when attaching would open an app to Anyone.
        #[serde(default)]
        confirm_open: bool,
    },
    UpdatePortGroup {
        group_id: PortGroupId,
        #[serde(default)]
        #[cfg_attr(feature = "ts", ts(optional))]
        label: Option<String>,
        #[serde(default)]
        #[cfg_attr(feature = "ts", ts(optional))]
        ports: Option<Vec<PortRange>>,
        /// Needed when new ports would open an app to Anyone.
        #[serde(default)]
        confirm_open: bool,
    },
    DeletePortGroup {
        group_id: PortGroupId,
    },
    AttachPortGroup {
        group_id: PortGroupId,
        app_id: AppId,
        /// Needed when the app or a tag it is in has a grant to Anyone that would cover
        /// the group's ports.
        #[serde(default)]
        confirm_open: bool,
    },
    DetachPortGroup {
        group_id: PortGroupId,
        app_id: AppId,
    },
    AddGrant {
        target: Target,
        #[serde(default)]
        scope: Scope,
        #[serde(default)]
        #[cfg_attr(feature = "ts", ts(optional))]
        network_id: Option<NetworkId>,
        subject: Subject,
        /// Needed when the subject is Anyone; without it the whole batch is refused.
        #[serde(default)]
        confirm_open: bool,
    },
    RemoveGrant {
        grant_id: GrantId,
    },
    AddTagMember {
        tag_id: TagId,
        app_id: AppId,
        #[serde(default)]
        scope: Scope,
        /// Needed when the tag has a grant to Anyone, which would open the app.
        #[serde(default)]
        confirm_open: bool,
    },
    RemoveTagMember {
        tag_id: TagId,
        app_id: AppId,
        #[serde(default)]
        scope: Scope,
    },
    CreateReservation {
        #[serde(rename = "ref", default)]
        #[cfg_attr(feature = "ts", ts(optional, rename = "ref"))]
        ref_: Option<String>,
        label: String,
        #[serde(default)]
        bindings: Vec<BindingTarget>,
        #[serde(default)]
        confirm_open: bool,
    },
    /// Turn an automatic address into a reservation, keeping the address.
    ReserveAddress {
        #[serde(rename = "ref", default)]
        #[cfg_attr(feature = "ts", ts(optional, rename = "ref"))]
        ref_: Option<String>,
        address_id: String,
        label: String,
    },
    RenameReservation {
        reservation_id: ReservationId,
        label: String,
    },
    AddBinding {
        reservation_id: ReservationId,
        target: BindingTarget,
        /// Needed when the reservation has a grant to Anyone.
        #[serde(default)]
        confirm_open: bool,
    },
    RemoveBinding {
        reservation_id: ReservationId,
        binding_id: BindingId,
    },
    /// Delete the reservation, its addresses and the grants on it.
    ReleaseReservation {
        reservation_id: ReservationId,
    },
    /// Move grants, tag memberships, addresses and bindings from one app to another.
    MoveApp {
        from: AppId,
        to: AppId,
        #[serde(default)]
        confirm_open: bool,
    },
}

/// Body of `POST /api/changes`: the operations are applied in order, all or nothing, with
/// one firewall update. With `dry_run` nothing is saved.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesRequest {
    pub ops: Vec<ChangeOp>,
    #[serde(default)]
    pub dry_run: bool,
}

/// One entry of the diff of a batch.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchChange {
    #[serde(flatten)]
    pub change: Change,
    /// The id of what was created or removed (a dry run shows the id it would get).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub id: Option<String>,
    /// For a grant: how well its subject is identified on each network it applies to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reach: Vec<GrantReach>,
}

/// Result of `POST /api/changes`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangesResponse {
    pub dry_run: bool,
    /// Each `ref` of the request and the id it stands for.
    pub refs: std::collections::BTreeMap<String, String>,
    pub changes: Vec<BatchChange>,
    /// The batch gives someone access to something they could not reach before (a new
    /// grant, or a new member of a tag that has grants). Removals never set it.
    #[serde(default)]
    pub changes_reach: bool,
}

// ─── Tor client keys and sharing ─────────────────────────────────────────────

/// Result of `POST /api/peers/{id}/tor-key`: the new credential and, once, its private
/// key in base32 (the daemon keeps it too, for `share`).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorKeyResponse {
    pub credential: Credential,
    pub private_key: String,
}

/// What a granted Tor peer needs to reach an app's onion service.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorShare {
    pub network_id: NetworkId,
    /// The service's `.onion` name.
    pub hostname: String,
    pub peer_id: PeerId,
    pub peer_label: String,
    /// The line for a file `<name>.auth_private` in the client's `ClientOnionAuthDir`:
    /// `<onion name without .onion>:descriptor:x25519:<base32 private key>`.
    pub auth_private: String,
}

/// Response of `GET /api/apps/{id}/share`: what the app's own addresses cannot tell.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareResponse {
    /// One entry per granted peer with a key the daemon generated, per onion service.
    pub tor: Vec<TorShare>,
}

// ─── Events ──────────────────────────────────────────────────────────────────

/// Names of the `GET /api/events` server-sent events.
pub mod event_name {
    pub const APPS_CHANGED: &str = "apps_changed";
    pub const APP_DISCOVERED: &str = "app_discovered";
    pub const PEERS_CHANGED: &str = "peers_changed";
    pub const GRANTS_CHANGED: &str = "grants_changed";
    pub const TAGS_CHANGED: &str = "tags_changed";
    pub const PORT_GROUPS_CHANGED: &str = "port_groups_changed";
    pub const RESERVATIONS_CHANGED: &str = "reservations_changed";
    pub const ADDRESSES_CHANGED: &str = "addresses_changed";
    pub const NETWORKS_CHANGED: &str = "networks_changed";
    pub const SETTINGS_CHANGED: &str = "settings_changed";
    pub const ACTIVITY: &str = "activity";
}

/// A parsed server-sent event.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum ApiEvent {
    AppsChanged,
    /// A new app; carries its id.
    AppDiscovered(String),
    PeersChanged,
    GrantsChanged,
    TagsChanged,
    PortGroupsChanged,
    ReservationsChanged,
    AddressesChanged,
    NetworksChanged,
    SettingsChanged,
    Activity,
    /// An event name this version does not know.
    Unknown {
        name: String,
        data: String,
    },
}

impl ApiEvent {
    /// The SSE event name (see [`event_name`]).
    pub fn name(&self) -> &str {
        match self {
            ApiEvent::AppsChanged => event_name::APPS_CHANGED,
            ApiEvent::AppDiscovered(_) => event_name::APP_DISCOVERED,
            ApiEvent::PeersChanged => event_name::PEERS_CHANGED,
            ApiEvent::GrantsChanged => event_name::GRANTS_CHANGED,
            ApiEvent::TagsChanged => event_name::TAGS_CHANGED,
            ApiEvent::PortGroupsChanged => event_name::PORT_GROUPS_CHANGED,
            ApiEvent::ReservationsChanged => event_name::RESERVATIONS_CHANGED,
            ApiEvent::AddressesChanged => event_name::ADDRESSES_CHANGED,
            ApiEvent::NetworksChanged => event_name::NETWORKS_CHANGED,
            ApiEvent::SettingsChanged => event_name::SETTINGS_CHANGED,
            ApiEvent::Activity => event_name::ACTIVITY,
            ApiEvent::Unknown { name, .. } => name,
        }
    }

    /// Parse an SSE event name and its data.
    pub fn from_wire(name: &str, data: &str) -> ApiEvent {
        use event_name::*;
        match name {
            APPS_CHANGED => ApiEvent::AppsChanged,
            APP_DISCOVERED => ApiEvent::AppDiscovered(data.to_string()),
            PEERS_CHANGED => ApiEvent::PeersChanged,
            GRANTS_CHANGED => ApiEvent::GrantsChanged,
            TAGS_CHANGED => ApiEvent::TagsChanged,
            PORT_GROUPS_CHANGED => ApiEvent::PortGroupsChanged,
            RESERVATIONS_CHANGED => ApiEvent::ReservationsChanged,
            ADDRESSES_CHANGED => ApiEvent::AddressesChanged,
            NETWORKS_CHANGED => ApiEvent::NetworksChanged,
            SETTINGS_CHANGED => ApiEvent::SettingsChanged,
            ACTIVITY => ApiEvent::Activity,
            _ => ApiEvent::Unknown {
                name: name.to_string(),
                data: data.to_string(),
            },
        }
    }
}
