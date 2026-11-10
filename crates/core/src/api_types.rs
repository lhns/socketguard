//! Request and response bodies of the local API (ADR 0032, docs/api.md). The domain types
//! they carry live in [`crate::model`]. With the `ts` feature each type also derives its
//! TypeScript binding (ADR 0033).

use crate::config::BackendConfig;
use crate::model::{AddressId, AddressMode, CredentialKind, Network, PeerId, PortRef, Settings};
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
    pub pending_apps: u32,
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
}

// ─── Apps ────────────────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRequest {
    pub reviewed: bool,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRequest {
    pub network_id: String,
    pub port: u16,
    pub proto: Protocol,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeRequest {
    pub network_id: String,
    pub address_ids: Vec<AddressId>,
}

// ─── Peers and groups ────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewPeer {
    pub label: String,
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

/// Body of `PUT /api/settings`. Absent fields stay as they are.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateSettings {
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub address_mode: Option<AddressMode>,
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
    pub grants: Vec<ExportGrant>,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportAppRef {
    pub id: String,
    /// For humans; ignored on apply.
    pub name: String,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportGrant {
    pub app: ExportAppRef,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub port: Option<PortRef>,
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

// ─── Events ──────────────────────────────────────────────────────────────────

/// Names of the `GET /api/events` server-sent events.
pub mod event_name {
    pub const APPS_CHANGED: &str = "apps_changed";
    pub const APP_DISCOVERED: &str = "app_discovered";
    pub const PEERS_CHANGED: &str = "peers_changed";
    pub const GRANTS_CHANGED: &str = "grants_changed";
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
    /// A new, pending app; carries its id.
    AppDiscovered(String),
    PeersChanged,
    GrantsChanged,
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
