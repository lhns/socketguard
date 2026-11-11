//! The domain types (ADR 0027, 0028, 0037): apps, networks, addresses, peers, credentials,
//! grants, settings and activity. The functions that work on them live in
//! [`crate::credential`] (normalization), [`crate::reach`] (the reach table) and
//! [`crate::identity`] (app identity).

use crate::reach::GrantReach;
use crate::scope::{PortGroup, PortRange, Scope};
use crate::types::{AddrFamily, Protocol};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};

pub type AppId = String;
pub type NetworkId = String;
pub type PeerId = String;
pub type PeerGroupId = String;
pub type GrantId = String;
pub type TagId = String;
pub type AddressId = String;

/// A fresh random identifier (uuid v4) for peers, groups, grants, addresses, credentials.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ─── Apps ────────────────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct App {
    pub id: AppId,
    /// Display name: script or service name for interpreters, else the process name.
    pub name: String,
    pub process_name: String,
    pub exe_path: Option<String>,
    /// Normalized script / jar / main class / service name.
    pub interpreter_arg: Option<String>,
    /// Why the identity is special (inline code, unrecognized arguments, no executable
    /// path, foreign mount namespace), for the frontends; None for an ordinary app.
    #[serde(default)]
    pub identity_note: Option<String>,
    /// The app has a known executable path that no longer exists on disk (moved, reinstalled
    /// or removed). Computed by the daemon at poll time; not stored.
    #[serde(default)]
    pub exe_missing: bool,
    /// An OS component (service or system process), so frontends can group it away from
    /// the user's own apps.
    #[serde(default)]
    pub system: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub ports: Vec<AppPort>,
    pub addresses: Vec<Address>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPort {
    pub port: u16,
    pub proto: Protocol,
    pub listening: bool,
    pub last_seen: DateTime<Utc>,
    /// Over which IP versions the port accepts connections (the monitor's reading).
    #[serde(default)]
    pub family: AddrFamily,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortRef {
    pub port: u16,
    pub proto: Protocol,
}

impl AppPort {
    pub fn port_ref(&self) -> PortRef {
        PortRef {
            port: self.port,
            proto: self.proto,
        }
    }
}

impl App {
    /// Whether the app has `port`, listening or not.
    pub fn has_port(&self, port: PortRef) -> bool {
        self.ports.iter().any(|p| p.port_ref() == port)
    }
}

impl std::fmt::Display for PortRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.port, self.proto)
    }
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub id: AddressId,
    pub network_id: NetworkId,
    pub locator: Locator,
    pub created_at: DateTime<Utc>,
    /// Automatic addresses: the app whose row this is. None for a reservation's address.
    #[serde(default)]
    pub app_id: Option<AppId>,
    /// Automatic addresses: which sockets of the app; addresses overlap (ADR 0047).
    #[serde(default)]
    pub scope: Scope,
    /// The reservation this is the static address of, on its network (ADR 0047).
    #[serde(default)]
    pub reservation_id: Option<ReservationId>,
    /// Computed for the API (false as stored): the address is on its interface or
    /// published only while up.
    #[serde(default)]
    pub up: bool,
    /// Computed: ports of its scope(s) left out because another app listens on them.
    #[serde(default)]
    pub excluded: Vec<PortRange>,
    /// Computed, Tor: why the service is unpublished or leaves clients out.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl Address {
    /// An automatic address for a row of an app.
    pub fn automatic(app_id: &str, scope: Scope, network_id: &str, locator: Locator) -> Address {
        Address {
            id: new_id(),
            network_id: network_id.to_string(),
            locator,
            created_at: Utc::now(),
            app_id: Some(app_id.to_string()),
            scope,
            reservation_id: None,
            up: false,
            excluded: vec![],
            notes: vec![],
        }
    }

    /// The address of a reservation on a network.
    pub fn of_reservation(reservation_id: &str, network_id: &str, locator: Locator) -> Address {
        Address {
            app_id: None,
            reservation_id: Some(reservation_id.to_string()),
            ..Address::automatic("", Scope::All, network_id, locator)
        }
    }
}

pub type ReservationId = String;
pub type BindingId = String;

/// What a binding stands for: a row of an app, or the rows of the members of a tag.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BindingTarget {
    App {
        app_id: AppId,
        #[serde(default)]
        scope: Scope,
    },
    Tag {
        tag_id: TagId,
    },
}

/// One binding of a reservation; its own record so an outside port can be added later.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub id: BindingId,
    pub reservation_id: ReservationId,
    pub target: BindingTarget,
}

/// A named object that behaves like an app assembled from rows of several apps (ADR 0047):
/// grants can target it, and it has one static address per network once a grant covers
/// something it serves there. The daemon never deletes it or changes its addresses.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub id: ReservationId,
    pub label: String,
    pub bindings: Vec<Binding>,
    pub created_at: DateTime<Utc>,
}

/// Ports that bindings of several apps claim, and what is done about them.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortConflict {
    pub ports: PortRange,
    /// The bindings that claim these ports.
    pub bindings: Vec<BindingId>,
    /// The app they are served for; None = closed.
    pub served_app: Option<AppId>,
}

/// A reservation as the API shows it.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReservationView {
    #[serde(flatten)]
    pub reservation: Reservation,
    /// Its static address on each network where it has one, with `up`, `excluded`, `notes`.
    pub addresses: Vec<Address>,
    /// Ports claimed by bindings of several apps, and who is served.
    pub conflicts: Vec<PortConflict>,
    /// Grants that target the reservation.
    pub grants: Vec<GrantView>,
}

/// Where an address can be reached; network-specific. The interface ID of an IPv6 locator
/// is the low 64 bits of `addr`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Locator {
    Ipv6 { addr: Ipv6Addr },
    Onion { hostname: String },
}

impl Locator {
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            Locator::Ipv6 { addr } => Some(*addr),
            Locator::Onion { .. } => None,
        }
    }
}

// ─── Networks ────────────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    Local,
    Lan,
    Yggdrasil,
    /// Reserved for the planned WireGuard network (ADR 0036); no backend produces it yet.
    #[serde(rename = "wireguard")]
    WireGuard,
    Tor,
}

impl From<crate::types::BackendType> for NetworkKind {
    fn from(t: crate::types::BackendType) -> Self {
        use crate::types::BackendType as B;
        match t {
            B::Ula => NetworkKind::Local,
            B::Slaac | B::Dhcpv6 => NetworkKind::Lan,
            B::Yggdrasil => NetworkKind::Yggdrasil,
            B::Tor => NetworkKind::Tor,
        }
    }
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub id: NetworkId,
    pub kind: NetworkKind,
    pub name: String,
    pub interface: Option<String>,
    /// False for Local on a loopback interface: it is this machine only, grants have no
    /// effect there. Local on another interface takes grants like any IP network.
    pub grants_apply: bool,
    pub status: NetworkStatus,
    /// The /64 the network currently allocates from, as its network address. Needed to
    /// resolve `IpSuffix` credentials; None for Local and for networks without a /64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<Ipv6Addr>,
    /// The VLAN id when `interface` is a VLAN subinterface (Linux only; other systems
    /// show the adapter as a plain interface).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NetworkStatus {
    Up,
    Down { reason: String },
}

// ─── Peers, credentials, groups ──────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    YggKey,
    YggAddr,
    YggSubnet,
    Ip,
    IpSuffix,
    WgKey,
    TorClientKey,
    TlsSpki,
}

impl CredentialKind {
    pub const ALL: [CredentialKind; 8] = [
        CredentialKind::YggKey,
        CredentialKind::YggAddr,
        CredentialKind::YggSubnet,
        CredentialKind::Ip,
        CredentialKind::IpSuffix,
        CredentialKind::WgKey,
        CredentialKind::TorClientKey,
        CredentialKind::TlsSpki,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::YggKey => "ygg_key",
            CredentialKind::YggAddr => "ygg_addr",
            CredentialKind::YggSubnet => "ygg_subnet",
            CredentialKind::Ip => "ip",
            CredentialKind::IpSuffix => "ip_suffix",
            CredentialKind::WgKey => "wg_key",
            CredentialKind::TorClientKey => "tor_client_key",
            CredentialKind::TlsSpki => "tls_spki",
        }
    }
}

impl std::fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CredentialKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CredentialKind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| format!("invalid credential kind: {s}"))
    }
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub kind: CredentialKind,
    /// Normalized, see [`normalize_credential`].
    pub value: String,
    pub label: Option<String>,
}

/// A credential as given by a user, before normalization.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewCredential {
    pub kind: CredentialKind,
    pub value: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Peer {
    pub id: PeerId,
    pub label: String,
    pub credentials: Vec<Credential>,
    pub groups: Vec<PeerGroupId>,
    pub created_at: DateTime<Utc>,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerGroup {
    pub id: PeerGroupId,
    pub label: String,
    pub members: Vec<PeerId>,
    pub created_at: DateTime<Utc>,
}

// ─── Grants and reach ────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Subject {
    Peer(PeerId),
    Group(PeerGroupId),
    Anyone,
}

/// What a grant applies to (ADR 0043).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Target {
    App(AppId),
    Tag(TagId),
    /// A reservation: covers every bound row (ADR 0047). Its scope is always All.
    Reservation(ReservationId),
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: GrantId,
    /// One app, or every member of a tag.
    pub target: Target,
    /// Which sockets of the app (or of each member) the grant covers.
    #[serde(default)]
    pub scope: Scope,
    /// None = every network on which grants apply.
    pub network_id: Option<NetworkId>,
    pub subject: Subject,
    pub created_at: DateTime<Utc>,
}

/// A grant with the reach the daemon computed for it, for frontends.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantView {
    #[serde(flatten)]
    pub grant: Grant,
    pub reach: Vec<GrantReach>,
}

/// An app with its grants.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppDetail {
    #[serde(flatten)]
    pub app: App,
    /// Grants on the app itself.
    pub grants: Vec<GrantView>,
    /// Everything that gives the app access, tag grants included, each with its origin.
    #[serde(default)]
    pub access: Vec<crate::tags::EffectiveAccess>,
    /// The tags the app is a member of (as a whole or by scope).
    #[serde(default)]
    pub tags: Vec<TagId>,
    /// The port groups attached to the app.
    #[serde(default)]
    pub port_groups: Vec<PortGroup>,
    /// Packets and bytes the firewall allowed in, per network and grant subject, as of
    /// the last reconcile pass. Empty where the platform has no counters.
    #[serde(default)]
    pub counters: Vec<AppCounter>,
}

/// Allowed traffic of an app through one grant, summed over its rules.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppCounter {
    pub network_id: NetworkId,
    /// Label of the grant's subject: a peer or group label, or "Anyone".
    pub subject: String,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub packets: u64,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub bytes: u64,
}

/// Request to create a grant. A grant to [`Subject::Anyone`] opens the app to everyone
/// and needs `confirm_open`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewGrant {
    pub target: Target,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub network_id: Option<NetworkId>,
    pub subject: Subject,
    #[serde(default)]
    pub confirm_open: bool,
}

// ─── Settings ────────────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub protect_host_interfaces: Vec<String>,
}

// ─── Activity ────────────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    AppDiscovered,
    AppRemoved,
    GrantAdded,
    GrantRemoved,
    PeerAdded,
    PeerChanged,
    PeerRemoved,
    GroupAdded,
    GroupChanged,
    GroupRemoved,
    TagAdded,
    TagChanged,
    TagRemoved,
    PortGroupAdded,
    PortGroupChanged,
    PortGroupRemoved,
    ReservationAdded,
    ReservationChanged,
    ReservationRemoved,
    AppMoved,
    ProtectHostChanged,
    Blocked,
    RemoteAdminExposed,
}

impl ActivityKind {
    pub const ALL: [ActivityKind; 23] = [
        ActivityKind::AppDiscovered,
        ActivityKind::AppRemoved,
        ActivityKind::GrantAdded,
        ActivityKind::GrantRemoved,
        ActivityKind::PeerAdded,
        ActivityKind::PeerChanged,
        ActivityKind::PeerRemoved,
        ActivityKind::GroupAdded,
        ActivityKind::GroupChanged,
        ActivityKind::GroupRemoved,
        ActivityKind::TagAdded,
        ActivityKind::TagChanged,
        ActivityKind::TagRemoved,
        ActivityKind::PortGroupAdded,
        ActivityKind::PortGroupChanged,
        ActivityKind::PortGroupRemoved,
        ActivityKind::ReservationAdded,
        ActivityKind::ReservationChanged,
        ActivityKind::ReservationRemoved,
        ActivityKind::AppMoved,
        ActivityKind::ProtectHostChanged,
        ActivityKind::Blocked,
        ActivityKind::RemoteAdminExposed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ActivityKind::AppDiscovered => "app_discovered",
            ActivityKind::AppRemoved => "app_removed",
            ActivityKind::GrantAdded => "grant_added",
            ActivityKind::GrantRemoved => "grant_removed",
            ActivityKind::PeerAdded => "peer_added",
            ActivityKind::PeerChanged => "peer_changed",
            ActivityKind::PeerRemoved => "peer_removed",
            ActivityKind::GroupAdded => "group_added",
            ActivityKind::GroupChanged => "group_changed",
            ActivityKind::GroupRemoved => "group_removed",
            ActivityKind::TagAdded => "tag_added",
            ActivityKind::TagChanged => "tag_changed",
            ActivityKind::TagRemoved => "tag_removed",
            ActivityKind::PortGroupAdded => "port_group_added",
            ActivityKind::PortGroupChanged => "port_group_changed",
            ActivityKind::PortGroupRemoved => "port_group_removed",
            ActivityKind::ReservationAdded => "reservation_added",
            ActivityKind::ReservationChanged => "reservation_changed",
            ActivityKind::ReservationRemoved => "reservation_removed",
            ActivityKind::AppMoved => "app_moved",
            ActivityKind::ProtectHostChanged => "protect_host_changed",
            ActivityKind::Blocked => "blocked",
            ActivityKind::RemoteAdminExposed => "remote_admin_exposed",
        }
    }
}

impl std::str::FromStr for ActivityKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ActivityKind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| format!("invalid activity kind: {s}"))
    }
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityRecord {
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub id: i64,
    pub at: DateTime<Utc>,
    pub kind: ActivityKind,
    pub app_id: Option<AppId>,
    pub peer_id: Option<PeerId>,
    pub network_id: Option<NetworkId>,
    pub src: Option<IpAddr>,
    pub port: Option<u16>,
    pub proto: Option<Protocol>,
    pub count: u32,
    pub message: String,
}

/// Filter for listing activity, newest first. Also the query string of
/// `GET /api/activity`, with the same field names.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ActivityKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<AppId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<PeerId>,
    /// Only records with an id below this one (paging).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(type = "number | null"))]
    pub before: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub(crate) fn net(id: &str, kind: NetworkKind, prefix: Option<&str>) -> Network {
        Network {
            id: id.into(),
            kind,
            name: id.into(),
            interface: Some("if0".into()),
            grants_apply: kind != NetworkKind::Local,
            status: NetworkStatus::Up,
            prefix: prefix.map(|p| p.parse().unwrap()),
            vlan_id: None,
        }
    }

    pub(crate) fn cred(kind: CredentialKind, value: &str) -> Credential {
        Credential {
            id: "c".into(),
            kind,
            value: value.into(),
            label: None,
        }
    }

    pub(crate) const TOR_KEY: &str = "ZGBMJ4VIRNVUOQ5SJ2JXPSSWHB2R4YGTKPDGSMZ4HWCD5WLT2YKQ";

    pub(crate) const KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_kind_names_roundtrip() {
        for k in CredentialKind::ALL {
            assert_eq!(k.as_str().parse::<CredentialKind>().unwrap(), k);
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
        }
        for k in ActivityKind::ALL {
            assert_eq!(k.as_str().parse::<ActivityKind>().unwrap(), k);
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
        }
    }

    #[test]
    fn subject_serde_shape() {
        let s = serde_json::to_value(Subject::Peer("p1".into())).unwrap();
        assert_eq!(s, serde_json::json!({"kind":"peer","id":"p1"}));
        let s = serde_json::to_value(Subject::Anyone).unwrap();
        assert_eq!(s, serde_json::json!({"kind":"anyone"}));
        assert_eq!(
            serde_json::from_value::<Subject>(serde_json::json!({"kind":"group","id":"g"}))
                .unwrap(),
            Subject::Group("g".into())
        );
    }
}
