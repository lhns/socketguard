//! The domain model (ADR 0027, 0028, 0037): apps, networks, addresses, peers, credentials
//! and grants, plus the pure functions that work on them: credential normalization, the
//! reach table and app identity.

use crate::types::Protocol;
use crate::yggdrasil::derive_yggdrasil_ipv6;
use chrono::{DateTime, Utc};
use ipnet::{IpNet, Ipv6Net};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv6Addr};

pub type AppId = String;
pub type NetworkId = String;
pub type PeerId = String;
pub type PeerGroupId = String;
pub type GrantId = String;
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
    /// False = pending: no decision has been made about this app yet.
    pub reviewed: bool,
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
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortRef {
    pub port: u16,
    pub proto: Protocol,
}

impl std::fmt::Display for PortRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.port, self.proto)
    }
}

/// Which of an app's ports an address serves.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortSet {
    /// Every app port not claimed by an `Only` address on the same network.
    All,
    Only(Vec<PortRef>),
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub id: AddressId,
    pub app_id: AppId,
    pub network_id: NetworkId,
    pub ports: PortSet,
    pub locator: Locator,
    pub created_at: DateTime<Utc>,
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

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: GrantId,
    pub app_id: AppId,
    /// None = every port of the app.
    pub port: Option<PortRef>,
    /// None = every network on which grants apply.
    pub network_id: Option<NetworkId>,
    pub subject: Subject,
    pub created_at: DateTime<Utc>,
}

/// How strongly a source is identified on a network.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    /// The source address is verified by a key (Yggdrasil: the interface only delivers
    /// packets from the address its peer's key derives).
    Verified,
    /// A whole subnet is trusted (Yggdrasil verifies the node, not the host behind it).
    WholeSubnet,
    /// Matched by source IP only; spoofable on a shared link.
    IpOnly,
    /// Anyone.
    Open,
    NotReachable,
}

impl Reach {
    /// Strength among credential reaches: Verified > WholeSubnet > IpOnly > the rest.
    fn rank(self) -> u8 {
        match self {
            Reach::Verified => 4,
            Reach::WholeSubnet => 3,
            Reach::IpOnly => 2,
            Reach::Open => 1,
            Reach::NotReachable => 0,
        }
    }

    pub fn best(self, other: Reach) -> Reach {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantReach {
    pub network_id: NetworkId,
    pub reach: Reach,
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
    pub grants: Vec<GrantView>,
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
    pub app_id: AppId,
    #[serde(default)]
    pub port: Option<PortRef>,
    #[serde(default)]
    pub network_id: Option<NetworkId>,
    pub subject: Subject,
    #[serde(default)]
    pub confirm_open: bool,
}

// ─── Settings ────────────────────────────────────────────────────────────────

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressMode {
    #[default]
    PerApp,
    PerPort,
}

impl AddressMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AddressMode::PerApp => "per_app",
            AddressMode::PerPort => "per_port",
        }
    }
}

impl std::str::FromStr for AddressMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "per_app" => Ok(AddressMode::PerApp),
            "per_port" => Ok(AddressMode::PerPort),
            _ => Err(format!("invalid address mode: {s}")),
        }
    }
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub address_mode: AddressMode,
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
    ProtectHostChanged,
    Blocked,
    RemoteAdminExposed,
}

impl ActivityKind {
    pub const ALL: [ActivityKind; 10] = [
        ActivityKind::AppDiscovered,
        ActivityKind::AppRemoved,
        ActivityKind::GrantAdded,
        ActivityKind::GrantRemoved,
        ActivityKind::PeerAdded,
        ActivityKind::PeerChanged,
        ActivityKind::PeerRemoved,
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

/// Filter for listing activity, newest first.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityQuery {
    pub since: Option<DateTime<Utc>>,
    pub kind: Option<ActivityKind>,
    pub app_id: Option<AppId>,
    pub peer_id: Option<PeerId>,
    /// Only records with an id below this one (paging).
    #[cfg_attr(feature = "ts", ts(type = "number | null"))]
    pub before: Option<i64>,
    pub limit: Option<u32>,
}

// ─── Credentials: normalization ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, CredentialError> {
    Err(CredentialError::Invalid(msg.into()))
}

fn ygg_range() -> Ipv6Net {
    "200::/7".parse().unwrap()
}

fn ygg_subnet_range() -> Ipv6Net {
    "300::/8".parse().unwrap()
}

/// Parse an IPv6 address or CIDR, with a clear error for IPv4.
fn parse_ip_or_net(value: &str) -> Result<Ipv6Net, CredentialError> {
    let value = value.trim();
    let net: IpNet = match value.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => match value.parse::<IpAddr>() {
            Ok(a) => IpNet::from(a),
            Err(_) => return invalid(format!("{value:?} is not an IP address or network")),
        },
    };
    match net {
        IpNet::V4(_) => invalid("IPv4 isn't supported yet"),
        IpNet::V6(n) => Ok(n),
    }
}

/// Decode `value` as 64 hex characters.
fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn is_base64(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
}

/// Validate and normalize a credential value, returning the kind to store and the
/// canonical value. Rejects invalid input with a message for the user.
///
/// - `YggKey`: 64 hex characters, stored lowercase.
/// - `YggAddr`: one address in `200::/7`, stored as an address.
/// - `YggSubnet`: a /64 in `300::/8`, stored as `net/64`.
/// - `Ip`: an IPv6 address or CIDR, stored as `net/len` (`/128` for a single address).
///   IPv4 is rejected. A value inside `200::/7` becomes `YggAddr` or `YggSubnet`; other
///   networks in that range are rejected.
/// - `IpSuffix`: an interface ID written as an address with zero upper 64 bits
///   (`::a:b:c:d`, optionally followed by `/64`), stored as the address.
/// - `WgKey`, `TorClientKey`, `TlsSpki`: base64, stored as given.
pub fn normalize_credential(
    kind: CredentialKind,
    value: &str,
) -> Result<(CredentialKind, String), CredentialError> {
    let value = value.trim();
    match kind {
        CredentialKind::YggKey => match parse_hex32(value) {
            Some(_) => Ok((kind, value.to_ascii_lowercase())),
            None => invalid("a Yggdrasil key is 64 hex characters"),
        },
        CredentialKind::WgKey | CredentialKind::TorClientKey | CredentialKind::TlsSpki => {
            if is_base64(value) {
                Ok((kind, value.to_string()))
            } else {
                invalid(format!("{kind} must be base64"))
            }
        }
        CredentialKind::IpSuffix => {
            let addr_part = value.strip_suffix("/64").unwrap_or(value);
            let addr: Ipv6Addr = match addr_part.parse() {
                Ok(a) => a,
                Err(_) => return invalid("an interface ID looks like ::a:b:c:d"),
            };
            if (u128::from(addr) >> 64) != 0 {
                return invalid("an interface ID has zero upper 64 bits (::a:b:c:d)");
            }
            if addr == Ipv6Addr::UNSPECIFIED {
                return invalid("an interface ID must not be zero");
            }
            Ok((kind, addr.to_string()))
        }
        CredentialKind::YggAddr | CredentialKind::YggSubnet | CredentialKind::Ip => {
            let net = parse_ip_or_net(value)?;
            let in_ygg = ygg_range().contains(&net);
            if kind == CredentialKind::Ip && !in_ygg && ygg_range().contains(&net.addr()) {
                return invalid("this network crosses the Yggdrasil range 200::/7");
            }
            if in_ygg || kind != CredentialKind::Ip {
                // Yggdrasil value: a single address, or a /64 in 300::/8.
                return normalize_ygg(kind, net);
            }
            if net.prefix_len() == 0 {
                return invalid("::/0 would match every source; grant to Anyone instead");
            }
            Ok((CredentialKind::Ip, net.trunc().to_string()))
        }
    }
}

fn normalize_ygg(
    kind: CredentialKind,
    net: Ipv6Net,
) -> Result<(CredentialKind, String), CredentialError> {
    if !ygg_range().contains(&net) {
        return invalid("a Yggdrasil address is in 200::/7");
    }
    match net.prefix_len() {
        128 if kind != CredentialKind::YggSubnet => {
            Ok((CredentialKind::YggAddr, net.addr().to_string()))
        }
        64 if kind != CredentialKind::YggAddr => {
            if !ygg_subnet_range().contains(&net) {
                return invalid("a Yggdrasil subnet is a /64 in 300::/8");
            }
            Ok((CredentialKind::YggSubnet, net.trunc().to_string()))
        }
        _ => match kind {
            CredentialKind::YggAddr => invalid("a Yggdrasil address is a single address"),
            CredentialKind::YggSubnet => invalid("a Yggdrasil subnet is a /64 in 300::/8"),
            _ => invalid("only a single Yggdrasil address or a /64 in 300::/8 is supported"),
        },
    }
}

// ─── Reach ───────────────────────────────────────────────────────────────────

fn is_ygg_subnet_host(addr: Ipv6Addr) -> bool {
    ygg_subnet_range().contains(&addr)
}

/// Whether `name` is a loopback interface (`lo`, `lo0`, "Loopback Pseudo-Interface 1").
/// Local networks on one are this machine only; grants have no effect there.
pub fn is_loopback_interface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "lo" || n == "lo0" || n.contains("loopback")
}

/// How well `credential` identifies a source on `network` (ADR 0028). A network on which
/// grants do not apply (Local on loopback) reaches nothing.
pub fn reach(credential: &Credential, network: &Network) -> Reach {
    if !network.grants_apply {
        return Reach::NotReachable;
    }
    match (credential.kind, network.kind) {
        (CredentialKind::YggKey, NetworkKind::Yggdrasil) => {
            if parse_hex32(&credential.value).is_some() {
                Reach::Verified
            } else {
                Reach::NotReachable
            }
        }
        (CredentialKind::YggAddr, NetworkKind::Yggdrasil) => match credential.value.parse() {
            Ok(a) if is_ygg_subnet_host(a) => Reach::WholeSubnet,
            Ok(a) if ygg_range().contains(&a) => Reach::Verified,
            _ => Reach::NotReachable,
        },
        (CredentialKind::YggSubnet, NetworkKind::Yggdrasil) => Reach::WholeSubnet,
        // Local takes grants only when its interface is not loopback (ADR 0027); it then
        // behaves like any IP network.
        (CredentialKind::Ip, NetworkKind::Lan | NetworkKind::Local) => Reach::IpOnly,
        (CredentialKind::IpSuffix, NetworkKind::Lan | NetworkKind::Local)
            if network.prefix.is_some() =>
        {
            Reach::IpOnly
        }
        _ => Reach::NotReachable,
    }
}

/// The best reach among `credentials` on `network`.
pub fn best_reach(credentials: &[Credential], network: &Network) -> Reach {
    credentials
        .iter()
        .fold(Reach::NotReachable, |acc, c| acc.best(reach(c, network)))
}

/// The source network a credential contributes on `network`, or None when it is
/// `NotReachable` there. Yggdrasil sources must additionally be bound to the network's
/// interface by the caller.
pub fn credential_source(credential: &Credential, network: &Network) -> Option<IpNet> {
    if reach(credential, network) == Reach::NotReachable {
        return None;
    }
    match credential.kind {
        CredentialKind::YggKey => {
            let key = parse_hex32(&credential.value)?;
            Some(IpNet::V6(
                Ipv6Net::new(derive_yggdrasil_ipv6(&key), 128).ok()?,
            ))
        }
        CredentialKind::YggAddr => {
            let a: Ipv6Addr = credential.value.parse().ok()?;
            Some(IpNet::V6(Ipv6Net::new(a, 128).ok()?))
        }
        CredentialKind::YggSubnet | CredentialKind::Ip => {
            credential.value.parse::<Ipv6Net>().ok().map(IpNet::V6)
        }
        CredentialKind::IpSuffix => {
            let suffix: Ipv6Addr = credential.value.parse().ok()?;
            let prefix = network.prefix?;
            let bits = (u128::from(prefix) & !(u64::MAX as u128))
                | (u128::from(suffix) & u64::MAX as u128);
            Some(IpNet::V6(Ipv6Net::new(Ipv6Addr::from(bits), 128).ok()?))
        }
        CredentialKind::WgKey | CredentialKind::TorClientKey | CredentialKind::TlsSpki => None,
    }
}

/// The reach of a grant on each network it applies to: `network_id`, or every network on
/// which grants apply. `credentials` are those of the subject's peers (all peers of a
/// group); `Subject::Anyone` is open everywhere.
pub fn grant_reach(
    subject: &Subject,
    credentials: &[Credential],
    network_id: Option<&str>,
    networks: &[Network],
) -> Vec<GrantReach> {
    networks
        .iter()
        .filter(|n| match network_id {
            Some(id) => n.id == id,
            None => n.grants_apply,
        })
        .map(|n| GrantReach {
            network_id: n.id.clone(),
            reach: match subject {
                Subject::Anyone if n.grants_apply => Reach::Open,
                Subject::Anyone => Reach::NotReachable,
                _ => best_reach(credentials, n),
            },
        })
        .collect()
}

// ─── App identity ────────────────────────────────────────────────────────────

/// The operating system whose conventions normalize a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
    Macos,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        }
    }
}

/// Normalize an executable path so it is stable across upgrades: Linux appends
/// ` (deleted)` to /proc/pid/exe when the binary was replaced; Windows paths are
/// case-insensitive.
pub fn normalize_exe_path(path: &str, platform: Platform) -> String {
    match platform {
        Platform::Windows => path.to_lowercase(),
        Platform::Linux => path.strip_suffix(" (deleted)").unwrap_or(path).to_string(),
        Platform::Macos => path.to_string(),
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Host {
    /// Script path is the first non-option argument.
    Script,
    Python,
    Deno,
    Java,
    Dotnet,
    Svchost,
}

/// Known interpreters and hosts, matched on the lowercased executable name without `.exe`.
fn host_of(exe_name: &str) -> Option<Host> {
    let lower = exe_name.to_lowercase();
    let name = lower.strip_suffix(".exe").unwrap_or(&lower);
    if name == "python" || name == "pythonw" {
        return Some(Host::Python);
    }
    if let Some(ver) = name.strip_prefix("python") {
        if ver.starts_with(|c: char| c.is_ascii_digit())
            && ver.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return Some(Host::Python);
        }
    }
    match name {
        "node" | "bun" | "ruby" | "perl" | "php" => Some(Host::Script),
        "deno" => Some(Host::Deno),
        "java" | "javaw" => Some(Host::Java),
        "dotnet" => Some(Host::Dotnet),
        "svchost" => Some(Host::Svchost),
        _ => None,
    }
}

fn first_non_option(args: &[String]) -> Option<&str> {
    args.iter()
        .map(String::as_str)
        .find(|a| !a.starts_with('-'))
}

fn java_target(args: &[String]) -> Option<&str> {
    let mut it = args.iter().map(String::as_str);
    while let Some(a) = it.next() {
        match a {
            "-jar" => return it.next(),
            "-cp" | "-classpath" | "--class-path" | "-p" | "--module-path" => {
                it.next();
            }
            _ if a.starts_with('-') => {}
            _ => return Some(a),
        }
    }
    None
}

fn interpreter_arg_of(host: Host, args: &[String]) -> Option<String> {
    let arg = match host {
        Host::Script => first_non_option(args),
        Host::Python => {
            let mut it = args.iter().map(String::as_str);
            let mut found = None;
            while let Some(a) = it.next() {
                if a == "-m" {
                    found = it.next();
                    break;
                }
                if a == "-c" {
                    break;
                }
                if !a.starts_with('-') {
                    found = Some(a);
                    break;
                }
            }
            found
        }
        Host::Deno => {
            let a = first_non_option(args);
            if a == Some("run") {
                args.iter()
                    .map(String::as_str)
                    .skip_while(|a| *a != "run")
                    .skip(1)
                    .find(|a| !a.starts_with('-'))
            } else {
                a
            }
        }
        Host::Java => java_target(args),
        Host::Dotnet => args
            .iter()
            .map(String::as_str)
            .find(|a| a.to_ascii_lowercase().ends_with(".dll")),
        Host::Svchost => args
            .iter()
            .position(|a| a == "-s")
            .and_then(|i| args.get(i + 1))
            .map(String::as_str),
    };
    arg.filter(|a| !a.is_empty()).map(str::to_string)
}

/// App identity (ADR 0027): `(id, display name, interpreter argument)`.
///
/// The id is the first 16 hex characters of SHA-256 over the executable path (or the
/// process name when unknown), a NUL, and, for known interpreters and hosts, the script,
/// jar, main class or service argument. The executable path is normalized first so that
/// toolchain upgrades keep the identity. `cmdline` is argv with `argv[0]` first. Relative
/// script paths are used as given: the working directory is not captured.
pub fn app_identity(
    process_name: &str,
    exe_path: Option<&str>,
    cmdline: Option<&[String]>,
) -> (AppId, String, Option<String>) {
    app_identity_on(Platform::current(), process_name, exe_path, cmdline)
}

/// [`app_identity`] with the platform's conventions chosen explicitly.
pub fn app_identity_on(
    platform: Platform,
    process_name: &str,
    exe_path: Option<&str>,
    cmdline: Option<&[String]>,
) -> (AppId, String, Option<String>) {
    let exe = exe_path.map(|p| normalize_exe_path(p, platform));
    let exe_name = exe.as_deref().map(file_name).unwrap_or(process_name);
    let interpreter_arg = host_of(exe_name).and_then(|host| {
        let args = cmdline.map(|c| c.get(1..).unwrap_or(&[])).unwrap_or(&[]);
        interpreter_arg_of(host, args)
    });

    let key_exe = match &exe {
        Some(e) => e.clone(),
        None => normalize_exe_path(process_name, platform),
    };
    let key_arg = match (&interpreter_arg, platform) {
        (Some(a), Platform::Windows) => a.to_lowercase(),
        (Some(a), _) => a.clone(),
        (None, _) => String::new(),
    };
    let digest = Sha256::digest(format!("{key_exe}\0{key_arg}").as_bytes());
    let id: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();

    let name = interpreter_arg
        .as_deref()
        .map(file_name)
        .filter(|n| !n.is_empty())
        .unwrap_or(process_name)
        .to_string();
    (id, name, interpreter_arg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(id: &str, kind: NetworkKind, prefix: Option<&str>) -> Network {
        Network {
            id: id.into(),
            kind,
            name: id.into(),
            interface: Some("if0".into()),
            grants_apply: kind != NetworkKind::Local,
            status: NetworkStatus::Up,
            prefix: prefix.map(|p| p.parse().unwrap()),
        }
    }

    fn cred(kind: CredentialKind, value: &str) -> Credential {
        Credential {
            id: "c".into(),
            kind,
            value: value.into(),
            label: None,
        }
    }

    const KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";

    #[test]
    fn reach_table_every_cell() {
        use CredentialKind as C;
        use NetworkKind as N;
        use Reach::*;
        let creds: [(Credential, [Reach; 5]); 9] = [
            // Local, Lan, Yggdrasil, WireGuard, Tor
            (
                cred(C::YggKey, KEY),
                [
                    NotReachable,
                    NotReachable,
                    Verified,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::YggAddr, "200:1::5"),
                [
                    NotReachable,
                    NotReachable,
                    Verified,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::YggAddr, "300:1:2:3::5"),
                [
                    NotReachable,
                    NotReachable,
                    WholeSubnet,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::YggSubnet, "300:1:2:3::/64"),
                [
                    NotReachable,
                    NotReachable,
                    WholeSubnet,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::Ip, "fd00::5/128"),
                [
                    NotReachable,
                    IpOnly,
                    NotReachable,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::IpSuffix, "::a:b:c:d"),
                [
                    NotReachable,
                    IpOnly,
                    NotReachable,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (cred(C::WgKey, "AAAA"), [NotReachable; 5]),
            (cred(C::TorClientKey, "AAAA"), [NotReachable; 5]),
            (cred(C::TlsSpki, "AAAA"), [NotReachable; 5]),
        ];
        let kinds = [N::Local, N::Lan, N::Yggdrasil, N::WireGuard, N::Tor];
        for (c, expected) in &creds {
            for (k, want) in kinds.iter().zip(expected) {
                let n = net("n", *k, Some("fd00:1:2:3::"));
                assert_eq!(reach(c, &n), *want, "{:?} on {:?}", c.kind, k);
            }
        }
    }

    #[test]
    fn local_on_a_real_interface_takes_grants() {
        let mut local = net("local", NetworkKind::Local, Some("fd00:1:2:3::"));
        local.grants_apply = true;
        let ip = cred(CredentialKind::Ip, "fd00::5/128");
        let suffix = cred(CredentialKind::IpSuffix, "::a:b:c:d");
        let key = cred(CredentialKind::YggKey, KEY);
        assert_eq!(reach(&ip, &local), Reach::IpOnly);
        assert_eq!(reach(&suffix, &local), Reach::IpOnly);
        assert_eq!(reach(&key, &local), Reach::NotReachable);
        assert!(credential_source(&ip, &local).is_some());
        local.prefix = None;
        assert_eq!(reach(&suffix, &local), Reach::NotReachable);
        // Loopback keeps it machine-only.
        local.grants_apply = false;
        assert_eq!(reach(&ip, &local), Reach::NotReachable);
    }

    #[test]
    fn loopback_interface_names() {
        for n in ["lo", "lo0", "Loopback Pseudo-Interface 1"] {
            assert!(is_loopback_interface(n), "{n}");
        }
        for n in ["eth0", "dummy0", "Ethernet", "lo1"] {
            assert!(!is_loopback_interface(n), "{n}");
        }
    }

    #[test]
    fn ip_suffix_needs_a_prefix() {
        let c = cred(CredentialKind::IpSuffix, "::a:b:c:d");
        let lan = net("lan", NetworkKind::Lan, None);
        assert_eq!(reach(&c, &lan), Reach::NotReachable);
        assert_eq!(credential_source(&c, &lan), None);
        let lan = net("lan", NetworkKind::Lan, Some("2001:db8:1:2::"));
        assert_eq!(reach(&c, &lan), Reach::IpOnly);
        assert_eq!(
            credential_source(&c, &lan),
            Some("2001:db8:1:2:a:b:c:d/128".parse().unwrap())
        );
        let moved = net("lan", NetworkKind::Lan, Some("2001:db8:9:9::"));
        assert_eq!(
            credential_source(&c, &moved),
            Some("2001:db8:9:9:a:b:c:d/128".parse().unwrap())
        );
    }

    #[test]
    fn grants_do_not_apply_on_a_network_that_says_so() {
        let mut lan = net("lan", NetworkKind::Lan, None);
        lan.grants_apply = false;
        assert_eq!(
            reach(&cred(CredentialKind::Ip, "fd00::5/128"), &lan),
            Reach::NotReachable
        );
    }

    #[test]
    fn credential_sources() {
        let ygg = net("ygg", NetworkKind::Yggdrasil, None);
        let lan = net("lan", NetworkKind::Lan, None);
        assert_eq!(
            credential_source(&cred(CredentialKind::YggKey, KEY), &ygg),
            Some(
                "200:8af8:ba35:56ae:bef0:6284:981f:5972/128"
                    .parse()
                    .unwrap()
            )
        );
        assert_eq!(
            credential_source(&cred(CredentialKind::YggKey, KEY), &lan),
            None
        );
        assert_eq!(
            credential_source(&cred(CredentialKind::YggSubnet, "300:1:2:3::/64"), &ygg),
            Some("300:1:2:3::/64".parse().unwrap())
        );
        assert_eq!(
            credential_source(&cred(CredentialKind::Ip, "fd00::/48"), &lan),
            Some("fd00::/48".parse().unwrap())
        );
    }

    #[test]
    fn best_reach_prefers_the_strongest_credential() {
        let ygg = net("ygg", NetworkKind::Yggdrasil, None);
        let creds = [
            cred(CredentialKind::YggSubnet, "300:1:2:3::/64"),
            cred(CredentialKind::Ip, "fd00::1/128"),
            cred(CredentialKind::YggKey, KEY),
        ];
        assert_eq!(best_reach(&creds, &ygg), Reach::Verified);
        assert_eq!(best_reach(&creds[..2], &ygg), Reach::WholeSubnet);
        assert_eq!(best_reach(&[], &ygg), Reach::NotReachable);
    }

    #[test]
    fn grant_reach_covers_applicable_networks() {
        let nets = [
            net("local", NetworkKind::Local, None),
            net("lan", NetworkKind::Lan, None),
            net("ygg", NetworkKind::Yggdrasil, None),
        ];
        let creds = [cred(CredentialKind::YggKey, KEY)];
        let r = grant_reach(&Subject::Peer("p".into()), &creds, None, &nets);
        assert_eq!(
            r,
            vec![
                GrantReach {
                    network_id: "lan".into(),
                    reach: Reach::NotReachable
                },
                GrantReach {
                    network_id: "ygg".into(),
                    reach: Reach::Verified
                },
            ]
        );
        let r = grant_reach(&Subject::Anyone, &[], None, &nets);
        assert!(r.iter().all(|g| g.reach == Reach::Open) && r.len() == 2);
        let r = grant_reach(&Subject::Anyone, &[], Some("ygg"), &nets);
        assert_eq!(r.len(), 1);
    }

    fn norm(kind: CredentialKind, v: &str) -> Result<(CredentialKind, String), String> {
        normalize_credential(kind, v).map_err(|e| e.to_string())
    }

    #[test]
    fn ipv4_is_rejected() {
        for k in [
            CredentialKind::Ip,
            CredentialKind::YggAddr,
            CredentialKind::YggSubnet,
        ] {
            let err = norm(k, "192.168.1.5").unwrap_err();
            assert!(err.contains("IPv4"), "{err}");
        }
        assert!(norm(CredentialKind::Ip, "10.0.0.0/8")
            .unwrap_err()
            .contains("IPv4"));
    }

    #[test]
    fn ip_normalization() {
        use CredentialKind::*;
        assert_eq!(norm(Ip, "FD00::5").unwrap(), (Ip, "fd00::5/128".into()));
        assert_eq!(norm(Ip, "fd00::5/128").unwrap(), (Ip, "fd00::5/128".into()));
        assert_eq!(
            norm(Ip, "fd00:1:2::7/48").unwrap(),
            (Ip, "fd00:1:2::/48".into())
        );
        assert!(norm(Ip, "::/0").is_err());
        assert!(norm(Ip, "not an ip").is_err());
    }

    #[test]
    fn ygg_range_values_are_renormalized() {
        use CredentialKind::*;
        // 200::/7 values given as plain Ip become Yggdrasil credentials.
        assert_eq!(norm(Ip, "200:1::5").unwrap(), (YggAddr, "200:1::5".into()));
        assert_eq!(
            norm(Ip, "200:1::5/128").unwrap(),
            (YggAddr, "200:1::5".into())
        );
        assert_eq!(
            norm(Ip, "300:1:2:3::/64").unwrap(),
            (YggSubnet, "300:1:2:3::/64".into())
        );
        assert_eq!(
            norm(Ip, "300:1:2:3::9/64").unwrap(),
            (YggSubnet, "300:1:2:3::/64".into())
        );
        // A host behind a Yggdrasil node is a YggAddr in 300::/8, reached as WholeSubnet.
        let (k, v) = norm(Ip, "300:1:2:3::5").unwrap();
        assert_eq!((k, v.as_str()), (YggAddr, "300:1:2:3::5"));
        let ygg = net("ygg", NetworkKind::Yggdrasil, None);
        assert_eq!(reach(&cred(k, &v), &ygg), Reach::WholeSubnet);
        // Other networks in the range are rejected.
        assert!(norm(Ip, "200::/16").is_err());
        assert!(norm(Ip, "300:1:2::/48").is_err());
        assert!(norm(Ip, "200::/6").is_err());
        // Explicit kinds validate their shape.
        assert!(norm(YggAddr, "fd00::1").is_err());
        assert!(norm(YggAddr, "300:1:2:3::/64").is_err());
        assert!(norm(YggSubnet, "300:1:2:3::5").is_err());
        assert!(norm(YggSubnet, "200:1:2:3::/64").is_err());
        assert_eq!(
            norm(YggSubnet, "300:1:2:3::/64").unwrap(),
            (YggSubnet, "300:1:2:3::/64".into())
        );
    }

    #[test]
    fn ygg_key_normalization() {
        use CredentialKind::*;
        assert_eq!(
            norm(YggKey, &KEY.to_uppercase()).unwrap(),
            (YggKey, KEY.into())
        );
        assert!(norm(YggKey, "abcd").is_err());
        assert!(norm(YggKey, &"zz".repeat(32)).is_err());
    }

    #[test]
    fn ip_suffix_with_and_without_slash_64() {
        use CredentialKind::*;
        assert_eq!(
            norm(IpSuffix, "::a:b:c:d").unwrap(),
            (IpSuffix, "::a:b:c:d".into())
        );
        assert_eq!(
            norm(IpSuffix, "::a:b:c:d/64").unwrap(),
            (IpSuffix, "::a:b:c:d".into())
        );
        assert!(norm(IpSuffix, "::a:b:c:d/48").is_err());
        assert!(norm(IpSuffix, "fd00::1").is_err(), "non-zero upper bits");
        assert!(norm(IpSuffix, "::").is_err());
        assert!(norm(IpSuffix, "10.0.0.1").is_err());
    }

    #[test]
    fn base64_kinds_are_stored() {
        use CredentialKind::*;
        let k = "mFZTRZ0v3m0/yN7Zf3zH1yG2m1pE2n3YhQ5b7kqVQXY=";
        assert_eq!(norm(WgKey, k).unwrap(), (WgKey, k.into()));
        assert!(norm(TlsSpki, "not base64!").is_err());
        assert!(norm(TorClientKey, "").is_err());
    }

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
        assert_eq!(
            "per_port".parse::<AddressMode>().unwrap(),
            AddressMode::PerPort
        );
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

    // ─── App identity ────────────────────────────────────────────────────

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn ident(exe: &str, cmd: &[&str]) -> (AppId, String, Option<String>) {
        let name = file_name(exe).to_string();
        app_identity_on(Platform::Linux, &name, Some(exe), Some(&args(cmd)))
    }

    #[test]
    fn plain_binary_uses_the_process_name() {
        let (id, name, arg) = ident("/usr/sbin/nginx", &["nginx", "-g", "daemon off;"]);
        assert_eq!(name, "nginx");
        assert_eq!(arg, None);
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable: same input, same id, whatever the arguments.
        assert_eq!(id, ident("/usr/sbin/nginx", &["nginx"]).0);
        assert_ne!(id, ident("/usr/sbin/apache2", &["apache2"]).0);
    }

    #[test]
    fn python_scripts_are_separate_apps() {
        let a = ident(
            "/usr/bin/python3.12",
            &["python3", "-u", "/srv/a/server.py", "--port", "1"],
        );
        let b = ident("/usr/bin/python3.12", &["python3", "/srv/b/server.py"]);
        assert_eq!(a.2.as_deref(), Some("/srv/a/server.py"));
        assert_eq!(a.1, "server.py");
        assert_ne!(a.0, b.0);
        // Same script, different options: same app.
        assert_eq!(
            a.0,
            ident("/usr/bin/python3.12", &["python3", "/srv/a/server.py"]).0
        );
        let m = ident(
            "/usr/bin/python3",
            &["python3", "-m", "http.server", "8080"],
        );
        assert_eq!(m.2.as_deref(), Some("http.server"));
        assert_eq!(m.1, "http.server");
        let c = ident("/usr/bin/python3", &["python3", "-c", "print(1)"]);
        assert_eq!(c.2, None);
        assert_eq!(c.1, "python3");
    }

    #[test]
    fn java_jar_and_main_class() {
        let jar = ident(
            "/usr/lib/jvm/bin/java",
            &["java", "-Xmx1g", "-jar", "/opt/app/app.jar", "--x"],
        );
        assert_eq!(jar.2.as_deref(), Some("/opt/app/app.jar"));
        assert_eq!(jar.1, "app.jar");
        let class = ident(
            "/usr/lib/jvm/bin/java",
            &[
                "java",
                "-cp",
                "/lib/a.jar",
                "-Dx=1",
                "com.example.Main",
                "arg",
            ],
        );
        assert_eq!(class.2.as_deref(), Some("com.example.Main"));
        assert_eq!(class.1, "com.example.Main");
        assert_ne!(jar.0, class.0);
    }

    #[test]
    fn svchost_service_argument() {
        let p = Platform::Windows;
        let exe = r"C:\Windows\System32\svchost.exe";
        let dns = app_identity_on(
            p,
            "svchost.exe",
            Some(exe),
            Some(&args(&[
                "svchost.exe",
                "-k",
                "NetworkService",
                "-p",
                "-s",
                "Dnscache",
            ])),
        );
        assert_eq!(dns.2.as_deref(), Some("Dnscache"));
        assert_eq!(dns.1, "Dnscache");
        let other = app_identity_on(
            p,
            "svchost.exe",
            Some(exe),
            Some(&args(&["svchost.exe", "-k", "netsvcs", "-s", "Schedule"])),
        );
        assert_ne!(dns.0, other.0);
        // No -s: one generic svchost app.
        let bare = app_identity_on(
            p,
            "svchost.exe",
            Some(exe),
            Some(&args(&["svchost.exe", "-k", "x"])),
        );
        assert_eq!(bare.2, None);
        assert_eq!(bare.1, "svchost.exe");
    }

    #[test]
    fn dotnet_dll_and_other_hosts() {
        let d = ident(
            "/usr/bin/dotnet",
            &["dotnet", "exec", "/app/Web.dll", "--urls", "x"],
        );
        assert_eq!(d.2.as_deref(), Some("/app/Web.dll"));
        let n = ident("/usr/bin/node", &["node", "--inspect", "server.js"]);
        assert_eq!(n.2.as_deref(), Some("server.js"));
        let deno = ident("/usr/bin/deno", &["deno", "run", "-A", "main.ts"]);
        assert_eq!(deno.2.as_deref(), Some("main.ts"));
        let rb = ident("/usr/bin/ruby", &["ruby", "app.rb"]);
        assert_eq!(rb.2.as_deref(), Some("app.rb"));
        // No cmdline: falls back to the executable alone.
        let none = app_identity_on(Platform::Linux, "node", Some("/usr/bin/node"), None);
        assert_eq!(none.2, None);
    }

    #[test]
    fn windows_paths_are_case_insensitive() {
        let a = app_identity_on(
            Platform::Windows,
            "Python.exe",
            Some(r"C:\Python312\Python.exe"),
            Some(&args(&["python.exe", r"C:\Srv\App.py"])),
        );
        let b = app_identity_on(
            Platform::Windows,
            "python.exe",
            Some(r"c:\python312\python.exe"),
            Some(&args(&["python.exe", r"c:\srv\app.py"])),
        );
        assert_eq!(a.0, b.0);
        // The display name keeps the case it was started with.
        assert_eq!(a.1, "App.py");
        // On Linux, case matters.
        let l1 = app_identity_on(Platform::Linux, "x", Some("/opt/App"), None);
        let l2 = app_identity_on(Platform::Linux, "x", Some("/opt/app"), None);
        assert_ne!(l1.0, l2.0);
    }

    #[test]
    fn linux_deleted_suffix_is_stripped() {
        let a = app_identity_on(Platform::Linux, "nginx", Some("/usr/sbin/nginx"), None);
        let b = app_identity_on(
            Platform::Linux,
            "nginx",
            Some("/usr/sbin/nginx (deleted)"),
            None,
        );
        assert_eq!(a.0, b.0);
        assert_eq!(
            normalize_exe_path("/usr/sbin/nginx (deleted)", Platform::Linux),
            "/usr/sbin/nginx"
        );
        assert_eq!(
            normalize_exe_path(r"C:\Windows\Foo.EXE", Platform::Windows),
            r"c:\windows\foo.exe"
        );
        // A script-hosting interpreter that was upgraded keeps its app.
        let old = ident("/usr/bin/python3.11", &["python3", "/srv/x.py"]);
        let up = app_identity_on(
            Platform::Linux,
            "python3",
            Some("/usr/bin/python3.11 (deleted)"),
            Some(&args(&["python3", "/srv/x.py"])),
        );
        assert_eq!(old.0, up.0);
    }

    #[test]
    fn missing_exe_falls_back_to_process_name() {
        let a = app_identity_on(Platform::Linux, "mystery", None, None);
        let b = app_identity_on(Platform::Linux, "other", None, None);
        assert_ne!(a.0, b.0);
        assert_eq!(a.1, "mystery");
    }

    #[test]
    fn python_version_names() {
        for n in [
            "python",
            "python3",
            "python3.12",
            "pythonw",
            "Python.EXE",
            "python3.12.exe",
        ] {
            assert!(host_of(n).is_some(), "{n}");
        }
        for n in ["pythonista", "python-config", "nodejs"] {
            assert!(host_of(n).is_none(), "{n}");
        }
    }
}
