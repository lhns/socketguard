//! The domain model (ADR 0027, 0028, 0037): apps, networks, addresses, peers, credentials
//! and grants, plus the pure functions that work on them: credential normalization, the
//! reach table and app identity.

use crate::types::Protocol;
use crate::yggdrasil::derive_yggdrasil_ipv6;
use chrono::{DateTime, Utc};
use ipnet::{IpNet, Ipv6Net};
use serde::{Deserialize, Serialize};
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
    /// Why the identity is special (inline code, unrecognized arguments, no executable
    /// path, foreign mount namespace), for the frontends; None for an ordinary app.
    #[serde(default)]
    pub identity_note: Option<String>,
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
    GroupAdded,
    GroupChanged,
    GroupRemoved,
    ProtectHostChanged,
    Blocked,
    RemoteAdminExposed,
}

impl ActivityKind {
    pub const ALL: [ActivityKind; 13] = [
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
/// - `TorClientKey`: an x25519 public key in base32 (52 characters), or a full
///   `descriptor:x25519:<base32>` authorized_clients line; stored as the bare key,
///   uppercase.
/// - `WgKey`, `TlsSpki`: base64, stored as given.
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
        CredentialKind::TorClientKey => normalize_tor_key(value).map(|k| (kind, k)),
        CredentialKind::WgKey | CredentialKind::TlsSpki => {
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
            // A plain IP network must not contain the Yggdrasil range (`::/6`, `::/0`): it
            // would trust overlay sources without the interface binding. Networks inside
            // the range are normalized as Yggdrasil values below.
            if kind == CredentialKind::Ip && !in_ygg && net.contains(&ygg_range()) {
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

/// The x25519 points of small order (RFC 7748 / libsodium blocklist) in canonical and
/// non-canonical form, with the unused top bit cleared. A client key like these gives a
/// shared secret an observer can guess, so an authorization with it protects nothing.
const SMALL_ORDER: [[u8; 32]; 7] = [
    [0; 32],
    {
        let mut k = [0; 32];
        k[0] = 1;
        k
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    p_plus(0xec),
    p_plus(0xed),
    p_plus(0xee),
];

/// A value just below 2^255 (p-1, p, p+1 with p = 2^255 - 19), as little-endian bytes, by
/// its lowest byte.
const fn p_plus(low: u8) -> [u8; 32] {
    let mut k = [0xff; 32];
    k[0] = low;
    k[31] = 0x7f;
    k
}

/// 52 base32 characters (RFC 4648, no padding) as the 32 bytes they encode.
fn decode_tor_key(key: &str) -> Option<[u8; 32]> {
    let (mut out, mut n) = ([0u8; 32], 0usize);
    let (mut buf, mut bits) = (0u32, 0u32);
    for b in key.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if n == 32 {
                return None;
            }
            out[n] = (buf >> bits) as u8;
            n += 1;
        }
    }
    (n == 32).then_some(out)
}

/// Whether `key` is a Tor v3 client-auth public key: 52 base32 characters (no padding)
/// encoding 32 bytes, so the last character carries no extra bits, and not a small-order
/// point.
fn is_tor_key(key: &str) -> bool {
    let well_formed = key.len() == 52
        && key.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
        && matches!(key.as_bytes()[51], b'A' | b'Q');
    let Some(mut point) = well_formed.then(|| decode_tor_key(key)).flatten() else {
        return false;
    };
    point[31] &= 0x7f;
    !SMALL_ORDER.contains(&point)
}

fn normalize_tor_key(value: &str) -> Result<String, CredentialError> {
    let bare = match value.rsplit_once(':') {
        Some((prefix, key)) => {
            if !prefix.eq_ignore_ascii_case("descriptor:x25519") {
                return invalid(
                    "a Tor client key is 52 base32 characters, or a line like \
                     descriptor:x25519:<key> from authorized_clients",
                );
            }
            key
        }
        None => value,
    };
    let key = bare.to_ascii_uppercase();
    if is_tor_key(&key) {
        Ok(key)
    } else {
        invalid("a Tor client key is a public key in base32 (52 characters)")
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
        // Tor authorizes each client by its key (ClientAuthV3).
        (CredentialKind::TorClientKey, NetworkKind::Tor) if is_tor_key(&credential.value) => {
            Reach::Verified
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

    const TOR_KEY: &str = "ZGBMJ4VIRNVUOQ5SJ2JXPSSWHB2R4YGTKPDGSMZ4HWCD5WLT2YKQ";

    const KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";

    #[test]
    fn reach_table_every_cell() {
        use CredentialKind as C;
        use NetworkKind as N;
        use Reach::*;
        let creds: [(Credential, [Reach; 5]); 10] = [
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
            (
                cred(C::TorClientKey, TOR_KEY),
                [
                    NotReachable,
                    NotReachable,
                    NotReachable,
                    NotReachable,
                    Verified,
                ],
            ),
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
        // Networks that contain the range (`::/6`, `::/1`, `::/0`) must not pass as plain IP.
        for wide in ["::/6", "::/1", "::/0", "::/3", "200::/6"] {
            assert!(norm(Ip, wide).is_err(), "{wide}");
        }
        assert!(norm(Ip, "2001:db8::/32").is_ok());
        assert!(norm(Ip, "fc00::/7").is_ok());
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
    fn small_order_tor_keys_are_refused() {
        use CredentialKind::TorClientKey;
        for key in [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "4DVXU7B3IG4K4FSW4P5PDH6ENLNATDPLTQZLD7MGMICRMX2JXAAA",
            "L6OJLPFDKCGCJMOQWFKZZA7PLMCEIXGELAOI5BWYEJHN3UE7CFLQ",
            "5T7777777777777777777777777777777777777777777777757Q",
            "5X7777777777777777777777777777777777777777777777757Q",
            "537777777777777777777777777777777777777777777777757Q",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAA",
        ] {
            assert!(norm(TorClientKey, key).is_err(), "{key}");
        }
    }

    #[test]
    fn tor_client_keys_normalize() {
        use CredentialKind::TorClientKey;
        let want = (TorClientKey, TOR_KEY.to_string());
        assert_eq!(norm(TorClientKey, TOR_KEY).unwrap(), want);
        assert_eq!(norm(TorClientKey, &TOR_KEY.to_lowercase()).unwrap(), want);
        let line = format!("descriptor:x25519:{TOR_KEY}");
        assert_eq!(norm(TorClientKey, &line).unwrap(), want);
        assert_eq!(
            norm(TorClientKey, &format!(" {} ", line.to_lowercase())).unwrap(),
            want
        );
        // Wrong length, characters or trailing bits.
        assert!(norm(TorClientKey, &TOR_KEY[1..]).is_err());
        assert!(norm(TorClientKey, &format!("{TOR_KEY}A")).is_err());
        assert!(norm(TorClientKey, &format!("{}1", &TOR_KEY[..51])).is_err());
        assert!(norm(TorClientKey, &format!("{}B", &TOR_KEY[..51])).is_err());
        // A client's private-key line carries the onion name first.
        assert!(norm(TorClientKey, &format!("abc:descriptor:x25519:{TOR_KEY}")).is_err());
        assert!(norm(TorClientKey, &format!("other:{TOR_KEY}")).is_err());
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
}
