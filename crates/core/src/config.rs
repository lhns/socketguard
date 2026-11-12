use crate::types::BackendType;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Per-backend configuration. An unknown key is an error, so a stale config fails loudly.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum BackendConfig {
    Ula {
        /// Network interface (defaults to loopback)
        #[serde(default = "default_loopback")]
        interface: String,
    },
    /// SocketGuard's own Yggdrasil node (ADR 0052, 0056). Its interface is found at
    /// runtime (ADR 0048).
    Yggdrasil {
        /// Peers to connect to, as URIs (`tls://host:port`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        peers: Vec<String>,
    },
    Slaac {
        /// Physical network interface connected to the router
        interface: String,
        /// IPv6 prefix to use. None or "auto" = discover from interface.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    Dhcpv6 {
        /// Physical network interface connected to the router with DHCPv6 server
        interface: String,
    },
    /// Onion services through SocketGuard's own Tor (ADR 0037, 0052, 0056). The control
    /// endpoint and cookie are chosen by the daemon.
    Tor {
        /// obfs4 bridge lines, in canonical form (see `bridge`); empty (the default)
        /// connects directly.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        bridges: Vec<String>,
    },
}

impl BackendConfig {
    /// The Tor network (ADR 0052): nothing to configure.
    pub fn tor() -> Self {
        BackendConfig::Tor { bridges: vec![] }
    }

    /// The Yggdrasil network (ADR 0052) with `peers`.
    pub fn yggdrasil(peers: Vec<String>) -> Self {
        BackendConfig::Yggdrasil { peers }
    }

    /// SocketGuard runs this network's software itself as a child process (Tor, Yggdrasil).
    pub fn runs_child(&self) -> bool {
        matches!(
            self,
            BackendConfig::Tor { .. } | BackendConfig::Yggdrasil { .. }
        )
    }

    /// The bridge lines of a Tor network; empty otherwise.
    pub fn bridges(&self) -> &[String] {
        match self {
            BackendConfig::Tor { bridges } => bridges,
            _ => &[],
        }
    }

    /// The peers of a Yggdrasil network; empty otherwise.
    pub fn peers(&self) -> &[String] {
        match self {
            BackendConfig::Yggdrasil { peers } => peers,
            _ => &[],
        }
    }

    /// Whether the settings are consistent: every Tor bridge is a valid line and every
    /// Yggdrasil peer a URI, none twice.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            BackendConfig::Tor { bridges } => {
                // The torrc is written from the canonical form, whatever the file holds.
                crate::bridge::normalize_bridges(bridges)?;
                Ok(())
            }
            BackendConfig::Yggdrasil { peers } => {
                let mut seen = HashSet::new();
                for p in peers {
                    valid_peer_uri(p)?;
                    if !seen.insert(p) {
                        return Err(format!("peer {p} is listed twice"));
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// The URI schemes Yggdrasil accepts for a peer.
const PEER_SCHEMES: &[&str] = &["tcp", "tls", "quic", "ws", "wss", "socks", "sockstls"];

/// Check that `uri` looks like a Yggdrasil peer (`tls://host:port`, `tcp://[::1]:1234`):
/// a known scheme, a host and a port, and only characters that stay data when written
/// to a configuration file.
pub fn valid_peer_uri(uri: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("invalid peer {uri:?}: {why}"));
    if uri.len() > 255 {
        return bad("too long");
    }
    if !uri
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~:/?&=%[]@+,".contains(&b))
    {
        return bad("unexpected character");
    }
    let Some((scheme, rest)) = uri.split_once("://") else {
        return bad("expected scheme://host:port");
    };
    if !PEER_SCHEMES.contains(&scheme) {
        return bad("scheme must be one of tcp, tls, quic, ws, wss, socks, sockstls");
    }
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let authority = authority.rsplit('@').next().unwrap_or_default();
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let Some((h, p)) = v6.split_once("]:") else {
            return bad("expected [address]:port");
        };
        (h, p)
    } else {
        match authority.rsplit_once(':') {
            Some(hp) => hp,
            None => return bad("the port is missing"),
        }
    };
    if host.is_empty() {
        return bad("the host is missing");
    }
    if port.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
        return bad("the port must be a number from 1 to 65535");
    }
    Ok(())
}

impl Default for BackendConfig {
    fn default() -> Self {
        BackendConfig::Ula {
            interface: default_loopback(),
        }
    }
}

impl BackendConfig {
    /// Get the backend type
    pub fn backend_type(&self) -> BackendType {
        match self {
            BackendConfig::Ula { .. } => BackendType::Ula,
            BackendConfig::Yggdrasil { .. } => BackendType::Yggdrasil,
            BackendConfig::Slaac { .. } => BackendType::Slaac,
            BackendConfig::Dhcpv6 { .. } => BackendType::Dhcpv6,
            BackendConfig::Tor { .. } => BackendType::Tor,
        }
    }

    /// The network interface; None for networks without one (Tor, Yggdrasil: found at runtime).
    pub fn interface(&self) -> Option<&str> {
        match self {
            BackendConfig::Ula { interface } => Some(interface),
            BackendConfig::Slaac { interface, .. } => Some(interface),
            BackendConfig::Dhcpv6 { interface } => Some(interface),
            BackendConfig::Yggdrasil { .. } | BackendConfig::Tor { .. } => None,
        }
    }

    /// Whether this backend type is a singleton (at most one instance allowed)
    pub fn is_singleton(&self) -> bool {
        matches!(
            self,
            BackendConfig::Ula { .. } | BackendConfig::Yggdrasil { .. } | BackendConfig::Tor { .. }
        )
    }

    /// Generate a default instance ID from the backend type and interface
    pub fn default_id(&self) -> String {
        if self.is_singleton() {
            self.backend_type().to_string()
        } else {
            format!(
                "{}-{}",
                self.backend_type(),
                self.interface().unwrap_or_default()
            )
        }
    }
}

/// A backend instance with a stable ID. On input the `id` is optional and defaults to
/// [`BackendConfig::default_id`]; an unknown key is an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackendInstanceConfig {
    pub id: String,
    #[serde(flatten)]
    pub backend: BackendConfig,
}

/// Read through a generic value: `deny_unknown_fields` (on [`BackendConfig`], which owns the
/// other keys) cannot be combined with a flattened `id`.
impl<'de> Deserialize<'de> for BackendInstanceConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let serde_json::Value::Object(mut map) = serde_json::Value::deserialize(deserializer)?
        else {
            return Err(D::Error::custom("a backend must be an object"));
        };
        let id = match map.remove("id") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(s)) => Some(s),
            Some(_) => return Err(D::Error::custom("a backend's id must be a string")),
        };
        let backend =
            BackendConfig::deserialize(serde_json::Value::Object(map)).map_err(D::Error::custom)?;
        let id = id
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| backend.default_id());
        Ok(Self { id, backend })
    }
}

/// Process filter mode
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterMode {
    Allowlist,
    #[default]
    Denylist,
}

/// Process filter: controls which processes get IPv6 addresses assigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessFilter {
    #[serde(default)]
    pub mode: FilterMode,
    #[serde(default)]
    pub patterns: Vec<String>,
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self {
            mode: FilterMode::Denylist,
            patterns: Vec::new(),
        }
    }
}

impl ProcessFilter {
    /// Check if a process name is allowed by this filter.
    pub fn matches(&self, process_name: &str) -> bool {
        match self.mode {
            FilterMode::Denylist => {
                if self.patterns.is_empty() {
                    return true; // empty denylist = allow all
                }
                // Denied if any pattern matches
                !self.patterns.iter().any(|p| glob_match(p, process_name))
            }
            FilterMode::Allowlist => {
                if self.patterns.is_empty() {
                    return false; // empty allowlist = allow none
                }
                // Allowed if any pattern matches
                self.patterns.iter().any(|p| glob_match(p, process_name))
            }
        }
    }
}

/// Simple case-insensitive wildcard glob matcher: `*` matches any run of characters
/// (also none), `?` exactly one.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let text = text.to_lowercase();
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();

    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);

    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == txt[ti] || pat[pi] == '?') {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Daemon configuration
///
/// Backends are `{ "backends": [{ "id": "ula", "type": "ula" }, ...] }`. Without them,
/// one ULA backend on the loopback interface.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonConfig {
    /// Unix socket of the local API (ADR 0032). Ignored on Windows.
    pub api_socket: String,

    /// Named pipe of the local API on Windows (ADR 0032). Ignored elsewhere.
    pub api_pipe: String,

    /// Backend instances
    pub backends: Vec<BackendInstanceConfig>,

    /// Socket polling interval in seconds
    pub poll_interval_secs: u64,

    /// Path to the SQLite database: absolute, or relative to the config file's directory.
    /// Empty: `socketguard.db` in the default state directory (ADR 0050).
    pub db_path: String,

    /// Log level: trace, debug, info, warn, error
    pub log_level: String,

    /// Process filter (allowlist/denylist)
    #[serde(default)]
    pub process_filter: ProcessFilter,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let default_backend = BackendConfig::default();
        let id = default_backend.default_id();
        Self {
            api_socket: default_api_socket(),
            api_pipe: default_api_pipe(),
            backends: vec![BackendInstanceConfig {
                id,
                backend: default_backend,
            }],
            poll_interval_secs: default_poll_interval(),
            db_path: default_db_path(),
            log_level: default_log_level(),
            process_filter: ProcessFilter::default(),
        }
    }
}

impl DaemonConfig {
    /// Validate the backends list.
    pub fn validate_backends(backends: &[BackendInstanceConfig]) -> Result<(), String> {
        let mut ids = HashSet::new();
        let mut ula_count = 0u32;
        let mut ygg_count = 0u32;
        let mut tor_count = 0u32;

        for inst in backends {
            if !ids.insert(&inst.id) {
                return Err(format!("duplicate backend instance ID: '{}'", inst.id));
            }
            match inst.backend.backend_type() {
                BackendType::Ula => {
                    ula_count += 1;
                    if ula_count > 1 {
                        return Err("at most one ULA backend instance is allowed".into());
                    }
                }
                BackendType::Yggdrasil => {
                    ygg_count += 1;
                    if ygg_count > 1 {
                        return Err("at most one Yggdrasil backend instance is allowed".into());
                    }
                }
                BackendType::Tor => {
                    tor_count += 1;
                    if tor_count > 1 {
                        return Err("at most one Tor backend instance is allowed".into());
                    }
                }
                _ => {}
            }
            inst.backend
                .validate()
                .map_err(|e| format!("backend '{}': {e}", inst.id))?;
            if let Some(iface) = inst.backend.interface() {
                if iface.is_empty() {
                    return Err(format!(
                        "backend '{}': interface must not be empty",
                        inst.id
                    ));
                }
                if !valid_interface_name(iface) {
                    return Err(format!(
                        "backend '{}': invalid interface name {iface:?} (allowed: letters, digits, '.', '_', '-' and space, at most {MAX_INTERFACE_NAME} characters)",
                        inst.id
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Longest accepted interface name.
pub const MAX_INTERFACE_NAME: usize = 64;

/// Whether `name` may be used as a network interface name. Names end up inside firewall
/// scripts (nft, pf), so only `[A-Za-z0-9._-]` and the spaces and parentheses of Windows
/// aliases ("Ethernet 2", "vEthernet (WSL)") are allowed: no quotes, backslashes, newlines or other control
/// characters. One validator for config, API, settings and the renderers.
pub fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_INTERFACE_NAME
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b' ' | b'(' | b')')
        })
}

/// The loopback interface of this platform.
pub fn default_loopback() -> String {
    if cfg!(target_os = "linux") {
        "lo".to_string()
    } else if cfg!(target_os = "macos") {
        "lo0".to_string()
    } else {
        "Loopback Pseudo-Interface 1".to_string()
    }
}

/// Custom deserializer: validates the backends.
impl<'de> Deserialize<'de> for DaemonConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawConfig {
            #[serde(default = "default_api_socket")]
            api_socket: String,
            #[serde(default = "default_api_pipe")]
            api_pipe: String,
            #[serde(default)]
            backends: Option<Vec<BackendInstanceConfig>>,
            #[serde(default = "default_poll_interval")]
            poll_interval_secs: u64,
            #[serde(default = "default_db_path")]
            db_path: String,
            #[serde(default = "default_log_level")]
            log_level: String,
            #[serde(default)]
            process_filter: ProcessFilter,
        }

        let raw = RawConfig::deserialize(deserializer)?;

        let backends = raw
            .backends
            .unwrap_or_else(|| DaemonConfig::default().backends);

        DaemonConfig::validate_backends(&backends).map_err(serde::de::Error::custom)?;

        Ok(DaemonConfig {
            api_socket: raw.api_socket,
            api_pipe: raw.api_pipe,
            backends,
            poll_interval_secs: raw.poll_interval_secs,
            db_path: raw.db_path,
            log_level: raw.log_level,
            process_filter: raw.process_filter,
        })
    }
}

/// Default path of the API socket on macOS, which has no `/run` (the root volume is read-only,
/// so the daemon could not create it): `/var/run` is the writable equivalent.
pub const API_SOCKET_MACOS: &str = "/var/run/socketguard.sock";
/// Default path of the API socket on Linux.
pub const API_SOCKET_LINUX: &str = "/run/socketguard.sock";
/// Default path of the API socket on this Unix.
#[cfg(target_os = "macos")]
pub const DEFAULT_API_SOCKET: &str = API_SOCKET_MACOS;
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_API_SOCKET: &str = API_SOCKET_LINUX;

/// Default name of the API pipe on Windows.
pub const DEFAULT_API_PIPE: &str = r"\\.\pipe\socketguard";

fn default_api_socket() -> String {
    DEFAULT_API_SOCKET.to_string()
}

fn default_api_pipe() -> String {
    DEFAULT_API_PIPE.to_string()
}

fn default_poll_interval() -> u64 {
    2
}

/// Empty: the database is in the fixed place (ADR 0050); see `paths::resolve_db_path`.
fn default_db_path() -> String {
    String::new()
}

fn default_log_level() -> String {
    "info".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names_are_validated() {
        for ok in [
            "eth0",
            "ygg0",
            "Ethernet 2",
            "br-lan.100",
            "lo",
            "Loopback Pseudo-Interface 1",
            "vEthernet (WSL)",
        ] {
            assert!(valid_interface_name(ok), "{ok}");
        }
        for bad in [
            "",
            "eth0\"; drop",
            "a\nb",
            "a\rb",
            "eth0\" counter drop #",
            r"a\b",
            "a;b",
            "a{b}",
            "a#b",
            "a\0b",
            "a\tb",
            "ethé",
            &"x".repeat(65),
        ] {
            assert!(!valid_interface_name(bad), "{bad:?}");
        }
        assert!(valid_interface_name(&"x".repeat(64)));
    }

    #[test]
    fn hostile_interface_is_rejected_on_load() {
        let json = r#"{"backends":[{"type":"slaac","interface":"eth0\"\n flush ruleset"}]}"#;
        assert!(serde_json::from_str::<DaemonConfig>(json).is_err());
    }

    #[test]
    fn backend_id_is_optional_on_input() {
        let config: DaemonConfig =
            serde_json::from_str(r#"{"backends":[{"type":"ula"}]}"#).unwrap();
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.backends[0].id, "ula");

        let config: DaemonConfig = serde_json::from_str(
            r#"{"backends":[{"type":"slaac","interface":"eth0"},{"id":"mine","type":"dhcpv6","interface":"eth1"}]}"#,
        )
        .unwrap();
        assert_eq!(config.backends[0].id, "slaac-eth0");
        assert_eq!(config.backends[1].id, "mine");

        let inst: BackendInstanceConfig = serde_json::from_str(r#"{"type":"yggdrasil"}"#).unwrap();
        assert_eq!(inst.id, "yggdrasil");
    }

    #[test]
    fn default_config_has_sane_values() {
        let config = DaemonConfig::default();
        assert_eq!(config.api_socket, DEFAULT_API_SOCKET);
        assert_eq!(config.api_pipe, DEFAULT_API_PIPE);
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.backends[0].backend.backend_type(), BackendType::Ula);
        assert_eq!(config.poll_interval_secs, 2);
        assert_eq!(config.db_path, "");
        assert_eq!(config.log_level, "info");
        assert!(!config.backends[0].backend.interface().unwrap().is_empty());
    }

    #[test]
    fn config_deserialize_multi_backend() {
        let json = r#"{
            "backends": [
                {"id": "ula", "type": "ula"},
                {"id": "slaac-eth", "type": "slaac", "interface": "Ethernet"}
            ]
        }"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backends.len(), 2);
        assert_eq!(config.backends[0].id, "ula");
        assert_eq!(config.backends[0].backend.backend_type(), BackendType::Ula);
        assert_eq!(config.backends[1].id, "slaac-eth");
        assert_eq!(
            config.backends[1].backend.backend_type(),
            BackendType::Slaac
        );
        assert_eq!(config.backends[1].backend.interface(), Some("Ethernet"));
    }

    #[test]
    fn config_deserialize_empty() {
        let json = r#"{}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backends[0].backend.backend_type(), BackendType::Ula);
        assert_eq!(config.api_socket, DEFAULT_API_SOCKET);
    }

    #[test]
    fn config_serialize_roundtrip() {
        let config = DaemonConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.api_socket, config.api_socket);
        assert_eq!(parsed.api_pipe, config.api_pipe);
        assert_eq!(parsed.backends.len(), config.backends.len());
        assert_eq!(
            parsed.backends[0].backend.backend_type(),
            config.backends[0].backend.backend_type()
        );
        assert_eq!(parsed.poll_interval_secs, config.poll_interval_secs);
    }

    #[test]
    fn config_rejects_duplicate_ids() {
        let json = r#"{
            "backends": [
                {"id": "ula", "type": "ula"},
                {"id": "ula", "type": "slaac", "interface": "Ethernet"}
            ]
        }"#;
        let result: Result<DaemonConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn config_rejects_two_ula_instances() {
        let result = DaemonConfig::validate_backends(&[
            BackendInstanceConfig {
                id: "ula1".into(),
                backend: BackendConfig::Ula {
                    interface: "lo".into(),
                },
            },
            BackendInstanceConfig {
                id: "ula2".into(),
                backend: BackendConfig::Ula {
                    interface: "lo".into(),
                },
            },
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ULA"));
    }

    #[test]
    fn config_allows_two_slaac_instances() {
        let result = DaemonConfig::validate_backends(&[
            BackendInstanceConfig {
                id: "slaac-eth".into(),
                backend: BackendConfig::Slaac {
                    interface: "Ethernet".into(),
                    prefix: None,
                },
            },
            BackendInstanceConfig {
                id: "slaac-wifi".into(),
                backend: BackendConfig::Slaac {
                    interface: "Wi-Fi".into(),
                    prefix: None,
                },
            },
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn config_slaac_auto_prefix() {
        let json = r#"{"backends": [{"type": "slaac", "interface": "eth0"}]}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        match &config.backends[0].backend {
            BackendConfig::Slaac { prefix, .. } => assert!(prefix.is_none()),
            _ => panic!("expected Slaac"),
        }
    }

    #[test]
    fn config_deserialize_dhcpv6() {
        let json = r#"{"backends": [{"type": "dhcpv6", "interface": "Ethernet"}]}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.backends[0].backend.backend_type(),
            BackendType::Dhcpv6
        );
        assert_eq!(config.backends[0].backend.interface(), Some("Ethernet"));
    }

    #[test]
    fn backend_config_interface() {
        let ula = BackendConfig::Ula {
            interface: "lo".to_string(),
        };
        assert_eq!(ula.interface(), Some("lo"));

        let ygg = BackendConfig::yggdrasil(vec![]);
        assert_eq!(ygg.interface(), None);

        let slaac = BackendConfig::Slaac {
            interface: "eth0".to_string(),
            prefix: None,
        };
        assert_eq!(slaac.interface(), Some("eth0"));

        let tor = BackendConfig::tor();
        assert_eq!(tor.interface(), None);
        assert!(tor.is_singleton());
        assert_eq!(tor.default_id(), "tor");
    }

    #[test]
    fn tor_backend_config_roundtrip() {
        let defaults: BackendInstanceConfig = serde_json::from_str(r#"{"type":"tor"}"#).unwrap();
        assert_eq!(defaults.id, "tor");
        assert_eq!(defaults.backend, BackendConfig::tor());
        let inst = BackendInstanceConfig {
            id: "tor".into(),
            backend: BackendConfig::tor(),
        };
        let json = serde_json::to_string(&inst).unwrap();
        assert_eq!(json, r#"{"id":"tor","type":"tor"}"#);
        assert_eq!(
            serde_json::from_str::<BackendInstanceConfig>(&json).unwrap(),
            inst
        );
    }

    #[test]
    fn at_most_one_tor_backend() {
        let tor = |id: &str| BackendInstanceConfig {
            id: id.into(),
            backend: BackendConfig::tor(),
        };
        assert!(DaemonConfig::validate_backends(&[tor("tor")]).is_ok());
        let err = DaemonConfig::validate_backends(&[tor("a"), tor("b")]).unwrap_err();
        assert!(err.starts_with("at most one"), "{err}");
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("svchost*", "svchost.exe"));
        assert!(glob_match("svchost*", "svchost"));
        assert!(glob_match("*host*", "svchost.exe"));
        assert!(glob_match("System", "System"));
        assert!(glob_match("system", "System")); // case-insensitive
        assert!(glob_match("SYSTEM", "system"));
        assert!(!glob_match("svchost", "svchost.exe"));
        assert!(!glob_match("nginx", "svchost"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.*", "svc.exe"));
        assert!(!glob_match("*.*", "svchost"));
        assert!(glob_match("OneDrive*", "OneDrive.exe"));
    }

    #[test]
    fn process_filter_denylist_empty_allows_all() {
        let f = ProcessFilter::default();
        assert!(f.matches("nginx"));
        assert!(f.matches("svchost.exe"));
    }

    #[test]
    fn process_filter_denylist_blocks_matched() {
        let f = ProcessFilter {
            mode: FilterMode::Denylist,
            patterns: vec!["svchost*".into(), "System".into()],
        };
        assert!(!f.matches("svchost.exe"));
        assert!(!f.matches("System"));
        assert!(f.matches("nginx"));
    }

    #[test]
    fn process_filter_allowlist_empty_blocks_all() {
        let f = ProcessFilter {
            mode: FilterMode::Allowlist,
            patterns: vec![],
        };
        assert!(!f.matches("nginx"));
    }

    #[test]
    fn process_filter_allowlist_allows_matched() {
        let f = ProcessFilter {
            mode: FilterMode::Allowlist,
            patterns: vec!["nginx".into(), "httpd*".into()],
        };
        assert!(f.matches("nginx"));
        assert!(f.matches("httpd.exe"));
        assert!(!f.matches("svchost.exe"));
    }

    #[test]
    fn process_filter_serialization() {
        let f = ProcessFilter {
            mode: FilterMode::Allowlist,
            patterns: vec!["nginx".into()],
        };
        let json = serde_json::to_string(&f).unwrap();
        let parsed: ProcessFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(f, parsed);
    }

    #[test]
    fn config_with_process_filter() {
        let json = r#"{
            "process_filter": {
                "mode": "denylist",
                "patterns": ["svchost*", "System"]
            }
        }"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.process_filter.mode, FilterMode::Denylist);
        assert_eq!(config.process_filter.patterns.len(), 2);
        assert!(!config.process_filter.matches("svchost.exe"));
        assert!(config.process_filter.matches("nginx"));
    }

    #[test]
    fn config_without_process_filter_defaults() {
        let json = r#"{}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.process_filter.mode, FilterMode::Denylist);
        assert!(config.process_filter.patterns.is_empty());
        assert!(config.process_filter.matches("anything"));
    }

    #[test]
    fn backend_default_id() {
        assert_eq!(
            BackendConfig::Ula {
                interface: "lo".into()
            }
            .default_id(),
            "ula"
        );
        assert_eq!(BackendConfig::yggdrasil(vec![]).default_id(), "yggdrasil");
        assert_eq!(
            BackendConfig::Slaac {
                interface: "Ethernet".into(),
                prefix: None
            }
            .default_id(),
            "slaac-Ethernet"
        );
        assert_eq!(
            BackendConfig::Dhcpv6 {
                interface: "eth0".into()
            }
            .default_id(),
            "dhcpv6-eth0"
        );
    }

    #[test]
    fn peers_are_checked() {
        let ok: BackendInstanceConfig = serde_json::from_str(
            r#"{"type":"yggdrasil","peers":["tls://example.org:1234","tcp://[2001:db8::1]:9"]}"#,
        )
        .unwrap();
        assert_eq!(ok.id, "yggdrasil");
        assert_eq!(ok.backend.validate(), Ok(()));
        assert!(BackendConfig::tor().validate().is_ok());

        let bad = |json: &str| {
            let inst: BackendInstanceConfig = serde_json::from_str(json).unwrap();
            DaemonConfig::validate_backends(&[inst]).unwrap_err()
        };
        bad(r#"{"type":"yggdrasil","peers":["tls://a.b:1","tls://a.b:1"]}"#);
        bad(r#"{"type":"yggdrasil","peers":["http://a.b:1"]}"#);
    }

    #[test]
    fn bridges_must_be_bridge_lines() {
        let line = "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iat-mode=0";
        let check = |b: &str| {
            let inst: BackendInstanceConfig =
                serde_json::from_str(&format!(r#"{{"type":"tor","bridges":[{b}]}}"#)).unwrap();
            DaemonConfig::validate_backends(&[inst])
        };
        assert!(check(&format!("{line:?}")).is_ok());
        // Empty is the default and is not written.
        assert!(BackendConfig::tor().bridges().is_empty());
        assert!(!serde_json::to_string(&BackendConfig::tor())
            .unwrap()
            .contains("bridges"));
        assert!(check(r#""snowflake 192.0.2.3:80""#).is_err());
        assert!(check(r#""obfs4 1.2.3.4:5\nSocksPort 1""#).is_err());
    }

    #[test]
    fn peer_uris_are_checked() {
        for ok in [
            "tls://example.org:1234",
            "tcp://1.2.3.4:5",
            "tcp://[2001:db8::1]:9",
            "quic://host.name:443?key=abcdef",
            "ws://h:80/path",
        ] {
            assert_eq!(valid_peer_uri(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "example.org:1234",
            "http://example.org:80",
            "tls://example.org",
            "tls://:1234",
            "tls://h:0",
            "tls://h:70000",
            "tls://h:1 ",
            "tls://h:1\n\"x\"",
            "tls://h:1\",\"y",
            "tcp://[::1]",
        ] {
            assert!(valid_peer_uri(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unknown_keys_are_refused_and_named() {
        let err = |json: &str| {
            serde_json::from_str::<DaemonConfig>(json)
                .unwrap_err()
                .to_string()
        };
        // Top level.
        let e = err(r#"{"backend":"ula"}"#);
        assert!(e.contains("backend"), "{e}");
        // A backend: the keys of the removed own/existing distinction and of existing nodes.
        for key in [
            "managed",
            "control",
            "auth",
            "cookie_path",
            "interface",
            "admin_endpoint",
        ] {
            let tor = format!(r#"{{"backends":[{{"type":"tor","{key}":"x"}}]}}"#);
            let e = err(&tor);
            assert!(e.contains(key), "{key}: {e}");
        }
        let e = err(r#"{"backends":[{"type":"yggdrasil","managed":true}]}"#);
        assert!(e.contains("managed"), "{e}");
        // The process filter.
        let e = err(r#"{"process_filter":{"mode":"denylist","pattern":[]}}"#);
        assert!(e.contains("pattern"), "{e}");
        // The same keys are fine where they belong.
        serde_json::from_str::<DaemonConfig>(
            r#"{"backends":[{"type":"slaac","interface":"eth0","prefix":"auto"}],"log_level":"debug"}"#,
        )
        .unwrap();
    }
}
