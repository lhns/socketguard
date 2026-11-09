use crate::types::BackendType;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Per-backend configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BackendConfig {
    Ula {
        /// Network interface (defaults to loopback)
        #[serde(default = "default_loopback")]
        interface: String,
    },
    Yggdrasil {
        /// Network interface (e.g. Yggdrasil TUN)
        interface: String,
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
        }
    }

    /// Get the network interface
    pub fn interface(&self) -> &str {
        match self {
            BackendConfig::Ula { interface } => interface,
            BackendConfig::Yggdrasil { interface } => interface,
            BackendConfig::Slaac { interface, .. } => interface,
            BackendConfig::Dhcpv6 { interface } => interface,
        }
    }

    /// Whether this backend type is a singleton (at most one instance allowed)
    pub fn is_singleton(&self) -> bool {
        matches!(
            self,
            BackendConfig::Ula { .. } | BackendConfig::Yggdrasil { .. }
        )
    }

    /// Generate a default instance ID from the backend type and interface
    pub fn default_id(&self) -> String {
        if self.is_singleton() {
            self.backend_type().to_string()
        } else {
            format!("{}-{}", self.backend_type(), self.interface())
        }
    }
}

/// A backend instance with a stable ID
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendInstanceConfig {
    pub id: String,
    #[serde(flatten)]
    pub backend: BackendConfig,
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

/// Simple case-insensitive wildcard glob matcher supporting `*`.
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
/// Supports three JSON formats:
/// - Multi-backend: `{ "backends": [{ "id": "ula", "type": "ula" }, ...] }`
/// - Single backend (object): `{ "backend": { "type": "slaac", "interface": "Ethernet" }, ... }`
/// - Legacy: `{ "backend": "ula", "interface": "lo", ... }`
#[derive(Debug, Clone, Serialize)]
pub struct DaemonConfig {
    /// REST API listen address
    pub listen_addr: String,

    /// REST API listen port
    pub listen_port: u16,

    /// Backend instances
    pub backends: Vec<BackendInstanceConfig>,

    /// Socket polling interval in seconds
    pub poll_interval_secs: u64,

    /// Path to SQLite database
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
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 9476,
            backends: vec![BackendInstanceConfig {
                id,
                backend: default_backend,
            }],
            poll_interval_secs: 2,
            db_path: "socketguard.db".to_string(),
            log_level: "info".to_string(),
            process_filter: ProcessFilter::default(),
        }
    }
}

impl DaemonConfig {
    /// Convenience: get the first (primary) backend config, if any.
    /// Used for backwards compat in places that expected a single backend.
    pub fn primary_backend(&self) -> Option<&BackendInstanceConfig> {
        self.backends.first()
    }

    /// Validate the backends list.
    pub fn validate_backends(backends: &[BackendInstanceConfig]) -> Result<(), String> {
        let mut ids = HashSet::new();
        let mut ula_count = 0u32;
        let mut ygg_count = 0u32;

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
                _ => {}
            }
            if inst.backend.interface().is_empty() {
                return Err(format!(
                    "backend '{}': interface must not be empty",
                    inst.id
                ));
            }
        }
        Ok(())
    }
}

fn default_loopback() -> String {
    if cfg!(target_os = "linux") {
        "lo".to_string()
    } else if cfg!(target_os = "macos") {
        "lo0".to_string()
    } else {
        "Loopback Pseudo-Interface 1".to_string()
    }
}

/// Helper: parse a single BackendConfig from legacy or object format
fn parse_single_backend(
    backend_val: serde_json::Value,
    interface: Option<String>,
) -> Result<BackendConfig, String> {
    if backend_val.is_object() {
        serde_json::from_value(backend_val).map_err(|e| e.to_string())
    } else if backend_val.is_string() {
        let backend_str = backend_val.as_str().unwrap();
        let iface = interface.unwrap_or_else(default_loopback);
        match backend_str {
            "ula" => Ok(BackendConfig::Ula { interface: iface }),
            "yggdrasil" => Ok(BackendConfig::Yggdrasil { interface: iface }),
            "slaac" => Ok(BackendConfig::Slaac {
                interface: iface,
                prefix: None,
            }),
            "dhcpv6" => Ok(BackendConfig::Dhcpv6 { interface: iface }),
            other => Err(format!("invalid backend: {other}")),
        }
    } else {
        let iface = interface.unwrap_or_else(default_loopback);
        Ok(BackendConfig::Ula { interface: iface })
    }
}

/// Custom deserializer that handles legacy, single-backend, and multi-backend formats
impl<'de> Deserialize<'de> for DaemonConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawConfig {
            #[serde(default = "default_listen_addr")]
            listen_addr: String,
            #[serde(default = "default_listen_port")]
            listen_port: u16,
            // Multi-backend format: array of backend instances
            #[serde(default)]
            backends: Option<Vec<serde_json::Value>>,
            // Single-backend format: backend is an object or string
            #[serde(default)]
            backend: serde_json::Value,
            // Legacy format: separate interface field
            #[serde(default)]
            interface: Option<String>,
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

        let backends = if let Some(backends_arr) = raw.backends {
            // Multi-backend format: "backends": [{ "id": "...", "type": "...", ... }, ...]
            let mut result = Vec::new();
            for val in backends_arr {
                let inst: BackendInstanceConfig =
                    serde_json::from_value(val).map_err(serde::de::Error::custom)?;
                result.push(inst);
            }
            // Fill in missing IDs
            for inst in &mut result {
                if inst.id.is_empty() {
                    inst.id = inst.backend.default_id();
                }
            }
            result
        } else {
            // Single backend (object or string) or empty → wrap in vec
            let backend = parse_single_backend(raw.backend, raw.interface)
                .map_err(serde::de::Error::custom)?;
            let id = backend.default_id();
            vec![BackendInstanceConfig { id, backend }]
        };

        DaemonConfig::validate_backends(&backends).map_err(serde::de::Error::custom)?;

        Ok(DaemonConfig {
            listen_addr: raw.listen_addr,
            listen_port: raw.listen_port,
            backends,
            poll_interval_secs: raw.poll_interval_secs,
            db_path: raw.db_path,
            log_level: raw.log_level,
            process_filter: raw.process_filter,
        })
    }
}

fn default_listen_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_listen_port() -> u16 {
    9476
}

fn default_poll_interval() -> u64 {
    2
}

fn default_db_path() -> String {
    "socketguard.db".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let config = DaemonConfig::default();
        assert_eq!(config.listen_addr, "127.0.0.1");
        assert_eq!(config.listen_port, 9476);
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.backends[0].backend.backend_type(), BackendType::Ula);
        assert_eq!(config.poll_interval_secs, 2);
        assert_eq!(config.db_path, "socketguard.db");
        assert_eq!(config.log_level, "info");
        assert!(!config.backends[0].backend.interface().is_empty());
    }

    #[test]
    fn config_deserialize_legacy_format() {
        let json = r#"{"backend": "yggdrasil", "interface": "tun0"}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backends.len(), 1);
        assert_eq!(
            config.backends[0].backend.backend_type(),
            BackendType::Yggdrasil
        );
        assert_eq!(config.backends[0].backend.interface(), "tun0");
        assert_eq!(config.backends[0].id, "yggdrasil");
        assert_eq!(config.listen_addr, "127.0.0.1");
        assert_eq!(config.listen_port, 9476);
    }

    #[test]
    fn config_deserialize_single_backend_object() {
        let json = r#"{
            "backend": {"type": "slaac", "interface": "Ethernet", "prefix": "2001:db8::/64"}
        }"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backends.len(), 1);
        assert_eq!(
            config.backends[0].backend.backend_type(),
            BackendType::Slaac
        );
        assert_eq!(config.backends[0].backend.interface(), "Ethernet");
        assert_eq!(config.backends[0].id, "slaac-Ethernet");
        match &config.backends[0].backend {
            BackendConfig::Slaac { prefix, .. } => {
                assert_eq!(prefix.as_deref(), Some("2001:db8::/64"));
            }
            _ => panic!("expected Slaac"),
        }
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
        assert_eq!(config.backends[1].backend.interface(), "Ethernet");
    }

    #[test]
    fn config_deserialize_empty() {
        let json = r#"{}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backends[0].backend.backend_type(), BackendType::Ula);
        assert_eq!(config.listen_addr, "127.0.0.1");
    }

    #[test]
    fn config_serialize_roundtrip() {
        let config = DaemonConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.listen_addr, config.listen_addr);
        assert_eq!(parsed.listen_port, config.listen_port);
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
        let json = r#"{"backend": {"type": "slaac", "interface": "eth0"}}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        match &config.backends[0].backend {
            BackendConfig::Slaac { prefix, .. } => assert!(prefix.is_none()),
            _ => panic!("expected Slaac"),
        }
    }

    #[test]
    fn config_deserialize_dhcpv6() {
        let json = r#"{"backend": {"type": "dhcpv6", "interface": "Ethernet"}}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.backends[0].backend.backend_type(),
            BackendType::Dhcpv6
        );
        assert_eq!(config.backends[0].backend.interface(), "Ethernet");
    }

    #[test]
    fn backend_config_interface() {
        let ula = BackendConfig::Ula {
            interface: "lo".to_string(),
        };
        assert_eq!(ula.interface(), "lo");

        let ygg = BackendConfig::Yggdrasil {
            interface: "tun0".to_string(),
        };
        assert_eq!(ygg.interface(), "tun0");

        let slaac = BackendConfig::Slaac {
            interface: "eth0".to_string(),
            prefix: None,
        };
        assert_eq!(slaac.interface(), "eth0");
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
        assert_eq!(
            BackendConfig::Yggdrasil {
                interface: "tun0".into()
            }
            .default_id(),
            "yggdrasil"
        );
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
}
