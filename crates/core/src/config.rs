use crate::types::BackendType;
use serde::{Deserialize, Serialize};

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
}

/// Daemon configuration
///
/// Supports two JSON formats:
/// - New: `{ "backend": { "type": "slaac", "interface": "Ethernet" }, ... }`
/// - Legacy: `{ "backend": "ula", "interface": "lo", ... }`
#[derive(Debug, Clone, Serialize)]
pub struct DaemonConfig {
    /// REST API listen address
    pub listen_addr: String,

    /// REST API listen port
    pub listen_port: u16,

    /// Backend configuration (includes interface)
    pub backend: BackendConfig,

    /// Socket polling interval in seconds
    pub poll_interval_secs: u64,

    /// Path to SQLite database
    pub db_path: String,

    /// Log level: trace, debug, info, warn, error
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 9476,
            backend: BackendConfig::default(),
            poll_interval_secs: 2,
            db_path: "socketguard.db".to_string(),
            log_level: "info".to_string(),
        }
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

/// Custom deserializer that handles both new and legacy config formats
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
            // New format: backend is an object with "type" tag
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
        }

        let raw = RawConfig::deserialize(deserializer)?;

        let backend = if raw.backend.is_object() {
            // New format: { "type": "slaac", "interface": "Ethernet", ... }
            serde_json::from_value(raw.backend).map_err(serde::de::Error::custom)?
        } else if raw.backend.is_string() {
            // Legacy format: "ula" or "yggdrasil"
            let backend_str = raw.backend.as_str().unwrap();
            let iface = raw.interface.unwrap_or_else(default_loopback);
            match backend_str {
                "ula" => BackendConfig::Ula { interface: iface },
                "yggdrasil" => BackendConfig::Yggdrasil { interface: iface },
                "slaac" => BackendConfig::Slaac {
                    interface: iface,
                    prefix: None,
                },
                "dhcpv6" => BackendConfig::Dhcpv6 { interface: iface },
                other => {
                    return Err(serde::de::Error::custom(format!(
                        "invalid backend: {other}"
                    )))
                }
            }
        } else {
            // Missing or null: use defaults
            let iface = raw.interface.unwrap_or_else(default_loopback);
            BackendConfig::Ula { interface: iface }
        };

        Ok(DaemonConfig {
            listen_addr: raw.listen_addr,
            listen_port: raw.listen_port,
            backend,
            poll_interval_secs: raw.poll_interval_secs,
            db_path: raw.db_path,
            log_level: raw.log_level,
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
        assert_eq!(config.backend.backend_type(), BackendType::Ula);
        assert_eq!(config.poll_interval_secs, 2);
        assert_eq!(config.db_path, "socketguard.db");
        assert_eq!(config.log_level, "info");
        assert!(!config.backend.interface().is_empty());
    }

    #[test]
    fn config_deserialize_legacy_format() {
        let json = r#"{"backend": "yggdrasil", "interface": "tun0"}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backend.backend_type(), BackendType::Yggdrasil);
        assert_eq!(config.backend.interface(), "tun0");
        assert_eq!(config.listen_addr, "127.0.0.1");
        assert_eq!(config.listen_port, 9476);
    }

    #[test]
    fn config_deserialize_new_format() {
        let json = r#"{
            "backend": {"type": "slaac", "interface": "Ethernet", "prefix": "2001:db8::/64"}
        }"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backend.backend_type(), BackendType::Slaac);
        assert_eq!(config.backend.interface(), "Ethernet");
        match &config.backend {
            BackendConfig::Slaac { prefix, .. } => {
                assert_eq!(prefix.as_deref(), Some("2001:db8::/64"));
            }
            _ => panic!("expected Slaac"),
        }
    }

    #[test]
    fn config_deserialize_new_format_ula() {
        let json = r#"{"backend": {"type": "ula"}}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backend.backend_type(), BackendType::Ula);
    }

    #[test]
    fn config_deserialize_empty() {
        let json = r#"{}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backend.backend_type(), BackendType::Ula);
        assert_eq!(config.listen_addr, "127.0.0.1");
    }

    #[test]
    fn config_serialize_roundtrip() {
        let config = DaemonConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.listen_addr, config.listen_addr);
        assert_eq!(parsed.listen_port, config.listen_port);
        assert_eq!(parsed.backend.backend_type(), config.backend.backend_type());
        assert_eq!(parsed.backend.interface(), config.backend.interface());
        assert_eq!(parsed.poll_interval_secs, config.poll_interval_secs);
    }

    #[test]
    fn config_slaac_auto_prefix() {
        let json = r#"{"backend": {"type": "slaac", "interface": "eth0"}}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        match &config.backend {
            BackendConfig::Slaac { prefix, .. } => assert!(prefix.is_none()),
            _ => panic!("expected Slaac"),
        }
    }

    #[test]
    fn config_deserialize_dhcpv6() {
        let json = r#"{"backend": {"type": "dhcpv6", "interface": "Ethernet"}}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backend.backend_type(), BackendType::Dhcpv6);
        assert_eq!(config.backend.interface(), "Ethernet");
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
}
