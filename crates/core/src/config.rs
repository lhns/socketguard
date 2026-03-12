use crate::types::BackendType;
use serde::{Deserialize, Serialize};

/// Daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// REST API listen address
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// REST API listen port
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    /// Which IPv6 backend to use
    #[serde(default)]
    pub backend: BackendType,

    /// Network interface to manage IPv6 addresses on
    #[serde(default = "default_interface")]
    pub interface: String,

    /// Socket polling interval in seconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,

    /// Path to SQLite database
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Yggdrasil admin API address (if using Yggdrasil backend)
    pub yggdrasil_admin_addr: Option<String>,
}

impl Default for BackendType {
    fn default() -> Self {
        BackendType::Ula
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
            backend: BackendType::default(),
            interface: default_interface(),
            poll_interval_secs: default_poll_interval(),
            db_path: default_db_path(),
            log_level: default_log_level(),
            yggdrasil_admin_addr: None,
        }
    }
}

fn default_listen_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_listen_port() -> u16 {
    9476
}

fn default_interface() -> String {
    if cfg!(target_os = "linux") {
        "lo".to_string()
    } else if cfg!(target_os = "macos") {
        "lo0".to_string()
    } else {
        "Loopback Pseudo-Interface 1".to_string()
    }
}

fn default_poll_interval() -> u64 {
    5
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
        assert_eq!(config.backend, BackendType::Ula);
        assert_eq!(config.poll_interval_secs, 5);
        assert_eq!(config.db_path, "socketguard.db");
        assert_eq!(config.log_level, "info");
        assert!(!config.interface.is_empty());
    }

    #[test]
    fn config_deserialize_with_defaults() {
        let json = r#"{"backend": "yggdrasil"}"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backend, BackendType::Yggdrasil);
        // Other fields should have defaults
        assert_eq!(config.listen_addr, "127.0.0.1");
        assert_eq!(config.listen_port, 9476);
        assert_eq!(config.poll_interval_secs, 5);
    }

    #[test]
    fn config_deserialize_full() {
        let json = r#"{
            "listen_addr": "0.0.0.0",
            "listen_port": 8080,
            "backend": "ula",
            "interface": "eth0",
            "poll_interval_secs": 10,
            "db_path": "/tmp/sg.db"
        }"#;
        let config: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.listen_addr, "0.0.0.0");
        assert_eq!(config.listen_port, 8080);
        assert_eq!(config.backend, BackendType::Ula);
        assert_eq!(config.interface, "eth0");
        assert_eq!(config.poll_interval_secs, 10);
        assert_eq!(config.db_path, "/tmp/sg.db");
    }

    #[test]
    fn config_serialize_roundtrip() {
        let config = DaemonConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.listen_addr, config.listen_addr);
        assert_eq!(parsed.listen_port, config.listen_port);
        assert_eq!(parsed.backend, config.backend);
        assert_eq!(parsed.poll_interval_secs, config.poll_interval_secs);
    }
}
