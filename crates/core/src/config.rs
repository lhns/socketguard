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
