pub mod api;
pub mod apply;
pub mod backend;
pub mod config_file;
pub mod engine;
pub mod firewall;
pub mod metrics;
pub mod monitor;
pub mod network;
pub mod networks;
pub mod ruleset;
pub mod state;
pub mod telemetry;
/// Test support module — mock implementations for integration tests.
/// Not intended for production use.
pub mod test_support;
pub mod transport;

use tokio::sync::{broadcast, Mutex, RwLock};

pub struct AppState {
    pub config: RwLock<socketguard_core::config::DaemonConfig>,
    /// The config file the daemon loaded (or would create); networks added or removed
    /// through the API are written back to it. None: nothing is persisted.
    pub config_path: Option<std::path::PathBuf>,
    pub db: state::Database,
    pub engine: RwLock<engine::Engine>,
    /// Mutex to synchronize firewall rule modifications between the
    /// reconciliation loop and API-triggered ACL changes.
    pub firewall_lock: Mutex<()>,
    /// Broadcast channel for SSE push notifications to GUI
    pub events: broadcast::Sender<api::DaemonEvent>,
}
