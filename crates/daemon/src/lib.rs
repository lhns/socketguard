pub mod api;
pub mod apply;
pub mod config_file;
pub mod engine;
pub mod firewall;
pub mod iface;
pub mod metrics;
pub mod monitor;
pub mod networks;
pub mod ruleset;
pub mod state;
pub mod telemetry;
/// Mocks and a ready-made daemon for tests (feature `test-support`); not part of the product.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod transport;

use tokio::sync::{broadcast, Mutex, RwLock};

/// The daemon's shared state.
///
/// **Lock order**, outermost first: `engine`, then `firewall_lock`, then `config`. Take
/// them in that order and never wait for an earlier one while holding a later one.
///
/// - `engine` is read-locked by API handlers and queries, write-locked by the reconcile
///   pass and by adding or removing a network. The latter also saves the config file
///   before releasing it, so concurrent changes cannot write each other's stale list.
/// - `firewall_lock` serializes everything that changes the ruleset or a non-IP network
///   (the reconcile pass and API mutations).
/// - `config` is the configuration the daemon started with. After startup it is only read
///   (the process filter, the persisted settings); the live networks are the engine's.
pub struct AppState {
    pub config: RwLock<socketguard_core::config::DaemonConfig>,
    /// The config file the daemon loaded (or would create); networks added or removed
    /// through the API are written back to it. None: nothing is persisted.
    pub config_path: Option<std::path::PathBuf>,
    pub db: state::Database,
    pub engine: RwLock<engine::Engine>,
    /// See the lock order above.
    pub firewall_lock: Mutex<()>,
    /// Broadcast channel for SSE push notifications to GUI
    pub events: broadcast::Sender<api::DaemonEvent>,
}
