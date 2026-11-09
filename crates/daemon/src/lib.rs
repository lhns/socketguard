// Pre-existing style lints, allowed so CI can run `clippy -D warnings`; the model/engine code
// they sit in is being replaced (see redesign plan).
#![allow(
    clippy::new_without_default,
    clippy::needless_range_loop,
    clippy::type_complexity,
    clippy::unnecessary_map_or
)]

pub mod api;
pub mod auth;
pub mod backend;
pub mod engine;
pub mod firewall;
pub mod monitor;
pub mod network;
pub mod state;
pub mod telemetry;
/// Test support module — mock implementations for integration tests.
/// Not intended for production use.
pub mod test_support;

use tokio::sync::{broadcast, Mutex, RwLock};

pub struct AppState {
    pub config: RwLock<socketguard_core::config::DaemonConfig>,
    pub db: state::Database,
    pub engine: RwLock<engine::Engine>,
    /// Mutex to synchronize firewall rule modifications between the
    /// reconciliation loop and API-triggered ACL changes.
    pub firewall_lock: Mutex<()>,
    /// Broadcast channel for SSE push notifications to GUI
    pub events: broadcast::Sender<api::DaemonEvent>,
    /// Bearer token for API authentication
    pub api_token: String,
}
