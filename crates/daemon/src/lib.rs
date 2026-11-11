pub mod access;
pub mod api;
pub mod apply;
pub mod args;
pub mod bundled;
pub mod commands;
pub mod config_file;
pub mod disable;
pub mod engine;
pub mod firewall;
pub mod host;
pub mod iface;
pub mod install;
pub mod legacy;
pub mod metrics;
pub mod monitor;
pub mod networks;
pub mod report;
pub mod ruleset;
pub mod run;
pub mod service;
pub mod setup;
pub mod state;
pub mod telemetry;
/// Mocks and a ready-made daemon for tests (feature `test-support`); not part of the product.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod transport;
pub mod uninstall;

use tokio::sync::{broadcast, Mutex, RwLock};

/// The daemon's shared state.
///
/// **Lock order** (the single global order), outermost first. Take any subset in this
/// order and never wait for an earlier one while holding a later one:
///
/// 1. `engine` (RwLock). Read: API handlers, queries and mutations, the reconcile pass
///    (`run_loop`), `startup_reconcile`, `disable`/`enable`. Write: only adding or removing
///    a network, which also saves the config file before releasing it, so concurrent
///    changes cannot write each other's stale list.
/// 2. `Engine::poll_lock`: a whole pass, `startup_reconcile`, `disable`, `enable`.
/// 3. `Engine::apps_lock`: a pass's read-modify-write of apps, and forgetting an app.
/// 4. `Engine::alloc_lock`: creating addresses (`ensure_addresses`).
/// 5. `firewall_lock`: applying the ruleset and enforcing non-IP networks (Tor).
/// 6. `networks::ledger`'s `LOCK`: read-modify-write of the onion service ledger.
/// 7. `config` (RwLock): only read after startup, so a reader never waits; still, hold
///    it only for reads and the database, never while waiting for a lock above.
/// 8. A database connection or transaction: `Database` methods run SQL only, never wait
///    for a lock while holding one.
///
/// Leaves below all of them, taken only inside blocking calls and never held across an
/// `.await`: the engine's `std::sync::Mutex` fields, Tor's `io` then `state`.
///
/// The engine lock is fair (write-preferring): once a writer queues, new readers wait.
/// So a task that holds `engine.read()` or any lock above must never await
/// `engine.read()` again, nor wait for a task that does: with a network add or remove
/// queued that hangs. Engine methods get `&self` and never touch `state.engine`.
pub struct AppState {
    pub config: RwLock<socketguard_core::config::DaemonConfig>,
    /// The config file the daemon loaded (or would create); networks added or removed
    /// through the API are written back to it. None: nothing is persisted.
    pub config_path: Option<std::path::PathBuf>,
    pub db: state::Database,
    pub engine: RwLock<engine::Engine>,
    /// Serializes everything that changes the ruleset or a non-IP network. See the lock
    /// order above.
    pub firewall_lock: Mutex<()>,
    /// The shipped Tor and Yggdrasil files (ADR 0052).
    pub bundled: std::sync::Arc<bundled::Bundled>,
    /// Broadcast channel for SSE push notifications to GUI
    pub events: broadcast::Sender<api::DaemonEvent>,
}
