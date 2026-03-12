mod api;
mod backend;
mod engine;
mod firewall;
mod monitor;
mod network;
mod state;

use anyhow::Result;
use socketguard_core::config::DaemonConfig;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info};

pub struct AppState {
    pub config: RwLock<DaemonConfig>,
    pub db: state::Database,
    pub engine: engine::Engine,
    /// Mutex to synchronize firewall rule modifications between the
    /// reconciliation loop and API-triggered ACL changes.
    pub firewall_lock: Mutex<()>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("socketguard=info".parse().unwrap()),
        )
        .init();

    let config = load_config().await;
    info!("Starting SocketGuard daemon");
    info!("Backend: {}", config.backend);
    info!("Interface: {}", config.interface);

    let db = state::Database::new(&config.db_path).await?;
    db.migrate().await?;
    info!("Database initialized at {}", config.db_path);

    let engine = engine::Engine::new(&config);

    let state = Arc::new(AppState {
        config: RwLock::new(config.clone()),
        db,
        engine,
        firewall_lock: Mutex::new(()),
    });

    // Start the reconciliation loop with panic recovery
    let engine_state = state.clone();
    tokio::spawn(async move {
        loop {
            let s = engine_state.clone();
            let result = tokio::spawn(async move {
                engine::run_loop(s).await;
            })
            .await;

            match result {
                Ok(()) => break,
                Err(e) => {
                    error!("Reconciliation loop panicked: {e}, restarting in 5s...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
    });

    let listen_addr = format!("{}:{}", config.listen_addr, config.listen_port);
    info!("API listening on {listen_addr}");
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    let app = api::router(state);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn load_config() -> DaemonConfig {
    let config_path =
        std::env::var("SOCKETGUARD_CONFIG").unwrap_or_else(|_| "socketguard.json".to_string());
    if let Ok(content) = tokio::fs::read_to_string(&config_path).await {
        match serde_json::from_str(&content) {
            Ok(config) => {
                info!("Loaded config from {config_path}");
                config
            }
            Err(e) => {
                error!("Failed to parse config {config_path}: {e}, using defaults");
                DaemonConfig::default()
            }
        }
    } else {
        info!("No config file found, using defaults");
        DaemonConfig::default()
    }
}
