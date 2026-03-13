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
    pub engine: RwLock<engine::Engine>,
    /// Mutex to synchronize firewall rule modifications between the
    /// reconciliation loop and API-triggered ACL changes.
    pub firewall_lock: Mutex<()>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load config first so we can use its log_level for tracing
    let config = load_config_sync();

    let log_directive = format!("socketguard={}", config.log_level);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(log_directive.parse().unwrap_or_else(|_| {
                    "socketguard=info".parse().unwrap()
                })),
        )
        .init();
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
        engine: RwLock::new(engine),
        firewall_lock: Mutex::new(()),
    });

    // Shutdown signal channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start the API server FIRST so the UI can connect immediately
    let listen_addr = format!("{}:{}", config.listen_addr, config.listen_port);
    info!("API listening on {listen_addr}");
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    let app = api::router(state.clone());

    // Start serving in a background task
    let api_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
    });

    // Startup reconciliation runs AFTER the API is available
    {
        let engine = state.engine.read().await;
        engine.startup_reconcile(&state).await;
    }

    // Start the reconciliation loop with panic recovery
    let engine_state = state.clone();
    let recon_handle = tokio::spawn(async move {
        loop {
            let s = engine_state.clone();
            let rx = shutdown_rx.clone();
            let result = tokio::spawn(async move {
                engine::run_loop(s, rx).await;
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

    // Wait for the API server to finish (shutdown signal received)
    if let Err(e) = api_handle.await? {
        error!("API server error: {e}");
    }

    // Signal the reconciliation loop to stop
    info!("Shutdown signal received, cleaning up...");
    let _ = shutdown_tx.send(true);

    // Wait for reconciliation loop to finish
    let _ = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        recon_handle,
    )
    .await;

    // Graceful cleanup: remove firewall rules and IPv6 addresses
    {
        let engine = state.engine.read().await;
        engine.shutdown_cleanup(&state).await;
    }

    info!("SocketGuard daemon stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to install Ctrl+C handler");
    }
}

/// Load config before tracing is initialized, so we can't use tracing macros here.
fn load_config_sync() -> DaemonConfig {
    let config_path =
        std::env::var("SOCKETGUARD_CONFIG").unwrap_or_else(|_| "socketguard.json".to_string());
    if let Ok(content) = std::fs::read_to_string(&config_path) {
        match serde_json::from_str(&content) {
            Ok(config) => {
                eprintln!("[socketguard] Loaded config from {config_path}");
                config
            }
            Err(e) => {
                eprintln!("[socketguard] Failed to parse config {config_path}: {e}, using defaults");
                DaemonConfig::default()
            }
        }
    } else {
        eprintln!("[socketguard] No config file found, using defaults");
        DaemonConfig::default()
    }
}
