use anyhow::Result;
use socketguard_core::config::DaemonConfig;
use socketguard_daemon::*;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // Load config first so we can use its log_level for tracing
    let config = load_config_sync();

    if std::env::args().any(|a| a == "--disable") {
        return disable(&config).await;
    }

    let log_directive = format!("socketguard={}", config.log_level);
    let telemetry = telemetry::init(
        tracing_subscriber::EnvFilter::from_default_env().add_directive(
            log_directive
                .parse()
                .unwrap_or_else(|_| "socketguard=info".parse().unwrap()),
        ),
    );
    info!("Starting SocketGuard daemon");
    for inst in &config.backends {
        info!(
            "Backend '{}': {} on interface {}",
            inst.id,
            inst.backend.backend_type(),
            inst.backend.interface()
        );
    }

    let db = state::Database::new(&config.db_path).await?;
    db.migrate().await?;
    info!("Database initialized at {}", config.db_path);

    let ula_global_id = db.ula_global_id().await?;
    let engine = engine::Engine::new(&config, ula_global_id)?;
    engine.register_metrics(&opentelemetry::global::meter("socketguard"));

    let (events_tx, _) = broadcast::channel::<api::DaemonEvent>(64);

    let state = Arc::new(AppState {
        config: tokio::sync::RwLock::new(config.clone()),
        db,
        engine: tokio::sync::RwLock::new(engine),
        firewall_lock: tokio::sync::Mutex::new(()),
        events: events_tx,
    });

    // Shutdown signal channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start the API server FIRST so the UI can connect immediately
    let server = transport::bind(&config)?;
    let app = api::router(state.clone());

    // Start serving in a background task
    let api_handle = tokio::spawn(async move { server.serve(app, shutdown_signal()).await });

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
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), recon_handle).await;

    // Rules and addresses stay in place (ADR 0026); `--disable` removes them.
    {
        let engine = state.engine.read().await;
        engine.shutdown().await;
    }

    info!("SocketGuard daemon stopped");
    // Flush pending OTel data; the exporters block, so keep them off the runtime threads.
    let _ = tokio::task::spawn_blocking(move || telemetry.shutdown()).await;
    Ok(())
}

/// `--disable`: remove the SocketGuard firewall rules and addresses, then exit. For
/// uninstall and recovery, so it needs only the config and the database.
async fn disable(config: &DaemonConfig) -> Result<()> {
    // No telemetry here, but failures to remove an address should reach the terminal.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let db = state::Database::new(&config.db_path).await?;
    db.migrate().await?;
    let interfaces = config
        .backends
        .iter()
        .map(|b| (b.id.clone(), b.backend.interface().to_string()))
        .collect();
    engine::disable_all(
        &db,
        &interfaces,
        Arc::from(firewall::create_firewall()),
        Arc::from(network::create_network_interface()),
    )
    .await?;
    eprintln!("[socketguard] Firewall rules and addresses removed");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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
                eprintln!(
                    "[socketguard] Failed to parse config {config_path}: {e}, using defaults"
                );
                DaemonConfig::default()
            }
        }
    } else {
        eprintln!("[socketguard] No config file found, using defaults");
        DaemonConfig::default()
    }
}
