use anyhow::Result;
use socketguard_core::config::DaemonConfig;
use socketguard_daemon::*;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // Load config first so we can use its log_level for tracing
    let config = load_config_sync()?;

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
            inst.backend.interface().unwrap_or("-")
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
        config_path: Some(config_file::config_path()),
        db,
        engine: tokio::sync::RwLock::new(engine),
        firewall_lock: tokio::sync::Mutex::new(()),
        events: events_tx,
    });

    // A database migrated from v7 still has every address automatic; now that the networks
    // are known, the ones a grant covers without naming become reservations (ADR 0047).
    if let Err(e) = state
        .engine
        .read()
        .await
        .classify_legacy_addresses(&state)
        .await
    {
        error!("Could not classify the existing addresses: {e:#}");
    }

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

    // Stopping removes nothing: the ruleset and the addresses stay, so the host keeps its
    // protection while the daemon is down (ADR 0026). `--disable` removes them.
    info!("Firewall rules and addresses stay in place");

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
        .filter_map(|b| Some((b.id.clone(), b.backend.interface()?.to_string())))
        .collect();
    let mut nets = Vec::new();
    for b in &config.backends {
        // Tor holds services outside the firewall (a Yggdrasil without a configured
        // interface has addresses only on the host, which the owned-address table covers).
        if matches!(b.backend, socketguard_core::BackendConfig::Tor { .. }) {
            nets.push((
                b.id.clone(),
                networks::create(&b.backend, [0; 5], Arc::from(iface::create()))?,
            ));
        }
    }
    engine::disable_everything(
        &db,
        &interfaces,
        nets,
        Arc::from(firewall::create_firewall()),
        Arc::from(iface::create()),
    )
    .await?;
    eprintln!("[socketguard] Firewall rules, addresses and onion services removed");
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

/// Load config before tracing is initialized, so we can't use tracing macros here. A missing
/// file means defaults; a file that cannot be read or parsed stops the daemon, because
/// running on defaults would silently drop the admin's networks and filters.
fn load_config_sync() -> Result<DaemonConfig> {
    let path = config_file::config_path();
    match config_file::load(&path)? {
        Some(config) => {
            eprintln!("[socketguard] Loaded config from {}", path.display());
            Ok(config)
        }
        None => {
            eprintln!(
                "[socketguard] No config file at {}, using defaults",
                path.display()
            );
            Ok(DaemonConfig::default())
        }
    }
}
