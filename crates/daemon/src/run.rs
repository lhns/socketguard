//! Running the daemon: start-up, serving, shutdown. `main` and the Windows service entry
//! both call [`run`]; `shutdown` is Ctrl+C / SIGTERM for a process, the control manager's
//! stop request for a service, and ends the run the same graceful way.

use crate::config_file::{self, Resolved};
use crate::install::{self, Record};
use crate::*;
use anyhow::Result;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info};

/// Resolve the config for a run: with default locations, first move state left in the
/// working directory (ADR 0050), then make sure the directories exist.
pub fn resolve_for_run() -> Result<Resolved> {
    let path = config_file::config_path();
    if config_file::is_default_location(&path) {
        let db = socketguard_core::paths::default_db_path();
        if let Ok(cwd) = std::env::current_dir() {
            if !legacy::plan(&cwd, &path, &db).is_empty() {
                let record = Record::for_config(&path);
                install::prepare_dirs(&path, &db, &record)?;
                let moves = legacy::migrate(&cwd, &path, &db)?;
                for m in &moves {
                    eprintln!(
                        "[socketguard] Moved {} to {}",
                        m.from.display(),
                        m.to.display()
                    );
                }
            }
        }
    }
    let resolved = config_file::resolve_at(&path)?;
    install::prepare_dirs(
        &resolved.config_path,
        &resolved.db_path,
        &Record::for_config(&resolved.config_path),
    )?;
    if resolved.file_exists {
        eprintln!(
            "[socketguard] Loaded config from {}",
            resolved.config_path.display()
        );
    } else {
        eprintln!(
            "[socketguard] No config file at {}, using defaults",
            resolved.config_path.display()
        );
    }
    Ok(resolved)
}

/// Ctrl+C or SIGTERM.
pub async fn signal_shutdown() {
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

pub async fn run(
    resolved: Resolved,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let config = resolved.config;
    install::set_record_path(&resolved.config_path);

    let log_directive = format!("socketguard={}", config.log_level);
    let telemetry = telemetry::init(
        tracing_subscriber::EnvFilter::from_default_env().add_directive(
            log_directive
                .parse()
                .unwrap_or_else(|_| "socketguard=info".parse().unwrap()),
        ),
    );
    info!("Starting SocketGuard daemon");
    info!("Config {}", resolved.config_path.display());
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
    networks::ip::dhcpv6::use_store(db.blocking_store());
    let engine = engine::Engine::new(&config, ula_global_id)?;
    engine.register_metrics(&opentelemetry::global::meter("socketguard"));

    let (events_tx, _) = broadcast::channel::<api::DaemonEvent>(64);

    let state = Arc::new(AppState {
        config: tokio::sync::RwLock::new(config.clone()),
        config_path: Some(resolved.config_path.clone()),
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
    let api_handle = tokio::spawn(async move { server.serve(app, shutdown).await });

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

/// Whether something answers on the API endpoint of `config` (a stale socket file does not).
pub fn api_reachable(config: &socketguard_core::config::DaemonConfig) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(std::path::Path::new(&config.api_socket)).is_ok()
    }
    #[cfg(windows)]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config.api_pipe)
            .is_ok()
    }
}
