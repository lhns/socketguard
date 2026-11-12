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

/// Resolve the config for a run and make sure the directories exist.
pub fn resolve_for_run() -> Result<Resolved> {
    let path = config_file::config_path();
    if socketguard_core::portable::is_portable() {
        return resolve_portable(&path);
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

/// Portable mode (ADR 0054): config and database are in `data\` next to the program, the
/// API is on the portable pipe and no install record is written.
fn resolve_portable(path: &std::path::Path) -> Result<Resolved> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("no data folder for {}", path.display()))?;
    crate::portable::prepare_data_dir(dir)?;
    let mut resolved = config_file::resolve_at(path)?;
    // Nothing outside the folder: the config cannot point the database or the pipe elsewhere.
    let db = socketguard_core::paths::default_db_path();
    if resolved.db_path != db {
        eprintln!(
            "[socketguard] db_path in the config is ignored in portable mode; using {}",
            db.display()
        );
    }
    resolved.config.db_path = db.to_string_lossy().into_owned();
    resolved.db_path = db;
    resolved.config.api_pipe = socketguard_core::portable::API_PIPE.to_string();
    eprintln!(
        "[socketguard] Portable mode: everything is in {}",
        dir.display()
    );
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
    let is_portable = socketguard_core::portable::is_portable();
    // Portable mode writes no install record, not even in its own folder (ADR 0054).
    if !is_portable {
        install::set_record_path(&resolved.config_path);
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
    let bundled = engine.bundled();

    let (events_tx, _) = broadcast::channel::<api::DaemonEvent>(64);

    let state = Arc::new(AppState {
        config: tokio::sync::RwLock::new(config.clone()),
        config_path: Some(resolved.config_path.clone()),
        db,
        engine: tokio::sync::RwLock::new(engine),
        firewall_lock: tokio::sync::Mutex::new(()),
        bundled,
        events: events_tx,
    });

    let data_dir = resolved
        .config_path
        .parent()
        .map(std::path::Path::to_path_buf);
    if is_portable {
        // A kill leaves the addresses on their adapters with no filters to go with them:
        // take every recorded one off before anything else runs (they are put back, with
        // rules, by the first reconcile).
        if let Some(dir) = &data_dir {
            portable::write_session(dir, None);
        }
        state.engine.read().await.sweep_all_owned(&state).await;
    }

    // Shutdown signal channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start the API server FIRST so the UI can connect immediately
    let server = transport::bind(&config)?;
    let app = api::router(state.clone());

    // Start serving in a background task
    let api_handle = tokio::spawn(async move { server.serve(app, shutdown).await });

    // Startup reconciliation runs AFTER the API is available. Under systemd (`Type=notify`,
    // ordered before the network) the service is ready after the first ruleset apply
    // attempt, success or failure: a broken ruleset shows in the status and the log but
    // must not hang the boot. The first ruleset is built from stored state; Tor and
    // Yggdrasil start after it (ADR 0051).
    {
        let engine = state.engine.read().await;
        engine
            .startup_reconcile_with(&state, |failure| match failure {
                None => notify::ready("Rules applied"),
                Some(why) => {
                    notify::ready(&format!("Running, but the first ruleset failed: {why}"))
                }
            })
            .await;
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

    notify::stopping();
    // Signal the reconciliation loop to stop
    info!("Shutdown signal received, cleaning up...");
    let _ = shutdown_tx.send(true);

    // Wait for reconciliation loop to finish
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), recon_handle).await;

    // The children of Tor and Yggdrasil networks end with the daemon (gracefully, then by force).
    // Their onion services end with them; the ruleset does not.
    {
        let children = state.engine.read().await.children().clone();
        children.shutdown().await;
    }

    let mut left = Vec::new();
    if is_portable {
        // The one place portable mode tears down (ADR 0054): the same code as "turn off".
        // Whatever it cannot remove goes away with the process (WFP objects are dynamic),
        // except addresses, which the next start sweeps.
        info!("Removing rules and addresses");
        left = portable::teardown(&state).await;
        if let Some(dir) = data_dir.clone() {
            // The children are gone (the teardown waited for them), so the adapter is too:
            // the Wintun driver goes if this run put it there. Before the session record,
            // which holds that fact, is removed with the clean exit.
            let removal = tokio::task::spawn_blocking({
                let dir = dir.clone();
                move || {
                    portable::remove_wintun_driver(
                        &mut host::SystemHost,
                        &dir,
                        std::time::Duration::from_secs(1),
                    )
                }
            })
            .await;
            if let Ok(Some(why)) = removal {
                left.push(why);
            }
            portable::write_last_exit(&dir, &left);
        }
        // Handlers that must not return before the teardown (close, logoff) may now.
        portable::mark_done();
        for l in &left {
            error!("Left behind: {l}");
        }
    } else {
        // Stopping removes nothing: the ruleset and the addresses stay, so the host keeps its
        // protection while the daemon is down (ADR 0026). `--disable` removes them.
        info!("Firewall rules and addresses stay in place");
    }

    info!("SocketGuard daemon stopped");
    // Flush pending OTel data; the exporters block, so keep them off the runtime threads.
    let _ = tokio::task::spawn_blocking(move || telemetry.shutdown()).await;
    if !left.is_empty() {
        anyhow::bail!(
            "portable teardown left {} thing(s) behind: {}",
            left.len(),
            left.join("; ")
        );
    }
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
