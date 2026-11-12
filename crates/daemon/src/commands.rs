//! The administrator commands of the daemon binary (ADR 0050), wired to this machine.
//! Each returns the process exit code: 0 done, 1 something is left or failed.

use crate::access::{self, Tools};
use crate::args::{AccessCmd, ServiceCmd};
use crate::config_file::{self, Resolved};
use crate::disable::{self, NetworkSlot};
use crate::host::{require_admin, SystemHost};
use crate::install::{self, InstallPlan, Record, SystemPlatform};
use crate::report::Report;
use crate::uninstall::{self, Deps, UninstallOptions, UninstallPaths};
use crate::{engine, firewall, iface, networks, state};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

fn fail(e: anyhow::Error) -> i32 {
    eprintln!("socketguard-daemon: {e:#}");
    1
}

fn resolved() -> Result<Resolved> {
    config_file::resolve()
}

/// The config for the commands that remove things: a file that does not parse falls back to
/// the defaults with a warning, so `apt remove` does not fail on a stale key.
fn resolved_for_removal() -> Resolved {
    config_file::resolve_for_removal()
}

// ─── disable ────────────────────────────────────────────────────────────────

/// Build every configured network; one that cannot be built is kept as its error.
pub fn network_slots(
    config: &socketguard_core::config::DaemonConfig,
    ula: [u8; 5],
) -> Vec<NetworkSlot> {
    let ifaces: Arc<dyn iface::InterfaceManager> = Arc::from(iface::create());
    // No daemon runs here, so no child does either: a Tor's services ended with it.
    let ctx = networks::ChildCtx::inert();
    config
        .backends
        .iter()
        .map(|b| NetworkSlot {
            id: b.id.clone(),
            is_tor: matches!(b.backend, socketguard_core::BackendConfig::Tor { .. }),
            network: networks::create(&b.id, &b.backend, ula, ifaces.clone(), &ctx)
                .map_err(|e| format!("{e:#}")),
        })
        .collect()
}

/// The report of disabling for the config `r`; Err is a refusal that changed nothing.
pub async fn disable_report(r: &Resolved, force: bool, absent_ok: bool) -> Result<Report, String> {
    let interfaces: HashMap<String, String> = r
        .config
        .backends
        .iter()
        .filter_map(|b| Some((b.id.clone(), b.backend.interface()?.to_string())))
        .collect();
    let config = r.config.clone();
    disable::disable_command(
        &disable::Target {
            config: &r.config_path,
            config_found: r.file_exists,
            db: &r.db_path,
        },
        force,
        absent_ok,
        Arc::from(firewall::create_firewall()),
        Arc::from(iface::create()),
        &interfaces,
        &move |ula| network_slots(&config, ula),
    )
    .await
}

/// `--disable [--force]`.
pub async fn disable_cmd(force: bool) -> i32 {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let r = resolved_for_removal();
    match disable_report(&r, force, false).await {
        Ok(rep) => {
            socketguard_core::out!("{}", rep.render());
            if !r.file_exists {
                socketguard_core::outln!(
                    "note            no config file at {}; default networks assumed",
                    r.config_path.display()
                );
            }
            i32::from(!rep.complete())
        }
        Err(msg) => {
            eprintln!("socketguard-daemon: {msg}");
            1
        }
    }
}

// ─── service ────────────────────────────────────────────────────────────────

pub fn service_cmd(cmd: ServiceCmd) -> i32 {
    let mut host = SystemHost;
    let run = |host: &mut SystemHost, cmd: ServiceCmd| -> Result<i32> {
        match cmd {
            ServiceCmd::Status { json } => {
                let st = crate::service::with_system_manager(host, |m| m.status())?;
                if json {
                    socketguard_core::outln!("{}", serde_json::to_string(&st)?);
                } else {
                    socketguard_core::outln!(
                        "installed: {}\nrunning: {}",
                        yn(st.installed),
                        yn(st.running)
                    );
                }
                Ok(0)
            }
            ServiceCmd::Install { no_start } => {
                if crate::portable::portable_daemon_running() {
                    eprintln!(
                        "warning: a portable SocketGuard is running. The installed service does not \
                         run beside it: close the portable one, or the service will refuse to start."
                    );
                }
                let r = resolved()?;
                let exe = std::env::current_exe().context("cannot find this executable")?;
                let plan = InstallPlan {
                    exe: &exe,
                    config: &r.config_path,
                    db: &r.db_path,
                    no_start,
                    pf_conf: Path::new(install::PF_CONF),
                };
                let mut h2 = SystemHost;
                crate::service::with_system_manager(host, |m| {
                    install::service_install(
                        &mut h2,
                        m,
                        &mut Tools {
                            host: &mut SystemHost,
                        },
                        &plan,
                    )
                })?;
                Ok(0)
            }
            ServiceCmd::Start => {
                require_admin(host, "starting the service")?;
                crate::service::with_system_manager(host, |m| m.start())?;
                socketguard_core::outln!("SocketGuard service started.");
                Ok(0)
            }
            ServiceCmd::Stop => {
                require_admin(host, "stopping the service")?;
                crate::service::with_system_manager(host, |m| m.stop())?;
                socketguard_core::outln!(
                    "SocketGuard service stopped. Firewall rules and addresses stay in place."
                );
                Ok(0)
            }
            ServiceCmd::Uninstall => {
                require_admin(host, "removing the service")?;
                crate::service::with_system_manager(host, |m| m.uninstall())?;
                socketguard_core::outln!("SocketGuard service removed. Rules and addresses are not touched: use `uninstall`.");
                Ok(0)
            }
            ServiceCmd::Run => unreachable!("handled by main"),
        }
    };
    run(&mut host, cmd).unwrap_or_else(fail)
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

// ─── access ─────────────────────────────────────────────────────────────────

pub fn access_cmd(cmd: AccessCmd) -> i32 {
    let mut host = SystemHost;
    // Only where the record is: `access deny` must work with a config that does not parse.
    let record = Record::for_config(&config_file::config_path());
    let mut h2 = SystemHost;
    let mut groups = Tools { host: &mut h2 };
    let result = match cmd {
        AccessCmd::GroupEnsure => require_admin(&host, "creating the access group")
            .and_then(|()| access::ensure_group(&mut host, &mut groups, &record).map(|_| ())),
        AccessCmd::Allow(who) => access::allow(&mut host, &mut groups, &record, &who),
        AccessCmd::Deny(who) => access::deny(&mut host, &mut groups, &who),
        AccessCmd::List => access::list(&mut host, &mut groups),
    };
    match result {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

// ─── uninstall ──────────────────────────────────────────────────────────────

pub async fn uninstall_cmd(opts: UninstallOptions) -> i32 {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let r = resolved_for_removal();
    let paths = UninstallPaths {
        config: r.config_path.clone(),
        db: r.db_path.clone(),
        socket: if cfg!(unix) {
            Some(r.config.api_socket.clone().into())
        } else {
            None
        },
        state_dir: socketguard_core::paths::default_locations().state_dir,
    };
    let mut host = SystemHost;
    let mut h2 = SystemHost;
    let mut h3 = SystemHost;
    let mut groups = Tools { host: &mut h2 };
    let mut platform = SystemPlatform;
    let r = Arc::new(r);
    let (rd, re) = (r.clone(), r.clone());
    let api = r.clone();
    let result = crate::service::with_system_manager(&mut h3, |mgr| {
        // `with_system_manager` is synchronous; the async part runs on this runtime.
        let deps = Deps {
            host: &mut host,
            mgr,
            groups: &mut groups,
            platform: &mut platform,
            api_reachable: &move || crate::run::api_reachable(&api.config),
            disable: Box::new(move |force| {
                Box::pin(async move {
                    match disable_report(&rd, force, true).await {
                        Ok(rep) => rep,
                        Err(msg) => {
                            let mut rep = Report::default();
                            rep.left("disable", msg);
                            rep
                        }
                    }
                })
            }),
            export: Box::new(move |p| {
                let (re, p) = (re.clone(), p.to_path_buf());
                Box::pin(async move { export_to(&re, &p).await })
            }),
        };
        // Block on the future from this (async) context.
        Ok(tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(uninstall::uninstall(deps, &opts, &paths))
        }))
    });
    match result.and_then(|x| x) {
        Ok(report) => {
            socketguard_core::out!("{}", report.render());
            if report.complete() {
                socketguard_core::outln!("SocketGuard is uninstalled.");
                0
            } else {
                1
            }
        }
        Err(e) => fail(e),
    }
}

/// Write the settings export (the same document as `GET /api/export`) of the stopped
/// daemon's database to `file`. Onion private keys are not in it.
async fn export_to(r: &Resolved, file: &Path) -> Result<()> {
    let db = state::Database::open_existing(&r.db_path.to_string_lossy()).await?;
    db.init_schema().await?;
    let eng = engine::Engine::new(&r.config, db.ula_global_id().await?)?;
    let st = crate::AppState {
        config: tokio::sync::RwLock::new(r.config.clone()),
        config_path: Some(r.config_path.clone()),
        db,
        engine: tokio::sync::RwLock::new(eng),
        firewall_lock: tokio::sync::Mutex::new(()),
        bundled: std::sync::Arc::new(crate::bundled::Bundled::none()),
        events: tokio::sync::broadcast::channel(1).0,
    };
    let doc = {
        let e = st.engine.read().await;
        crate::apply::export(&e, &st)
            .await
            .map_err(|e| anyhow::anyhow!("{e:?}"))?
    };
    // Windows cannot delete a file that is still open (`uninstall --purge` does, next).
    st.db.close().await;
    let mut text = serde_json::to_string_pretty(&doc)?;
    text.push('\n');
    std::fs::write(file, text).with_context(|| format!("writing {}", file.display()))
}
