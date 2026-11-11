//! What managed networks (ADR 0052) share: the context the engine hands to the networks it
//! builds, and the choice of the child to run for a network's configuration.

use crate::account::{Accounts, SystemAccounts};
use crate::bundled::Bundled;
use crate::children::{Desired, Supervisor};
use socketguard_core::config::BackendConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The daemon's side of managed networks: the shipped files, the state directory their data
/// lives under, the supervisor that runs them, and the accounts they may run as.
#[derive(Clone)]
pub struct ManagedCtx {
    pub bundled: Arc<Bundled>,
    /// The directory of the database (`<state dir>/tor`, ...). None when there is none (an
    /// in-memory database).
    pub state_dir: Option<PathBuf>,
    pub daemon_pid: u32,
    pub children: Arc<Supervisor>,
    pub accounts: Arc<dyn Accounts>,
}

impl ManagedCtx {
    pub fn new(
        bundled: Arc<Bundled>,
        state_dir: Option<PathBuf>,
        children: Arc<Supervisor>,
        accounts: Arc<dyn Accounts>,
    ) -> Self {
        Self {
            bundled,
            state_dir,
            daemon_pid: std::process::id(),
            children,
            accounts,
        }
    }

    /// For the running daemon: the files beside the executable, the state directory of the
    /// database at `db_path`, real processes and accounts.
    pub fn system(db_path: &str) -> Self {
        let state_dir = (db_path != ":memory:")
            .then(|| Path::new(db_path).parent().map(Path::to_path_buf))
            .flatten()
            .filter(|p| !p.as_os_str().is_empty());
        Self::new(
            Arc::new(Bundled::locate()),
            state_dir,
            Arc::new(Supervisor::system()),
            Arc::new(SystemAccounts),
        )
    }

    /// Builds managed networks for display and teardown only: no files, and nothing is ever
    /// started (the commands that run without a daemon, tests that need no children).
    pub fn inert() -> Self {
        Self::new(
            Arc::new(Bundled::none()),
            None,
            Arc::new(Supervisor::system()),
            Arc::new(SystemAccounts),
        )
    }

    pub fn state_dir(&self) -> Result<&Path, String> {
        self.state_dir.as_deref().ok_or_else(|| {
            "no state directory is known, so a managed network cannot keep its data".to_string()
        })
    }
}

/// What the supervisor should do for the managed network `id` configured as `backend`, when
/// nothing holds it back: run its child, or say why that cannot be.
pub fn child_wish(ctx: &ManagedCtx, id: &str, backend: &BackendConfig) -> Desired {
    match backend {
        BackendConfig::Tor { managed: true, .. } => {
            match super::tor_managed::ManagedTor::new(id, ctx).spec() {
                Ok(spec) => Desired::Run(Box::new(spec)),
                Err(why) => Desired::Unavailable(why),
            }
        }
        // The managed Yggdrasil node is added here (generated configuration, key, spec).
        BackendConfig::Yggdrasil { managed: true, .. } => {
            Desired::Unavailable("managed Yggdrasil is not part of this build yet".into())
        }
        _ => Desired::Stopped,
    }
}
