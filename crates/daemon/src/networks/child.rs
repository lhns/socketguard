//! What Tor and Yggdrasil networks (ADR 0052) share: the context the engine hands to the networks it
//! builds, and the choice of the child to run for a network's configuration.

use super::ygg_key::KeyRing;
use crate::account::{Accounts, SystemAccounts};
use crate::bundled::Bundled;
use crate::children::{Desired, Supervisor};
use crate::iface::InterfaceManager;
use socketguard_core::config::BackendConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The daemon's side of Tor and Yggdrasil networks: the shipped files, the state directory their data
/// lives under, the supervisor that runs them, and the accounts they may run as.
#[derive(Clone)]
pub struct ChildCtx {
    pub bundled: Arc<Bundled>,
    /// The directory of the database (`<state dir>/tor`, ...). None when there is none (an
    /// in-memory database).
    pub state_dir: Option<PathBuf>,
    pub daemon_pid: u32,
    pub children: Arc<Supervisor>,
    pub accounts: Arc<dyn Accounts>,
    /// The keys of the Yggdrasil networks (loaded and created by the engine).
    pub keys: KeyRing,
    /// The admin valves of the Yggdrasil networks.
    pub valves: super::ygg_child::Valves,
    /// How many bridges each Tor network connects through (set when its child is
    /// specified), for its status.
    pub bridge_counts: BridgeCounts,
}

/// Bridge counts by network id.
#[derive(Clone, Default)]
pub struct BridgeCounts(Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>);

impl BridgeCounts {
    pub fn set(&self, id: &str, n: usize) {
        self.0.lock().unwrap().insert(id.to_string(), n);
    }

    pub fn get(&self, id: &str) -> usize {
        self.0.lock().unwrap().get(id).copied().unwrap_or(0)
    }
}

impl ChildCtx {
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
            keys: KeyRing::default(),
            valves: Default::default(),
            bridge_counts: Default::default(),
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

    /// Builds Tor and Yggdrasil networks for display and teardown only: no files, and nothing is ever
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
            "no state directory is known, so Tor and Yggdrasil cannot keep their data".to_string()
        })
    }
}

/// What the supervisor should do for the Tor or Yggdrasil network `id` configured as `backend`, when
/// nothing holds it back: run its child, or say why that cannot be.
pub fn child_wish(
    ctx: &ChildCtx,
    ifaces: &Arc<dyn InterfaceManager>,
    id: &str,
    backend: &BackendConfig,
) -> Desired {
    match backend {
        BackendConfig::Tor { bridges } => {
            match super::tor_child::TorChild::new(id, ctx).spec_with_bridges(bridges) {
                Ok(spec) => Desired::Run(Box::new(spec)),
                Err(why) => Desired::Unavailable(why),
            }
        }
        BackendConfig::Yggdrasil {
            peers,
            lan_discovery,
        } => {
            match super::ygg_child::YggChild::new(id, ctx, ifaces.clone())
                .spec(peers, *lan_discovery)
            {
                Ok(spec) => Desired::Run(Box::new(spec)),
                Err(why) => Desired::Unavailable(why),
            }
        }
        _ => Desired::Stopped,
    }
}
