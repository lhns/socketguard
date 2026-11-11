//! The engine (ADR 0007, 0027): reconciles the live sockets with the model, keeps the
//! firewall and the interface addresses matching it, and offers every mutation and query
//! the API needs.
//!
//! Ordering rules that carry over from ADR 0026: a ruleset that covers an address is
//! applied before the address goes on an interface, and an address leaves its interface
//! before the ruleset stops covering it. A failed apply keeps new addresses off the
//! interfaces. Stopping the daemon removes nothing; only [`disable_everything`] does.
//!
//! [`Engine`] is the facade; its methods live in the submodules: `firewall` (ruleset,
//! counters, drops), `enforce` (networks outside the firewall, adding and removing
//! networks), `addresses` (planning, allocating, the interfaces), `discovery` (sockets to
//! apps), `queries` and `mutations`. This file holds the types, the lifecycle and the
//! reconcile pass.

mod addresses;
mod batch;
mod discovery;
mod enforce;
mod firewall;
mod mutations;
mod queries;
mod socket_groups;
mod tags;
mod torkeys;

use addresses::disable_all;
pub use addresses::plan_addresses;
use enforce::disable_networks;
pub use socket_groups::clean_ranges;

use crate::api::DaemonEvent;
use crate::firewall::{DesiredRuleset, DropEvent, Firewall};
use crate::iface::{self, InterfaceManager};
use crate::metrics::{CounterKey, Metrics};
use crate::monitor::{self, SocketMonitor};
use crate::networks;
use crate::ruleset::LockoutRisk;
use crate::state::{Database, NewActivity};
use crate::AppState;
use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use socketguard_core::{AppId, CredentialError, Network, PortRef, Protocol};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

/// An unchanged ruleset is still re-applied every this many reconcile passes. Drift is
/// caught sooner: [`Firewall::verify`] runs at most this often (it can spawn a process).
const REAPPLY_EVERY: u32 = 30;

/// Minimum time between two [`Firewall::verify`] calls, except after a failed apply.
pub const VERIFY_INTERVAL: Duration = Duration::from_secs(5);

/// The time source of the verify cadence.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Every backend allocates single addresses.
const ADDRESS_PREFIX_LEN: u8 = 128;

/// Raw drop events held between reconcile passes; the platform rate-limits them, this is
/// only a bound.
const MAX_PENDING_DROPS: usize = 10_000;

/// Drop aggregates held while their minute is still open.
const MAX_DROP_KEYS: usize = 5_000;

pub struct ActiveBackend {
    pub config: BackendInstanceConfig,
    pub network: Arc<dyn networks::Network>,
}

/// Why `set_protect_host` did not change anything.
#[derive(Debug, thiserror::Error)]
pub enum ProtectHostError {
    #[error("whole-host protection would lock out remote administration: {}", .0.iter().map(|r| r.to_string()).collect::<Vec<_>>().join("; "))]
    Lockout(Vec<LockoutRisk>),
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Why a mutation was refused. The API maps these to 404, 400, 409 and 500.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    /// A grant on a network where grants have no effect.
    #[error("Local is this machine only")]
    LocalNetwork,
    /// A grant to Anyone without `confirm_open`.
    #[error("a grant to Anyone opens the app to everyone; confirm it with confirm_open")]
    ConfirmationRequired,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<CredentialError> for EngineError {
    fn from(e: CredentialError) -> Self {
        EngineError::Invalid(e.to_string())
    }
}

/// Filter for [`Engine::list_grants`].
#[derive(Debug, Clone, Default)]
pub struct GrantFilter {
    /// Grants on this app itself (not through a tag).
    pub app_id: Option<String>,
    /// Grants on this tag.
    pub tag_id: Option<String>,
    /// Grants to this peer, directly or through one of its groups.
    pub peer_id: Option<String>,
    pub group_id: Option<String>,
}

/// One closed minute of blocked connections from one source to one destination.
type DropKey = (IpAddr, IpAddr, Option<u16>, Option<Protocol>, i64);

pub struct Engine {
    monitor: Box<dyn SocketMonitor>,
    pub(crate) backends: HashMap<String, ActiveBackend>,
    firewall: Arc<dyn Firewall>,
    ifaces: Arc<dyn InterfaceManager>,
    /// Persisted ULA global ID handed to ULA backends.
    ula_global_id: [u8; 5],
    /// Interfaces already reported as unavailable (avoids a warning every poll).
    unavailable_ifaces: Mutex<HashSet<String>>,
    /// Networks whose last allocation failed (log once per outage).
    alloc_failing: Mutex<HashSet<String>>,
    /// Owned addresses whose removal failed (log once per outage).
    removal_failing: Mutex<HashSet<Ipv6Addr>>,
    /// The ruleset last applied successfully, to skip no-op applies.
    last_applied: Mutex<Option<DesiredRuleset>>,
    /// Reconcile passes since the last apply.
    passes_since_apply: AtomicU32,
    /// The last apply failed. Addresses are not added to interfaces then, because
    /// nothing would deny them.
    apply_failed: AtomicBool,
    /// When the firewall state was last verified or applied, and how often to verify.
    last_verified: Mutex<Option<Instant>>,
    verify_interval: Duration,
    /// Where the verify cadence reads the time (tests move it by hand).
    clock: Arc<dyn Clock>,
    /// Drop events from the firewall, drained on every reconcile pass.
    drops: Arc<Mutex<Vec<DropEvent>>>,
    /// Drops aggregated per (src, dst, port, proto, minute), flushed once the minute is over.
    drop_agg: Mutex<BTreeMap<DropKey, u32>>,
    /// Which app, network and subject each rule of the applied ruleset belongs to, for
    /// attributing its counter.
    counter_keys: Mutex<HashMap<String, CounterKey>>,
    metrics: Metrics,
    /// (app, scope) pairs already reported as `RemoteAdminExposed`.
    exposed_reported: Mutex<HashSet<(String, String)>>,
    /// Where each app port's listener is bound, from the last socket scan (Tor targets).
    binds: Mutex<HashMap<(AppId, PortRef), IpAddr>>,
    /// The last enforcement error per non-IP network (log each distinct one once).
    enforce_failing: Mutex<HashMap<String, String>>,
}

impl Engine {
    pub fn new(config: &DaemonConfig, ula_global_id: [u8; 5]) -> anyhow::Result<Self> {
        Self::new_with_deps(
            config,
            ula_global_id,
            monitor::create_monitor(),
            Arc::from(crate::firewall::create_firewall()),
            Arc::from(iface::create()),
        )
    }

    pub fn new_with_deps(
        config: &DaemonConfig,
        ula_global_id: [u8; 5],
        monitor: Box<dyn SocketMonitor>,
        firewall: Arc<dyn Firewall>,
        ifaces: Arc<dyn InterfaceManager>,
    ) -> anyhow::Result<Self> {
        let mut backends = HashMap::new();
        for inst in &config.backends {
            let network = networks::create(&inst.backend, ula_global_id, ifaces.clone())?;
            backends.insert(
                inst.id.clone(),
                ActiveBackend {
                    config: inst.clone(),
                    network,
                },
            );
        }
        Ok(Self::assemble(
            monitor,
            firewall,
            ifaces,
            backends,
            ula_global_id,
        ))
    }

    /// Fully injectable constructor — for tests only.
    pub fn new_injectable(
        monitor: Box<dyn SocketMonitor>,
        firewall: Arc<dyn Firewall>,
        ifaces: Arc<dyn InterfaceManager>,
        backends: HashMap<String, ActiveBackend>,
    ) -> Self {
        let mut engine = Self::assemble(
            monitor,
            firewall,
            ifaces,
            backends,
            crate::networks::ip::ula::UlaBackend::random_global_id(),
        );
        // Tests drive passes back to back: verify on every one unless they say otherwise.
        engine.verify_interval = Duration::ZERO;
        engine
    }

    /// Override [`VERIFY_INTERVAL`] — for tests only.
    pub fn set_verify_interval(&mut self, interval: Duration) {
        self.verify_interval = interval;
    }

    /// Replace the time source of the verify cadence — for tests only.
    pub fn set_clock(&mut self, clock: Arc<dyn Clock>) {
        self.clock = clock;
    }

    fn assemble(
        monitor: Box<dyn SocketMonitor>,
        firewall: Arc<dyn Firewall>,
        ifaces: Arc<dyn InterfaceManager>,
        backends: HashMap<String, ActiveBackend>,
        ula_global_id: [u8; 5],
    ) -> Self {
        Self {
            monitor,
            backends,
            firewall,
            ifaces,
            ula_global_id,
            unavailable_ifaces: Mutex::default(),
            alloc_failing: Mutex::default(),
            removal_failing: Mutex::default(),
            last_applied: Mutex::default(),
            passes_since_apply: AtomicU32::new(0),
            apply_failed: AtomicBool::new(false),
            last_verified: Mutex::default(),
            verify_interval: VERIFY_INTERVAL,
            clock: Arc::new(SystemClock),
            drops: Arc::default(),
            drop_agg: Mutex::default(),
            counter_keys: Mutex::default(),
            metrics: Metrics::default(),
            exposed_reported: Mutex::default(),
            binds: Mutex::default(),
            enforce_failing: Mutex::default(),
        }
    }

    /// Create the OpenTelemetry instruments on `meter` (ADR 0034). Without a meter
    /// provider they do nothing.
    pub fn register_metrics(&self, meter: &opentelemetry::metrics::Meter) {
        self.metrics.register(meter);
    }

    fn emit(&self, state: &AppState, ev: DaemonEvent) {
        // No subscriber is fine.
        let _ = state.events.send(ev);
    }

    async fn record(&self, state: &AppState, activity: NewActivity) {
        if let Err(e) = state.db.insert_activity(&[activity]).await {
            warn!("Could not record activity: {e}");
        }
        self.emit(state, DaemonEvent::Activity);
    }

    /// Finish a mutation whose data is already saved: record its activity, announce
    /// `events`, then report how the firewall apply went. The record and the events happen
    /// even when the apply failed, since the change is stored and visible; the caller still
    /// gets the apply error (HTTP 500) and the next pass retries the apply.
    pub(super) async fn commit(
        &self,
        state: &AppState,
        applied: anyhow::Result<()>,
        activity: Option<NewActivity>,
        events: &[DaemonEvent],
    ) -> anyhow::Result<()> {
        if let Some(activity) = activity {
            self.record(state, activity).await;
        }
        for ev in events {
            self.emit(state, ev.clone());
        }
        applied
    }

    fn sorted_backend_ids(&self) -> Vec<&String> {
        let mut ids: Vec<&String> = self.backends.keys().collect();
        ids.sort();
        ids
    }

    fn network_of(id: &str, active: &ActiveBackend) -> Network {
        let (status, prefix) = active.network.status();
        Network {
            id: id.to_string(),
            kind: active.network.kind(),
            name: id.to_string(),
            interface: active.config.backend.interface().map(str::to_string),
            grants_apply: active.network.capabilities().grants_apply,
            status,
            prefix,
            vlan_id: None,
        }
    }

    /// The configured networks with their current status.
    pub fn networks(&self) -> Vec<Network> {
        self.sorted_backend_ids()
            .into_iter()
            .map(|id| Self::network_of(id, &self.backends[id]))
            .collect()
    }

    /// [`Engine::networks`] for display, with the VLAN id of VLAN interfaces (this lists the
    /// host's interfaces, so the firewall's own passes do not use it).
    pub fn networks_described(&self) -> Vec<Network> {
        let interfaces = self.ifaces.list_interfaces().unwrap_or_default();
        let mut networks = self.networks();
        for n in &mut networks {
            n.vlan_id = interfaces
                .iter()
                .find(|i| Some(&i.name) == n.interface.as_ref())
                .and_then(|i| i.vlan_id);
        }
        networks
    }

    /// The configs of the networks that are live, ordered by id (what the config file
    /// should list).
    pub fn backend_configs(&self) -> Vec<BackendInstanceConfig> {
        self.sorted_backend_ids()
            .into_iter()
            .map(|id| self.backends[id].config.clone())
            .collect()
    }

    fn interface_of(&self, network_id: &str) -> Option<&str> {
        self.backends
            .get(network_id)
            .and_then(|b| b.config.backend.interface())
    }

    /// Startup: apply the desired state over whatever the previous run left (never a
    /// flush, ADR 0026), then make sure the addresses are on their interfaces.
    pub async fn startup_reconcile(&self, state: &AppState) {
        if let Err(e) = networks::ledger::adopt_stored_keys(&state.db).await {
            warn!("Could not adopt existing onion services: {e:#}");
        }
        self.detect_unadopted(state).await;
        match self.apply_firewall(state).await {
            Ok(()) => self.purge_states(),
            Err(e) => error!("Startup: could not apply the firewall ruleset: {e}"),
        }
        self.ensure_addresses_present(state).await;
        let pending = self.drops.clone();
        if let Err(e) = self.firewall.subscribe_drops(Box::new(move |ev| {
            debug!(
                "Blocked {} -> {} port {:?} on {:?} (scope {:?})",
                ev.src, ev.dst, ev.port, ev.iif, ev.scope_id
            );
            let mut q = pending.lock().unwrap();
            if q.len() < MAX_PENDING_DROPS {
                q.push(ev);
            }
        })) {
            warn!("Drop logging unavailable: {e}");
        }
        info!("Startup reconciliation complete");
    }

    /// A database created by this start that meets an existing SocketGuard ruleset (the
    /// database was lost or deleted) must not wipe it: the old addresses are still on their
    /// interfaces and the old ruleset is what denies them. Latch `unadopted` instead.
    async fn detect_unadopted(&self, state: &AppState) {
        let db = &state.db;
        if !db.fresh().await.unwrap_or(false) {
            return;
        }
        if !db.disabled().await {
            let fw = self.firewall.clone();
            match tokio::task::spawn_blocking(move || fw.verify()).await {
                Ok(Ok(true)) => match db.set_unadopted(true).await {
                    Ok(()) => error!(
                        "An existing SocketGuard ruleset was found, but the database is new and empty. \
                         The ruleset is left in place and nothing is applied or added. \
                         Run `socketguard enable` to adopt the new state (this replaces the existing \
                         ruleset) or `socketguard disable` to remove it."
                    ),
                    Err(e) => error!("Could not record the unadopted ruleset: {e}"),
                },
                Ok(Ok(false)) => {}
                Ok(Err(e)) => warn!("Could not check for an existing ruleset: {e:#}"),
                Err(e) => warn!("Ruleset check failed: {e}"),
            }
        }
        // Decided: the next start is not the first of this database.
        let _ = db.clear_fresh().await;
    }

    /// Remove the firewall rules and every SocketGuard address (`--disable`, uninstall).
    /// Sets the `disabled` latch first, so no pass puts them back; [`Engine::enable`]
    /// clears it.
    pub async fn disable(&self, state: &AppState) -> anyhow::Result<()> {
        state.db.set_disabled(true).await?;
        let _lock = state.firewall_lock.lock().await;
        *self.last_applied.lock().unwrap() = None;
        let ifaces = self
            .backends
            .iter()
            .filter_map(|(id, b)| Some((id.clone(), b.config.backend.interface()?.to_string())))
            .collect();
        let nets = self
            .backends
            .iter()
            .map(|(id, b)| (id.clone(), b.network.clone()))
            .collect();
        let removed = disable_everything(
            &state.db,
            &ifaces,
            nets,
            self.firewall.clone(),
            self.ifaces.clone(),
        )
        .await;
        self.commit(state, removed, None, &[DaemonEvent::SettingsChanged])
            .await
    }

    /// Clear the `disabled` latch and put the rules and addresses back.
    pub async fn enable(&self, state: &AppState) -> anyhow::Result<()> {
        state.db.set_disabled(false).await?;
        // Adopting: the next apply replaces whatever ruleset is installed.
        state.db.set_unadopted(false).await?;
        state.db.clear_fresh().await?;
        let applied = self.apply_and_ensure(state).await;
        self.commit(state, applied, None, &[DaemonEvent::SettingsChanged])
            .await
    }

    /// Reconcile: detect sockets, upsert apps and ports, give every app an address on
    /// every network, apply the ruleset, put the addresses on the interfaces.
    pub async fn reconcile(&mut self, state: &AppState) -> anyhow::Result<()> {
        let process_filter = state.config.read().await.process_filter.clone();

        self.rehome_prefix_changes(state).await;

        let current_sockets = match self.monitor.list_listening_sockets() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to list sockets: {e}");
                return Ok(());
            }
        };
        debug!(
            "Reconcile: detected {} listening sockets",
            current_sockets.len()
        );

        let changed = self
            .upsert_apps(state, &process_filter, &current_sockets)
            .await?;
        let created = match self.ensure_addresses(state).await {
            Ok(n) => n,
            Err(e) => {
                warn!("Reconcile: could not create addresses: {e}");
                0
            }
        };

        // One ruleset for everything above, then the addresses it now covers.
        if let Err(e) = self.apply_firewall_if_changed(state).await {
            warn!("Reconcile: firewall not updated: {e}");
        }
        self.ensure_addresses_present(state).await;
        self.flush_drops(state).await;
        self.poll_counters().await;
        self.refresh_metric_counts(state).await;
        self.check_remote_admin(state, &current_sockets).await;

        if changed || created > 0 {
            self.emit(state, DaemonEvent::AppsChanged);
        }
        Ok(())
    }
}

/// The teardown behind `disable`, for the engine and for `--disable` (which has no engine):
/// set the latch and take the addresses and the firewall rules away ([`disable_all`]), then
/// the services of the networks outside the firewall ([`disable_networks`]). The second
/// step runs even when the first fails, so a stuck address never leaves services published;
/// the first error is returned.
pub async fn disable_everything(
    db: &Database,
    interfaces: &HashMap<String, String>,
    networks: Vec<(String, Arc<dyn networks::Network>)>,
    firewall: Arc<dyn Firewall>,
    ifaces: Arc<dyn InterfaceManager>,
) -> anyhow::Result<()> {
    let removed = disable_all(db, interfaces, firewall, ifaces).await;
    disable_networks(db, networks).await;
    removed
}

/// Run the reconciliation loop with shutdown support.
pub async fn run_loop(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    loop {
        let interval = {
            let config = state.config.read().await;
            config.poll_interval_secs
        };

        {
            let mut engine = state.engine.write().await;
            if let Err(e) = engine.reconcile(&state).await {
                error!("Reconciliation error: {e}");
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(interval)) => {}
            _ = shutdown.changed() => {
                info!("Reconciliation loop received shutdown signal");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networks::{Capabilities, LocatorRequest, NetworkEnforcement, NewLocator};
    use crate::test_support::*;
    use socketguard_core::{Address, NetworkKind, NetworkStatus};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A network outside the firewall that counts how often it was told to disable.
    #[derive(Default)]
    struct CountingNetwork(AtomicUsize);

    impl networks::Network for CountingNetwork {
        fn kind(&self) -> NetworkKind {
            NetworkKind::Tor
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                ip_locators: false,
                verifies: &[],
                grants_apply: true,
                udp: false,
            }
        }
        fn status(&self) -> (NetworkStatus, Option<Ipv6Addr>) {
            (NetworkStatus::Up, None)
        }
        fn ensure_locator(&self, _: &LocatorRequest) -> anyhow::Result<NewLocator> {
            unimplemented!()
        }
        fn remove_locator(&self, _: &Address) -> anyhow::Result<()> {
            Ok(())
        }
        fn enforce(&self, _: &NetworkEnforcement) -> anyhow::Result<()> {
            Ok(())
        }
        fn disable(&self, _: &[Address]) -> anyhow::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn disable_everything_tears_down_networks_even_when_an_address_stays() {
        let db = Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        db.claim_address(addr, "lo", Some("local")).await.unwrap();
        let net = MockInterfaceManager::new(Arc::new(Mutex::new(vec![])));
        net.plant_address("lo", addr);
        net.set_remove_failing(true);
        let tor = Arc::new(CountingNetwork::default());

        let result = disable_everything(
            &db,
            &HashMap::from([("local".to_string(), "lo".to_string())]),
            vec![("tor".to_string(), tor.clone())],
            Arc::new(MockFirewall::new(Arc::new(Mutex::new(vec![])))),
            Arc::new(net),
        )
        .await;

        assert!(result.is_err(), "the stuck address is reported");
        assert_eq!(tor.0.load(Ordering::SeqCst), 1, "the services still leave");
    }
}
