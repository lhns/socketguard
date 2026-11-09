//! The engine (ADR 0007, 0027): reconciles the live sockets with the model, keeps the
//! firewall and the interface addresses matching it, and offers every mutation and query
//! the API needs.
//!
//! Ordering rules that carry over from ADR 0026: a ruleset that covers an address is
//! applied before the address goes on an interface, and an address leaves its interface
//! before the ruleset stops covering it. A failed apply keeps new addresses off the
//! interfaces. Stopping the daemon removes nothing; only [`disable_all`] does.

use crate::api::DaemonEvent;
use crate::backend::{self, iid_of, same_prefix64, with_prefix64, Ipv6Backend};
use crate::firewall::{self, DesiredRuleset, DropEvent, Firewall};
use crate::metrics::{CounterKey, Metrics};
use crate::monitor::{self, SocketMonitor};
use crate::network::{self, NetworkInterface};
use crate::ruleset::{self, HostInterface, LockoutRisk, Snapshot};
use crate::state::{self, Database, NewActivity};
use crate::AppState;
use chrono::Utc;
use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use socketguard_core::{
    app_identity, grant_reach, is_loopback_interface, new_id, normalize_credential, ActivityKind,
    ActivityQuery, ActivityRecord, Address, AddressId, AddressMode, App, AppDetail, AppId,
    Credential, CredentialError, Grant, GrantView, Locator, Network, NetworkKind, NetworkStatus,
    NewCredential, NewGrant, Peer, PeerGroup, PortRef, PortSet, Protocol, Settings, Subject,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

/// An unchanged ruleset is still re-applied every this many reconcile passes, which
/// corrects drift (e.g. someone deleting the table) without hammering `nft`.
const REAPPLY_EVERY: u32 = 30;

/// Every backend allocates single addresses.
const ADDRESS_PREFIX_LEN: u8 = 128;

/// Raw drop events held between reconcile passes; the platform rate-limits them, this is
/// only a bound.
const MAX_PENDING_DROPS: usize = 10_000;

/// Drop aggregates held while their minute is still open.
const MAX_DROP_KEYS: usize = 5_000;

pub struct ActiveBackend {
    pub config: BackendInstanceConfig,
    pub backend: Box<dyn Ipv6Backend>,
}

/// Why `set_protect_host` did not change anything.
#[derive(Debug, thiserror::Error)]
pub enum ProtectHostError {
    #[error("whole-host protection would lock out remote administration: {}", .0.iter().map(|r| r.to_string()).collect::<Vec<_>>().join("; "))]
    Lockout(Vec<LockoutRisk>),
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
    pub app_id: Option<String>,
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
    network: Arc<dyn NetworkInterface>,
    /// Track which backend configs the engine was built with (by ID)
    current_backend_ids: Vec<String>,
    /// Persisted ULA global ID handed to ULA backends.
    ula_global_id: [u8; 5],
    /// Interfaces already reported as unavailable (avoids a warning every poll).
    unavailable_ifaces: Mutex<HashSet<String>>,
    /// Networks whose last allocation failed (log once per outage).
    alloc_failing: Mutex<HashSet<String>>,
    /// The ruleset last applied successfully, to skip no-op applies.
    last_applied: Mutex<Option<DesiredRuleset>>,
    /// Reconcile passes since the last apply.
    passes_since_apply: AtomicU32,
    /// The last apply failed. Addresses are not added to interfaces then, because
    /// nothing would deny them.
    apply_failed: AtomicBool,
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
}

impl Engine {
    pub fn new(config: &DaemonConfig, ula_global_id: [u8; 5]) -> anyhow::Result<Self> {
        Self::new_with_deps(
            config,
            ula_global_id,
            monitor::create_monitor(),
            Arc::from(firewall::create_firewall()),
            Arc::from(network::create_network_interface()),
        )
    }

    pub fn new_with_deps(
        config: &DaemonConfig,
        ula_global_id: [u8; 5],
        monitor: Box<dyn SocketMonitor>,
        firewall: Arc<dyn Firewall>,
        network: Arc<dyn NetworkInterface>,
    ) -> anyhow::Result<Self> {
        let mut backends = HashMap::new();
        for inst in &config.backends {
            let b = backend::create_backend(&inst.backend, ula_global_id)?;
            backends.insert(
                inst.id.clone(),
                ActiveBackend {
                    config: inst.clone(),
                    backend: b,
                },
            );
        }
        let current_backend_ids: Vec<String> =
            config.backends.iter().map(|b| b.id.clone()).collect();

        Ok(Self::assemble(
            monitor,
            firewall,
            network,
            backends,
            current_backend_ids,
            ula_global_id,
        ))
    }

    /// Fully injectable constructor — for tests only.
    pub fn new_injectable(
        monitor: Box<dyn SocketMonitor>,
        firewall: Arc<dyn Firewall>,
        network: Arc<dyn NetworkInterface>,
        backends: HashMap<String, ActiveBackend>,
        backend_ids: Vec<String>,
    ) -> Self {
        Self::assemble(
            monitor,
            firewall,
            network,
            backends,
            backend_ids,
            backend::ula::UlaBackend::random_global_id(),
        )
    }

    fn assemble(
        monitor: Box<dyn SocketMonitor>,
        firewall: Arc<dyn Firewall>,
        network: Arc<dyn NetworkInterface>,
        backends: HashMap<String, ActiveBackend>,
        current_backend_ids: Vec<String>,
        ula_global_id: [u8; 5],
    ) -> Self {
        Self {
            monitor,
            backends,
            firewall,
            network,
            current_backend_ids,
            ula_global_id,
            unavailable_ifaces: Mutex::default(),
            alloc_failing: Mutex::default(),
            last_applied: Mutex::default(),
            passes_since_apply: AtomicU32::new(0),
            apply_failed: AtomicBool::new(false),
            drops: Arc::default(),
            drop_agg: Mutex::default(),
            counter_keys: Mutex::default(),
            metrics: Metrics::default(),
            exposed_reported: Mutex::default(),
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

    // ─── Networks ────────────────────────────────────────────────────────────

    fn sorted_backend_ids(&self) -> Vec<&String> {
        let mut ids: Vec<&String> = self.backends.keys().collect();
        ids.sort();
        ids
    }

    fn network_of(id: &str, active: &ActiveBackend) -> Network {
        let kind = NetworkKind::from(active.config.backend.backend_type());
        let (status, prefix) = match active.backend.current_prefix() {
            Ok(Some(p)) if p.len == 64 => (NetworkStatus::Up, Some(p.addr)),
            Ok(_) => (NetworkStatus::Up, None),
            Err(e) => (
                NetworkStatus::Down {
                    reason: e.to_string(),
                },
                None,
            ),
        };
        Network {
            id: id.to_string(),
            kind,
            name: id.to_string(),
            interface: Some(active.config.backend.interface().to_string()),
            // Local on loopback is this machine only; on another interface it takes grants
            // like any IP network (ADR 0027).
            grants_apply: kind != NetworkKind::Local
                || !is_loopback_interface(active.config.backend.interface()),
            status,
            prefix,
        }
    }

    /// The configured networks with their current status.
    pub fn networks(&self) -> Vec<Network> {
        self.sorted_backend_ids()
            .into_iter()
            .map(|id| Self::network_of(id, &self.backends[id]))
            .collect()
    }

    fn interface_of(&self, network_id: &str) -> Option<&str> {
        self.backends
            .get(network_id)
            .map(|b| b.config.backend.interface())
    }

    // ─── Firewall ────────────────────────────────────────────────────────────

    /// Gather the producer's input from the DB and the active networks.
    async fn gather_snapshot(&self, state: &AppState) -> anyhow::Result<Snapshot> {
        let db = &state.db;
        Ok(Snapshot {
            apps: db.list_apps().await?,
            networks: self.networks(),
            peers: db.list_peers().await?,
            groups: db.list_groups().await?,
            grants: db.list_grants().await?,
            protect_host: db.protect_host().await?,
        })
    }

    /// Build the desired ruleset from the current state and apply it atomically. The
    /// caller holds the firewall lock. With `only_if_changed`, an unchanged ruleset is
    /// not re-sent (except every `REAPPLY_EVERY` passes).
    async fn apply_locked(&self, state: &AppState, only_if_changed: bool) -> anyhow::Result<()> {
        if state.db.disabled().await? {
            return Ok(());
        }
        let snapshot = self.gather_snapshot(state).await?;
        let (desired, warnings) = ruleset::build_with_warnings(&snapshot);

        if only_if_changed && !self.apply_failed.load(Ordering::Relaxed) {
            let unchanged = self.last_applied.lock().unwrap().as_ref() == Some(&desired);
            if unchanged
                && self.passes_since_apply.fetch_add(1, Ordering::Relaxed) + 1 < REAPPLY_EVERY
            {
                return Ok(());
            }
        }
        self.passes_since_apply.store(0, Ordering::Relaxed);
        for w in warnings {
            warn!("{w}");
        }

        let fw = self.firewall.clone();
        let to_apply = desired.clone();
        let result = tokio::task::spawn_blocking(move || fw.apply(&to_apply)).await?;
        match result {
            Ok(()) => {
                debug!(
                    "Applied ruleset: {} scopes, {} rules",
                    desired.scopes.len(),
                    desired.rules.len()
                );
                *self.counter_keys.lock().unwrap() = counter_keys(&snapshot, &desired);
                // The table was replaced, so the platform's counters restarted at zero.
                self.metrics.counters_reset();
                *self.last_applied.lock().unwrap() = Some(desired);
                self.apply_failed.store(false, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                *self.last_applied.lock().unwrap() = None;
                self.apply_failed.store(true, Ordering::Relaxed);
                error!("Failed to apply firewall ruleset: {e}");
                Err(e)
            }
        }
    }

    /// Rebuild the ruleset from the current state and apply it. Call after any change to
    /// apps, addresses, peers, groups, grants or networks.
    pub async fn apply_firewall(&self, state: &AppState) -> anyhow::Result<()> {
        let _lock = state.firewall_lock.lock().await;
        self.apply_locked(state, false).await
    }

    async fn apply_firewall_if_changed(&self, state: &AppState) -> anyhow::Result<()> {
        let _lock = state.firewall_lock.lock().await;
        self.apply_locked(state, true).await
    }

    /// Apply, then put missing addresses on their interfaces (the ruleset first).
    async fn apply_and_ensure(&self, state: &AppState) -> anyhow::Result<()> {
        self.apply_firewall(state).await?;
        self.ensure_addresses_present(state).await;
        Ok(())
    }

    /// Enable (or with an empty list, disable) whole-host protection for `interfaces`.
    /// Refuses with [`ProtectHostError::Lockout`] when a remote-admin listener would lose
    /// access, unless `force`. Returns the risks that were overridden.
    pub async fn set_protect_host(
        &self,
        state: &AppState,
        interfaces: Vec<String>,
        force: bool,
    ) -> Result<Vec<LockoutRisk>, ProtectHostError> {
        let mut interfaces = interfaces;
        interfaces.retain(|i| !i.trim().is_empty());
        interfaces.sort();
        interfaces.dedup();
        let mut risks = Vec::new();
        if !interfaces.is_empty() {
            let snapshot = self.gather_snapshot(state).await?;
            let listeners = self.monitor.list_listening_sockets()?;
            let host_ifaces: Vec<HostInterface> = interfaces
                .iter()
                .map(|name| HostInterface {
                    name: name.clone(),
                    addrs: self
                        .network
                        .list_addresses(name)
                        .unwrap_or_default()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                })
                .collect();
            if let Err(found) = ruleset::check_protect_host(&snapshot, &listeners, &host_ifaces) {
                if !force {
                    return Err(ProtectHostError::Lockout(found));
                }
                warn!("Enabling whole-host protection despite lockout risks: {found:?}");
                risks = found;
            }
        }
        state.db.set_protect_host(&interfaces).await?;
        self.apply_firewall(state).await?;
        self.record(
            state,
            NewActivity::new(
                ActivityKind::ProtectHostChanged,
                if interfaces.is_empty() {
                    "Whole-host protection off".to_string()
                } else {
                    format!("Whole-host protection on for {}", interfaces.join(", "))
                },
            ),
        )
        .await;
        self.emit(state, DaemonEvent::SettingsChanged);
        Ok(risks)
    }

    // ─── Lifecycle ───────────────────────────────────────────────────────────

    /// Startup: apply the desired state over whatever the previous run left (never a
    /// flush, ADR 0026), then make sure the addresses are on their interfaces.
    pub async fn startup_reconcile(&self, state: &AppState) {
        if let Err(e) = self.apply_firewall(state).await {
            error!("Startup: could not apply the firewall ruleset: {e}");
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

    /// Graceful shutdown removes nothing: the ruleset and the addresses stay, so the host
    /// keeps its protection while the daemon is down (ADR 0026).
    pub async fn shutdown(&self) {
        info!("Shutting down; firewall rules and addresses stay in place");
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
            .map(|(id, b)| (id.clone(), b.config.backend.interface().to_string()))
            .collect();
        disable_all(
            &state.db,
            &ifaces,
            self.firewall.clone(),
            self.network.clone(),
        )
        .await?;
        self.emit(state, DaemonEvent::SettingsChanged);
        Ok(())
    }

    /// Clear the `disabled` latch and put the rules and addresses back.
    pub async fn enable(&self, state: &AppState) -> anyhow::Result<()> {
        state.db.set_disabled(false).await?;
        self.apply_and_ensure(state).await?;
        self.emit(state, DaemonEvent::SettingsChanged);
        Ok(())
    }

    // ─── Networks: add and remove ────────────────────────────────────────────

    /// Check if backends config has changed and apply additions/removals.
    /// Returns true if changes were detected.
    async fn check_config_change(&mut self, config: &DaemonConfig, state: &AppState) -> bool {
        let new_ids: Vec<String> = config.backends.iter().map(|b| b.id.clone()).collect();
        if new_ids == self.current_backend_ids {
            return false;
        }

        let old_ids: HashSet<String> = self.current_backend_ids.iter().cloned().collect();
        let new_id_set: HashSet<String> = new_ids.iter().cloned().collect();

        let removed: Vec<String> = old_ids.difference(&new_id_set).cloned().collect();
        for old_id in &removed {
            info!("Backend '{}' removed from config", old_id);
            self.remove_backend_instance(state, old_id).await;
        }

        let added: Vec<String> = new_id_set.difference(&old_ids).cloned().collect();
        for new_id in &added {
            if let Some(inst) = config.backends.iter().find(|b| b.id == *new_id) {
                info!("Backend '{}' added to config", new_id);
                self.add_backend_instance(state, inst).await;
            }
        }

        self.current_backend_ids = new_ids;
        true
    }

    /// Add a network and give every app an address on it.
    pub async fn add_backend_instance(&mut self, state: &AppState, inst: &BackendInstanceConfig) {
        match backend::create_backend(&inst.backend, self.ula_global_id) {
            Ok(b) => self.add_backend_instance_with(state, inst, b).await,
            Err(e) => error!("Failed to create backend '{}': {e}", inst.id),
        }
    }

    /// The API's add: validate against the current networks, create the backend, add it
    /// and return the network as it now stands.
    pub async fn add_network(
        &mut self,
        state: &AppState,
        inst: BackendInstanceConfig,
    ) -> Result<Network, EngineError> {
        if self.backends.contains_key(&inst.id) {
            return Err(EngineError::Conflict(format!(
                "network {} already exists",
                inst.id
            )));
        }
        let mut all: Vec<BackendInstanceConfig> =
            self.backends.values().map(|b| b.config.clone()).collect();
        all.push(inst.clone());
        DaemonConfig::validate_backends(&all).map_err(|e| {
            if e.starts_with("at most one") {
                EngineError::Conflict(e)
            } else {
                EngineError::Invalid(e)
            }
        })?;
        let b = backend::create_backend(&inst.backend, self.ula_global_id)
            .map_err(|e| EngineError::Invalid(format!("cannot create network: {e}")))?;
        self.add_backend_instance_with(state, &inst, b).await;
        self.networks()
            .into_iter()
            .find(|n| n.id == inst.id)
            .ok_or_else(|| EngineError::Internal(anyhow::anyhow!("network vanished")))
    }

    /// The API's remove.
    pub async fn remove_network(&mut self, state: &AppState, id: &str) -> Result<(), EngineError> {
        if !self.backends.contains_key(id) {
            return Err(EngineError::NotFound(format!("network {id}")));
        }
        self.remove_backend_instance(state, id).await;
        Ok(())
    }

    /// [`Engine::add_backend_instance`] with the allocator already built (tests inject mocks).
    pub async fn add_backend_instance_with(
        &mut self,
        state: &AppState,
        inst: &BackendInstanceConfig,
        b: Box<dyn Ipv6Backend>,
    ) {
        // The ruleset (overlay scope, managed addresses) must know the network before
        // its addresses go on the interface.
        self.backends.insert(
            inst.id.clone(),
            ActiveBackend {
                config: inst.clone(),
                backend: b,
            },
        );
        // Keep the config (and the change detector) in step, so the next reconcile does
        // not see this network as new.
        {
            let mut config = state.config.write().await;
            if !config.backends.iter().any(|b| b.id == inst.id) {
                config.backends.push(inst.clone());
            }
        }
        if !self.current_backend_ids.contains(&inst.id) {
            self.current_backend_ids.push(inst.id.clone());
        }
        let created = match self.ensure_addresses(state).await {
            Ok(n) => n,
            Err(e) => {
                error!("Could not allocate addresses for '{}': {e}", inst.id);
                0
            }
        };
        let _ = self.apply_and_ensure(state).await;
        self.emit(state, DaemonEvent::NetworksChanged);
        self.emit(state, DaemonEvent::AppsChanged);
        info!(
            "Backend '{}' initialized, allocated {created} addresses",
            inst.id
        );
    }

    /// Remove a network: its addresses leave the interfaces, then the DB, then the ruleset.
    pub async fn remove_backend_instance(&mut self, state: &AppState, backend_id: &str) {
        let deleted = match state.db.delete_addresses_by_network(backend_id).await {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to delete addresses for backend '{backend_id}': {e}");
                Vec::new()
            }
        };
        let iface = self.interface_of(backend_id).map(str::to_string);
        if let Some(iface) = iface {
            self.remove_from_interface(
                deleted
                    .iter()
                    .filter_map(|a| a.locator.ipv6().map(|ip| (iface.clone(), ip)))
                    .collect(),
            )
            .await;
        }
        self.backends.remove(backend_id);
        state
            .config
            .write()
            .await
            .backends
            .retain(|b| b.id != backend_id);
        self.current_backend_ids.retain(|id| id != backend_id);
        let _ = self.apply_firewall(state).await;
        self.emit(state, DaemonEvent::NetworksChanged);
        self.emit(state, DaemonEvent::AppsChanged);
        self.emit(state, DaemonEvent::GrantsChanged);
        info!("Backend '{}' removed", backend_id);
    }

    async fn remove_from_interface(&self, addrs: Vec<(String, Ipv6Addr)>) {
        let mut join_set = JoinSet::new();
        for (iface, addr) in addrs {
            let network = self.network.clone();
            join_set.spawn_blocking(move || {
                if let Err(e) = network.remove_address(&iface, addr) {
                    warn!("Failed to remove address {addr} from {iface}: {e}");
                }
            });
        }
        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                warn!("Remove address task failed: {e}");
            }
        }
    }

    // ─── Reconcile ───────────────────────────────────────────────────────────

    /// Reconcile: detect sockets, upsert apps and ports, give every app an address on
    /// every network, apply the ruleset, put the addresses on the interfaces.
    pub async fn reconcile(&mut self, state: &AppState) -> anyhow::Result<()> {
        let config_snapshot = state.config.read().await.clone();

        self.check_config_change(&config_snapshot, state).await;
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
            .upsert_apps(state, &config_snapshot, &current_sockets)
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

    /// Steps 1 of the reconcile: live sockets -> apps and their ports. Returns whether
    /// anything user-visible changed.
    async fn upsert_apps(
        &self,
        state: &AppState,
        config: &DaemonConfig,
        sockets: &[socketguard_core::ListeningSocket],
    ) -> anyhow::Result<bool> {
        struct Live {
            name: String,
            process_name: String,
            exe_path: Option<String>,
            interpreter_arg: Option<String>,
            ports: BTreeSet<PortRef>,
        }
        let mut live: BTreeMap<AppId, Live> = BTreeMap::new();
        for ls in sockets {
            if !config.process_filter.matches(&ls.process_name) {
                continue;
            }
            let (id, name, interpreter_arg) = app_identity(
                &ls.process_name,
                ls.exe_path.as_deref(),
                ls.cmdline.as_deref(),
            );
            live.entry(id)
                .or_insert_with(|| Live {
                    name,
                    process_name: ls.process_name.clone(),
                    exe_path: ls.exe_path.clone(),
                    interpreter_arg,
                    ports: BTreeSet::new(),
                })
                .ports
                .insert(PortRef {
                    port: ls.port,
                    proto: ls.protocol,
                });
        }

        let db = &state.db;
        let now = Utc::now();
        let known: HashMap<AppId, App> = db
            .list_apps()
            .await?
            .into_iter()
            .map(|a| (a.id.clone(), a))
            .collect();
        let mut changed = false;

        for (id, l) in &live {
            let ports: Vec<PortRef> = l.ports.iter().copied().collect();
            if !known.contains_key(id) {
                info!("New app detected: {} ({id})", l.name);
                db.insert_app(&App {
                    id: id.clone(),
                    name: l.name.clone(),
                    process_name: l.process_name.clone(),
                    exe_path: l.exe_path.clone(),
                    interpreter_arg: l.interpreter_arg.clone(),
                    reviewed: false,
                    first_seen: now,
                    last_seen: now,
                    ports: vec![],
                    addresses: vec![],
                })
                .await?;
                self.record(
                    state,
                    NewActivity::new(
                        ActivityKind::AppDiscovered,
                        format!("New app {} is listening", l.name),
                    )
                    .app(id),
                )
                .await;
                self.emit(state, DaemonEvent::AppDiscovered(id.clone()));
                changed = true;
            } else {
                db.touch_app(id, &l.process_name, l.exe_path.as_deref(), now)
                    .await?;
            }
            let was_listening: BTreeSet<PortRef> = known
                .get(id)
                .map(|a| {
                    a.ports
                        .iter()
                        .filter(|p| p.listening)
                        .map(|p| PortRef {
                            port: p.port,
                            proto: p.proto,
                        })
                        .collect()
                })
                .unwrap_or_default();
            let new_ports = db.sync_app_ports(id, &ports, now).await?;
            if !new_ports.is_empty() || was_listening != l.ports {
                changed = true;
            }
        }

        // Apps that stopped listening keep their records, addresses and grants.
        for (id, app) in &known {
            if !live.contains_key(id) && app.ports.iter().any(|p| p.listening) {
                db.sync_app_ports(id, &[], now).await?;
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Give every app the addresses its layout calls for on every network; a failed
    /// allocation is retried on the next pass. Returns the number created.
    async fn ensure_addresses(&self, state: &AppState) -> anyhow::Result<usize> {
        let mode = state.db.address_mode().await?;
        let mut created = 0;
        for app in state.db.list_apps().await? {
            for nid in self.sorted_backend_ids() {
                let active = &self.backends[nid];
                let existing: Vec<&Address> = app
                    .addresses
                    .iter()
                    .filter(|a| a.network_id == *nid)
                    .collect();
                for ports in plan_addresses(mode, &app.ports_refs(), &existing) {
                    match active.backend.allocate(None) {
                        Ok(alloc) => {
                            self.alloc_failing.lock().unwrap().remove(nid);
                            let address = Address {
                                id: new_id(),
                                app_id: app.id.clone(),
                                network_id: nid.clone(),
                                ports,
                                locator: Locator::Ipv6 {
                                    addr: alloc.address,
                                },
                                created_at: Utc::now(),
                            };
                            state.db.insert_address(&address).await?;
                            info!(
                                "Assigned {} ({nid}) to {} ({})",
                                alloc.address, app.name, app.id
                            );
                            created += 1;
                        }
                        Err(e) => {
                            if self.alloc_failing.lock().unwrap().insert(nid.clone()) {
                                warn!("Cannot allocate an address on '{nid}', will retry: {e}");
                            }
                            break;
                        }
                    }
                }
            }
        }
        Ok(created)
    }

    /// Re-home stored addresses of prefix-based networks whose /64 changed: keep the
    /// interface ID, swap the prefix, update the DB, take the old addresses off the
    /// interface, apply the ruleset that covers the new ones and only then add them.
    async fn rehome_prefix_changes(&self, state: &AppState) {
        let mut moves: Vec<(String, Ipv6Addr, Ipv6Addr)> = Vec::new();
        let addresses = match state.db.list_addresses().await {
            Ok(a) => a,
            Err(e) => {
                warn!("Failed to list addresses for prefix check: {e}");
                return;
            }
        };
        for network_id in self.sorted_backend_ids() {
            let active = &self.backends[network_id];
            let prefix = match active.backend.current_prefix() {
                Ok(Some(p)) if p.len == 64 => p,
                Ok(_) => continue,
                Err(e) => {
                    warn!("Cannot read current prefix of backend '{network_id}': {e}");
                    continue;
                }
            };
            let iface = active.config.backend.interface();
            for a in addresses.iter().filter(|a| a.network_id == *network_id) {
                let Some(old) = a.locator.ipv6() else {
                    continue;
                };
                if same_prefix64(old, prefix.addr) {
                    continue;
                }
                let new = with_prefix64(prefix.addr, iid_of(old));
                info!("Prefix of backend '{network_id}' changed: moving {old} to {new}");
                match state.db.update_address_ipv6(&a.id, new).await {
                    Ok(_) => moves.push((iface.to_string(), old, new)),
                    Err(e) => error!("Failed to save re-homed address: {e}"),
                }
            }
        }
        if moves.is_empty() {
            return;
        }

        // Old addresses leave the interface before the ruleset stops covering them; new
        // ones are added only once a ruleset that covers them is in place. Without one the
        // ensure-present pass adds them after the next successful apply.
        self.remove_from_interface(moves.iter().map(|(i, old, _)| (i.clone(), *old)).collect())
            .await;
        // Disabled: the apply was a no-op, and nothing may put addresses back.
        let applied = self.apply_firewall(state).await.is_ok();
        if applied && !state.db.disabled().await.unwrap_or(false) {
            for (iface, _, new) in moves {
                if let Err(e) = self.network.add_address(&iface, new, ADDRESS_PREFIX_LEN) {
                    warn!("Failed to add {new} to {iface}: {e}");
                }
            }
        }
        self.emit(state, DaemonEvent::AppsChanged);
    }

    /// Re-add expected addresses that are missing from their interface, e.g. after
    /// Yggdrasil restarted and recreated its tun. Interfaces that don't exist are skipped.
    /// Does nothing while the last ruleset apply failed: an address no scope covers would
    /// be exposed.
    async fn ensure_addresses_present(&self, state: &AppState) {
        if state.db.disabled().await.unwrap_or(false) {
            return;
        }
        if self.apply_failed.load(Ordering::Relaxed) {
            debug!("Not adding addresses: the firewall ruleset is not in place");
            return;
        }
        let mut expected: HashMap<String, Vec<Ipv6Addr>> = HashMap::new();
        for a in state.db.list_addresses().await.unwrap_or_default() {
            if let (Some(addr), Some(iface)) = (a.locator.ipv6(), self.interface_of(&a.network_id))
            {
                expected.entry(iface.to_string()).or_default().push(addr);
            }
        }

        for (iface, wanted) in expected {
            let present = match self.network.list_addresses(&iface) {
                Ok(p) => {
                    self.unavailable_ifaces.lock().unwrap().remove(&iface);
                    p
                }
                Err(e) => {
                    // Log once per outage, not on every poll.
                    if self
                        .unavailable_ifaces
                        .lock()
                        .unwrap()
                        .insert(iface.clone())
                    {
                        warn!("Interface {iface} unavailable, skipping address check: {e}");
                    }
                    continue;
                }
            };
            for addr in wanted {
                if present.contains(&addr) {
                    continue;
                }
                match self.network.add_address(&iface, addr, ADDRESS_PREFIX_LEN) {
                    Ok(()) => info!("Added address {addr} to {iface}"),
                    Err(e) => warn!("Failed to add {addr} to {iface}: {e}"),
                }
            }
        }
    }

    // ─── Counters, metrics, exposure ─────────────────────────────────────────

    /// Read the firewall's counters and fold them into the metrics.
    async fn poll_counters(&self) {
        let fw = self.firewall.clone();
        let counters = match tokio::task::spawn_blocking(move || fw.counters()).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                debug!("Could not read firewall counters: {e}");
                return;
            }
            Err(e) => {
                warn!("Counter task failed: {e}");
                return;
            }
        };
        let keys = self.counter_keys.lock().unwrap();
        self.metrics.record(counters.into_iter().filter_map(|c| {
            let key = keys.get(&c.id)?.clone();
            Some((c.id, key, c.packets, c.bytes))
        }));
    }

    async fn refresh_metric_counts(&self, state: &AppState) {
        let db = &state.db;
        let (Ok(apps), Ok(peers), Ok(grants)) = (
            db.list_apps().await,
            db.list_peers().await,
            db.list_grants().await,
        ) else {
            return;
        };
        let addresses = apps.iter().map(|a| a.addresses.len()).sum();
        self.metrics
            .set_counts(apps.len(), addresses, peers.len(), grants.len());
    }

    /// Report remote-admin listeners (sshd, RDP) that sit inside a protected scope (an
    /// overlay or a protected host interface) that no grant reaches: they are cut off
    /// from there. Once per app and scope, until the situation clears.
    async fn check_remote_admin(
        &self,
        state: &AppState,
        sockets: &[socketguard_core::ListeningSocket],
    ) {
        let Ok(snapshot) = self.gather_snapshot(state).await else {
            return;
        };
        // (scope key, interface, network id): the key is the network id when the interface
        // belongs to a network, else the interface name.
        let mut scopes: Vec<(String, String, Option<String>)> = Vec::new();
        for n in &snapshot.networks {
            if let (NetworkKind::Yggdrasil, Some(iface)) = (n.kind, &n.interface) {
                scopes.push((n.id.clone(), iface.clone(), Some(n.id.clone())));
            }
        }
        for iface in &snapshot.protect_host {
            let net = snapshot
                .networks
                .iter()
                .find(|n| n.interface.as_deref() == Some(iface));
            let key = net.map(|n| n.id.clone()).unwrap_or_else(|| iface.clone());
            if !scopes.iter().any(|(k, _, _)| *k == key) {
                scopes.push((key, iface.clone(), net.map(|n| n.id.clone())));
            }
        }
        let mut current: HashSet<(String, String)> = HashSet::new();
        let mut fresh = Vec::new();
        for (key, iface, net_id) in scopes {
            let host = HostInterface {
                addrs: self
                    .network
                    .list_addresses(&iface)
                    .unwrap_or_default()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                name: iface,
            };
            let Err(risks) = ruleset::check_protect_host(&snapshot, sockets, &[host]) else {
                continue;
            };
            for risk in risks {
                if current.insert((risk.app_id.clone(), key.clone())) {
                    fresh.push((key.clone(), net_id.clone(), risk));
                }
            }
        }
        let new: Vec<_> = {
            let mut seen = self.exposed_reported.lock().unwrap();
            let new = fresh
                .into_iter()
                .filter(|(key, _, risk)| !seen.contains(&(risk.app_id.clone(), key.clone())))
                .collect();
            *seen = current;
            new
        };
        for (key, net_id, risk) in new {
            let message = format!(
                "Remote administration is cut off: {} (port {}/{}) is inside the protected scope {key} and no grant reaches it",
                risk.process_name, risk.port, risk.protocol
            );
            warn!("{message}");
            let mut act =
                NewActivity::new(ActivityKind::RemoteAdminExposed, message).app(&risk.app_id);
            act.network_id = net_id;
            act.port = Some(risk.port);
            act.proto = Some(risk.protocol);
            self.record(state, act).await;
        }
    }

    // ─── Drops ───────────────────────────────────────────────────────────────

    /// Fold the pending drop events into per-minute aggregates and write the closed
    /// minutes as Blocked activity.
    async fn flush_drops(&self, state: &AppState) {
        let events: Vec<DropEvent> = std::mem::take(&mut *self.drops.lock().unwrap());
        let now_minute = Utc::now().timestamp() / 60;
        let closed: Vec<(DropKey, u32)> = {
            let mut agg = self.drop_agg.lock().unwrap();
            for ev in events {
                let secs = ev
                    .at
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let key = (ev.src, ev.dst, ev.port, ev.proto, secs / 60);
                if agg.len() < MAX_DROP_KEYS || agg.contains_key(&key) {
                    *agg.entry(key).or_default() += 1;
                }
            }
            let keys: Vec<DropKey> = agg.keys().filter(|k| k.4 < now_minute).copied().collect();
            keys.into_iter()
                .filter_map(|k| agg.remove(&k).map(|c| (k, c)))
                .collect()
        };
        if closed.is_empty() {
            return;
        }

        let apps = state.db.list_apps().await.unwrap_or_default();
        let mut by_dst: HashMap<Ipv6Addr, (&App, &Address)> = HashMap::new();
        for app in &apps {
            for a in &app.addresses {
                if let Some(ip) = a.locator.ipv6() {
                    by_dst.insert(ip, (app, a));
                }
            }
        }
        let records: Vec<NewActivity> = closed
            .into_iter()
            .map(|((src, dst, port, proto, minute), count)| {
                let target = match dst {
                    IpAddr::V6(d) => by_dst.get(&d).copied(),
                    IpAddr::V4(_) => None,
                };
                let what = match (port, proto) {
                    (Some(p), Some(pr)) => format!(" port {p}/{pr}"),
                    _ => String::new(),
                };
                let message = match target {
                    Some((app, _)) => format!("Blocked {src} from {}{what}", app.name),
                    None => format!("Blocked {src} from {dst}{what}"),
                };
                let mut n = NewActivity::new(ActivityKind::Blocked, message);
                n.at = chrono::DateTime::from_timestamp(minute * 60, 0).unwrap_or_else(Utc::now);
                n.app_id = target.map(|(app, _)| app.id.clone());
                n.network_id = target.map(|(_, a)| a.network_id.clone());
                n.src = Some(src);
                n.port = port;
                n.proto = proto;
                n.count = count;
                n
            })
            .collect();
        if let Err(e) = state.db.insert_activity(&records).await {
            warn!("Could not record blocked connections: {e}");
        }
        self.emit(state, DaemonEvent::Activity);
    }

    // ─── Queries ─────────────────────────────────────────────────────────────

    pub async fn list_apps(
        &self,
        state: &AppState,
        pending_only: bool,
    ) -> Result<Vec<App>, EngineError> {
        let mut apps = state.db.list_apps().await?;
        if pending_only {
            apps.retain(|a| !a.reviewed);
        }
        Ok(apps)
    }

    /// An app with its addresses, ports and grants (with reach).
    pub async fn get_app(&self, state: &AppState, id: &str) -> Result<AppDetail, EngineError> {
        let app = state
            .db
            .get_app(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("app {id}")))?;
        let grants = self
            .list_grants(
                state,
                GrantFilter {
                    app_id: Some(id.to_string()),
                    ..Default::default()
                },
            )
            .await?;
        Ok(AppDetail {
            counters: self.metrics.app_counters(&app.id),
            app,
            grants,
        })
    }

    pub async fn list_peers(&self, state: &AppState) -> Result<Vec<Peer>, EngineError> {
        Ok(state.db.list_peers().await?)
    }

    pub async fn get_peer(&self, state: &AppState, id: &str) -> Result<Peer, EngineError> {
        state
            .db
            .get_peer(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("peer {id}")))
    }

    pub async fn list_groups(&self, state: &AppState) -> Result<Vec<PeerGroup>, EngineError> {
        Ok(state.db.list_groups().await?)
    }

    pub async fn get_group(&self, state: &AppState, id: &str) -> Result<PeerGroup, EngineError> {
        state
            .db
            .get_group(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("peer group {id}")))
    }

    /// Grants with the reach the daemon computes for each network they apply to.
    pub async fn list_grants(
        &self,
        state: &AppState,
        filter: GrantFilter,
    ) -> Result<Vec<GrantView>, EngineError> {
        let db = &state.db;
        let peers: HashMap<String, Peer> = db
            .list_peers()
            .await?
            .into_iter()
            .map(|p| (p.id.clone(), p))
            .collect();
        let groups: HashMap<String, PeerGroup> = db
            .list_groups()
            .await?
            .into_iter()
            .map(|g| (g.id.clone(), g))
            .collect();
        let networks = self.networks();
        let mut out = Vec::new();
        for grant in db.list_grants().await? {
            if filter.app_id.as_ref().is_some_and(|a| *a != grant.app_id) {
                continue;
            }
            if let Some(pid) = &filter.peer_id {
                let hit = match &grant.subject {
                    Subject::Peer(p) => p == pid,
                    Subject::Group(g) => groups.get(g).is_some_and(|g| g.members.contains(pid)),
                    Subject::Anyone => false,
                };
                if !hit {
                    continue;
                }
            }
            if let Some(gid) = &filter.group_id {
                if grant.subject != Subject::Group(gid.clone()) {
                    continue;
                }
            }
            let creds: Vec<Credential> = match &grant.subject {
                Subject::Anyone => Vec::new(),
                Subject::Peer(p) => peers
                    .get(p)
                    .map(|p| p.credentials.clone())
                    .unwrap_or_default(),
                Subject::Group(g) => groups
                    .get(g)
                    .into_iter()
                    .flat_map(|g| g.members.iter())
                    .filter_map(|m| peers.get(m))
                    .flat_map(|p| p.credentials.clone())
                    .collect(),
            };
            let reach = grant_reach(
                &grant.subject,
                &creds,
                grant.network_id.as_deref(),
                &networks,
            );
            out.push(GrantView { grant, reach });
        }
        Ok(out)
    }

    pub async fn get_grant(&self, state: &AppState, id: &str) -> Result<GrantView, EngineError> {
        let grant = state
            .db
            .get_grant(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("grant {id}")))?;
        self.list_grants(
            state,
            GrantFilter {
                app_id: Some(grant.app_id.clone()),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .find(|g| g.grant.id == id)
        .ok_or_else(|| EngineError::NotFound(format!("grant {id}")))
    }

    pub async fn settings(&self, state: &AppState) -> Result<Settings, EngineError> {
        Ok(state.db.settings().await?)
    }

    pub async fn activity(
        &self,
        state: &AppState,
        query: &ActivityQuery,
    ) -> Result<Vec<ActivityRecord>, EngineError> {
        Ok(state.db.list_activity(query).await?)
    }

    // ─── Settings ────────────────────────────────────────────────────────────

    /// Choose how new apps and ports get addresses; existing layouts are untouched.
    pub async fn set_address_mode(
        &self,
        state: &AppState,
        mode: AddressMode,
    ) -> Result<(), EngineError> {
        state.db.set_address_mode(mode).await?;
        self.emit(state, DaemonEvent::SettingsChanged);
        Ok(())
    }

    // ─── Apps ────────────────────────────────────────────────────────────────

    /// Mark an app reviewed (or pending again). It stays closed until granted.
    pub async fn review_app(
        &self,
        state: &AppState,
        id: &str,
        reviewed: bool,
    ) -> Result<(), EngineError> {
        if !state.db.set_reviewed(id, reviewed).await? {
            return Err(EngineError::NotFound(format!("app {id}")));
        }
        self.emit(state, DaemonEvent::AppsChanged);
        Ok(())
    }

    /// Forget an app: its addresses leave the interfaces, then it and its grants go. It
    /// reappears as pending the next time it listens.
    pub async fn delete_app(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let app = state
            .db
            .get_app(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("app {id}")))?;
        self.remove_from_interface(self.interface_addrs(&app.addresses))
            .await;
        state.db.delete_app(id).await?;
        self.apply_firewall(state).await?;
        self.record(
            state,
            NewActivity::new(
                ActivityKind::AppRemoved,
                format!("Removed app {}", app.name),
            )
            .app(id),
        )
        .await;
        self.emit(state, DaemonEvent::AppsChanged);
        self.emit(state, DaemonEvent::GrantsChanged);
        Ok(())
    }

    fn interface_addrs(&self, addresses: &[Address]) -> Vec<(String, Ipv6Addr)> {
        addresses
            .iter()
            .filter_map(|a| {
                Some((
                    self.interface_of(&a.network_id)?.to_string(),
                    a.locator.ipv6()?,
                ))
            })
            .collect()
    }

    /// Give `port` of an app its own address on a network.
    pub async fn split(
        &self,
        state: &AppState,
        app_id: &str,
        network_id: &str,
        port: PortRef,
    ) -> Result<Address, EngineError> {
        let app = state
            .db
            .get_app(app_id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?;
        let active = self
            .backends
            .get(network_id)
            .ok_or_else(|| EngineError::NotFound(format!("network {network_id}")))?;
        if !app
            .ports
            .iter()
            .any(|p| p.port == port.port && p.proto == port.proto)
        {
            return Err(EngineError::Invalid(format!(
                "{} has no port {port}",
                app.name
            )));
        }
        // The port may sit in an Only address with others; it moves out of that one.
        let mut shrink: Option<(&Address, Vec<PortRef>)> = None;
        for a in app.addresses.iter().filter(|a| a.network_id == network_id) {
            if let PortSet::Only(list) = &a.ports {
                if list.contains(&port) {
                    if list.len() == 1 {
                        return Err(EngineError::Conflict(format!(
                            "port {port} already has its own address"
                        )));
                    }
                    shrink = Some((a, list.iter().copied().filter(|p| *p != port).collect()));
                }
            }
        }
        let alloc = active
            .backend
            .allocate(None)
            .map_err(|e| EngineError::Conflict(format!("cannot allocate an address: {e}")))?;
        let address = Address {
            id: new_id(),
            app_id: app_id.to_string(),
            network_id: network_id.to_string(),
            ports: PortSet::Only(vec![port]),
            locator: Locator::Ipv6 {
                addr: alloc.address,
            },
            created_at: Utc::now(),
        };
        state.db.insert_address(&address).await?;
        if let Some((a, rest)) = shrink {
            state
                .db
                .update_address_ports(&a.id, &PortSet::Only(rest))
                .await?;
        }
        self.apply_and_ensure(state).await?;
        self.emit(state, DaemonEvent::AppsChanged);
        Ok(address)
    }

    /// Merge addresses of one app on one network into the first listed; the ports of the
    /// others move onto it and their addresses go.
    pub async fn merge(
        &self,
        state: &AppState,
        app_id: &str,
        network_id: &str,
        address_ids: &[AddressId],
    ) -> Result<Address, EngineError> {
        let app = state
            .db
            .get_app(app_id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("app {app_id}")))?;
        let unique: BTreeSet<&AddressId> = address_ids.iter().collect();
        if unique.len() < 2 || unique.len() != address_ids.len() {
            return Err(EngineError::Invalid(
                "merge needs at least two different addresses".into(),
            ));
        }
        let mut picked: Vec<&Address> = Vec::new();
        for id in address_ids {
            let a = app
                .addresses
                .iter()
                .find(|a| a.id == *id && a.network_id == network_id)
                .ok_or_else(|| {
                    EngineError::NotFound(format!("address {id} of this app on {network_id}"))
                })?;
            picked.push(a);
        }
        let merged = if picked.iter().any(|a| a.ports == PortSet::All) {
            PortSet::All
        } else {
            PortSet::Only(
                picked
                    .iter()
                    .flat_map(|a| match &a.ports {
                        PortSet::Only(l) => l.clone(),
                        PortSet::All => Vec::new(),
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            )
        };
        let keep = picked[0];
        let gone: Vec<Address> = picked[1..].iter().map(|a| (*a).clone()).collect();
        // The others' addresses leave the interface before their rules go.
        self.remove_from_interface(self.interface_addrs(&gone))
            .await;
        state.db.update_address_ports(&keep.id, &merged).await?;
        for a in &gone {
            state.db.delete_address(&a.id).await?;
        }
        self.apply_and_ensure(state).await?;
        self.emit(state, DaemonEvent::AppsChanged);
        let mut out = keep.clone();
        out.ports = merged;
        Ok(out)
    }

    // ─── Peers ───────────────────────────────────────────────────────────────

    fn clean_label(label: &str, what: &str) -> Result<String, EngineError> {
        let label = label.trim();
        if label.is_empty() {
            return Err(EngineError::Invalid(format!(
                "{what} label must not be empty"
            )));
        }
        Ok(label.to_string())
    }

    async fn new_credential(
        &self,
        state: &AppState,
        input: &NewCredential,
    ) -> Result<Credential, EngineError> {
        let (kind, value) = normalize_credential(input.kind, &input.value)?;
        if let Some(owner) = state.db.find_credential_owner(kind, &value).await? {
            let label = state
                .db
                .get_peer(&owner)
                .await?
                .map(|p| p.label)
                .unwrap_or(owner);
            return Err(EngineError::Conflict(format!(
                "{kind} {value} already belongs to peer {label}"
            )));
        }
        Ok(Credential {
            id: new_id(),
            kind,
            value,
            label: input.label.clone().filter(|l| !l.trim().is_empty()),
        })
    }

    fn conflict_or_internal(e: anyhow::Error, what: &str) -> EngineError {
        if state::is_unique_violation(&e) {
            EngineError::Conflict(format!("{what} already exists"))
        } else {
            EngineError::Internal(e)
        }
    }

    pub async fn create_peer(
        &self,
        state: &AppState,
        label: &str,
        credentials: &[NewCredential],
    ) -> Result<Peer, EngineError> {
        let label = Self::clean_label(label, "peer")?;
        let mut creds: Vec<Credential> = Vec::new();
        for input in credentials {
            let c = self.new_credential(state, input).await?;
            if creds.iter().any(|x| x.kind == c.kind && x.value == c.value) {
                return Err(EngineError::Invalid(format!(
                    "{} {} is listed twice",
                    c.kind, c.value
                )));
            }
            creds.push(c);
        }
        let peer = Peer {
            id: new_id(),
            label: label.clone(),
            credentials: creds,
            groups: vec![],
            created_at: Utc::now(),
        };
        state
            .db
            .insert_peer(&peer)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("peer {label}")))?;
        self.record(
            state,
            NewActivity::new(ActivityKind::PeerAdded, format!("Added peer {label}")).peer(&peer.id),
        )
        .await;
        self.emit(state, DaemonEvent::PeersChanged);
        Ok(peer)
    }

    pub async fn update_peer_label(
        &self,
        state: &AppState,
        id: &str,
        label: &str,
    ) -> Result<Peer, EngineError> {
        let label = Self::clean_label(label, "peer")?;
        if !state
            .db
            .rename_peer(id, &label)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("peer {label}")))?
        {
            return Err(EngineError::NotFound(format!("peer {id}")));
        }
        self.record(
            state,
            NewActivity::new(
                ActivityKind::PeerChanged,
                format!("Renamed peer to {label}"),
            )
            .peer(id),
        )
        .await;
        self.emit(state, DaemonEvent::PeersChanged);
        self.get_peer(state, id).await
    }

    /// Delete a peer; the grants that name it go with it, and with them their rules.
    pub async fn delete_peer(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let peer = self.get_peer(state, id).await?;
        state.db.delete_peer(id).await?;
        self.apply_firewall(state).await?;
        self.record(
            state,
            NewActivity::new(
                ActivityKind::PeerRemoved,
                format!("Removed peer {}", peer.label),
            )
            .peer(id),
        )
        .await;
        self.emit(state, DaemonEvent::PeersChanged);
        self.emit(state, DaemonEvent::GrantsChanged);
        Ok(())
    }

    pub async fn add_credential(
        &self,
        state: &AppState,
        peer_id: &str,
        input: &NewCredential,
    ) -> Result<Credential, EngineError> {
        let peer = self.get_peer(state, peer_id).await?;
        let c = self.new_credential(state, input).await?;
        state
            .db
            .add_credential(peer_id, &c)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("{} {}", c.kind, c.value)))?;
        self.apply_firewall(state).await?;
        self.record(
            state,
            NewActivity::new(
                ActivityKind::PeerChanged,
                format!("Added {} to peer {}", c.kind, peer.label),
            )
            .peer(peer_id),
        )
        .await;
        self.emit(state, DaemonEvent::PeersChanged);
        self.emit(state, DaemonEvent::GrantsChanged);
        Ok(c)
    }

    pub async fn remove_credential(
        &self,
        state: &AppState,
        peer_id: &str,
        cred_id: &str,
    ) -> Result<(), EngineError> {
        let peer = self.get_peer(state, peer_id).await?;
        if !state.db.remove_credential(peer_id, cred_id).await? {
            return Err(EngineError::NotFound(format!("credential {cred_id}")));
        }
        self.apply_firewall(state).await?;
        self.record(
            state,
            NewActivity::new(
                ActivityKind::PeerChanged,
                format!("Removed a credential from peer {}", peer.label),
            )
            .peer(peer_id),
        )
        .await;
        self.emit(state, DaemonEvent::PeersChanged);
        self.emit(state, DaemonEvent::GrantsChanged);
        Ok(())
    }

    // ─── Peer groups ─────────────────────────────────────────────────────────

    pub async fn create_group(
        &self,
        state: &AppState,
        label: &str,
        members: &[String],
    ) -> Result<PeerGroup, EngineError> {
        let label = Self::clean_label(label, "group")?;
        self.check_peers_exist(state, members).await?;
        let group = PeerGroup {
            id: new_id(),
            label: label.clone(),
            members: members
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            created_at: Utc::now(),
        };
        state
            .db
            .insert_group(&group)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("group {label}")))?;
        self.emit(state, DaemonEvent::PeersChanged);
        Ok(group)
    }

    pub async fn rename_group(
        &self,
        state: &AppState,
        id: &str,
        label: &str,
    ) -> Result<PeerGroup, EngineError> {
        let label = Self::clean_label(label, "group")?;
        if !state
            .db
            .rename_group(id, &label)
            .await
            .map_err(|e| Self::conflict_or_internal(e, &format!("group {label}")))?
        {
            return Err(EngineError::NotFound(format!("peer group {id}")));
        }
        self.emit(state, DaemonEvent::PeersChanged);
        self.get_group(state, id).await
    }

    pub async fn delete_group(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        self.get_group(state, id).await?;
        state.db.delete_group(id).await?;
        self.apply_firewall(state).await?;
        self.emit(state, DaemonEvent::PeersChanged);
        self.emit(state, DaemonEvent::GrantsChanged);
        Ok(())
    }

    /// Replace a group's members.
    pub async fn set_group_members(
        &self,
        state: &AppState,
        id: &str,
        peer_ids: &[String],
    ) -> Result<PeerGroup, EngineError> {
        self.get_group(state, id).await?;
        self.check_peers_exist(state, peer_ids).await?;
        state.db.set_group_members(id, peer_ids).await?;
        self.apply_firewall(state).await?;
        self.emit(state, DaemonEvent::PeersChanged);
        self.emit(state, DaemonEvent::GrantsChanged);
        self.get_group(state, id).await
    }

    async fn check_peers_exist(&self, state: &AppState, ids: &[String]) -> Result<(), EngineError> {
        let known: HashSet<String> = state
            .db
            .list_peers()
            .await?
            .into_iter()
            .map(|p| p.id)
            .collect();
        match ids.iter().find(|i| !known.contains(*i)) {
            Some(missing) => Err(EngineError::NotFound(format!("peer {missing}"))),
            None => Ok(()),
        }
    }

    // ─── Grants ──────────────────────────────────────────────────────────────

    /// Create a grant. Rejected: a grant on Local ([`EngineError::LocalNetwork`]), a grant
    /// to Anyone without `confirm_open`, and unknown apps, ports, networks or subjects.
    pub async fn create_grant(
        &self,
        state: &AppState,
        req: &NewGrant,
    ) -> Result<GrantView, EngineError> {
        let app = state
            .db
            .get_app(&req.app_id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("app {}", req.app_id)))?;
        if let Some(nid) = &req.network_id {
            let net = self
                .networks()
                .into_iter()
                .find(|n| n.id == *nid)
                .ok_or_else(|| EngineError::NotFound(format!("network {nid}")))?;
            if !net.grants_apply {
                return Err(EngineError::LocalNetwork);
            }
        }
        if let Some(p) = req.port {
            if !app
                .ports
                .iter()
                .any(|x| x.port == p.port && x.proto == p.proto)
            {
                return Err(EngineError::Invalid(format!(
                    "{} has no port {p}",
                    app.name
                )));
            }
        }
        let subject_label = match &req.subject {
            Subject::Anyone => {
                if !req.confirm_open {
                    return Err(EngineError::ConfirmationRequired);
                }
                "Anyone".to_string()
            }
            Subject::Peer(id) => self.get_peer(state, id).await?.label,
            Subject::Group(id) => self.get_group(state, id).await?.label,
        };
        let existing = state.db.list_grants().await?;
        if existing.iter().any(|g| {
            g.app_id == req.app_id
                && g.port == req.port
                && g.network_id == req.network_id
                && g.subject == req.subject
        }) {
            return Err(EngineError::Conflict("this grant already exists".into()));
        }
        let grant = Grant {
            id: new_id(),
            app_id: req.app_id.clone(),
            port: req.port,
            network_id: req.network_id.clone(),
            subject: req.subject.clone(),
            created_at: Utc::now(),
        };
        state.db.insert_grant(&grant).await?;
        self.apply_firewall(state).await?;
        let peer_id = match &grant.subject {
            Subject::Peer(id) => Some(id.clone()),
            _ => None,
        };
        let mut act = NewActivity::new(
            ActivityKind::GrantAdded,
            format!("Granted {} access to {}", subject_label, app.name),
        )
        .app(&app.id);
        act.peer_id = peer_id;
        act.network_id = grant.network_id.clone();
        self.record(state, act).await;
        self.emit(state, DaemonEvent::GrantsChanged);
        self.get_grant(state, &grant.id).await
    }

    pub async fn delete_grant(&self, state: &AppState, id: &str) -> Result<(), EngineError> {
        let grant = state
            .db
            .get_grant(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("grant {id}")))?;
        state.db.delete_grant(id).await?;
        self.apply_firewall(state).await?;
        let app_name = state
            .db
            .get_app(&grant.app_id)
            .await?
            .map(|a| a.name)
            .unwrap_or_else(|| grant.app_id.clone());
        let mut act = NewActivity::new(
            ActivityKind::GrantRemoved,
            format!("Removed a grant for {app_name}"),
        )
        .app(&grant.app_id);
        if let Subject::Peer(p) = &grant.subject {
            act.peer_id = Some(p.clone());
        }
        act.network_id = grant.network_id.clone();
        self.record(state, act).await;
        self.emit(state, DaemonEvent::GrantsChanged);
        Ok(())
    }
}

/// Attribute every rule and scope of `desired` for the metrics. Rule ids are
/// `a:<address>:<port>:<proto>:<grant>[:<iif>]` (see `ruleset::build_with_warnings`).
fn counter_keys(snap: &Snapshot, desired: &DesiredRuleset) -> HashMap<String, CounterKey> {
    let mut out = HashMap::new();
    for sc in &desired.scopes {
        out.insert(
            sc.id.clone(),
            CounterKey::Scope {
                scope: sc.id.clone(),
            },
        );
    }
    let peers: HashMap<&str, &str> = snap
        .peers
        .iter()
        .map(|p| (p.id.as_str(), p.label.as_str()))
        .collect();
    let groups: HashMap<&str, &str> = snap
        .groups
        .iter()
        .map(|g| (g.id.as_str(), g.label.as_str()))
        .collect();
    for rule in &desired.rules {
        let mut parts = rule.id.splitn(5, ':');
        let (Some("a"), Some(address_id), Some(_), Some(_), Some(rest)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        let grant_id = rest.split(':').next().unwrap_or(rest);
        let Some((app, address)) = snap.apps.iter().find_map(|a| {
            a.addresses
                .iter()
                .find(|x| x.id == address_id)
                .map(|x| (a, x))
        }) else {
            continue;
        };
        let Some(grant) = snap.grants.iter().find(|g| g.id == grant_id) else {
            continue;
        };
        let subject = match &grant.subject {
            Subject::Anyone => "Anyone".to_string(),
            Subject::Peer(id) => peers.get(id.as_str()).unwrap_or(&"unknown").to_string(),
            Subject::Group(id) => groups.get(id.as_str()).unwrap_or(&"unknown").to_string(),
        };
        out.insert(
            rule.id.clone(),
            CounterKey::Rule {
                app_id: app.id.clone(),
                app: app.name.clone(),
                network: address.network_id.clone(),
                subject,
            },
        );
    }
    out
}

trait AppPortsExt {
    fn ports_refs(&self) -> Vec<PortRef>;
}

impl AppPortsExt for App {
    fn ports_refs(&self) -> Vec<PortRef> {
        self.ports
            .iter()
            .map(|p| PortRef {
                port: p.port,
                proto: p.proto,
            })
            .collect()
    }
}

/// Which new addresses an app needs on a network, given its ports and what it has there.
///
/// - Per app: one `All` address, only if there is none and nothing else serves the
///   ports (an app whose addresses were all split or merged into `Only` sets keeps that
///   layout, but a port none of them names gets an `All`).
/// - Per port: an `Only([port])` address for each port that no address serves yet; an
///   existing `All` serves every port that is not claimed.
///
/// Existing layouts are never rearranged.
pub fn plan_addresses(mode: AddressMode, ports: &[PortRef], existing: &[&Address]) -> Vec<PortSet> {
    let has_all = existing.iter().any(|a| a.ports == PortSet::All);
    let claimed: BTreeSet<PortRef> = existing
        .iter()
        .filter_map(|a| match &a.ports {
            PortSet::Only(l) => Some(l.iter().copied()),
            PortSet::All => None,
        })
        .flatten()
        .collect();
    let unserved: Vec<PortRef> = ports
        .iter()
        .copied()
        .filter(|p| !has_all && !claimed.contains(p))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    match mode {
        AddressMode::PerApp => {
            if existing.is_empty() || (!has_all && !unserved.is_empty()) {
                vec![PortSet::All]
            } else {
                vec![]
            }
        }
        AddressMode::PerPort => unserved
            .into_iter()
            .map(|p| PortSet::Only(vec![p]))
            .collect(),
    }
}

/// Set the `disabled` latch, then remove the firewall rules and every SocketGuard address
/// in the DB. Needs only the database and the network-to-interface map, so `--disable`
/// works without an engine.
/// Addresses of a network that is no longer configured cannot be located and are left.
pub async fn disable_all(
    db: &Database,
    interfaces: &HashMap<String, String>,
    firewall: Arc<dyn Firewall>,
    network: Arc<dyn NetworkInterface>,
) -> anyhow::Result<()> {
    db.set_disabled(true).await?;
    let mut addrs: Vec<(String, Ipv6Addr)> = Vec::new();
    for a in db.list_addresses().await? {
        let Some(ip) = a.locator.ipv6() else {
            continue;
        };
        match interfaces.get(&a.network_id) {
            Some(iface) => addrs.push((iface.clone(), ip)),
            None => warn!(
                "Network '{}' is not configured; cannot remove {ip}",
                a.network_id
            ),
        }
    }
    tokio::task::spawn_blocking(move || {
        // Addresses first: removing the rules first would briefly expose them.
        for (iface, addr) in addrs {
            if let Err(e) = network.remove_address(&iface, addr) {
                warn!("Failed to remove {addr} from {iface}: {e}");
            }
        }
        firewall.disable()
    })
    .await?
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

    fn p(port: u16) -> PortRef {
        PortRef {
            port,
            proto: Protocol::Tcp,
        }
    }

    fn addr(ports: PortSet) -> Address {
        Address {
            id: new_id(),
            app_id: "a".into(),
            network_id: "n".into(),
            ports,
            locator: Locator::Ipv6 {
                addr: "fd00::1".parse().unwrap(),
            },
            created_at: Utc::now(),
        }
    }

    #[test]
    fn per_app_creates_one_all_address() {
        assert_eq!(
            plan_addresses(AddressMode::PerApp, &[p(80), p(443)], &[]),
            vec![PortSet::All]
        );
        let all = addr(PortSet::All);
        assert!(plan_addresses(AddressMode::PerApp, &[p(80), p(8080)], &[&all]).is_empty());
    }

    #[test]
    fn per_app_leaves_split_layouts_but_covers_new_ports() {
        let all = addr(PortSet::All);
        let only = addr(PortSet::Only(vec![p(80)]));
        assert!(plan_addresses(AddressMode::PerApp, &[p(80), p(443)], &[&all, &only]).is_empty());
        // Only addresses and no All: a port none of them names gets an All.
        let only2 = addr(PortSet::Only(vec![p(80), p(443)]));
        assert!(plan_addresses(AddressMode::PerApp, &[p(80), p(443)], &[&only2]).is_empty());
        assert_eq!(
            plan_addresses(AddressMode::PerApp, &[p(80), p(443), p(9)], &[&only2]),
            vec![PortSet::All]
        );
    }

    #[test]
    fn per_port_creates_one_address_per_unserved_port() {
        assert_eq!(
            plan_addresses(AddressMode::PerPort, &[p(80), p(443), p(80)], &[]),
            vec![PortSet::Only(vec![p(80)]), PortSet::Only(vec![p(443)])]
        );
        let only = addr(PortSet::Only(vec![p(80)]));
        assert_eq!(
            plan_addresses(AddressMode::PerPort, &[p(80), p(443)], &[&only]),
            vec![PortSet::Only(vec![p(443)])]
        );
        // An existing All serves everything not claimed: nothing to add.
        let all = addr(PortSet::All);
        assert!(plan_addresses(AddressMode::PerPort, &[p(80), p(443)], &[&all]).is_empty());
    }

    #[test]
    fn udp_and_tcp_ports_are_distinct() {
        let udp = PortRef {
            port: 53,
            proto: Protocol::Udp,
        };
        let plan = plan_addresses(AddressMode::PerPort, &[p(53), udp], &[]);
        assert_eq!(plan.len(), 2);
    }

    #[tokio::test]
    async fn disable_all_skips_networks_that_are_not_configured() {
        use crate::test_support::*;
        let db = Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();
        let now = Utc::now();
        db.insert_app(&App {
            id: "a".into(),
            name: "a".into(),
            process_name: "a".into(),
            exe_path: None,
            interpreter_arg: None,
            reviewed: false,
            first_seen: now,
            last_seen: now,
            ports: vec![],
            addresses: vec![],
        })
        .await
        .unwrap();
        for (net, ip) in [("known", "fd00::1"), ("gone", "fd00::2")] {
            let mut a = addr(PortSet::All);
            a.network_id = net.into();
            a.locator = Locator::Ipv6 {
                addr: ip.parse().unwrap(),
            };
            db.insert_address(&a).await.unwrap();
        }
        let calls = Arc::new(Mutex::new(vec![]));
        let ifaces = HashMap::from([("known".to_string(), "lo".to_string())]);
        disable_all(
            &db,
            &ifaces,
            Arc::new(MockFirewall::new(Arc::new(Mutex::new(vec![])))),
            Arc::new(MockNetworkInterface::new(calls.clone())),
        )
        .await
        .unwrap();
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(matches!(&calls[0], NetworkCall::RemoveAddress { iface, .. } if iface == "lo"));
    }
}
