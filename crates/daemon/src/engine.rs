use crate::backend::{self, iid_of, same_prefix64, with_prefix64, Ipv6Backend};
use crate::firewall::{self, DesiredRuleset, Firewall};
use crate::monitor::{self, SocketMonitor};
use crate::network::{self, NetworkInterface};
use crate::ruleset::{
    self, AclGroupSnapshot, BackendInfo, HostInterface, LockoutRisk, Snapshot, SocketGroupSnapshot,
    SocketSnapshot, PROTECT_HOST_KEY,
};
use crate::state::Database;
use crate::AppState;
use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use socketguard_core::{socket_id, ManagedSocket, Policy, SocketAddress, SocketGroupAddress};
use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

/// An unchanged ruleset is still re-applied every this many reconcile passes, which
/// corrects drift (e.g. someone deleting the table) without hammering `nft`.
const REAPPLY_EVERY: u32 = 30;

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
    /// The ruleset last applied successfully, to skip no-op applies.
    last_applied: Mutex<Option<DesiredRuleset>>,
    /// Reconcile passes since the last apply.
    passes_since_apply: AtomicU32,
    /// The last apply failed. Addresses are not added to interfaces then, because
    /// nothing would deny them.
    apply_failed: AtomicBool,
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
            last_applied: Mutex::default(),
            passes_since_apply: AtomicU32::new(0),
            apply_failed: AtomicBool::new(false),
        }
    }

    // ─── Firewall ────────────────────────────────────────────────────────────

    /// Gather the producer's input from the DB and the active backends.
    async fn gather_snapshot(&self, state: &AppState) -> anyhow::Result<Snapshot> {
        let db = &state.db;
        let mut sockets = Vec::new();
        for socket in db.list_sockets().await? {
            let acl = db.get_acl(&socket.id).await?;
            sockets.push(SocketSnapshot { socket, acl });
        }
        let mut acl_groups = Vec::new();
        for group in db.list_acl_groups().await? {
            let entries = db.get_acl_group_entries(&group.id).await?;
            acl_groups.push(AclGroupSnapshot { group, entries });
        }
        let mut socket_groups = Vec::new();
        for group in db.list_socket_groups().await? {
            let mut members = Vec::new();
            for sid in db.get_socket_group_members(&group.id).await? {
                if let Some(s) = db.get_socket(&sid).await? {
                    members.push((s.port, s.protocol));
                }
            }
            socket_groups.push(SocketGroupSnapshot {
                addresses: db.get_socket_group_addresses(&group.id).await?,
                acl: db.get_socket_group_acl_entries(&group.id).await?,
                members,
                group,
            });
        }
        let backends = self
            .backends
            .iter()
            .map(|(id, b)| BackendInfo {
                id: id.clone(),
                backend_type: b.config.backend.backend_type(),
                interface: b.config.backend.interface().to_string(),
            })
            .collect();
        let protect_host =
            ruleset::parse_protect_host(db.get_setting(PROTECT_HOST_KEY).await?.as_deref());
        Ok(Snapshot {
            sockets,
            acl_groups,
            socket_groups,
            backends,
            protect_host,
        })
    }

    /// Build the desired ruleset from the current state and apply it atomically. The
    /// caller holds the firewall lock. With `only_if_changed`, an unchanged ruleset is
    /// not re-sent (except every `REAPPLY_EVERY` passes).
    async fn apply_locked(&self, state: &AppState, only_if_changed: bool) -> anyhow::Result<()> {
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
    /// sockets, addresses, policies, ACLs, groups or backends.
    pub async fn apply_firewall(&self, state: &AppState) -> anyhow::Result<()> {
        let _lock = state.firewall_lock.lock().await;
        self.apply_locked(state, false).await
    }

    async fn apply_firewall_if_changed(&self, state: &AppState) -> anyhow::Result<()> {
        let _lock = state.firewall_lock.lock().await;
        self.apply_locked(state, true).await
    }

    /// Re-apply after a change to one socket's policy or ACL.
    pub async fn apply_socket_acl(&self, state: &AppState, socket_id: &str) -> anyhow::Result<()> {
        if state.db.get_socket(socket_id).await?.is_none() {
            anyhow::bail!("socket not found");
        }
        self.apply_firewall(state).await
    }

    /// Re-apply after a change to a socket group's policy, members or ACL.
    pub async fn apply_socket_group_acl(
        &self,
        state: &AppState,
        _group_id: &str,
    ) -> anyhow::Result<()> {
        self.apply_firewall(state).await
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
        let json = serde_json::to_string(&interfaces).map_err(anyhow::Error::from)?;
        state.db.set_setting(PROTECT_HOST_KEY, &json).await?;
        self.apply_firewall(state).await?;
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
        if let Err(e) = self.firewall.subscribe_drops(Box::new(|ev| {
            debug!(
                "Blocked {} -> {} port {:?} on {:?} (scope {:?})",
                ev.src, ev.dst, ev.port, ev.iif, ev.scope_id
            );
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
    pub async fn disable(&self, state: &AppState) -> anyhow::Result<()> {
        let _lock = state.firewall_lock.lock().await;
        *self.last_applied.lock().unwrap() = None;
        disable_all(&state.db, self.firewall.clone(), self.network.clone()).await
    }

    // ─── Backends ────────────────────────────────────────────────────────────

    /// Check if backends config has changed and apply additions/removals.
    /// Returns true if changes were detected.
    async fn check_config_change(&mut self, config: &DaemonConfig, state: &AppState) -> bool {
        let new_ids: Vec<String> = config.backends.iter().map(|b| b.id.clone()).collect();
        if new_ids == self.current_backend_ids {
            return false;
        }

        let old_ids: std::collections::HashSet<String> =
            self.current_backend_ids.iter().cloned().collect();
        let new_id_set: std::collections::HashSet<String> = new_ids.iter().cloned().collect();

        // Removed backends: clean up addresses
        let removed: Vec<String> = old_ids.difference(&new_id_set).cloned().collect();
        for old_id in &removed {
            info!("Backend '{}' removed from config", old_id);
            self.remove_backend_instance(state, old_id).await;
        }

        // Added backends: allocate addresses for all existing sockets
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

    /// Add a new backend instance and allocate addresses for all existing sockets.
    pub async fn add_backend_instance(&mut self, state: &AppState, inst: &BackendInstanceConfig) {
        let b = match backend::create_backend(&inst.backend, self.ula_global_id) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to create backend '{}': {e}", inst.id);
                return;
            }
        };

        let sockets = match state.db.list_sockets().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to list sockets for new backend: {e}");
                return;
            }
        };

        let iface = inst.backend.interface().to_string();
        let backend_id = inst.id.clone();
        let backend_type = inst.backend.backend_type();
        let mut allocated = 0;

        for socket in &sockets {
            // Skip if socket already has an address from this backend
            if socket.addresses.iter().any(|a| a.backend_id == backend_id) {
                continue;
            }

            match b.allocate(None) {
                Ok(alloc) => {
                    let addr = SocketAddress {
                        backend_id: backend_id.clone(),
                        backend_type,
                        address: alloc.address,
                        interface: iface.clone(),
                        prefix_len: alloc.prefix_len,
                        policy: socket.policy, // inherit socket's default policy
                    };

                    if let Err(e) = state.db.upsert_socket_address(&socket.id, &addr).await {
                        error!("Failed to save socket address: {e}");
                        continue;
                    }
                    allocated += 1;
                }
                Err(e) => {
                    error!("Failed to allocate address from '{}': {e}", backend_id);
                }
            }
        }

        // The ruleset (overlay scope, managed addresses) must know the backend before
        // its addresses go on the interface.
        self.backends.insert(
            inst.id.clone(),
            ActiveBackend {
                config: inst.clone(),
                backend: b,
            },
        );
        let _ = self.apply_firewall(state).await;
        self.ensure_addresses_present(state).await;

        info!(
            "Backend '{}' initialized, allocated {} addresses",
            inst.id, allocated
        );
    }

    /// Remove a backend instance: clean up all its addresses from interfaces, firewall, and DB.
    pub async fn remove_backend_instance(&mut self, state: &AppState, backend_id: &str) {
        // Remove from DB and get the addresses to clean up
        let deleted = match state.db.delete_addresses_by_backend(backend_id).await {
            Ok(d) => d,
            Err(e) => {
                error!(
                    "Failed to delete addresses for backend '{}': {e}",
                    backend_id
                );
                Vec::new()
            }
        };

        // Take the addresses off the interfaces first, then drop their rules.
        let mut join_set = JoinSet::new();
        for (_socket_id, addr) in deleted {
            let network = self.network.clone();
            join_set.spawn_blocking(move || {
                if let Err(e) = network.remove_address(&addr.interface, addr.address) {
                    warn!(
                        "Failed to remove address {} from {}: {e}",
                        addr.address, addr.interface
                    );
                }
            });
        }
        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                warn!("Remove address task failed: {e}");
            }
        }

        self.backends.remove(backend_id);
        let _ = self.apply_firewall(state).await;
        info!("Backend '{}' removed", backend_id);
    }

    // ─── Reconcile ───────────────────────────────────────────────────────────

    /// Reconcile: detect sockets, assign IPs, apply the firewall ruleset.
    pub async fn reconcile(&mut self, state: &AppState) -> anyhow::Result<()> {
        // Check for config changes
        let config = state.config.read().await;
        let config_snapshot = config.clone();
        drop(config);

        self.check_config_change(&config_snapshot, state).await;
        self.rehome_prefix_changes(state).await;

        // 1. Detect current listening sockets
        let current_sockets = match self.monitor.list_listening_sockets() {
            Ok(s) => {
                info!("Reconcile: detected {} listening sockets", s.len());
                s
            }
            Err(e) => {
                warn!("Failed to list sockets: {e}");
                return Ok(());
            }
        };

        let now = chrono::Utc::now();
        let mut had_new_sockets = false;

        // 2. Update known sockets, provision new ones (DB only; the ruleset and the
        // interface addresses follow below, in that order).
        for ls in &current_sockets {
            // Apply process filter
            if !config_snapshot.process_filter.matches(&ls.process_name) {
                continue;
            }

            let sid = socket_id(&ls.process_name, ls.port, ls.protocol);

            if let Ok(Some(mut existing)) = state.db.get_socket(&sid).await {
                existing.pid = ls.pid;
                existing.process_name = ls.process_name.clone();
                existing.exe_path = ls.exe_path.clone();
                existing.cmdline = ls.cmdline.clone();
                existing.last_seen = now;
                if let Err(e) = state.db.upsert_socket(&existing).await {
                    error!("Failed to update socket {sid}: {e}");
                }
                continue;
            }

            // New socket — allocate IPv6 from all active backends
            info!(
                "New socket detected: {}:{} (PID {} - {})",
                ls.protocol, ls.port, ls.pid, ls.process_name
            );

            let mut addresses = Vec::new();
            for (backend_id, active) in &self.backends {
                match active.backend.allocate(None) {
                    Ok(alloc) => {
                        addresses.push(SocketAddress {
                            backend_id: backend_id.clone(),
                            backend_type: alloc.backend,
                            address: alloc.address,
                            interface: active.config.backend.interface().to_string(),
                            prefix_len: alloc.prefix_len,
                            policy: Policy::Closed,
                        });
                    }
                    Err(e) => {
                        error!("Failed to allocate IPv6 from backend '{}': {e}", backend_id);
                    }
                }
            }

            if addresses.is_empty() && !self.backends.is_empty() {
                error!("Failed to allocate any addresses for socket {sid}");
                continue;
            }

            let managed = ManagedSocket {
                id: sid.clone(),
                pid: ls.pid,
                process_name: ls.process_name.clone(),
                port: ls.port,
                protocol: ls.protocol,
                addresses: addresses.clone(),
                policy: Policy::Closed,
                exe_path: ls.exe_path.clone(),
                cmdline: ls.cmdline.clone(),
                first_seen: now,
                last_seen: now,
                acl_group_id: None,
                socket_group_ids: vec![],
            };

            if let Err(e) = state.db.upsert_socket(&managed).await {
                error!("Failed to save socket: {e}");
                continue;
            }
            for addr in &addresses {
                if let Err(e) = state.db.upsert_socket_address(&sid, addr).await {
                    error!("Failed to save socket address: {e}");
                }
                info!(
                    "Assigned {} ({}) to {}:{} ({})",
                    addr.address, addr.backend_id, ls.process_name, ls.port, ls.protocol
                );
            }
            had_new_sockets = true;
        }

        // 3. Clean up stale sockets: addresses off the interfaces, then out of the DB.
        let stale_threshold =
            now - chrono::Duration::seconds(config_snapshot.poll_interval_secs as i64 * 3);

        let mut had_stale = false;
        if let Ok(stale) = state.db.stale_sockets(stale_threshold).await {
            had_stale = !stale.is_empty();
            let ids: Vec<String> = stale.iter().map(|s| s.id.clone()).collect();
            for s in &stale {
                info!(
                    "Cleaning up stale socket: {}:{} ({})",
                    s.process_name, s.port, s.id
                );
            }
            let network = self.network.clone();
            let addrs: Vec<_> = stale
                .into_iter()
                .flat_map(|s| s.addresses)
                .map(|a| (a.interface, a.address))
                .collect();
            let removed = tokio::task::spawn_blocking(move || {
                for (iface, addr) in addrs {
                    if let Err(e) = network.remove_address(&iface, addr) {
                        warn!("Failed to remove IPv6 {addr}: {e}");
                    }
                }
            })
            .await;
            if let Err(e) = removed {
                warn!("Stale cleanup task failed: {e}");
            }
            for id in ids {
                if let Err(e) = state.db.delete_socket(&id).await {
                    error!("Failed to delete socket {id}: {e}");
                }
            }
        }

        // 4. Ensure socket groups have addresses allocated for all active backends
        if let Ok(groups) = state.db.list_socket_groups().await {
            for group in &groups {
                let members = state
                    .db
                    .get_socket_group_members(&group.id)
                    .await
                    .unwrap_or_default();
                if !members.is_empty() {
                    if let Err(e) = self.ensure_socket_group_addresses(state, &group.id).await {
                        warn!(
                            "Failed to ensure socket group addresses for {}: {e}",
                            group.id
                        );
                    }
                }
            }
        }

        // 5. One ruleset for everything above, then the addresses it now covers.
        if let Err(e) = self.apply_firewall_if_changed(state).await {
            warn!("Reconcile: firewall not updated: {e}");
        }
        self.ensure_addresses_present(state).await;

        if had_new_sockets || had_stale {
            let _ = state.events.send(crate::api::DaemonEvent::SocketsChanged);
        }

        Ok(())
    }

    /// Re-home stored addresses of prefix-based backends whose /64 changed: keep the
    /// interface ID, swap the prefix, update the DB, take the old addresses off the
    /// interface, apply the ruleset that covers the new ones and only then add them.
    async fn rehome_prefix_changes(&self, state: &AppState) {
        let mut moves: Vec<(String, Ipv6Addr, Ipv6Addr, u8)> = Vec::new();
        for (backend_id, active) in &self.backends {
            let prefix = match active.backend.current_prefix() {
                Ok(Some(p)) if p.len == 64 => p,
                Ok(_) => continue,
                Err(e) => {
                    warn!("Cannot read current prefix of backend '{backend_id}': {e}");
                    continue;
                }
            };

            let sockets = match state.db.list_sockets().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to list sockets for prefix check: {e}");
                    continue;
                }
            };
            for socket in sockets {
                for addr in socket
                    .addresses
                    .iter()
                    .filter(|a| a.backend_id == *backend_id)
                {
                    if same_prefix64(addr.address, prefix.addr) {
                        continue;
                    }
                    let new = with_prefix64(prefix.addr, iid_of(addr.address));
                    info!(
                        "Prefix of backend '{backend_id}' changed: moving {} to {new}",
                        addr.address
                    );
                    let updated = SocketAddress {
                        address: new,
                        ..addr.clone()
                    };
                    match state.db.upsert_socket_address(&socket.id, &updated).await {
                        Ok(()) => {
                            moves.push((addr.interface.clone(), addr.address, new, addr.prefix_len))
                        }
                        Err(e) => error!("Failed to save re-homed address: {e}"),
                    }
                }
            }

            let groups = state.db.list_socket_groups().await.unwrap_or_default();
            for group in groups {
                let addrs = state
                    .db
                    .get_socket_group_addresses(&group.id)
                    .await
                    .unwrap_or_default();
                for addr in addrs.iter().filter(|a| a.backend_id == *backend_id) {
                    if same_prefix64(addr.address, prefix.addr) {
                        continue;
                    }
                    let new = with_prefix64(prefix.addr, iid_of(addr.address));
                    info!(
                        "Prefix of backend '{backend_id}' changed: moving group {} address {} to {new}",
                        group.id, addr.address
                    );
                    let updated = SocketGroupAddress {
                        address: new,
                        ..addr.clone()
                    };
                    match state.db.upsert_socket_group_address(&updated).await {
                        Ok(()) => {
                            moves.push((addr.interface.clone(), addr.address, new, addr.prefix_len))
                        }
                        Err(e) => error!("Failed to save re-homed group address: {e}"),
                    }
                }
            }
        }
        if moves.is_empty() {
            return;
        }

        // Old addresses leave the interface before the ruleset stops covering them; new
        // ones are added only once a ruleset that covers them is in place. Without one the
        // ensure-present pass adds them after the next successful apply.
        for (iface, old, _, _) in &moves {
            if let Err(e) = self.network.remove_address(iface, *old) {
                warn!("Failed to remove {old} from {iface}: {e}");
            }
        }
        if self.apply_firewall(state).await.is_ok() {
            for (iface, _, new, prefix_len) in moves {
                if let Err(e) = self.network.add_address(&iface, new, prefix_len) {
                    warn!("Failed to add {new} to {iface}: {e}");
                }
            }
        }
    }

    /// Re-add expected addresses that are missing from their interface, e.g. after
    /// Yggdrasil restarted and recreated its tun. Interfaces that don't exist are skipped.
    /// Does nothing while the last ruleset apply failed: an address no scope covers would
    /// be exposed.
    async fn ensure_addresses_present(&self, state: &AppState) {
        if self.apply_failed.load(Ordering::Relaxed) {
            debug!("Not adding addresses: the firewall ruleset is not in place");
            return;
        }
        let mut expected: HashMap<String, Vec<(Ipv6Addr, u8)>> = HashMap::new();
        for socket in state.db.list_sockets().await.unwrap_or_default() {
            for addr in &socket.addresses {
                expected
                    .entry(addr.interface.clone())
                    .or_default()
                    .push((addr.address, addr.prefix_len));
            }
        }
        for group in state.db.list_socket_groups().await.unwrap_or_default() {
            for addr in state
                .db
                .get_socket_group_addresses(&group.id)
                .await
                .unwrap_or_default()
            {
                expected
                    .entry(addr.interface.clone())
                    .or_default()
                    .push((addr.address, addr.prefix_len));
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
            for (addr, prefix_len) in wanted {
                if present.contains(&addr) {
                    continue;
                }
                match self.network.add_address(&iface, addr, prefix_len) {
                    Ok(()) => info!("Added address {addr} to {iface}"),
                    Err(e) => warn!("Failed to add {addr} to {iface}: {e}"),
                }
            }
        }
    }

    /// Ensure a socket group has addresses allocated for all active backends.
    /// Called when members are added to a group.
    pub async fn ensure_socket_group_addresses(
        &self,
        state: &AppState,
        group_id: &str,
    ) -> anyhow::Result<()> {
        let existing = state.db.get_socket_group_addresses(group_id).await?;
        let existing_backend_ids: Vec<&str> =
            existing.iter().map(|a| a.backend_id.as_str()).collect();
        let mut allocated = false;

        for (backend_id, active) in &self.backends {
            if existing_backend_ids.contains(&backend_id.as_str()) {
                continue;
            }

            match active.backend.allocate(None) {
                Ok(alloc) => {
                    let sg_addr = SocketGroupAddress {
                        group_id: group_id.to_string(),
                        backend_id: backend_id.clone(),
                        address: alloc.address,
                        interface: active.config.backend.interface().to_string(),
                        prefix_len: alloc.prefix_len,
                        policy: Policy::Closed,
                    };

                    if let Err(e) = state.db.upsert_socket_group_address(&sg_addr).await {
                        error!("Failed to save socket group address: {e}");
                    } else {
                        info!(
                            "Allocated {} ({}) for socket group {}",
                            sg_addr.address, backend_id, group_id
                        );
                        allocated = true;
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to allocate IPv6 from backend '{}' for socket group: {e}",
                        backend_id
                    );
                }
            }
        }

        if allocated {
            // Ruleset first, then the addresses it covers.
            self.apply_firewall(state).await?;
            self.ensure_addresses_present(state).await;
        }
        Ok(())
    }

    /// Delete a socket group: its addresses leave the interfaces, then the ruleset drops
    /// their scope and rules.
    pub async fn delete_socket_group(
        &self,
        state: &AppState,
        group_id: &str,
    ) -> anyhow::Result<()> {
        let addrs = state.db.get_socket_group_addresses(group_id).await?;
        state.db.delete_socket_group(group_id).await?;
        for a in addrs {
            if let Err(e) = self.network.remove_address(&a.interface, a.address) {
                warn!("Failed to remove {} from {}: {e}", a.address, a.interface);
            }
        }
        self.apply_firewall(state).await
    }
}

/// Remove the firewall rules and every SocketGuard address in the DB. Needs only the
/// database, so `--disable` works without starting an engine.
pub async fn disable_all(
    db: &Database,
    firewall: Arc<dyn Firewall>,
    network: Arc<dyn NetworkInterface>,
) -> anyhow::Result<()> {
    let mut addrs: Vec<(String, Ipv6Addr)> = Vec::new();
    for s in db.list_sockets().await? {
        addrs.extend(s.addresses.into_iter().map(|a| (a.interface, a.address)));
    }
    for g in db.list_socket_groups().await? {
        for a in db.get_socket_group_addresses(&g.id).await? {
            addrs.push((a.interface, a.address));
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
    use socketguard_core::{BackendType, Protocol};

    fn test_socket(policy: Policy) -> ManagedSocket {
        ManagedSocket {
            id: "test123".to_string(),
            pid: 1000,
            process_name: "test".to_string(),
            port: 8080,
            protocol: Protocol::Tcp,
            addresses: vec![SocketAddress {
                backend_id: "ula".to_string(),
                backend_type: BackendType::Ula,
                address: "fd00::1".parse().unwrap(),
                interface: "lo".to_string(),
                prefix_len: 128,
                policy,
            }],
            policy,
            exe_path: None,
            cmdline: None,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            acl_group_id: None,
            socket_group_ids: vec![],
        }
    }

    #[test]
    fn closed_policy_is_default() {
        let socket = test_socket(Policy::default());
        assert_eq!(socket.policy, Policy::Closed);
    }

    #[test]
    fn managed_string_parses_as_closed() {
        let policy: Policy = "managed".parse().unwrap();
        assert_eq!(policy, Policy::Closed);
    }

    #[tokio::test]
    async fn reconcile_detects_stale_sockets() {
        let db = crate::state::Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();

        let mut stale = test_socket(Policy::Closed);
        stale.last_seen = chrono::Utc::now() - chrono::Duration::seconds(3600);
        db.upsert_socket(&stale).await.unwrap();

        let stale_threshold = chrono::Utc::now() - chrono::Duration::seconds(60);
        let stale_sockets = db.stale_sockets(stale_threshold).await.unwrap();
        assert_eq!(stale_sockets.len(), 1);
        assert_eq!(stale_sockets[0].id, "test123");
    }

    #[tokio::test]
    async fn fresh_socket_not_stale() {
        let db = crate::state::Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();

        let fresh = test_socket(Policy::Closed);
        db.upsert_socket(&fresh).await.unwrap();

        let stale_threshold = chrono::Utc::now() - chrono::Duration::seconds(60);
        let stale_sockets = db.stale_sockets(stale_threshold).await.unwrap();
        assert!(stale_sockets.is_empty());
    }
}
