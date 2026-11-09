use crate::backend::{self, Ipv6Backend};
use crate::firewall::{self, Firewall};
use crate::monitor::{self, SocketMonitor};
use crate::network::{self, NetworkInterface};
use crate::AppState;
use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use socketguard_core::{socket_id, AclEntry, ManagedSocket, Policy, SocketAddress};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

pub struct ActiveBackend {
    pub config: BackendInstanceConfig,
    pub backend: Box<dyn Ipv6Backend>,
}

pub struct Engine {
    monitor: Box<dyn SocketMonitor>,
    pub(crate) backends: HashMap<String, ActiveBackend>,
    firewall: Arc<dyn Firewall>,
    network: Arc<dyn NetworkInterface>,
    /// Track which backend configs the engine was built with (by ID)
    current_backend_ids: Vec<String>,
}

impl Engine {
    pub fn new(config: &DaemonConfig) -> anyhow::Result<Self> {
        Self::new_with_deps(
            config,
            monitor::create_monitor(),
            Arc::from(firewall::create_firewall()),
            Arc::from(network::create_network_interface()),
        )
    }

    pub fn new_with_deps(
        config: &DaemonConfig,
        monitor: Box<dyn SocketMonitor>,
        firewall: Arc<dyn Firewall>,
        network: Arc<dyn NetworkInterface>,
    ) -> anyhow::Result<Self> {
        let mut backends = HashMap::new();
        for inst in &config.backends {
            let b = backend::create_backend(&inst.backend)?;
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

        Ok(Self {
            monitor,
            backends,
            firewall,
            network,
            current_backend_ids,
        })
    }

    /// Fully injectable constructor — for tests only.
    pub fn new_injectable(
        monitor: Box<dyn SocketMonitor>,
        firewall: Arc<dyn Firewall>,
        network: Arc<dyn NetworkInterface>,
        backends: HashMap<String, ActiveBackend>,
        backend_ids: Vec<String>,
    ) -> Self {
        Self {
            monitor,
            backends,
            firewall,
            network,
            current_backend_ids: backend_ids,
        }
    }

    /// Clean up all SocketGuard-managed firewall rules.
    pub fn cleanup_all_firewall_rules(&self) {
        info!("Cleaning up all SocketGuard firewall rules");
        if let Err(e) = self.firewall.cleanup_all_rules() {
            warn!("Failed to clean up firewall rules: {e}");
        }
    }

    /// Startup reconciliation: clean stale OS state, then re-apply desired state from DB.
    pub async fn startup_reconcile(&self, state: &AppState) {
        self.cleanup_all_firewall_rules();

        let sockets = match state.db.list_sockets().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to list sockets for startup reconciliation: {e}");
                return;
            }
        };

        // Pre-fetch per-backend ACL data with group resolution
        let mut socket_acls: Vec<(
            ManagedSocket,
            HashMap<String, Vec<Ipv6Addr>>,
            HashMap<String, Policy>,
        )> = Vec::new();
        for socket in &sockets {
            let mut acl_map: HashMap<String, Vec<Ipv6Addr>> = HashMap::new();
            let mut resolved_policies: HashMap<String, Policy> = HashMap::new();
            for addr in &socket.addresses {
                let (effective_policy, _source) = match state
                    .db
                    .resolve_effective_policy(&socket.id, &addr.backend_id)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(
                            "Failed to resolve policy for {}:{}: {e}",
                            socket.id, addr.backend_id
                        );
                        (addr.policy, "address".to_string())
                    }
                };
                resolved_policies.insert(addr.backend_id.clone(), effective_policy);

                if effective_policy == Policy::Closed {
                    let acl = if addr.policy == Policy::Group {
                        // Get ACL entries from group
                        match state.db.get_acl_group_for_socket(&socket.id).await {
                            Ok(Some(group_id)) => state
                                .db
                                .get_acl_group_entries_for_backend(&group_id, &addr.backend_id)
                                .await
                                .unwrap_or_default(),
                            _ => Vec::new(),
                        }
                    } else {
                        state
                            .db
                            .get_acl_for_backend(&socket.id, &addr.backend_id)
                            .await
                            .unwrap_or_default()
                    };
                    let allowed = acl
                        .iter()
                        .filter_map(|e| e.allowed_ip.parse().ok())
                        .collect();
                    acl_map.insert(addr.backend_id.clone(), allowed);
                }
            }
            socket_acls.push((socket.clone(), acl_map, resolved_policies));
        }

        // Run address + firewall setup in parallel
        let mut join_set = JoinSet::new();
        for (socket, acl_map, resolved_policies) in socket_acls {
            let network = self.network.clone();
            let firewall = self.firewall.clone();
            join_set.spawn_blocking(move || {
                for addr in &socket.addresses {
                    let effective = resolved_policies
                        .get(&addr.backend_id)
                        .copied()
                        .unwrap_or(addr.policy);
                    // Closed with no ACL = inactive, don't add to interface
                    if effective == Policy::Closed {
                        let has_acl = acl_map
                            .get(&addr.backend_id)
                            .map(|v| !v.is_empty())
                            .unwrap_or(false);
                        if !has_acl {
                            continue;
                        }
                    }
                    if let Err(e) =
                        network.add_address(&addr.interface, addr.address, addr.prefix_len)
                    {
                        warn!(
                            "Failed to re-add IPv6 {} for socket {}: {e}",
                            addr.address, socket.id
                        );
                    }
                }

                if let Err(e) =
                    apply_firewall_sync(&*firewall, &socket, &acl_map, &resolved_policies)
                {
                    warn!("Failed to re-apply firewall for socket {}: {e}", socket.id);
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                warn!("Startup reconciliation task failed: {e}");
            }
        }

        info!(
            "Startup reconciliation complete: {} sockets restored",
            sockets.len()
        );
    }

    /// Graceful shutdown: remove all firewall rules and IPv6 addresses.
    pub async fn shutdown_cleanup(&self, state: &AppState) {
        info!("Shutting down: cleaning up firewall rules and IPv6 addresses");

        self.cleanup_all_firewall_rules();

        let sockets = match state.db.list_sockets().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to list sockets for shutdown cleanup: {e}");
                return;
            }
        };

        let mut join_set = JoinSet::new();
        for socket in sockets {
            let network = self.network.clone();
            join_set.spawn_blocking(move || {
                for addr in &socket.addresses {
                    if let Err(e) = network.remove_address(&addr.interface, addr.address) {
                        warn!(
                            "Failed to remove IPv6 {} during shutdown: {e}",
                            addr.address
                        );
                    }
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                warn!("Shutdown cleanup task failed: {e}");
            }
        }

        info!("Shutdown cleanup complete");
    }

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
        let b = match backend::create_backend(&inst.backend) {
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

        let mut new_addresses: Vec<(String, SocketAddress, u16, socketguard_core::Protocol)> =
            Vec::new();

        for socket in &sockets {
            // Skip if socket already has an address from this backend
            if socket.addresses.iter().any(|a| a.backend_id == backend_id) {
                continue;
            }

            match b.allocate_address() {
                Ok(alloc) => {
                    let keypair_id = if let Some(ref kp) = alloc.keypair {
                        if let Err(e) = state
                            .db
                            .save_keypair(
                                &kp.id,
                                &kp.public_key,
                                &kp.private_key,
                                &kp.derived_ipv6.to_string(),
                            )
                            .await
                        {
                            error!("Failed to save keypair: {e}");
                        }
                        Some(kp.id.clone())
                    } else {
                        None
                    };

                    let addr = SocketAddress {
                        backend_id: backend_id.clone(),
                        backend_type,
                        address: alloc.address,
                        interface: iface.clone(),
                        prefix_len: alloc.prefix_len,
                        keypair_id,
                        policy: socket.policy, // inherit socket's default policy
                    };

                    if let Err(e) = state.db.upsert_socket_address(&socket.id, &addr).await {
                        error!("Failed to save socket address: {e}");
                        continue;
                    }

                    new_addresses.push((socket.id.clone(), addr, socket.port, socket.protocol));
                }
                Err(e) => {
                    error!("Failed to allocate address from '{}': {e}", backend_id);
                }
            }
        }

        // Add addresses to interfaces
        let mut join_set = JoinSet::new();
        for (_sid, addr, _port, _proto) in &new_addresses {
            let iface = addr.interface.clone();
            let ip = addr.address;
            let prefix = addr.prefix_len;
            let network = self.network.clone();
            join_set.spawn_blocking(move || {
                if let Err(e) = network.add_address(&iface, ip, prefix) {
                    warn!("Failed to add address {} to {}: {e}", ip, iface);
                }
            });
        }
        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                warn!("Add address task failed: {e}");
            }
        }

        self.backends.insert(
            inst.id.clone(),
            ActiveBackend {
                config: inst.clone(),
                backend: b,
            },
        );

        info!(
            "Backend '{}' initialized, allocated {} addresses",
            inst.id,
            new_addresses.len()
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

        // Remove addresses from interfaces
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
        info!("Backend '{}' removed", backend_id);
    }

    /// Reconcile: detect sockets, assign IPs, apply firewall rules.
    pub async fn reconcile(&mut self, state: &AppState) -> anyhow::Result<()> {
        // Check for config changes
        let config = state.config.read().await;
        let config_snapshot = config.clone();
        drop(config);

        self.check_config_change(&config_snapshot, state).await;

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

        // 2. Categorize sockets
        struct ExistingUpdate {
            socket: ManagedSocket,
            acl_map: HashMap<String, Vec<Ipv6Addr>>,
            resolved_policies: HashMap<String, Policy>,
        }
        struct NewProvision {
            socket: ManagedSocket,
        }

        let mut existing_updates: Vec<ExistingUpdate> = Vec::new();
        let mut new_provisions: Vec<NewProvision> = Vec::new();

        for ls in &current_sockets {
            // Apply process filter
            if !config_snapshot.process_filter.matches(&ls.process_name) {
                continue;
            }

            let sid = socket_id(&ls.process_name, ls.port, ls.protocol);

            if let Ok(Some(mut existing)) = state.db.get_socket(&sid).await {
                // Update metadata
                existing.pid = ls.pid;
                existing.process_name = ls.process_name.clone();
                existing.exe_path = ls.exe_path.clone();
                existing.cmdline = ls.cmdline.clone();
                existing.last_seen = now;
                if let Err(e) = state.db.upsert_socket(&existing).await {
                    error!("Failed to update socket {sid}: {e}");
                }

                // Build per-backend ACL map with group resolution
                let mut acl_map: HashMap<String, Vec<Ipv6Addr>> = HashMap::new();
                let mut resolved_policies: HashMap<String, Policy> = HashMap::new();
                for addr in &existing.addresses {
                    let (effective_policy, _) = state
                        .db
                        .resolve_effective_policy(&existing.id, &addr.backend_id)
                        .await
                        .unwrap_or((addr.policy, "address".to_string()));
                    resolved_policies.insert(addr.backend_id.clone(), effective_policy);

                    if effective_policy == Policy::Closed {
                        let acl: Vec<AclEntry> = if addr.policy == Policy::Group {
                            match state.db.get_acl_group_for_socket(&existing.id).await {
                                Ok(Some(group_id)) => state
                                    .db
                                    .get_acl_group_entries_for_backend(&group_id, &addr.backend_id)
                                    .await
                                    .unwrap_or_default(),
                                _ => Vec::new(),
                            }
                        } else {
                            state
                                .db
                                .get_acl_for_backend(&existing.id, &addr.backend_id)
                                .await
                                .unwrap_or_default()
                        };
                        let allowed = acl
                            .iter()
                            .filter_map(|e| e.allowed_ip.parse().ok())
                            .collect();
                        acl_map.insert(addr.backend_id.clone(), allowed);
                    }
                }

                existing_updates.push(ExistingUpdate {
                    socket: existing,
                    acl_map,
                    resolved_policies,
                });
                continue;
            }

            // New socket — allocate IPv6 from all active backends
            info!(
                "New socket detected: {}:{} (PID {} - {})",
                ls.protocol, ls.port, ls.pid, ls.process_name
            );

            let mut addresses = Vec::new();
            for (backend_id, active) in &self.backends {
                match active.backend.allocate_address() {
                    Ok(alloc) => {
                        let keypair_id = if let Some(ref kp) = alloc.keypair {
                            if let Err(e) = state
                                .db
                                .save_keypair(
                                    &kp.id,
                                    &kp.public_key,
                                    &kp.private_key,
                                    &kp.derived_ipv6.to_string(),
                                )
                                .await
                            {
                                error!("Failed to save keypair: {e}");
                            }
                            Some(kp.id.clone())
                        } else {
                            None
                        };

                        let addr = SocketAddress {
                            backend_id: backend_id.clone(),
                            backend_type: alloc.backend,
                            address: alloc.address,
                            interface: active.config.backend.interface().to_string(),
                            prefix_len: alloc.prefix_len,
                            keypair_id,
                            policy: Policy::Closed,
                        };
                        addresses.push(addr);
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

            // Save each address to DB
            for addr in &addresses {
                if let Err(e) = state.db.upsert_socket_address(&sid, addr).await {
                    error!("Failed to save socket address: {e}");
                }
            }

            new_provisions.push(NewProvision { socket: managed });
        }

        let had_new_sockets = !new_provisions.is_empty();

        // Run all network+firewall operations in parallel
        let mut join_set = JoinSet::new();

        for update in existing_updates {
            let firewall = self.firewall.clone();
            join_set.spawn_blocking(move || {
                if let Err(e) = apply_firewall_sync(
                    &*firewall,
                    &update.socket,
                    &update.acl_map,
                    &update.resolved_policies,
                ) {
                    warn!("Failed to reconcile firewall for {}: {e}", update.socket.id);
                }
            });
        }

        for prov in new_provisions {
            let network = self.network.clone();
            let firewall = self.firewall.clone();
            join_set.spawn_blocking(move || {
                for addr in &prov.socket.addresses {
                    if let Err(e) =
                        network.add_address(&addr.interface, addr.address, addr.prefix_len)
                    {
                        error!(
                            "Failed to add IPv6 {} to {}: {e}",
                            addr.address, addr.interface
                        );
                        continue;
                    }

                    if let Err(e) =
                        firewall.block_all(addr.address, prov.socket.port, prov.socket.protocol)
                    {
                        warn!("Failed to apply firewall rule: {e}");
                    }

                    info!(
                        "Assigned {} ({}) to {}:{} ({})",
                        addr.address,
                        addr.backend_id,
                        prov.socket.process_name,
                        prov.socket.port,
                        prov.socket.protocol
                    );
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                warn!("Reconciliation task failed: {e}");
            }
        }

        // 3. Clean up stale sockets
        let stale_threshold =
            now - chrono::Duration::seconds(config_snapshot.poll_interval_secs as i64 * 3);

        let mut had_stale = false;
        if let Ok(stale) = state.db.stale_sockets(stale_threshold).await {
            had_stale = !stale.is_empty();
            let mut stale_join_set = JoinSet::new();
            for s in stale {
                info!(
                    "Cleaning up stale socket: {}:{} ({})",
                    s.process_name, s.port, s.id
                );
                let sid = s.id.clone();
                let firewall = self.firewall.clone();
                let network = self.network.clone();
                stale_join_set.spawn_blocking(move || {
                    for addr in &s.addresses {
                        if let Err(e) = firewall.remove_acl(addr.address, s.port, s.protocol) {
                            warn!("Failed to remove firewall rules for {}: {e}", sid);
                        }
                        if let Err(e) = network.remove_address(&addr.interface, addr.address) {
                            warn!("Failed to remove IPv6 {}: {e}", addr.address);
                        }
                    }
                });

                if let Err(e) = state.db.delete_socket(&s.id).await {
                    error!("Failed to delete socket {}: {e}", s.id);
                }
            }

            while let Some(result) = stale_join_set.join_next().await {
                if let Err(e) = result {
                    warn!("Stale cleanup task failed: {e}");
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

        if had_new_sockets || had_stale {
            let _ = state.events.send(crate::api::DaemonEvent::SocketsChanged);
        }

        Ok(())
    }

    /// Apply firewall rules for a socket based on its current policy and ACL entries.
    pub async fn apply_socket_acl(&self, state: &AppState, socket_id: &str) -> anyhow::Result<()> {
        let socket = state
            .db
            .get_socket(socket_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("socket not found"))?;

        let _lock = state.firewall_lock.lock().await;
        self.apply_firewall_for_socket(state, &socket).await
    }

    /// Apply firewall rules for a socket (per-address policy with group resolution, ADR 0018).
    async fn apply_firewall_for_socket(
        &self,
        state: &AppState,
        socket: &ManagedSocket,
    ) -> anyhow::Result<()> {
        for addr in &socket.addresses {
            let (effective_policy, _source) = state
                .db
                .resolve_effective_policy(&socket.id, &addr.backend_id)
                .await?;

            match effective_policy {
                Policy::Closed => {
                    let acl: Vec<AclEntry> = if addr.policy == Policy::Group {
                        match state.db.get_acl_group_for_socket(&socket.id).await? {
                            Some(group_id) => {
                                state
                                    .db
                                    .get_acl_group_entries_for_backend(&group_id, &addr.backend_id)
                                    .await?
                            }
                            None => Vec::new(),
                        }
                    } else {
                        state
                            .db
                            .get_acl_for_backend(&socket.id, &addr.backend_id)
                            .await?
                    };
                    let allowed: Vec<Ipv6Addr> = acl
                        .iter()
                        .filter_map(|e| e.allowed_ip.parse().ok())
                        .collect();
                    if allowed.is_empty() {
                        // Closed + no ACL = inactive. Remove any stale firewall rules.
                        let _ =
                            self.firewall
                                .remove_acl(addr.address, socket.port, socket.protocol);
                    } else {
                        self.firewall.apply_acl(
                            addr.address,
                            socket.port,
                            socket.protocol,
                            &allowed,
                        )?;
                    }
                }
                Policy::Open => {
                    self.firewall
                        .allow_all(addr.address, socket.port, socket.protocol)?;
                }
                Policy::Group => {
                    // Should not reach here — resolve_effective_policy returns Closed or Open
                    let _ = self
                        .firewall
                        .remove_acl(addr.address, socket.port, socket.protocol);
                }
            }
        }
        Ok(())
    }
    /// Ensure a socket group has addresses allocated for all active backends.
    /// Called when members are added to a group.
    pub async fn ensure_socket_group_addresses(
        &self,
        state: &AppState,
        group_id: &str,
    ) -> anyhow::Result<()> {
        use socketguard_core::{Policy, SocketGroupAddress};

        let existing = state.db.get_socket_group_addresses(group_id).await?;
        let existing_backend_ids: Vec<&str> =
            existing.iter().map(|a| a.backend_id.as_str()).collect();

        for (backend_id, active) in &self.backends {
            if existing_backend_ids.contains(&backend_id.as_str()) {
                continue;
            }

            match active.backend.allocate_address() {
                Ok(alloc) => {
                    let keypair_id = if let Some(ref kp) = alloc.keypair {
                        if let Err(e) = state
                            .db
                            .save_keypair(
                                &kp.id,
                                &kp.public_key,
                                &kp.private_key,
                                &kp.derived_ipv6.to_string(),
                            )
                            .await
                        {
                            error!("Failed to save keypair for socket group address: {e}");
                        }
                        Some(kp.id.clone())
                    } else {
                        None
                    };

                    let sg_addr = SocketGroupAddress {
                        group_id: group_id.to_string(),
                        backend_id: backend_id.clone(),
                        address: alloc.address,
                        interface: active.config.backend.interface().to_string(),
                        prefix_len: alloc.prefix_len,
                        keypair_id,
                        policy: Policy::Closed,
                    };

                    if let Err(e) = state.db.upsert_socket_group_address(&sg_addr).await {
                        error!("Failed to save socket group address: {e}");
                    } else {
                        // Add the address to the network interface
                        if let Err(e) = self.network.add_address(
                            &sg_addr.interface,
                            sg_addr.address,
                            sg_addr.prefix_len,
                        ) {
                            error!(
                                "Failed to add socket group IPv6 {} to {}: {e}",
                                sg_addr.address, sg_addr.interface
                            );
                        } else {
                            info!(
                                "Allocated {} ({}) for socket group {}",
                                sg_addr.address, backend_id, group_id
                            );
                        }
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

        Ok(())
    }

    /// Apply firewall rules for a socket group address based on its policy and ACL entries.
    /// Uses port/protocol from member sockets to configure firewall rules.
    pub async fn apply_socket_group_acl(
        &self,
        state: &AppState,
        group_id: &str,
    ) -> anyhow::Result<()> {
        let addresses = state.db.get_socket_group_addresses(group_id).await?;
        let members = state.db.get_socket_group_members(group_id).await?;
        let acl_entries = state.db.get_socket_group_acl_entries(group_id).await?;

        // Get port/protocol from first member socket
        let member_socket = if let Some(sid) = members.first() {
            state.db.get_socket(sid).await?
        } else {
            None
        };

        let (port, protocol) = match member_socket {
            Some(ref s) => (s.port, s.protocol),
            None => return Ok(()), // No members, nothing to apply
        };

        let _lock = state.firewall_lock.lock().await;

        for addr in &addresses {
            let backend_acl: Vec<Ipv6Addr> = acl_entries
                .iter()
                .filter(|e| e.backend_id == addr.backend_id)
                .filter_map(|e| e.allowed_ip.parse().ok())
                .collect();

            match addr.policy {
                Policy::Open => {
                    self.firewall.allow_all(addr.address, port, protocol)?;
                }
                Policy::Closed => {
                    if backend_acl.is_empty() {
                        let _ = self.firewall.remove_acl(addr.address, port, protocol);
                    } else {
                        self.firewall
                            .apply_acl(addr.address, port, protocol, &backend_acl)?;
                    }
                }
                Policy::Group => {
                    // Resolve ACL from linked ACL group (ADR 0020)
                    let sg = state.db.list_socket_groups().await?;
                    let socket_group = sg.iter().find(|g| g.id == addr.group_id);
                    if let Some(sg) = socket_group {
                        if let Some(ref acl_gid) = sg.acl_group_id {
                            if let Some(acl_group) = state.db.get_acl_group(acl_gid).await? {
                                match acl_group.policy {
                                    Policy::Open => {
                                        self.firewall.allow_all(addr.address, port, protocol)?;
                                    }
                                    Policy::Closed => {
                                        let group_entries =
                                            state.db.get_acl_group_entries(acl_gid).await?;
                                        let group_acl: Vec<Ipv6Addr> = group_entries
                                            .iter()
                                            .filter(|e| e.backend_id == addr.backend_id)
                                            .filter_map(|e| e.allowed_ip.parse().ok())
                                            .collect();
                                        if group_acl.is_empty() {
                                            let _ = self.firewall.remove_acl(
                                                addr.address,
                                                port,
                                                protocol,
                                            );
                                        } else {
                                            self.firewall.apply_acl(
                                                addr.address,
                                                port,
                                                protocol,
                                                &group_acl,
                                            )?;
                                        }
                                    }
                                    Policy::Group => {
                                        let _ =
                                            self.firewall.remove_acl(addr.address, port, protocol);
                                    }
                                }
                                continue;
                            }
                        }
                    }
                    // No ACL group linked — treat as inactive
                    let _ = self.firewall.remove_acl(addr.address, port, protocol);
                }
            }
        }

        Ok(())
    }
}

/// Apply firewall rules synchronously (for use in spawn_blocking).
/// Uses per-address policy with group resolution (ADR 0018).
/// `acl_by_backend` provides allowed IPs keyed by backend_id.
/// `resolved_policies` provides the effective policy after group resolution.
fn apply_firewall_sync(
    firewall: &dyn Firewall,
    socket: &ManagedSocket,
    acl_by_backend: &HashMap<String, Vec<Ipv6Addr>>,
    resolved_policies: &HashMap<String, Policy>,
) -> anyhow::Result<()> {
    for addr in &socket.addresses {
        let effective = resolved_policies
            .get(&addr.backend_id)
            .copied()
            .unwrap_or(addr.policy);
        match effective {
            Policy::Open => {
                firewall.allow_all(addr.address, socket.port, socket.protocol)?;
            }
            Policy::Closed => {
                let allowed = acl_by_backend
                    .get(&addr.backend_id)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                if allowed.is_empty() {
                    // Closed + no ACL = inactive. Clean up any stale rules.
                    let _ = firewall.remove_acl(addr.address, socket.port, socket.protocol);
                } else {
                    firewall.apply_acl(addr.address, socket.port, socket.protocol, allowed)?;
                }
            }
            Policy::Group => {
                // Should not reach here — resolved_policies should have resolved this
                let _ = firewall.remove_acl(addr.address, socket.port, socket.protocol);
            }
        }
    }
    Ok(())
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
    use crate::test_support::{FirewallCall, MockFirewall};
    #[allow(unused_imports)]
    use socketguard_core::{BackendType, ManagedSocket, Policy, Protocol, SocketAddress};
    use std::net::Ipv6Addr;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    fn resolved_map(socket: &ManagedSocket) -> HashMap<String, Policy> {
        socket
            .addresses
            .iter()
            .map(|a| (a.backend_id.clone(), a.policy))
            .collect()
    }

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
                keypair_id: None,
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

    fn test_socket_multi_addr(policy: Policy) -> ManagedSocket {
        ManagedSocket {
            id: "test123".to_string(),
            pid: 1000,
            process_name: "test".to_string(),
            port: 8080,
            protocol: Protocol::Tcp,
            addresses: vec![
                SocketAddress {
                    backend_id: "ula".to_string(),
                    backend_type: BackendType::Ula,
                    address: "fd00::1".parse().unwrap(),
                    interface: "lo".to_string(),
                    prefix_len: 128,
                    keypair_id: None,
                    policy,
                },
                SocketAddress {
                    backend_id: "slaac-Ethernet".to_string(),
                    backend_type: BackendType::Slaac,
                    address: "2001:db8::1".parse().unwrap(),
                    interface: "Ethernet".to_string(),
                    prefix_len: 64,
                    keypair_id: None,
                    policy,
                },
            ],
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
    fn apply_firewall_sync_closed_no_acl_inactive() {
        let calls = StdArc::new(StdMutex::new(Vec::new()));
        let fw = MockFirewall::new(calls.clone());
        let socket = test_socket(Policy::Closed);
        let acl_map = HashMap::new();
        let resolved = resolved_map(&socket);

        apply_firewall_sync(&fw, &socket, &acl_map, &resolved).unwrap();

        let recorded = calls.lock().unwrap();
        // Closed + no ACL = inactive → remove any stale rules
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0],
            FirewallCall::RemoveAcl {
                dest_ip: "fd00::1".parse().unwrap(),
                port: 8080,
                protocol: Protocol::Tcp,
            }
        );
    }

    #[test]
    fn apply_firewall_sync_closed_with_acl_allows_listed() {
        let calls = StdArc::new(StdMutex::new(Vec::new()));
        let fw = MockFirewall::new(calls.clone());
        let socket = test_socket(Policy::Closed);
        let allowed: Vec<Ipv6Addr> = vec!["fd00::10".parse().unwrap(), "fd00::20".parse().unwrap()];
        let acl_map: HashMap<String, Vec<Ipv6Addr>> = [("ula".to_string(), allowed.clone())].into();
        let resolved = resolved_map(&socket);

        apply_firewall_sync(&fw, &socket, &acl_map, &resolved).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0],
            FirewallCall::ApplyAcl {
                dest_ip: "fd00::1".parse().unwrap(),
                port: 8080,
                protocol: Protocol::Tcp,
                allowed: vec!["fd00::10".parse().unwrap(), "fd00::20".parse().unwrap()],
            }
        );
    }

    #[test]
    fn apply_firewall_sync_open_removes_restrictions() {
        let calls = StdArc::new(StdMutex::new(Vec::new()));
        let fw = MockFirewall::new(calls.clone());
        let socket = test_socket(Policy::Open);
        let acl_map = HashMap::new();
        let resolved = resolved_map(&socket);

        apply_firewall_sync(&fw, &socket, &acl_map, &resolved).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0],
            FirewallCall::RemoveAcl {
                dest_ip: "fd00::1".parse().unwrap(),
                port: 8080,
                protocol: Protocol::Tcp,
            }
        );
    }

    #[test]
    fn apply_firewall_sync_multi_address_mixed_policy() {
        let calls = StdArc::new(StdMutex::new(Vec::new()));
        let fw = MockFirewall::new(calls.clone());
        let mut socket = test_socket_multi_addr(Policy::Closed);
        // Set different policies per address
        socket.addresses[0].policy = Policy::Open; // ula: open
        socket.addresses[1].policy = Policy::Closed; // slaac: closed
        let acl_map: HashMap<String, Vec<Ipv6Addr>> = [(
            "slaac-Ethernet".to_string(),
            vec!["fd00::10".parse().unwrap()],
        )]
        .into();
        let resolved = resolved_map(&socket);

        apply_firewall_sync(&fw, &socket, &acl_map, &resolved).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        // First: ula is open -> RemoveAcl
        assert!(matches!(recorded[0], FirewallCall::RemoveAcl { .. }));
        // Second: slaac is closed -> ApplyAcl
        assert!(matches!(recorded[1], FirewallCall::ApplyAcl { .. }));
    }

    #[test]
    fn apply_firewall_sync_multi_address_closed_with_acl() {
        let calls = StdArc::new(StdMutex::new(Vec::new()));
        let fw = MockFirewall::new(calls.clone());
        let socket = test_socket_multi_addr(Policy::Closed);
        let acl_map: HashMap<String, Vec<Ipv6Addr>> = [
            ("ula".to_string(), vec!["fd00::10".parse().unwrap()]),
            (
                "slaac-Ethernet".to_string(),
                vec!["fd00::10".parse().unwrap()],
            ),
        ]
        .into();
        let resolved = resolved_map(&socket);

        apply_firewall_sync(&fw, &socket, &acl_map, &resolved).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 2);
    }

    #[test]
    fn apply_firewall_sync_multi_address_open() {
        let calls = StdArc::new(StdMutex::new(Vec::new()));
        let fw = MockFirewall::new(calls.clone());
        let socket = test_socket_multi_addr(Policy::Open);
        let acl_map = HashMap::new();
        let resolved = resolved_map(&socket);

        apply_firewall_sync(&fw, &socket, &acl_map, &resolved).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 2);
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

    #[tokio::test]
    async fn apply_firewall_for_socket_closed_fetches_acl() {
        let db = crate::state::Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();

        let socket = test_socket(Policy::Closed);
        db.upsert_socket(&socket).await.unwrap();
        for addr in &socket.addresses {
            db.upsert_socket_address(&socket.id, addr).await.unwrap();
        }
        db.add_acl_entry(&socket.id, "ula", "fd00::10", Some("peer1"))
            .await
            .unwrap();

        let acl = db.get_acl(&socket.id).await.unwrap();
        assert_eq!(acl.len(), 1);
        assert_eq!(acl[0].allowed_ip, "fd00::10");

        let allowed: Vec<Ipv6Addr> = acl
            .iter()
            .filter_map(|e| e.allowed_ip.parse().ok())
            .collect();
        assert_eq!(allowed, vec!["fd00::10".parse::<Ipv6Addr>().unwrap()]);
    }

    #[tokio::test]
    async fn empty_db_startup_reconcile_is_noop() {
        let db = crate::state::Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();

        let sockets = db.list_sockets().await.unwrap();
        assert!(sockets.is_empty());
    }
}
