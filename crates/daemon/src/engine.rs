use crate::backend::{self, Ipv6Backend};
use crate::firewall::{self, Firewall};
use crate::monitor::{self, SocketMonitor};
use crate::network::{self, NetworkInterface};
use crate::AppState;
use socketguard_core::config::DaemonConfig;
use socketguard_core::{socket_id, BackendType, ManagedSocket, Policy};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info, warn};

pub struct Engine {
    monitor: Box<dyn SocketMonitor>,
    backend: Box<dyn Ipv6Backend>,
    firewall: Box<dyn Firewall>,
    network: Box<dyn NetworkInterface>,
    /// Track which backend/interface the engine was built with
    current_backend: BackendType,
    current_interface: String,
}

impl Engine {
    pub fn new(config: &DaemonConfig) -> Self {
        Self {
            monitor: monitor::create_monitor(),
            backend: backend::create_backend(config.backend),
            firewall: firewall::create_firewall(),
            network: network::create_network_interface(),
            current_backend: config.backend,
            current_interface: config.interface.clone(),
        }
    }

    /// Clean up all SocketGuard-managed firewall rules.
    /// Called on startup (to clear stale rules from a previous crash) and on shutdown.
    pub fn cleanup_all_firewall_rules(&self) {
        info!("Cleaning up all SocketGuard firewall rules");
        if let Err(e) = self.firewall.cleanup_all_rules() {
            warn!("Failed to clean up firewall rules: {e}");
        }
    }

    /// Startup reconciliation: clean stale OS state, then re-apply desired state from DB.
    pub async fn startup_reconcile(&self, state: &AppState) {
        // 1. Clean all firewall rules (they may be stale from a crash)
        self.cleanup_all_firewall_rules();

        // 2. Re-apply firewall rules for all sockets in the DB
        let sockets = match state.db.list_sockets().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to list sockets for startup reconciliation: {e}");
                return;
            }
        };

        let config = state.config.read().await;
        let iface = config.interface.clone();
        drop(config);

        for socket in &sockets {
            // Ensure IPv6 address is bound to the interface
            if let Err(e) = self.network.add_address(&iface, socket.assigned_ipv6, 128) {
                warn!(
                    "Failed to re-add IPv6 {} for socket {}: {e}",
                    socket.assigned_ipv6, socket.id
                );
            }

            // Re-apply firewall rules based on policy
            if let Err(e) = self.apply_firewall_for_socket(state, socket).await {
                warn!("Failed to re-apply firewall for socket {}: {e}", socket.id);
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

        let config = state.config.read().await;
        let iface = config.interface.clone();
        drop(config);

        for socket in &sockets {
            if let Err(e) = self.network.remove_address(&iface, socket.assigned_ipv6) {
                warn!(
                    "Failed to remove IPv6 {} during shutdown: {e}",
                    socket.assigned_ipv6
                );
            }
        }

        info!("Shutdown cleanup complete");
    }

    /// Check if config has changed and rebuild subsystems if needed.
    /// Returns the old interface name if it changed (addresses need migration).
    fn check_config_change(&mut self, config: &DaemonConfig) -> Option<String> {
        let mut old_interface = None;

        if config.backend != self.current_backend {
            info!(
                "Backend changed from {} to {}, new sockets will use new backend",
                self.current_backend, config.backend
            );
            self.backend = backend::create_backend(config.backend);
            self.current_backend = config.backend;
        }

        if config.interface != self.current_interface {
            info!(
                "Interface changed from {} to {}, migrating addresses",
                self.current_interface, config.interface
            );
            old_interface = Some(self.current_interface.clone());
            self.current_interface = config.interface.clone();
        }

        old_interface
    }

    /// Reconcile: detect sockets, assign IPs, apply firewall rules.
    /// This is the main declarative reconciliation loop body.
    pub async fn reconcile(&mut self, state: &AppState) -> anyhow::Result<()> {
        // Check for config changes and migrate if needed
        let config = state.config.read().await;
        let config_snapshot = config.clone();
        drop(config);

        if let Some(old_iface) = self.check_config_change(&config_snapshot) {
            self.migrate_addresses(state, &old_iface, &config_snapshot.interface)
                .await;
        }

        let iface = config_snapshot.interface.clone();

        // 1. Detect current listening sockets
        let current_sockets = match self.monitor.list_listening_sockets() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to list sockets: {e}");
                return Ok(());
            }
        };

        let now = chrono::Utc::now();

        // 2. For each detected socket, ensure it has an assigned IPv6
        for ls in &current_sockets {
            let sid = socket_id(&ls.process_name, ls.port, ls.protocol);

            if let Ok(Some(mut existing)) = state.db.get_socket(&sid).await {
                // Update metadata (PID may have changed after restart)
                existing.pid = ls.pid;
                existing.process_name = ls.process_name.clone();
                existing.exe_path = ls.exe_path.clone();
                existing.cmdline = ls.cmdline.clone();
                existing.last_seen = now;
                if let Err(e) = state.db.upsert_socket(&existing).await {
                    error!("Failed to update socket {sid}: {e}");
                }

                // Declarative: ensure firewall rules match desired state
                let _lock = state.firewall_lock.lock().await;
                if let Err(e) = self.apply_firewall_for_socket(state, &existing).await {
                    warn!("Failed to reconcile firewall for {sid}: {e}");
                }
                drop(_lock);

                continue;
            }

            // New socket - allocate IPv6
            info!(
                "New socket detected: {}:{} (PID {} - {})",
                ls.protocol, ls.port, ls.pid, ls.process_name
            );

            match self.backend.allocate_address() {
                Ok(alloc) => {
                    if let Err(e) =
                        self.network
                            .add_address(&iface, alloc.address, alloc.prefix_len)
                    {
                        error!("Failed to add IPv6 {} to {}: {e}", alloc.address, iface);
                        continue;
                    }

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

                    let managed = ManagedSocket {
                        id: sid.clone(),
                        pid: ls.pid,
                        process_name: ls.process_name.clone(),
                        port: ls.port,
                        protocol: ls.protocol,
                        assigned_ipv6: alloc.address,
                        backend: alloc.backend,
                        policy: Policy::Closed,
                        keypair_id,
                        exe_path: ls.exe_path.clone(),
                        cmdline: ls.cmdline.clone(),
                        first_seen: now,
                        last_seen: now,
                    };

                    let _lock = state.firewall_lock.lock().await;
                    if let Err(e) = self.firewall.block_all(alloc.address, ls.port, ls.protocol) {
                        warn!("Failed to apply firewall rule: {e}");
                    }
                    drop(_lock);

                    if let Err(e) = state.db.upsert_socket(&managed).await {
                        error!("Failed to save socket: {e}");
                    }

                    info!(
                        "Assigned {} to {}:{} ({})",
                        alloc.address, ls.process_name, ls.port, ls.protocol
                    );
                }
                Err(e) => {
                    error!("Failed to allocate IPv6: {e}");
                }
            }
        }

        // 3. Clean up stale sockets (not seen for 3 poll cycles)
        let stale_threshold =
            now - chrono::Duration::seconds(config_snapshot.poll_interval_secs as i64 * 3);

        if let Ok(stale) = state.db.stale_sockets(stale_threshold).await {
            for s in stale {
                info!(
                    "Cleaning up stale socket: {}:{} ({})",
                    s.process_name, s.port, s.id
                );

                let _lock = state.firewall_lock.lock().await;
                if let Err(e) = self.firewall.remove_acl(s.assigned_ipv6, s.port, s.protocol) {
                    warn!("Failed to remove firewall rules for {}: {e}", s.id);
                }
                drop(_lock);

                if let Err(e) = self.network.remove_address(&iface, s.assigned_ipv6) {
                    warn!("Failed to remove IPv6 {}: {e}", s.assigned_ipv6);
                }

                if let Err(e) = state.db.delete_socket(&s.id).await {
                    error!("Failed to delete socket {}: {e}", s.id);
                }
            }
        }

        Ok(())
    }

    /// Apply firewall rules for a socket based on its current policy and ACL entries.
    /// Acquires the firewall lock.
    pub async fn apply_socket_acl(&self, state: &AppState, socket_id: &str) -> anyhow::Result<()> {
        let socket = state
            .db
            .get_socket(socket_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("socket not found"))?;

        let _lock = state.firewall_lock.lock().await;
        self.apply_firewall_for_socket(state, &socket).await
    }

    /// Apply firewall rules for a socket (does not acquire firewall_lock — caller's responsibility).
    async fn apply_firewall_for_socket(
        &self,
        state: &AppState,
        socket: &ManagedSocket,
    ) -> anyhow::Result<()> {
        match socket.policy {
            Policy::Closed => {
                self.firewall
                    .block_all(socket.assigned_ipv6, socket.port, socket.protocol)?;
            }
            Policy::Open => {
                self.firewall
                    .allow_all(socket.assigned_ipv6, socket.port, socket.protocol)?;
            }
            Policy::Managed => {
                let acl = state.db.get_acl(&socket.id).await?;
                let allowed: Vec<Ipv6Addr> = acl
                    .iter()
                    .filter_map(|e| e.allowed_ip.parse().ok())
                    .collect();
                self.firewall.apply_acl(
                    socket.assigned_ipv6,
                    socket.port,
                    socket.protocol,
                    &allowed,
                )?;
            }
        }
        Ok(())
    }

    /// Migrate all managed IPv6 addresses from one interface to another.
    async fn migrate_addresses(&self, state: &AppState, old_iface: &str, new_iface: &str) {
        let sockets = match state.db.list_sockets().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to list sockets for migration: {e}");
                return;
            }
        };

        for socket in &sockets {
            if let Err(e) = self
                .network
                .add_address(new_iface, socket.assigned_ipv6, 128)
            {
                warn!(
                    "Failed to add {} to {}: {e}",
                    socket.assigned_ipv6, new_iface
                );
            }
            if let Err(e) = self.network.remove_address(old_iface, socket.assigned_ipv6) {
                warn!(
                    "Failed to remove {} from {}: {e}",
                    socket.assigned_ipv6, old_iface
                );
            }
        }

        info!(
            "Migrated {} addresses from {} to {}",
            sockets.len(),
            old_iface,
            new_iface
        );
    }
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
