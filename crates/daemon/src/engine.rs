use crate::backend::{self, Ipv6Backend};
use crate::firewall::{self, Firewall};
use crate::monitor::{self, SocketMonitor};
use crate::AppState;
use socketguard_core::config::DaemonConfig;
use socketguard_core::{socket_id, BackendType, ManagedSocket, Policy};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

pub struct Engine {
    monitor: Box<dyn SocketMonitor>,
    backend: Box<dyn Ipv6Backend>,
    firewall: Box<dyn Firewall>,
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
    /// Network and firewall operations run in parallel via spawn_blocking.
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

        // Pre-fetch ACL data for closed sockets (async DB calls)
        let mut socket_acls: Vec<(ManagedSocket, Vec<Ipv6Addr>)> = Vec::new();
        for socket in &sockets {
            let allowed = if socket.policy == Policy::Closed {
                match state.db.get_acl(&socket.id).await {
                    Ok(acl) => acl.iter().filter_map(|e| e.allowed_ip.parse().ok()).collect(),
                    Err(e) => {
                        warn!("Failed to fetch ACL for {}: {e}", socket.id);
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };
            socket_acls.push((socket.clone(), allowed));
        }

        // Run address + firewall setup in parallel via spawn_blocking
        let mut join_set = JoinSet::new();
        for (socket, allowed) in socket_acls {
            let iface = iface.clone();
            join_set.spawn_blocking(move || {
                let network = crate::network::create_network_interface();
                let firewall = crate::firewall::create_firewall();

                if let Err(e) = network.add_address(&iface, socket.assigned_ipv6, 128) {
                    warn!(
                        "Failed to re-add IPv6 {} for socket {}: {e}",
                        socket.assigned_ipv6, socket.id
                    );
                }

                if let Err(e) =
                    apply_firewall_sync(&*firewall, &socket, &allowed)
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

        let config = state.config.read().await;
        let iface = config.interface.clone();
        drop(config);

        // Remove addresses in parallel
        let mut join_set = JoinSet::new();
        for socket in sockets {
            let iface = iface.clone();
            join_set.spawn_blocking(move || {
                let network = crate::network::create_network_interface();
                if let Err(e) = network.remove_address(&iface, socket.assigned_ipv6) {
                    warn!(
                        "Failed to remove IPv6 {} during shutdown: {e}",
                        socket.assigned_ipv6
                    );
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
    /// Network/firewall operations are parallelized via spawn_blocking.
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

        // 2. Categorize sockets: existing (update) vs new (provision)
        //    Collect data first, then run OS operations in parallel.
        struct ExistingUpdate {
            socket: ManagedSocket,
            allowed: Vec<Ipv6Addr>,
        }
        struct NewProvision {
            socket: ManagedSocket,
            prefix_len: u8,
        }

        let mut existing_updates: Vec<ExistingUpdate> = Vec::new();
        let mut new_provisions: Vec<NewProvision> = Vec::new();

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

                // Pre-fetch ACL for closed sockets (ACL-based access)
                let allowed = if existing.policy == Policy::Closed {
                    state.db.get_acl(&existing.id).await
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|e| e.allowed_ip.parse().ok())
                        .collect()
                } else {
                    Vec::new()
                };

                existing_updates.push(ExistingUpdate { socket: existing, allowed });
                continue;
            }

            // New socket - allocate IPv6
            info!(
                "New socket detected: {}:{} (PID {} - {})",
                ls.protocol, ls.port, ls.pid, ls.process_name
            );

            match self.backend.allocate_address() {
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

                    if let Err(e) = state.db.upsert_socket(&managed).await {
                        error!("Failed to save socket: {e}");
                        continue;
                    }

                    new_provisions.push(NewProvision {
                        socket: managed,
                        prefix_len: alloc.prefix_len,
                    });
                }
                Err(e) => {
                    error!("Failed to allocate IPv6: {e}");
                }
            }
        }

        // Run all network+firewall operations in parallel
        let mut join_set = JoinSet::new();

        for update in existing_updates {
            join_set.spawn_blocking(move || {
                let firewall = crate::firewall::create_firewall();
                if let Err(e) = apply_firewall_sync(&*firewall, &update.socket, &update.allowed) {
                    warn!("Failed to reconcile firewall for {}: {e}", update.socket.id);
                }
            });
        }

        for prov in new_provisions {
            let iface = iface.clone();
            let addr = prov.socket.assigned_ipv6;
            let port = prov.socket.port;
            let proto = prov.socket.protocol;
            let name = prov.socket.process_name.clone();
            join_set.spawn_blocking(move || {
                let network = crate::network::create_network_interface();
                let firewall = crate::firewall::create_firewall();

                if let Err(e) = network.add_address(&iface, addr, prov.prefix_len) {
                    error!("Failed to add IPv6 {} to {}: {e}", addr, iface);
                    return;
                }

                if let Err(e) = firewall.block_all(addr, port, proto) {
                    warn!("Failed to apply firewall rule: {e}");
                }

                info!("Assigned {} to {}:{} ({})", addr, name, port, proto);
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                warn!("Reconciliation task failed: {e}");
            }
        }

        // 3. Clean up stale sockets (not seen for 3 poll cycles)
        let stale_threshold =
            now - chrono::Duration::seconds(config_snapshot.poll_interval_secs as i64 * 3);

        if let Ok(stale) = state.db.stale_sockets(stale_threshold).await {
            let mut stale_join_set = JoinSet::new();
            for s in stale {
                info!(
                    "Cleaning up stale socket: {}:{} ({})",
                    s.process_name, s.port, s.id
                );
                let iface = iface.clone();
                let sid = s.id.clone();
                stale_join_set.spawn_blocking(move || {
                    let firewall = crate::firewall::create_firewall();
                    let network = crate::network::create_network_interface();
                    if let Err(e) = firewall.remove_acl(s.assigned_ipv6, s.port, s.protocol) {
                        warn!("Failed to remove firewall rules for {}: {e}", sid);
                    }
                    if let Err(e) = network.remove_address(&iface, s.assigned_ipv6) {
                        warn!("Failed to remove IPv6 {}: {e}", s.assigned_ipv6);
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
                // Closed = ACL-based: block all unless ACL entries exist
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
            Policy::Open => {
                self.firewall
                    .allow_all(socket.assigned_ipv6, socket.port, socket.protocol)?;
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

        let count = sockets.len();
        let mut join_set = JoinSet::new();
        for socket in sockets {
            let old = old_iface.to_string();
            let new = new_iface.to_string();
            join_set.spawn_blocking(move || {
                let network = crate::network::create_network_interface();
                if let Err(e) = network.add_address(&new, socket.assigned_ipv6, 128) {
                    warn!("Failed to add {} to {}: {e}", socket.assigned_ipv6, new);
                }
                if let Err(e) = network.remove_address(&old, socket.assigned_ipv6) {
                    warn!("Failed to remove {} from {}: {e}", socket.assigned_ipv6, old);
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                warn!("Migration task failed: {e}");
            }
        }

        info!("Migrated {count} addresses from {old_iface} to {new_iface}");
    }
}

/// Apply firewall rules synchronously (for use in spawn_blocking).
fn apply_firewall_sync(
    firewall: &dyn Firewall,
    socket: &ManagedSocket,
    allowed: &[Ipv6Addr],
) -> anyhow::Result<()> {
    match socket.policy {
        Policy::Open => {
            firewall.allow_all(socket.assigned_ipv6, socket.port, socket.protocol)?;
        }
        Policy::Closed => {
            firewall.apply_acl(socket.assigned_ipv6, socket.port, socket.protocol, allowed)?;
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
    use crate::firewall::Firewall;
    use anyhow::Result;
    use socketguard_core::{BackendType, ManagedSocket, Policy, Protocol};
    use std::net::Ipv6Addr;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    /// Mock firewall that records all operations for verification.
    struct MockFirewall {
        calls: StdArc<StdMutex<Vec<FirewallCall>>>,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum FirewallCall {
        ApplyAcl {
            dest_ip: Ipv6Addr,
            port: u16,
            protocol: Protocol,
            allowed: Vec<Ipv6Addr>,
        },
        RemoveAcl {
            dest_ip: Ipv6Addr,
            port: u16,
            protocol: Protocol,
        },
        CleanupAll,
    }

    impl MockFirewall {
        fn new(calls: StdArc<StdMutex<Vec<FirewallCall>>>) -> Self {
            Self { calls }
        }
    }

    impl Firewall for MockFirewall {
        fn apply_acl(
            &self,
            dest_ip: Ipv6Addr,
            dest_port: u16,
            protocol: Protocol,
            allowed: &[Ipv6Addr],
        ) -> Result<()> {
            self.calls.lock().unwrap().push(FirewallCall::ApplyAcl {
                dest_ip,
                port: dest_port,
                protocol,
                allowed: allowed.to_vec(),
            });
            Ok(())
        }

        fn remove_acl(
            &self,
            dest_ip: Ipv6Addr,
            dest_port: u16,
            protocol: Protocol,
        ) -> Result<()> {
            self.calls.lock().unwrap().push(FirewallCall::RemoveAcl {
                dest_ip,
                port: dest_port,
                protocol,
            });
            Ok(())
        }

        fn cleanup_all_rules(&self) -> Result<()> {
            self.calls.lock().unwrap().push(FirewallCall::CleanupAll);
            Ok(())
        }
    }

    fn test_socket(policy: Policy) -> ManagedSocket {
        ManagedSocket {
            id: "test123".to_string(),
            pid: 1000,
            process_name: "test".to_string(),
            port: 8080,
            protocol: Protocol::Tcp,
            assigned_ipv6: "fd00::1".parse().unwrap(),
            backend: BackendType::Ula,
            policy,
            keypair_id: None,
            exe_path: None,
            cmdline: None,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
        }
    }

    #[test]
    fn apply_firewall_sync_closed_no_acl_blocks_all() {
        let calls = StdArc::new(StdMutex::new(Vec::new()));
        let fw = MockFirewall::new(calls.clone());
        let socket = test_socket(Policy::Closed);

        apply_firewall_sync(&fw, &socket, &[]).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0],
            FirewallCall::ApplyAcl {
                dest_ip: "fd00::1".parse().unwrap(),
                port: 8080,
                protocol: Protocol::Tcp,
                allowed: vec![],
            }
        );
    }

    #[test]
    fn apply_firewall_sync_closed_with_acl_allows_listed() {
        let calls = StdArc::new(StdMutex::new(Vec::new()));
        let fw = MockFirewall::new(calls.clone());
        let socket = test_socket(Policy::Closed);
        let allowed: Vec<Ipv6Addr> = vec!["fd00::10".parse().unwrap(), "fd00::20".parse().unwrap()];

        apply_firewall_sync(&fw, &socket, &allowed).unwrap();

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

        // allowed list is ignored for open policy
        apply_firewall_sync(&fw, &socket, &["fd00::99".parse().unwrap()]).unwrap();

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
    fn closed_policy_is_default() {
        let socket = test_socket(Policy::default());
        assert_eq!(socket.policy, Policy::Closed);
    }

    #[test]
    fn managed_string_parses_as_closed() {
        // Backwards compat: "managed" in DB should be treated as Closed
        let policy: Policy = "managed".parse().unwrap();
        assert_eq!(policy, Policy::Closed);
    }

    #[tokio::test]
    async fn reconcile_detects_stale_sockets() {
        let db = crate::state::Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();

        // Insert a socket with a very old last_seen timestamp
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

        // Add an ACL entry
        db.add_acl_entry(&socket.id, "fd00::10", Some("peer1")).await.unwrap();

        let acl = db.get_acl(&socket.id).await.unwrap();
        assert_eq!(acl.len(), 1);
        assert_eq!(acl[0].allowed_ip, "fd00::10");

        // Verify the ACL translates to allowed IPs
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
