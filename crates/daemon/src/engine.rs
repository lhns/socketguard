use crate::backend::{self, Ipv6Backend};
use crate::firewall::{self, Firewall};
use crate::monitor::{self, SocketMonitor};
use crate::network::{self, NetworkInterface};
use crate::AppState;
use socketguard_core::config::DaemonConfig;
use socketguard_core::{socket_id, ManagedSocket, Policy};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct Engine {
    monitor: Box<dyn SocketMonitor>,
    backend: Box<dyn Ipv6Backend>,
    firewall: Box<dyn Firewall>,
    network: Box<dyn NetworkInterface>,
}

impl Engine {
    pub fn new(config: &DaemonConfig) -> Self {
        Self {
            monitor: monitor::create_monitor(),
            backend: backend::create_backend(config.backend),
            firewall: firewall::create_firewall(),
            network: network::create_network_interface(),
        }
    }

    /// Reconcile: detect sockets, assign IPs, apply firewall rules
    pub async fn reconcile(&self, state: &AppState) -> anyhow::Result<()> {
        let config = state.config.read().await;
        let iface = config.interface.clone();
        drop(config);

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
            // Identity is based on process name + port + protocol (not PID).
            // This means a process restart keeps its IPv6 and ACLs.
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
                continue;
            }

            // New socket - allocate IPv6
            info!(
                "New socket detected: {}:{} (PID {} - {})",
                ls.protocol, ls.port, ls.pid, ls.process_name
            );

            match self.backend.allocate_address() {
                Ok(alloc) => {
                    // Add address to interface
                    if let Err(e) = self.network.add_address(&iface, alloc.address, alloc.prefix_len) {
                        error!("Failed to add IPv6 {} to {}: {e}", alloc.address, iface);
                        continue;
                    }

                    // Save keypair if present
                    let keypair_id = if let Some(ref kp) = alloc.keypair {
                        if let Err(e) = state.db.save_keypair(
                            &kp.id,
                            &kp.public_key,
                            &kp.private_key,
                            &kp.derived_ipv6.to_string(),
                        ).await {
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

                    // Apply default closed policy (acquire lock for firewall ops)
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
        let config = state.config.read().await;
        let stale_threshold = now - chrono::Duration::seconds(config.poll_interval_secs as i64 * 3);
        drop(config);

        if let Ok(stale) = state.db.stale_sockets(stale_threshold).await {
            for s in stale {
                info!("Cleaning up stale socket: {}:{} ({})", s.process_name, s.port, s.id);

                let _lock = state.firewall_lock.lock().await;
                if let Err(e) = self.firewall.remove_acl(s.assigned_ipv6, s.port, s.protocol) {
                    warn!("Failed to remove firewall rules for {}: {e}", s.id);
                }
                drop(_lock);

                let config = state.config.read().await;
                if let Err(e) = self.network.remove_address(&config.interface, s.assigned_ipv6) {
                    warn!("Failed to remove IPv6 {}: {e}", s.assigned_ipv6);
                }
                drop(config);

                if let Err(e) = state.db.delete_socket(&s.id).await {
                    error!("Failed to delete socket {}: {e}", s.id);
                }
            }
        }

        Ok(())
    }

    /// Apply ACL for a socket based on its current policy and ACL entries.
    /// Acquires the firewall lock to prevent concurrent rule modifications.
    pub async fn apply_socket_acl(&self, state: &AppState, socket_id: &str) -> anyhow::Result<()> {
        let socket = state
            .db
            .get_socket(socket_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("socket not found"))?;

        let _lock = state.firewall_lock.lock().await;

        match socket.policy {
            Policy::Closed => {
                self.firewall.block_all(socket.assigned_ipv6, socket.port, socket.protocol)?;
            }
            Policy::Open => {
                self.firewall.allow_all(socket.assigned_ipv6, socket.port, socket.protocol)?;
            }
            Policy::Managed => {
                let acl = state.db.get_acl(socket_id).await?;
                let allowed: Vec<Ipv6Addr> = acl
                    .iter()
                    .filter_map(|e| e.allowed_ip.parse().ok())
                    .collect();
                self.firewall
                    .apply_acl(socket.assigned_ipv6, socket.port, socket.protocol, &allowed)?;
            }
        }

        Ok(())
    }
}

/// Run the reconciliation loop with panic recovery.
/// If the loop panics, it logs the error and restarts after a delay.
pub async fn run_loop(state: Arc<AppState>) {
    loop {
        let interval = {
            let config = state.config.read().await;
            config.poll_interval_secs
        };

        if let Err(e) = state.engine.reconcile(&state).await {
            error!("Reconciliation error: {e}");
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}
