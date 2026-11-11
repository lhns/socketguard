//! What the block on a Yggdrasil network keeps off the host, and whether it is in force
//! (ADR 0051). Read-only: the frontends show it before the block goes (turn off, remove a
//! network) and `networks setup` checks it before it starts any software.

use super::*;
use crate::firewall::ScopeMatch;
use crate::ruleset::overlay_addr_scope_id;
use socketguard_core::api_types::{ExposedListener, ExposureResponse, NetworkExposure};
use socketguard_core::setup::YggdrasilBlock;
use socketguard_core::{NetworkKind, NetworkStatus};
use std::net::IpAddr;
use std::sync::atomic::Ordering;

/// Reasons for a status that mean the node itself is not running.
fn node_is_down(reason: &str) -> bool {
    reason == networks::ip::yggdrasil::NOT_FOUND
        || reason.starts_with(networks::ip::yggdrasil::NOT_RUNNING)
}

impl Engine {
    /// The Yggdrasil network the engine manages, if any.
    fn yggdrasil_backend(&self) -> Option<(&String, &ActiveBackend)> {
        self.backends
            .iter()
            .find(|(_, b)| b.network.kind() == NetworkKind::Yggdrasil)
    }

    /// Whether the block of the Yggdrasil network is in the ruleset last applied, and that
    /// apply succeeded. None without a Yggdrasil network.
    pub async fn yggdrasil_block(&self, state: &AppState) -> Option<YggdrasilBlock> {
        let (id, active) = self.yggdrasil_backend()?;
        let iface = Self::interface_in_use(active);
        // An interface rule holds for an adapter that is not there yet on nftables and pf,
        // not on WFP, which can only bind a filter to an adapter that exists.
        let adapter_ok = self.firewall.blocks_absent_interfaces()
            || iface.as_ref().is_some_and(|name| {
                self.ifaces
                    .list_interfaces()
                    .is_ok_and(|l| l.iter().any(|i| &i.name == name))
            });
        let applied = self.last_applied.lock().unwrap().clone();
        let failed = self.apply_failed.load(Ordering::Relaxed);
        let (address_blocked, interface_blocked) = match (&applied, failed) {
            (Some(rs), false) => (
                rs.scopes.iter().any(|s| s.id == overlay_addr_scope_id(id)),
                adapter_ok
                    && rs.scopes.iter().any(|s| {
                        matches!(&s.matcher, ScopeMatch::Interface { name, .. }
                            if Some(name) == iface.as_ref())
                    }),
            ),
            _ => (false, false),
        };
        let reason = if state.db.disabled().await {
            Some("SocketGuard is turned off".to_string())
        } else if failed {
            Some("the last attempt to apply the firewall rules failed".to_string())
        } else if applied.is_none() {
            Some("the firewall rules are not applied yet".to_string())
        } else if !address_blocked && !adapter_ok {
            Some("the node's address is not known yet, and the firewall can only block an adapter that exists".to_string())
        } else if !address_blocked {
            Some("the node's address is not known yet".to_string())
        } else {
            None
        };
        Some(YggdrasilBlock {
            closed: address_blocked,
            address_blocked,
            interface_blocked,
            reason,
        })
    }

    /// What becomes reachable over the networks without SocketGuard's block: `without` is
    /// a network id, or None for all of them.
    pub async fn exposure(
        &self,
        state: &AppState,
        without: Option<&str>,
    ) -> Result<ExposureResponse, EngineError> {
        if let Some(id) = without {
            if !self.backends.contains_key(id) {
                return Err(EngineError::NotFound(format!("network {id}")));
            }
        }
        let apps = state.db.list_apps().await?;
        // The sockets themselves: a port also bound on loopback is still reachable on `::`.
        let sockets = self.monitor.list_listening_sockets()?;
        let mut listeners: Vec<ExposedListener> = sockets
            .iter()
            .filter(|ls| matches!(ls.bind_address, IpAddr::V6(a) if a.is_unspecified()))
            .map(|ls| {
                let id = socketguard_core::app_identity(ls).id;
                ExposedListener {
                    app: apps
                        .iter()
                        .find(|a| a.id == id)
                        .map_or_else(|| ls.process_name.clone(), |a| a.name.clone()),
                    port: ls.port,
                    proto: ls.protocol,
                }
            })
            .collect();
        listeners.sort_by(|a, b| (&a.app, a.port, a.proto).cmp(&(&b.app, b.port, b.proto)));
        listeners.dedup();
        let started = started_by_setup(state.config_path.as_deref());
        let mut ids: Vec<&String> = self
            .backends
            .iter()
            .filter(|(id, b)| {
                b.network.kind() == NetworkKind::Yggdrasil
                    && without.is_none_or(|w| w == id.as_str())
            })
            .map(|(id, _)| id)
            .collect();
        ids.sort();
        let networks = ids
            .into_iter()
            .map(|id| {
                let active = &self.backends[id];
                let (status, _) = active.network.status();
                let node_running = match &status {
                    NetworkStatus::Up => true,
                    NetworkStatus::Down { reason } => !node_is_down(reason),
                };
                NetworkExposure {
                    network: id.clone(),
                    kind: NetworkKind::Yggdrasil,
                    interface: Self::interface_in_use(active),
                    node_running,
                    listeners: if node_running {
                        listeners.clone()
                    } else {
                        vec![]
                    },
                    services_started_by_setup: started.clone(),
                }
            })
            .collect();
        Ok(ExposureResponse { networks })
    }
}

/// The services `networks setup yggdrasil` started, from the setup log next to the config
/// file. Read as plain JSON so that the log's writer owns its type.
fn started_by_setup(config: Option<&std::path::Path>) -> Vec<String> {
    let Some(config) = config else {
        return vec![];
    };
    let path = config
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("setup-log.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) else {
        return vec![];
    };
    let mut out: Vec<String> = doc["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["kind"] == "yggdrasil" && e["type"] == "service_started")
        .filter_map(|e| e["service"].as_str().map(str::to_string))
        .collect();
    out.sort();
    out.dedup();
    out
}
