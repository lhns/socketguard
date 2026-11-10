//! Networks that are not enforced by the firewall (Tor), and adding and removing networks.

use super::*;
use crate::api::DaemonEvent;
use crate::backend::Ipv6Backend;
use crate::networks::{self, IpNetwork};
use crate::state::Database;
use crate::AppState;
use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use socketguard_core::{Address, Network};
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use tracing::{error, info, warn};

impl Engine {
    /// Enforce the grants on the networks that do not use the firewall (Tor). The caller
    /// holds the firewall lock, which also keeps two enforcements from interleaving. A
    /// failure (e.g. Tor is down) is logged, shows as the network's status and in
    /// [`Engine::enforcement_pending`] (so API mutations answer 202); the next pass
    /// retries, including removals recorded in the ledger (`networks::ledger`).
    pub(super) async fn enforce_networks(&self, state: &AppState) {
        if state.db.unadopted().await.unwrap_or(false) {
            return; // an unadopted ruleset: nothing is added or removed until `enable`
        }
        let nets: Vec<(String, Arc<dyn networks::Network>)> = self
            .sorted_backend_ids()
            .into_iter()
            .map(|id| (id.clone(), self.backends[id].network.clone()))
            .filter(|(_, n)| !n.capabilities().ip_locators)
            .collect();
        if nets.is_empty() {
            return;
        }
        // While disabled nothing is wanted, so every owned service is removed and the
        // removal keeps being retried (e.g. Tor was down when `disable` ran). An unreadable
        // latch counts as disabled: failing closed means unpublished.
        let disabled = state.db.disabled().await.unwrap_or(true);
        let prepared = async {
            let snapshot = self.gather_snapshot(state).await?;
            let secrets = state.db.onion_keys().await?;
            anyhow::Ok((snapshot, secrets))
        }
        .await;
        let (snapshot, secrets) = match prepared {
            Ok(p) => p,
            Err(e) => {
                warn!("Could not gather the state to enforce: {e}");
                return;
            }
        };
        let binds = self.binds.lock().unwrap().clone();
        let ledger = networks::ledger::load(&state.db).await.unwrap_or_else(|e| {
            warn!("Could not read the onion service ledger: {e:#}");
            Default::default()
        });
        for (id, net) in nets {
            let Some(info) = snapshot.networks.iter().find(|n| n.id == id) else {
                continue;
            };
            let mut enforcement = networks::enforcement_for(info, &snapshot, &secrets, &binds);
            if disabled {
                enforcement.addresses.clear();
            }
            let wanted: BTreeSet<String> = enforcement
                .addresses
                .iter()
                .filter_map(|a| networks::tor::service_id(&a.locator))
                .collect();
            // Record what may come to exist before it is published, so a crash cannot
            // leave a service nobody would sweep.
            if let Err(e) = networks::ledger::add_owned(&state.db, &wanted).await {
                warn!("Could not record the onion services: {e:#}");
            }
            enforcement.owned = ledger.owned.union(&wanted).cloned().collect();
            enforcement.tombstones = ledger.tombstones.clone();
            let passed = networks::ledger::Ledger {
                owned: enforcement.owned.clone(),
                tombstones: enforcement.tombstones.clone(),
            };
            let result = tokio::task::spawn_blocking(move || net.enforce(&enforcement)).await;
            let outcome = match result {
                Ok(r) => r,
                Err(e) => Err(anyhow::anyhow!("enforcement task failed: {e}")),
            };
            let settled = match outcome {
                Ok(()) => {
                    if self.enforce_failing.lock().unwrap().remove(&id).is_some() {
                        info!("Network '{id}' enforcement recovered");
                    }
                    true
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    let mut failing = self.enforce_failing.lock().unwrap();
                    if failing.insert(id.clone(), msg.clone()).as_deref() != Some(msg.as_str()) {
                        warn!("Cannot enforce grants on network '{id}', will retry: {msg}");
                    }
                    false
                }
            };
            if settled {
                // Everything not wanted that we passed in is gone now.
                if let Err(e) = networks::ledger::settle(&state.db, &passed, &wanted).await {
                    warn!("Could not update the onion service ledger: {e:#}");
                }
            }
        }
    }

    /// Some network has a saved change it has not confirmed yet
    /// ([`networks::Network::pending`]), e.g. Tor is down and a service must be published
    /// or removed. Mutations report it to their caller (HTTP 202); a network that is merely
    /// down with nothing to do does not count.
    pub fn enforcement_pending(&self) -> Option<socketguard_core::api_types::Enforcement> {
        let failing = self.enforce_failing.lock().unwrap();
        let mut parts: Vec<String> = self
            .backends
            .iter()
            .filter(|(_, b)| b.network.pending())
            .map(|(id, _)| match failing.get(id) {
                Some(msg) => format!("network '{id}': {msg}"),
                None => format!("network '{id}': not yet applied"),
            })
            .collect();
        if parts.is_empty() {
            return None;
        }
        parts.sort();
        Some(socketguard_core::api_types::Enforcement {
            status: socketguard_core::api_types::EnforcementStatus::Pending,
            message: format!(
                "saved, but not yet enforced; retrying ({})",
                parts.join("; ")
            ),
        })
    }

    /// Check if backends config has changed and apply additions/removals.
    /// Returns true if changes were detected.
    pub(super) async fn check_config_change(
        &mut self,
        config: &DaemonConfig,
        state: &AppState,
    ) -> bool {
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
        match networks::create(&inst.backend, self.ula_global_id, self.network.clone()) {
            Ok(n) => self.add_network_instance(state, inst, n).await,
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
        let mut all = self.backend_configs();
        all.push(inst.clone());
        DaemonConfig::validate_backends(&all).map_err(|e| {
            if e.starts_with("at most one") {
                EngineError::Conflict(e)
            } else {
                EngineError::Invalid(e)
            }
        })?;
        let n = networks::create(&inst.backend, self.ula_global_id, self.network.clone())
            .map_err(|e| EngineError::Invalid(format!("cannot create network: {e}")))?;
        self.add_network_instance(state, &inst, n).await;
        self.networks()
            .into_iter()
            .find(|n| n.id == inst.id)
            .ok_or_else(|| EngineError::Internal(anyhow::anyhow!("network vanished")))
    }

    /// The API's remove. A network that is not an IP network (Tor) first removes every
    /// service this daemon owns on it; once the network is gone nothing retries a removal
    /// that failed, so that failure refuses the request (409) unless `force`.
    pub async fn remove_network(
        &mut self,
        state: &AppState,
        id: &str,
        force: bool,
    ) -> Result<(), EngineError> {
        let Some(active) = self.backends.get(id) else {
            return Err(EngineError::NotFound(format!("network {id}")));
        };
        let mut swept = None;
        if !active.network.capabilities().ip_locators {
            match self
                .remove_owned_services(state, active.network.clone())
                .await
            {
                Ok(passed) => swept = Some(passed),
                Err(e) if force => {
                    warn!("Removing network '{id}' although its services were not removed: {e:#}")
                }
                Err(e) => {
                    return Err(EngineError::Conflict(format!(
                        "Tor services are still being removed; retry when Tor is reachable, or \
                         use --force ({e:#})"
                    )))
                }
            }
        }
        self.remove_backend_instance(state, id).await;
        if let Some(passed) = swept {
            // Deleting the addresses recorded their services again; they are gone.
            if let Err(e) = networks::ledger::settle(&state.db, &passed, &BTreeSet::new()).await {
                warn!("Could not update the onion service ledger: {e:#}");
            }
        }
        Ok(())
    }

    /// Take down every service the ledger lists as owned or to be removed, as a
    /// [`Engine::enforce_networks`] pass with no addresses would. Returns the ledger that
    /// was swept once Tor confirmed it (or there was nothing to remove).
    pub(super) async fn remove_owned_services(
        &self,
        state: &AppState,
        net: Arc<dyn networks::Network>,
    ) -> anyhow::Result<networks::ledger::Ledger> {
        let _lock = state.firewall_lock.lock().await;
        let ledger = networks::ledger::load(&state.db).await?;
        if ledger.owned.is_empty() && ledger.tombstones.is_empty() {
            return Ok(ledger);
        }
        let enforcement = networks::NetworkEnforcement {
            addresses: Vec::new(),
            owned: ledger.owned.union(&ledger.tombstones).cloned().collect(),
            tombstones: ledger.tombstones.clone(),
        };
        let passed = networks::ledger::Ledger {
            owned: enforcement.owned.clone(),
            tombstones: enforcement.tombstones.clone(),
        };
        tokio::task::spawn_blocking(move || net.enforce(&enforcement)).await??;
        networks::ledger::settle(&state.db, &passed, &BTreeSet::new()).await?;
        Ok(passed)
    }

    /// [`Engine::add_backend_instance`] with the allocator already built (tests inject mocks).
    pub async fn add_backend_instance_with(
        &mut self,
        state: &AppState,
        inst: &BackendInstanceConfig,
        b: Box<dyn Ipv6Backend>,
    ) {
        let network = Arc::new(IpNetwork::for_config(&inst.backend, b));
        self.add_network_instance(state, inst, network).await;
    }

    /// Add a network that is already built.
    pub async fn add_network_instance(
        &mut self,
        state: &AppState,
        inst: &BackendInstanceConfig,
        network: Arc<dyn networks::Network>,
    ) {
        // The ruleset (overlay scope, managed addresses) must know the network before
        // its addresses go on the interface.
        self.backends.insert(
            inst.id.clone(),
            ActiveBackend {
                config: inst.clone(),
                network,
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
        // Write ahead: the addresses are marked retiring before their rows go, and stay
        // denied until they are really off the interface.
        let existing: Vec<Address> = state
            .db
            .list_addresses()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.network_id == backend_id)
            .collect();
        if let Err(e) = self.retire_addresses(state, &existing).await {
            error!("Could not record the addresses of '{backend_id}' as retiring: {e}");
        }
        let deleted = match state.db.delete_addresses_by_network(backend_id).await {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to delete addresses for backend '{backend_id}': {e}");
                Vec::new()
            }
        };
        self.remove_locators(state, backend_id, &deleted).await;
        self.backends.remove(backend_id);
        state
            .config
            .write()
            .await
            .backends
            .retain(|b| b.id != backend_id);
        self.current_backend_ids.retain(|id| id != backend_id);
        let _ = self.apply_firewall(state).await;
        self.sweep_owned(state).await;
        self.emit(state, DaemonEvent::NetworksChanged);
        self.emit(state, DaemonEvent::AppsChanged);
        self.emit(state, DaemonEvent::GrantsChanged);
        info!("Backend '{}' removed", backend_id);
    }

    /// Release the locators of `addresses` on a network that is not an IP network (the
    /// onion services leave Tor). IP addresses are taken off their interface by
    /// `remove_from_interface` instead.
    pub(super) async fn remove_locators(
        &self,
        state: &AppState,
        network_id: &str,
        addresses: &[Address],
    ) {
        let Some(active) = self.backends.get(network_id) else {
            return;
        };
        if active.network.capabilities().ip_locators {
            return;
        }
        for a in addresses {
            // Tombstone first: if the network cannot be reached now (or we crash), the
            // service is still removed by a later enforcement pass.
            let id: Vec<String> = networks::tor::service_id(&a.locator).into_iter().collect();
            if let Err(e) = networks::ledger::add_tombstones(&state.db, &id).await {
                warn!("Could not record the removal of {id:?}: {e:#}");
            }
            let net = active.network.clone();
            let addr = a.clone();
            match tokio::task::spawn_blocking(move || net.remove_locator(&addr)).await {
                Ok(Ok(())) => {
                    if let Err(e) = networks::ledger::clear_tombstones(&state.db, &id).await {
                        warn!("Could not clear the removal of {id:?}: {e:#}");
                    }
                }
                Ok(Err(e)) => {
                    warn!("Could not release a locator on '{network_id}', will retry: {e:#}")
                }
                Err(e) => warn!("Release task failed: {e}"),
            }
        }
    }
}

/// Take everything of ours off the networks that are not IP networks (the onion services
/// leave Tor), for the `disable` latch. A network that cannot be reached is logged; its
/// services stay until it is back and the latch is still set (enforcement is suspended).
pub(super) async fn disable_networks(
    db: &Database,
    networks: Vec<(String, Arc<dyn networks::Network>)>,
) {
    let addresses = match db.list_addresses().await {
        Ok(a) => a,
        Err(e) => {
            warn!("Could not list addresses to disable: {e}");
            return;
        }
    };
    for (id, net) in networks {
        if net.capabilities().ip_locators {
            continue;
        }
        let mine: Vec<Address> = addresses
            .iter()
            .filter(|a| a.network_id == id)
            .cloned()
            .collect();
        match tokio::task::spawn_blocking(move || net.disable(&mine)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("Could not disable network '{id}': {e}"),
            Err(e) => warn!("Disable task failed: {e}"),
        }
    }
}
