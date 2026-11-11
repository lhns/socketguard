//! Networks that are not enforced by the firewall (Tor), and adding and removing networks.

use super::*;
use crate::api::DaemonEvent;
use crate::networks;
use crate::ruleset::Snapshot;
use crate::state::Database;
use crate::AppState;
use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use socketguard_core::{Address, Network};
use std::collections::BTreeSet;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Complete `enforcement` with the service ids this daemon owns and the ledger's
/// tombstones, and return with it the ledger that is being passed to the network, to
/// settle once the network confirms.
fn with_ledger(
    mut enforcement: networks::NetworkEnforcement,
    owned: BTreeSet<String>,
    ledger: &networks::ledger::Ledger,
) -> (networks::NetworkEnforcement, networks::ledger::Ledger) {
    enforcement.owned = owned;
    enforcement.tombstones = ledger.tombstones.clone();
    let passed = networks::ledger::Ledger {
        owned: enforcement.owned.clone(),
        tombstones: enforcement.tombstones.clone(),
    };
    (enforcement, passed)
}

impl Engine {
    /// Enforce the grants on the networks that do not use the firewall (Tor). The caller
    /// holds the firewall lock, which also keeps two enforcements from interleaving. A
    /// failure (e.g. Tor is down) is logged, shows as the network's status and in
    /// [`Engine::enforcement_pending`] (so API mutations answer 202); the next pass
    /// retries, including removals recorded in the ledger (`networks::ledger`).
    pub(super) async fn enforce_networks(&self, state: &AppState, snapshot: &Snapshot) {
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
        let disabled = state.db.disabled().await;
        let secrets = match state.db.onion_keys().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Could not gather the state to enforce: {e}");
                return;
            }
        };
        let binds = self.binds.lock().unwrap().clone();
        let model = socketguard_core::Model::new(snapshot.world());
        let address_info = model.address_info();
        let ledger = networks::ledger::load(&state.db).await.unwrap_or_else(|e| {
            warn!("Could not read the onion service ledger: {e:#}");
            Default::default()
        });
        for (id, net) in nets {
            let Some(info) = snapshot.networks.iter().find(|n| n.id == id) else {
                continue;
            };
            let mut enforcement =
                networks::enforcement_for(info, snapshot, &model, &address_info, &secrets, &binds);
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
            let (enforcement, passed) = with_ledger(
                enforcement,
                ledger.owned.union(&wanted).cloned().collect(),
                &ledger,
            );
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
        let n = networks::create(&inst.backend, self.ula_global_id, self.ifaces.clone())
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
        let (enforcement, passed) = with_ledger(
            networks::NetworkEnforcement::default(),
            ledger.owned.union(&ledger.tombstones).cloned().collect(),
            &ledger,
        );
        tokio::task::spawn_blocking(move || net.enforce(&enforcement)).await??;
        networks::ledger::settle(&state.db, &passed, &BTreeSet::new()).await?;
        Ok(passed)
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
        let created = match self.ensure_addresses(state).await {
            Ok(n) => n,
            Err(e) => {
                error!("Could not allocate addresses for '{}': {e}", inst.id);
                0
            }
        };
        // The network is live either way; a failed apply is retried by the next pass.
        let applied = self.apply_and_ensure(state).await;
        let _ = self
            .commit(
                state,
                applied,
                None,
                &[DaemonEvent::NetworksChanged, DaemonEvent::AppsChanged],
            )
            .await;
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
        let applied = self.apply_firewall(state).await;
        self.sweep_owned(state).await;
        let _ = self
            .commit(
                state,
                applied,
                None,
                &[
                    DaemonEvent::NetworksChanged,
                    DaemonEvent::AppsChanged,
                    DaemonEvent::GrantsChanged,
                ],
            )
            .await;
        info!("Backend '{}' removed", backend_id);
    }

    /// Release the locators of `addresses` on a network that is not an IP network (the
    /// onion services leave Tor). IP addresses are taken off their interface by
    /// `remove_from_interface` instead; here they only give their lease back (DHCPv6).
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
            let ips: Vec<_> = addresses.iter().filter_map(|a| a.locator.ipv6()).collect();
            let net = active.network.clone();
            let released = tokio::task::spawn_blocking(move || {
                for ip in ips {
                    if let Err(e) = net.release_lease(ip) {
                        warn!("Could not release the lease of {ip}: {e:#}");
                    }
                }
            })
            .await;
            if let Err(e) = released {
                warn!("Release task failed: {e}");
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networks::ip::{AllocatedAddress, Ipv6Backend, Prefix};
    use crate::test_support::*;
    use socketguard_core::{Locator, Scope};
    use std::net::Ipv6Addr;
    use std::sync::Mutex;

    /// A DHCPv6-like allocator that only records the releases it is asked for.
    #[derive(Clone, Default)]
    struct ReleaseLog(Arc<Mutex<Vec<Ipv6Addr>>>);

    impl Ipv6Backend for ReleaseLog {
        fn current_prefix(&self) -> anyhow::Result<Option<Prefix>> {
            Ok(None)
        }
        fn allocate(&self, _iid: Option<u64>) -> anyhow::Result<AllocatedAddress> {
            anyhow::bail!("not used")
        }
        fn release_address(&self, addr: &Ipv6Addr) -> anyhow::Result<()> {
            self.0.lock().unwrap().push(*addr);
            anyhow::bail!("server unreachable")
        }
    }

    #[tokio::test]
    async fn removing_the_addresses_of_an_ip_network_releases_their_leases() {
        let log = ReleaseLog::default();
        let inst = BackendInstanceConfig {
            id: "dhcp".into(),
            backend: socketguard_core::config::BackendConfig::Dhcpv6 {
                interface: "eth0".into(),
            },
        };
        let mut backends = std::collections::HashMap::new();
        backends.insert(
            "dhcp".to_string(),
            ip_backend(inst.clone(), Box::new(log.clone())),
        );
        let engine = crate::engine::Engine::new_injectable(
            Box::new(MockSocketMonitor::new(vec![])),
            Arc::new(MockFirewall::new(Arc::new(Mutex::new(vec![])))),
            Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
            backends,
        );
        let state = test_app_state(
            engine,
            DaemonConfig {
                backends: vec![inst],
                ..Default::default()
            },
        )
        .await;
        let address = |addr: &str| {
            Address::automatic(
                "a",
                Scope::All,
                "dhcp",
                Locator::Ipv6 {
                    addr: addr.parse().unwrap(),
                },
            )
        };
        let engine = state.engine.read().await;
        // A failing release does not stop the others.
        engine
            .remove_locators(
                &state,
                "dhcp",
                &[address("2001:db8::1"), address("2001:db8::2")],
            )
            .await;
        assert_eq!(
            *log.0.lock().unwrap(),
            ["2001:db8::1", "2001:db8::2"].map(|a| a.parse::<Ipv6Addr>().unwrap())
        );
    }
}
