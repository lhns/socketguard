//! The addresses apps get on each network and their presence on the interfaces: planning,
//! allocating, re-homing, sweeping, `split` and `merge`.

use super::*;
use crate::api::DaemonEvent;
use crate::backend::{iid_of, same_prefix64, with_prefix64};
use crate::firewall::{Firewall, ScopeMatch};
use crate::network::NetworkInterface;
use crate::networks::{LocatorRequest, NewLocator};
use crate::state::{Database, OwnedAddress};
use crate::AppState;
use chrono::Utc;
use socketguard_core::{
    new_id, Address, AddressId, AddressMode, AppPort, Locator, PortRef, PortSet, Protocol,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

impl Engine {
    /// Write ahead of taking `addresses` off their interfaces: mark them retiring. They
    /// stay in the ruleset's managed scope until [`Engine::sweep_owned`] has confirmed
    /// their removal, so no address is ever on an interface without deny rules.
    pub(super) async fn retire_addresses(
        &self,
        state: &AppState,
        addresses: &[Address],
    ) -> anyhow::Result<()> {
        for a in addresses {
            if let (Some(ip), Some(iface)) = (a.locator.ipv6(), self.interface_of(&a.network_id)) {
                state
                    .db
                    .retire_address(ip, iface, Some(&a.network_id))
                    .await?;
            }
        }
        Ok(())
    }

    /// Take every owned address that no longer belongs to an app off its interface, and
    /// retry the ones whose removal failed before. A row is deleted only once the removal
    /// is confirmed. Run after the ruleset is applied; needs no ruleset itself.
    pub(super) async fn sweep_owned(&self, state: &AppState) {
        let db = &state.db;
        let (owned, addresses) = match (db.list_owned_addresses().await, db.list_addresses().await)
        {
            (Ok(o), Ok(a)) => (o, a),
            (Err(e), _) | (_, Err(e)) => {
                // Never sweep on a guess: without the address list everything looks orphaned.
                warn!("Cannot sweep owned addresses: {e}");
                return;
            }
        };
        let referenced: HashSet<Ipv6Addr> =
            addresses.iter().filter_map(|a| a.locator.ipv6()).collect();
        let disabled = db.disabled().await;
        let due: Vec<OwnedAddress> = owned
            .into_iter()
            .filter(|o| !referenced.contains(&o.addr) || (disabled && o.retiring))
            .collect();
        if due.is_empty() {
            self.removal_failing.lock().unwrap().clear();
            return;
        }
        let due_count = due.len();
        let failures = release_owned(db, &self.network, due).await;
        {
            let mut failing = self.removal_failing.lock().unwrap();
            let still: HashSet<Ipv6Addr> = failures.iter().map(|(o, _)| o.addr).collect();
            for (o, e) in &failures {
                if failing.insert(o.addr) {
                    warn!(
                        "Cannot remove {} from {}, it stays denied and the removal is retried: {e}",
                        o.addr, o.interface
                    );
                }
            }
            failing.retain(|a| still.contains(a));
        }
        if failures.len() < due_count {
            // Gone for good: the ruleset can stop naming them.
            let _ = self.apply_firewall_if_changed(state).await;
        }
        // A `disable` that left the rules because some address would not go: the last one
        // is gone now, so finish the job.
        if disabled
            && failures.is_empty()
            && db.list_owned_addresses().await.is_ok_and(|o| o.is_empty())
        {
            let fw = self.firewall.clone();
            let removed = tokio::task::spawn_blocking(move || {
                // Only if rules are still installed (a finished `disable` left none).
                if fw.verify()? {
                    fw.disable()?;
                    return anyhow::Ok(true);
                }
                Ok(false)
            })
            .await;
            match removed {
                Ok(Ok(true)) => info!("All addresses are gone; the firewall rules were removed"),
                Ok(Ok(false)) => {}
                Ok(Err(e)) => warn!("Could not remove the firewall rules: {e:#}"),
                Err(e) => warn!("Rule removal task failed: {e}"),
            }
        }
    }

    /// Whether the ruleset that is in force denies `addr` (it is in the managed scope).
    pub(super) fn covered_by_applied(&self, addr: Ipv6Addr) -> bool {
        let applied = self.last_applied.lock().unwrap();
        applied.as_ref().is_some_and(|rs| {
            rs.scopes.iter().any(|s| {
                matches!(&s.matcher, ScopeMatch::Destinations(d) if d.contains(&IpAddr::V6(addr)))
            })
        })
    }

    /// Put `addr` on `iface`: only if the ruleset last applied successfully denies it, and
    /// recorded as owned before the interface changes. Returns whether it was added.
    pub(super) async fn add_to_interface(
        &self,
        state: &AppState,
        iface: &str,
        network_id: &str,
        addr: Ipv6Addr,
    ) -> bool {
        if !self.covered_by_applied(addr) {
            debug!("Not adding {addr} to {iface}: the applied ruleset does not cover it");
            return false;
        }
        if let Err(e) = state.db.claim_address(addr, iface, Some(network_id)).await {
            warn!("Not adding {addr} to {iface}: cannot record it first: {e}");
            return false;
        }
        match self.network.add_address(iface, addr, ADDRESS_PREFIX_LEN) {
            Ok(()) => true,
            Err(e) => {
                warn!("Failed to add {addr} to {iface}: {e}");
                false
            }
        }
    }

    /// Give every app the addresses its layout calls for on every network; a failed
    /// allocation is retried on the next pass. Returns the number created.
    pub(super) async fn ensure_addresses(&self, state: &AppState) -> anyhow::Result<usize> {
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
                let mut app_ports: Vec<PortRef> = app.ports.iter().map(AppPort::port_ref).collect();
                if !active.network.capabilities().udp {
                    app_ports.retain(|p| p.proto == Protocol::Tcp);
                    if app_ports.is_empty() {
                        continue; // nothing this network can serve
                    }
                }
                for ports in plan_addresses(mode, &app_ports, &existing) {
                    let address_id = new_id();
                    match self
                        .make_locator(active, &app.id, &address_id, &ports)
                        .await
                    {
                        Ok(NewLocator { locator, secret }) => {
                            self.alloc_failing.lock().unwrap().remove(nid);
                            let address = Address {
                                id: address_id,
                                app_id: app.id.clone(),
                                network_id: nid.clone(),
                                ports,
                                locator,
                                created_at: Utc::now(),
                            };
                            state
                                .db
                                .insert_address_with_secret(&address, secret.as_deref())
                                .await?;
                            info!(
                                "Assigned {} ({nid}) to {} ({})",
                                locator_text(&address.locator),
                                app.name,
                                app.id
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

    /// Ask a network for the locator of a new address.
    pub(super) async fn make_locator(
        &self,
        active: &ActiveBackend,
        app_id: &str,
        address_id: &str,
        ports: &PortSet,
    ) -> anyhow::Result<NewLocator> {
        let net = active.network.clone();
        let req = LocatorRequest {
            app_id: app_id.to_string(),
            address_id: address_id.to_string(),
            ports: ports.clone(),
        };
        tokio::task::spawn_blocking(move || net.ensure_locator(&req)).await?
    }

    /// Re-home stored addresses of prefix-based networks whose /64 changed: keep the
    /// interface ID, swap the prefix, update the DB, apply the ruleset that covers the new
    /// addresses, add them, and only then take the old ones off (they stay denied as
    /// retiring until then).
    pub(super) async fn rehome_prefix_changes(&self, state: &AppState) {
        let mut moves: Vec<(String, String, Ipv6Addr)> = Vec::new();
        let addresses = match state.db.list_addresses().await {
            Ok(a) => a,
            Err(e) => {
                warn!("Failed to list addresses for prefix check: {e}");
                return;
            }
        };
        for network_id in self.sorted_backend_ids() {
            let active = &self.backends[network_id];
            let prefix = match active.network.current_prefix() {
                Ok(Some(p)) if p.len == 64 => p,
                Ok(_) => continue,
                Err(e) => {
                    debug!("Cannot read current prefix of backend '{network_id}': {e}");
                    continue;
                }
            };
            let Some(iface) = active.config.backend.interface() else {
                continue;
            };
            for a in addresses.iter().filter(|a| a.network_id == *network_id) {
                let Some(old) = a.locator.ipv6() else {
                    continue;
                };
                if same_prefix64(old, prefix.addr) {
                    continue;
                }
                let new = with_prefix64(prefix.addr, iid_of(old));
                info!("Prefix of backend '{network_id}' changed: moving {old} to {new}");
                // Write ahead: the old address is retiring before the row stops naming it.
                if let Err(e) = state
                    .db
                    .retire_address(old, iface, Some(network_id.as_str()))
                    .await
                {
                    error!("Failed to record {old} as retiring: {e}");
                    continue;
                }
                match state.db.update_address_ipv6(&a.id, new).await {
                    Ok(_) => moves.push((iface.to_string(), network_id.clone(), new)),
                    Err(e) => error!("Failed to save re-homed address: {e}"),
                }
            }
        }
        if moves.is_empty() {
            return;
        }

        // New addresses go on only once a ruleset that covers them is in place; without
        // one the ensure-present pass adds them after the next successful apply. Disabled:
        // the apply was a no-op, and nothing may put addresses back.
        let _ = self.apply_firewall(state).await;
        if !state.db.disabled().await {
            for (iface, network_id, new) in moves {
                self.add_to_interface(state, &iface, &network_id, new).await;
            }
        }
        self.sweep_owned(state).await;
        self.emit(state, DaemonEvent::AppsChanged);
    }

    /// Take retired and orphaned addresses off their interfaces, then re-add expected
    /// addresses that are missing, e.g. after Yggdrasil restarted and recreated its tun.
    /// Interfaces that don't exist are skipped. An address is added only if the ruleset
    /// last applied successfully denies it: otherwise it would be exposed.
    pub(super) async fn ensure_addresses_present(&self, state: &AppState) {
        self.sweep_owned(state).await;
        if state.db.disabled().await {
            return;
        }
        let mut expected: HashMap<String, Vec<(Ipv6Addr, String)>> = HashMap::new();
        for a in state.db.list_addresses().await.unwrap_or_default() {
            if let (Some(addr), Some(iface)) = (a.locator.ipv6(), self.interface_of(&a.network_id))
            {
                expected
                    .entry(iface.to_string())
                    .or_default()
                    .push((addr, a.network_id.clone()));
            }
        }
        let active: HashSet<Ipv6Addr> = state
            .db
            .list_owned_addresses()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|o| !o.retiring)
            .map(|o| o.addr)
            .collect();

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
            for (addr, network_id) in wanted {
                if present.contains(&addr) {
                    // Already there (e.g. from before ownership was recorded): own it.
                    if !active.contains(&addr) {
                        if let Err(e) = state
                            .db
                            .claim_address(addr, &iface, Some(&network_id))
                            .await
                        {
                            warn!("Cannot record ownership of {addr}: {e}");
                        }
                    }
                    continue;
                }
                if self
                    .add_to_interface(state, &iface, &network_id, addr)
                    .await
                {
                    info!("Added address {addr} to {iface}");
                }
            }
        }
    }

    pub(super) async fn remove_app_locators(&self, state: &AppState, addresses: &[Address]) {
        let networks: BTreeSet<&str> = addresses.iter().map(|a| a.network_id.as_str()).collect();
        for nid in networks {
            let of_network: Vec<Address> = addresses
                .iter()
                .filter(|a| a.network_id == nid)
                .cloned()
                .collect();
            self.remove_locators(state, nid, &of_network).await;
        }
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
        if !app.has_port(port) {
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
        if port.proto == Protocol::Udp && !active.network.capabilities().udp {
            return Err(EngineError::Invalid(format!(
                "network {network_id} does not serve UDP ports"
            )));
        }
        let address_id = new_id();
        let ports = PortSet::Only(vec![port]);
        let NewLocator { locator, secret } = self
            .make_locator(active, app_id, &address_id, &ports)
            .await
            .map_err(|e| EngineError::Conflict(format!("cannot allocate an address: {e}")))?;
        let address = Address {
            id: address_id,
            app_id: app_id.to_string(),
            network_id: network_id.to_string(),
            ports,
            locator,
            created_at: Utc::now(),
        };
        let shrink = shrink.map(|(a, rest)| (a.id.as_str(), PortSet::Only(rest)));
        state
            .db
            .split_address(
                &address,
                secret.as_deref(),
                shrink.as_ref().map(|(id, ports)| (*id, ports)),
            )
            .await?;
        let applied = self.apply_and_ensure(state).await;
        self.commit(state, applied, None, &[DaemonEvent::AppsChanged])
            .await?;
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
        // The others' addresses leave the interface (retiring, so still denied) before
        // their rules go.
        self.retire_addresses(state, &gone).await?;
        self.remove_locators(state, network_id, &gone).await;
        state.db.update_address_ports(&keep.id, &merged).await?;
        for a in &gone {
            state.db.delete_address(&a.id).await?;
        }
        let applied = self.apply_and_ensure(state).await;
        self.commit(state, applied, None, &[DaemonEvent::AppsChanged])
            .await?;
        let mut out = keep.clone();
        out.ports = merged;
        Ok(out)
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
pub(super) async fn disable_all(
    db: &Database,
    interfaces: &HashMap<String, String>,
    firewall: Arc<dyn Firewall>,
    network: Arc<dyn NetworkInterface>,
) -> anyhow::Result<()> {
    db.set_disabled(true).await?;
    // Removing the rules answers the unadopted question too.
    db.set_unadopted(false).await?;
    for a in db.list_addresses().await? {
        let Some(ip) = a.locator.ipv6() else {
            continue;
        };
        match interfaces.get(&a.network_id) {
            // Adopt addresses from before ownership was recorded.
            Some(iface) => {
                if let Err(e) = db.retire_address(ip, iface, Some(&a.network_id)).await {
                    warn!("Cannot record {ip} as retiring: {e}");
                }
            }
            None => warn!(
                "Network '{}' is not configured; cannot remove {ip}",
                a.network_id
            ),
        }
    }
    // Addresses first: removing the rules first would briefly expose them. A row stays
    // until its address is confirmed gone, and the rules stay while any address does: it
    // remains denied, and the disabled daemon's sweep removes the rules once the last one
    // is gone.
    let owned = db.list_owned_addresses().await?;
    let failures = release_owned(db, &network, owned).await;
    if !failures.is_empty() {
        let list: Vec<String> = failures
            .iter()
            .map(|(o, e)| format!("{} on {} ({e})", o.addr, o.interface))
            .collect();
        anyhow::bail!(
            "could not remove {} address(es): {}; the firewall rules stay so they remain denied, and the removal is retried",
            failures.len(),
            list.join("; ")
        );
    }
    tokio::task::spawn_blocking(move || firewall.disable()).await?
}

/// Take owned addresses off their interfaces: mark each retiring, remove it, and delete its
/// row only when the removal is confirmed (it succeeded, or the interface no longer has
/// the address). Returns the ones that are still there.
async fn release_owned(
    db: &Database,
    network: &Arc<dyn NetworkInterface>,
    rows: Vec<OwnedAddress>,
) -> Vec<(OwnedAddress, anyhow::Error)> {
    let mut failures = Vec::new();
    for o in rows {
        if !o.retiring {
            if let Err(e) = db
                .retire_address(o.addr, &o.interface, o.network_id.as_deref())
                .await
            {
                warn!("Cannot record {} as retiring: {e}", o.addr);
            }
        }
        let net = network.clone();
        let (iface, addr) = (o.interface.clone(), o.addr);
        let removed = tokio::task::spawn_blocking(move || match net.remove_address(&iface, addr) {
            Ok(()) => Ok(()),
            Err(e) => match net.list_addresses(&iface) {
                Ok(list) if !list.contains(&addr) => Ok(()),
                _ => Err(e),
            },
        })
        .await;
        match removed {
            Ok(Ok(())) => {
                if let Err(e) = db.forget_address(o.addr).await {
                    failures.push((o, e));
                }
            }
            Ok(Err(e)) => failures.push((o, e)),
            Err(e) => failures.push((o, e.into())),
        }
    }
    failures
}

fn locator_text(l: &Locator) -> String {
    match l {
        Locator::Ipv6 { addr } => addr.to_string(),
        Locator::Onion { hostname } => hostname.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socketguard_core::App;

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
            identity_note: None,
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
