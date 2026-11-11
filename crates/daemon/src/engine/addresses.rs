//! The addresses of apps and reservations on each network and their presence on the
//! interfaces: allocating, re-homing, sweeping (ADR 0047). Which addresses exist and are up
//! is decided by [`Model`]; this module makes the database and the interfaces match it.
//!
//! A dormant address is taken off its interface and out of the ruleset but its row stays.
//! For DHCPv6 that is all that happens: the lease is released only when the address is
//! deleted (`remove_locator`), never when it merely goes dormant, so the server keeps the
//! address reserved for us and the same one goes back on the interface with the next grant.

use super::*;
use crate::api::DaemonEvent;
use crate::firewall::ScopeMatch;
use crate::iface::InterfaceManager;
use crate::networks::ip::{iid_of, same_prefix64, with_prefix64};
use crate::networks::{LocatorRequest, NewLocator};
use crate::state::{Database, OwnedAddress};
use crate::AppState;
use chrono::Utc;
use futures_util::StreamExt;
use socketguard_core::{
    classify_legacy, Binding, BindingTarget, LegacyClass, Model, Reservation, Row,
};
use socketguard_core::{new_id, Address, Locator, Scope};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// How many interface calls to add addresses run at once.
const ADD_CONCURRENCY: usize = 4;

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
                    .retire_address(ip, &iface, Some(&a.network_id))
                    .await?;
            }
        }
        Ok(())
    }

    /// Take every owned address that no longer belongs to an app off its interface, and
    /// retry the ones whose removal failed before. A row is deleted only once the removal
    /// is confirmed. Run after the ruleset is applied; needs no ruleset itself.
    pub(super) async fn sweep_owned(&self, state: &AppState) {
        match self.wanted_on_interfaces(state).await {
            Ok(wanted) => self.sweep_owned_except(state, &wanted).await,
            // Never sweep on a guess: without the list everything looks orphaned.
            Err(e) => warn!("Cannot sweep owned addresses: {e:#}"),
        }
    }

    /// [`Engine::sweep_owned`] for a `referenced` set the caller already worked out.
    async fn sweep_owned_except(&self, state: &AppState, referenced: &HashSet<Ipv6Addr>) {
        let db = &state.db;
        let owned = match db.list_owned_addresses().await {
            Ok(o) => o,
            Err(e) => {
                warn!("Cannot sweep owned addresses: {e}");
                return;
            }
        };
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
        let failures = release_owned(db, &self.ifaces, due).await;
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
        self.add_to_interfaces(
            state,
            vec![(iface.to_string(), network_id.to_string(), addr)],
        )
        .await
            == 1
    }

    /// [`Engine::add_to_interface`] for several addresses. Each is gated and recorded in
    /// turn; the interface calls, which can take a while each (Windows), then run a few at
    /// a time off the runtime threads. Returns how many were added.
    pub(super) async fn add_to_interfaces(
        &self,
        state: &AppState,
        wanted: Vec<(String, String, Ipv6Addr)>,
    ) -> usize {
        let mut recorded = Vec::new();
        for (iface, network_id, addr) in wanted {
            if !self.covered_by_applied(addr) {
                debug!("Not adding {addr} to {iface}: the applied ruleset does not cover it");
                continue;
            }
            if let Err(e) = state
                .db
                .claim_address(addr, &iface, Some(&network_id))
                .await
            {
                warn!("Not adding {addr} to {iface}: cannot record it first: {e}");
                continue;
            }
            recorded.push((iface, addr));
        }
        let results: Vec<(String, Ipv6Addr, bool)> = futures_util::stream::iter(recorded)
            .map(|(iface, addr)| {
                let ifaces = self.ifaces.clone();
                async move {
                    let on = iface.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        ifaces.add_address(&on, addr, ADDRESS_PREFIX_LEN)
                    })
                    .await;
                    let added = match result {
                        Ok(Ok(())) => true,
                        Ok(Err(e)) => {
                            warn!("Failed to add {addr} to {iface}: {e}");
                            false
                        }
                        Err(e) => {
                            warn!("Failed to add {addr} to {iface}: {e}");
                            false
                        }
                    };
                    (iface, addr, added)
                }
            })
            .buffer_unordered(ADD_CONCURRENCY)
            .collect()
            .await;
        let added = results.iter().filter(|(_, _, ok)| *ok).count();
        for (iface, addr, _) in results.iter().filter(|(_, _, ok)| *ok) {
            debug!("Added address {addr} to {iface}");
        }
        added
    }

    /// The IPv6 addresses that belong on an interface now: those that are up.
    pub(super) async fn wanted_on_interfaces(
        &self,
        state: &AppState,
    ) -> anyhow::Result<HashSet<Ipv6Addr>> {
        let snap = self.gather_snapshot(state).await?;
        let info = Model::new(snap.world()).address_info();
        Ok(snap
            .addresses
            .iter()
            .filter(|a| info.get(&a.id).is_some_and(|i| i.up))
            .filter_map(|a| a.locator.ipv6())
            .collect())
    }

    /// Create the addresses that grants call for and that do not exist yet: one per row a
    /// grant names, one per reservation and network where a grant covers it. A failed
    /// allocation is retried on the next pass. Returns the number created.
    pub(super) async fn ensure_addresses(&self, state: &AppState) -> anyhow::Result<usize> {
        // Mutations run side by side; two must not both create the same address.
        let _guard = self.alloc_lock.lock().await;
        let snap = self.gather_snapshot(state).await?;
        let model = Model::new(snap.world());
        let mut wanted: Vec<(String, String, Address)> = Vec::new();
        for (nid, row) in model.missing_automatic() {
            let name = snap
                .apps
                .iter()
                .find(|a| a.id == row.app_id)
                .map_or(row.app_id.clone(), |a| a.name.clone());
            let blank = Locator::Onion {
                hostname: String::new(),
            };
            wanted.push((
                nid.clone(),
                name,
                Address::automatic(&row.app_id, row.scope, &nid, blank),
            ));
        }
        for (rid, nid) in model.missing_reserved() {
            let name = snap
                .reservations
                .iter()
                .find(|r| r.id == rid)
                .map_or(rid.clone(), |r| format!("reservation {}", r.label));
            let blank = Locator::Onion {
                hostname: String::new(),
            };
            wanted.push((
                nid.clone(),
                name,
                Address::of_reservation(&rid, &nid, blank),
            ));
        }
        let mut created = 0;
        let mut failed: HashSet<String> = HashSet::new();
        for (nid, name, mut address) in wanted {
            let Some(active) = self.backends.get(&nid) else {
                continue;
            };
            if failed.contains(&nid) {
                continue;
            }
            let owner = address
                .app_id
                .clone()
                .or_else(|| address.reservation_id.clone())
                .unwrap_or_default();
            match self
                .make_locator(active, &owner, &address.id, &address.scope)
                .await
            {
                Ok(NewLocator { locator, secret }) => {
                    self.alloc_failing.lock().unwrap().remove(&nid);
                    address.locator = locator;
                    address.created_at = Utc::now();
                    state
                        .db
                        .insert_address_with_secret(&address, secret.as_deref())
                        .await?;
                    info!(
                        "Assigned {} ({nid}) to {name}",
                        locator_text(&address.locator)
                    );
                    created += 1;
                }
                Err(e) => {
                    if self.alloc_failing.lock().unwrap().insert(nid.clone()) {
                        warn!("Cannot allocate an address on '{nid}', will retry: {e}");
                    }
                    failed.insert(nid);
                }
            }
        }
        Ok(created)
    }

    /// Ask a network for the locator of a new address. `owner` is the app, or the
    /// reservation, the address is for.
    pub(super) async fn make_locator(
        &self,
        active: &ActiveBackend,
        owner: &str,
        address_id: &str,
        scope: &Scope,
    ) -> anyhow::Result<NewLocator> {
        let net = active.network.clone();
        let req = LocatorRequest {
            app_id: owner.to_string(),
            address_id: address_id.to_string(),
            scope: scope.clone(),
        };
        tokio::task::spawn_blocking(move || net.ensure_locator(&req)).await?
    }

    /// The v7 -> v8 migration left every address automatic. Now that the networks are
    /// known, turn the ones that a grant covers without naming their row into
    /// reservations with that row bound (ADR 0047), once. Returns how many.
    pub async fn classify_legacy_addresses(&self, state: &AppState) -> anyhow::Result<usize> {
        let db = &state.db;
        if db.get_setting("classify_addresses").await?.as_deref() != Some("pending") {
            return Ok(0);
        }
        let snap = self.gather_snapshot(state).await?;
        let mut by_row: HashMap<Row, String> = HashMap::new();
        let mut writes: Vec<crate::state::Write> = Vec::new();
        let mut moved = 0;
        for (address_id, class) in classify_legacy(snap.world()) {
            let LegacyClass::Reservation { label } = class else {
                continue;
            };
            let Some(a) = snap.addresses.iter().find(|a| a.id == address_id) else {
                continue;
            };
            let Some(app_id) = a.app_id.clone() else {
                continue;
            };
            let row = Row {
                app_id: app_id.clone(),
                scope: a.scope.clone(),
            };
            // One reservation per row, with an address on each network it had one.
            let reservation_id = match by_row.get(&row) {
                Some(id) => id.clone(),
                None => {
                    let id = new_id();
                    writes.push(crate::state::Write::InsertReservation(Reservation {
                        id: id.clone(),
                        label,
                        bindings: vec![Binding {
                            id: new_id(),
                            reservation_id: id.clone(),
                            target: BindingTarget::App {
                                app_id,
                                scope: a.scope.clone(),
                            },
                        }],
                        created_at: Utc::now(),
                    }));
                    by_row.insert(row, id.clone());
                    id
                }
            };
            writes.push(crate::state::Write::AssignAddress {
                address_id,
                reservation_id,
            });
            moved += 1;
        }
        db.apply_writes(&writes).await?;
        db.set_setting("classify_addresses", "done").await?;
        if moved > 0 {
            info!("Turned {moved} existing address(es) into reservations");
        }
        Ok(moved)
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
        // Only addresses that are on an interface (or wanted there) move with the prefix;
        // a remembered one just gets the new prefix in the database. Which those are is
        // looked up when the first address needs to move.
        let mut placed: Option<(HashSet<Ipv6Addr>, HashSet<Ipv6Addr>)> = None;
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
            let Some(iface) = Self::interface_in_use(active) else {
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
                if placed.is_none() {
                    let owned = state
                        .db
                        .list_owned_addresses()
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|o| o.addr)
                        .collect();
                    let wanted = self.wanted_on_interfaces(state).await.unwrap_or_default();
                    placed = Some((owned, wanted));
                }
                let (owned, wanted) = placed.as_ref().expect("looked up above");
                // Write ahead: the old address is retiring before the row stops naming it.
                if owned.contains(&old) {
                    if let Err(e) = state
                        .db
                        .retire_address(old, &iface, Some(network_id.as_str()))
                        .await
                    {
                        error!("Failed to record {old} as retiring: {e}");
                        continue;
                    }
                }
                match state.db.update_address_ipv6(&a.id, new).await {
                    Ok(_) if wanted.contains(&old) => {
                        moves.push((iface.to_string(), network_id.clone(), new))
                    }
                    Ok(_) => {}
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
        // What belongs on the interfaces does not change by sweeping, so it is worked out
        // once (without it, nothing is swept: everything would look orphaned).
        let Ok(wanted) = self.wanted_on_interfaces(state).await else {
            warn!("Cannot work out the addresses to keep on the interfaces");
            return;
        };
        self.sweep_owned_except(state, &wanted).await;
        if state.db.disabled().await {
            return;
        }
        let mut expected: HashMap<String, Vec<(Ipv6Addr, String)>> = HashMap::new();
        for a in state.db.list_addresses().await.unwrap_or_default() {
            if let (Some(addr), Some(iface)) = (a.locator.ipv6(), self.interface_of(&a.network_id))
            {
                if !wanted.contains(&addr) {
                    continue;
                }
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

        let mut missing: Vec<(String, String, Ipv6Addr)> = Vec::new();
        for (iface, wanted) in expected {
            let present = match self.ifaces.list_addresses(&iface) {
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
                missing.push((iface.clone(), network_id, addr));
            }
        }
        let added = self.add_to_interfaces(state, missing).await;
        if added > 0 {
            info!("Added {added} address(es) to the interfaces");
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
}

/// Take owned addresses off their interfaces: mark each retiring, remove it, and delete its
/// row only when the removal is confirmed (it succeeded, or the interface no longer has
/// the address). Returns the ones that are still there.
async fn release_owned(
    db: &Database,
    ifaces: &Arc<dyn InterfaceManager>,
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
        let net = ifaces.clone();
        let (iface, addr) = (o.interface.clone(), o.addr);
        let removed = tokio::task::spawn_blocking(move || {
            match net.remove_address(&iface, addr, ADDRESS_PREFIX_LEN) {
                Ok(()) => Ok(()),
                Err(e) => match net.list_addresses(&iface) {
                    Ok(list) if !list.contains(&addr) => Ok(()),
                    _ => Err(e),
                },
            }
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

