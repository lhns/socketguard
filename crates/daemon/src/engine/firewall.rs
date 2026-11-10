//! Building and applying the ruleset, and what the firewall reports back (counters, drops,
//! exposed remote administration).

use super::*;
use crate::api::DaemonEvent;
use crate::firewall::{self, DesiredRuleset, DropEvent};
use crate::metrics::CounterKey;
use crate::ruleset::{self, HostInterface, LockoutRisk, Snapshot};
use crate::state::NewActivity;
use crate::AppState;
use chrono::Utc;
use socketguard_core::{valid_interface_name, ActivityKind, Address, App, NetworkKind, Subject};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::time::{Instant, UNIX_EPOCH};
use tracing::{debug, error, warn};

impl Engine {
    /// Gather the producer's input from the DB and the active networks.
    pub(super) async fn gather_snapshot(&self, state: &AppState) -> anyhow::Result<Snapshot> {
        let db = &state.db;
        Ok(Snapshot {
            apps: db.list_apps().await?,
            networks: self.networks(),
            peers: db.list_peers().await?,
            groups: db.list_groups().await?,
            grants: db.list_grants().await?,
            protect_host: db.protect_host().await?,
            // Owned addresses stay denied until they are really off their interface.
            owned: db
                .list_owned_addresses()
                .await?
                .into_iter()
                .map(|o| IpAddr::V6(o.addr))
                .collect(),
        })
    }

    /// Build the desired ruleset from the current state and apply it atomically. The
    /// caller holds the firewall lock. With `only_if_changed`, an unchanged ruleset is
    /// not re-sent (except every `REAPPLY_EVERY` passes).
    pub(super) async fn apply_locked(
        &self,
        state: &AppState,
        only_if_changed: bool,
    ) -> anyhow::Result<()> {
        if state.db.disabled().await || state.db.unadopted().await? {
            return Ok(());
        }
        let snapshot = self.gather_snapshot(state).await?;
        let (desired, warnings) = ruleset::build_with_warnings(&snapshot);

        if only_if_changed && !self.apply_failed.load(Ordering::Relaxed) {
            let unchanged = self.last_applied.lock().unwrap().as_ref() == Some(&desired);
            if unchanged {
                let passes = self.passes_since_apply.fetch_add(1, Ordering::Relaxed) + 1;
                let fw = self.firewall.clone();
                let verify_due = self
                    .last_verified
                    .lock()
                    .unwrap()
                    .is_none_or(|t| t.elapsed() >= self.verify_interval);
                if verify_due {
                    *self.last_verified.lock().unwrap() = Some(Instant::now());
                }
                let in_force = tokio::task::spawn_blocking(move || {
                    // The interface check is cheap; `verify` may spawn a process.
                    if fw.interfaces_changed() {
                        return false;
                    }
                    if !verify_due {
                        return true;
                    }
                    match fw.verify() {
                        Ok(in_force) => in_force,
                        Err(e) => {
                            debug!("Could not verify the firewall state: {e:#}");
                            true
                        }
                    }
                })
                .await?;
                if in_force && passes < REAPPLY_EVERY {
                    return Ok(());
                }
                if !in_force {
                    warn!("The firewall state changed under us; re-applying the ruleset");
                }
            }
        }
        self.passes_since_apply.store(0, Ordering::Relaxed);
        for w in warnings {
            warn!("{w}");
        }

        let fw = self.firewall.clone();
        let to_apply = desired.clone();
        let previous = self.last_applied.lock().unwrap().clone();
        let result = tokio::task::spawn_blocking(move || fw.apply(&to_apply)).await?;
        match result {
            Ok(()) => {
                // Established flows outlive the rule that allowed them; cut those.
                let revoked = previous
                    .map(|old| firewall::revocations(&old, &desired))
                    .unwrap_or_default();
                if !revoked.is_empty() {
                    let fw = self.firewall.clone();
                    match tokio::task::spawn_blocking(move || fw.revoke(&revoked)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => warn!("Could not cut revoked connections: {e:#}"),
                        Err(e) => warn!("Revocation task failed: {e}"),
                    }
                }
                debug!(
                    "Applied ruleset: {} scopes, {} rules",
                    desired.scopes.len(),
                    desired.rules.len()
                );
                *self.counter_keys.lock().unwrap() = counter_keys(&snapshot, &desired);
                // The table was replaced, so the platform's counters restarted at zero.
                self.metrics.counters_reset();
                *self.last_applied.lock().unwrap() = Some(desired);
                *self.last_verified.lock().unwrap() = Some(Instant::now());
                self.apply_failed.store(false, Ordering::Relaxed);
                // The database now owns the kernel state: it is no longer "fresh".
                if state.db.fresh().await.unwrap_or(false) {
                    let _ = state.db.clear_fresh().await;
                }
                Ok(())
            }
            Err(e) => {
                // A failed apply leaves the previous ruleset in force, which stays
                // `last_applied` (the diff base for revocations); `apply_failed` forces
                // the retry.
                self.apply_failed.store(true, Ordering::Relaxed);
                // Verify as soon as an apply works again, whatever the interval.
                *self.last_verified.lock().unwrap() = None;
                error!("Failed to apply firewall ruleset: {e}");
                Err(e)
            }
        }
    }

    /// Rebuild the ruleset from the current state and apply it. Call after any change to
    /// apps, addresses, peers, groups, grants or networks.
    pub async fn apply_firewall(&self, state: &AppState) -> anyhow::Result<()> {
        let _lock = state.firewall_lock.lock().await;
        let result = self.apply_locked(state, false).await;
        self.enforce_networks(state).await;
        result
    }

    pub(super) async fn apply_firewall_if_changed(&self, state: &AppState) -> anyhow::Result<()> {
        let _lock = state.firewall_lock.lock().await;
        let result = self.apply_locked(state, true).await;
        self.enforce_networks(state).await;
        result
    }

    /// Apply, then put missing addresses on their interfaces (the ruleset first).
    pub(super) async fn apply_and_ensure(&self, state: &AppState) -> anyhow::Result<()> {
        let applied = self.apply_firewall(state).await;
        // Also after a failed apply: it adds nothing then, but still takes retired
        // addresses off their interfaces.
        self.ensure_addresses_present(state).await;
        applied
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
        if let Some(bad) = interfaces.iter().find(|i| !valid_interface_name(i)) {
            return Err(ProtectHostError::Invalid(format!(
                "invalid interface name {bad:?}"
            )));
        }
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
        state.db.set_protect_host(&interfaces).await?;
        let applied = self.apply_firewall(state).await;
        let activity = NewActivity::new(
            ActivityKind::ProtectHostChanged,
            if interfaces.is_empty() {
                "Whole-host protection off".to_string()
            } else {
                format!("Whole-host protection on for {}", interfaces.join(", "))
            },
        );
        self.commit(
            state,
            applied,
            Some(activity),
            &[DaemonEvent::SettingsChanged],
        )
        .await?;
        Ok(risks)
    }

    /// After the first apply of a daemon run: let the firewall drop states that outlive a
    /// ruleset swap (pf; no-op on nftables and WFP).
    pub(super) fn purge_states(&self) {
        let applied = self.last_applied.lock().unwrap().clone();
        let Some(applied) = applied else { return };
        if let Err(e) = self.firewall.purge_states(&applied) {
            warn!("Could not drop old firewall states: {e:#}");
        }
    }

    /// Read the firewall's counters and fold them into the metrics.
    pub(super) async fn poll_counters(&self) {
        let fw = self.firewall.clone();
        let counters = match tokio::task::spawn_blocking(move || fw.counters()).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                debug!("Could not read firewall counters: {e}");
                return;
            }
            Err(e) => {
                warn!("Counter task failed: {e}");
                return;
            }
        };
        let keys = self.counter_keys.lock().unwrap();
        self.metrics.record(counters.into_iter().filter_map(|c| {
            let key = keys.get(&c.id)?.clone();
            Some((c.id, key, c.packets, c.bytes))
        }));
    }

    pub(super) async fn refresh_metric_counts(&self, state: &AppState) {
        let db = &state.db;
        let (Ok(apps), Ok(peers), Ok(grants)) = (
            db.list_apps().await,
            db.list_peers().await,
            db.list_grants().await,
        ) else {
            return;
        };
        let addresses = apps.iter().map(|a| a.addresses.len()).sum();
        self.metrics
            .set_counts(apps.len(), addresses, peers.len(), grants.len());
    }

    /// Report remote-admin listeners (sshd, RDP) that sit inside a protected scope (an
    /// overlay or a protected host interface) that no grant reaches: they are cut off
    /// from there. Once per app and scope, until the situation clears.
    pub(super) async fn check_remote_admin(
        &self,
        state: &AppState,
        sockets: &[socketguard_core::ListeningSocket],
    ) {
        let Ok(snapshot) = self.gather_snapshot(state).await else {
            return;
        };
        // (scope key, interface, network id): the key is the network id when the interface
        // belongs to a network, else the interface name.
        let mut scopes: Vec<(String, String, Option<String>)> = Vec::new();
        for n in &snapshot.networks {
            if let (NetworkKind::Yggdrasil, Some(iface)) = (n.kind, &n.interface) {
                scopes.push((n.id.clone(), iface.clone(), Some(n.id.clone())));
            }
        }
        for iface in &snapshot.protect_host {
            let net = snapshot
                .networks
                .iter()
                .find(|n| n.interface.as_deref() == Some(iface));
            let key = net.map(|n| n.id.clone()).unwrap_or_else(|| iface.clone());
            if !scopes.iter().any(|(k, _, _)| *k == key) {
                scopes.push((key, iface.clone(), net.map(|n| n.id.clone())));
            }
        }
        let mut current: HashSet<(String, String)> = HashSet::new();
        let mut fresh = Vec::new();
        for (key, iface, net_id) in scopes {
            let host = HostInterface {
                addrs: self
                    .network
                    .list_addresses(&iface)
                    .unwrap_or_default()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                name: iface,
            };
            let Err(risks) = ruleset::check_protect_host(&snapshot, sockets, &[host]) else {
                continue;
            };
            for risk in risks {
                if current.insert((risk.app_id.clone(), key.clone())) {
                    fresh.push((key.clone(), net_id.clone(), risk));
                }
            }
        }
        let new: Vec<_> = {
            let mut seen = self.exposed_reported.lock().unwrap();
            let new = fresh
                .into_iter()
                .filter(|(key, _, risk)| !seen.contains(&(risk.app_id.clone(), key.clone())))
                .collect();
            *seen = current;
            new
        };
        for (key, net_id, risk) in new {
            let message = format!(
                "Remote administration is cut off: {} (port {}/{}) is inside the protected scope {key} and no grant reaches it",
                risk.process_name, risk.port, risk.protocol
            );
            warn!("{message}");
            let mut act =
                NewActivity::new(ActivityKind::RemoteAdminExposed, message).app(&risk.app_id);
            act.network_id = net_id;
            act.port = Some(risk.port);
            act.proto = Some(risk.protocol);
            self.record(state, act).await;
        }
    }

    /// Fold the pending drop events into per-minute aggregates and write the closed
    /// minutes as Blocked activity.
    pub(super) async fn flush_drops(&self, state: &AppState) {
        let events: Vec<DropEvent> = std::mem::take(&mut *self.drops.lock().unwrap());
        let now_minute = Utc::now().timestamp() / 60;
        let closed: Vec<(DropKey, u32)> = {
            let mut agg = self.drop_agg.lock().unwrap();
            for ev in events {
                let secs = ev
                    .at
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let key = (ev.src, ev.dst, ev.port, ev.proto, secs / 60);
                if agg.len() < MAX_DROP_KEYS || agg.contains_key(&key) {
                    *agg.entry(key).or_default() += 1;
                }
            }
            let keys: Vec<DropKey> = agg.keys().filter(|k| k.4 < now_minute).copied().collect();
            keys.into_iter()
                .filter_map(|k| agg.remove(&k).map(|c| (k, c)))
                .collect()
        };
        if closed.is_empty() {
            return;
        }

        let apps = state.db.list_apps().await.unwrap_or_default();
        let mut by_dst: HashMap<Ipv6Addr, (&App, &Address)> = HashMap::new();
        for app in &apps {
            for a in &app.addresses {
                if let Some(ip) = a.locator.ipv6() {
                    by_dst.insert(ip, (app, a));
                }
            }
        }
        let records: Vec<NewActivity> = closed
            .into_iter()
            .map(|((src, dst, port, proto, minute), count)| {
                let target = match dst {
                    IpAddr::V6(d) => by_dst.get(&d).copied(),
                    IpAddr::V4(_) => None,
                };
                let what = match (port, proto) {
                    (Some(p), Some(pr)) => format!(" port {p}/{pr}"),
                    _ => String::new(),
                };
                let message = match target {
                    Some((app, _)) => format!("Blocked {src} from {}{what}", app.name),
                    None => format!("Blocked {src} from {dst}{what}"),
                };
                let mut n = NewActivity::new(ActivityKind::Blocked, message);
                n.at = chrono::DateTime::from_timestamp(minute * 60, 0).unwrap_or_else(Utc::now);
                n.app_id = target.map(|(app, _)| app.id.clone());
                n.network_id = target.map(|(_, a)| a.network_id.clone());
                n.src = Some(src);
                n.port = port;
                n.proto = proto;
                n.count = count;
                n
            })
            .collect();
        if let Err(e) = state.db.insert_activity(&records).await {
            warn!("Could not record blocked connections: {e}");
        }
        self.emit(state, DaemonEvent::Activity);
    }
}

/// Attribute every rule and scope of `desired` for the metrics. Rule ids are
/// `a:<address>:<port>:<proto>:<grant>[:<iif>]` (see `ruleset::build_with_warnings`).
fn counter_keys(snap: &Snapshot, desired: &DesiredRuleset) -> HashMap<String, CounterKey> {
    let mut out = HashMap::new();
    for sc in &desired.scopes {
        out.insert(
            sc.id.clone(),
            CounterKey::Scope {
                scope: sc.id.clone(),
            },
        );
    }
    let peers: HashMap<&str, &str> = snap
        .peers
        .iter()
        .map(|p| (p.id.as_str(), p.label.as_str()))
        .collect();
    let groups: HashMap<&str, &str> = snap
        .groups
        .iter()
        .map(|g| (g.id.as_str(), g.label.as_str()))
        .collect();
    for rule in &desired.rules {
        let mut parts = rule.id.splitn(5, ':');
        let (Some("a"), Some(address_id), Some(_), Some(_), Some(rest)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        let grant_id = rest.split(':').next().unwrap_or(rest);
        let Some((app, address)) = snap.apps.iter().find_map(|a| {
            a.addresses
                .iter()
                .find(|x| x.id == address_id)
                .map(|x| (a, x))
        }) else {
            continue;
        };
        let Some(grant) = snap.grants.iter().find(|g| g.id == grant_id) else {
            continue;
        };
        let subject = match &grant.subject {
            Subject::Anyone => "Anyone".to_string(),
            Subject::Peer(id) => peers.get(id.as_str()).unwrap_or(&"unknown").to_string(),
            Subject::Group(id) => groups.get(id.as_str()).unwrap_or(&"unknown").to_string(),
        };
        out.insert(
            rule.id.clone(),
            CounterKey::Rule {
                app_id: app.id.clone(),
                app: app.name.clone(),
                network: address.network_id.clone(),
                subject,
            },
        );
    }
    out
}
