//! Live sockets to apps and ports.

use super::*;
use crate::api::DaemonEvent;
use crate::networks::{self};
use crate::state::{NewActivity, Sighting, Touch};
use crate::AppState;
use chrono::Utc;
use socketguard_core::config::ProcessFilter;
use socketguard_core::{
    app_identity, ActivityKind, AddrFamily, App, AppId, AppIdentity, AppPort, PortRef,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use tracing::info;

/// How stale the last sighting of an unchanged app may get before a poll writes it again.
const SIGHTING_REFRESH: chrono::Duration = chrono::Duration::seconds(60);

impl Engine {
    /// Steps 1 of the reconcile: live sockets -> apps and their ports. Returns whether
    /// anything user-visible changed.
    pub(super) async fn upsert_apps(
        &self,
        state: &AppState,
        process_filter: &ProcessFilter,
        sockets: &[socketguard_core::ListeningSocket],
    ) -> anyhow::Result<bool> {
        struct Live {
            name: String,
            process_name: String,
            exe_path: Option<String>,
            interpreter_arg: Option<String>,
            identity_note: Option<String>,
            system: bool,
            ports: BTreeMap<PortRef, AddrFamily>,
        }
        let mut live: BTreeMap<AppId, Live> = BTreeMap::new();
        let mut binds: HashMap<(AppId, PortRef), IpAddr> = HashMap::new();
        for ls in sockets {
            if !process_filter.matches(&ls.process_name) {
                continue;
            }
            let AppIdentity {
                id,
                name,
                interpreter_arg,
                note,
                system,
            } = app_identity(ls);
            let port_ref = PortRef {
                port: ls.port,
                proto: ls.protocol,
            };
            let slot = binds
                .entry((id.clone(), port_ref))
                .or_insert(ls.bind_address);
            if networks::bind_rank(&ls.bind_address) < networks::bind_rank(slot) {
                *slot = ls.bind_address;
            }
            live.entry(id)
                .or_insert_with(|| Live {
                    name,
                    process_name: ls.process_name.clone(),
                    exe_path: ls.exe_path.clone(),
                    interpreter_arg,
                    identity_note: note,
                    system,
                    ports: BTreeMap::new(),
                })
                .ports
                .entry(port_ref)
                .and_modify(|f| *f = f.union(ls.family()))
                .or_insert(ls.family());
        }

        *self.binds.lock().unwrap() = binds;

        let db = &state.db;
        let _apps = self.apps_lock.lock().await;
        let now = Utc::now();
        let known: HashMap<AppId, App> = db
            .list_apps()
            .await?
            .into_iter()
            .map(|a| (a.id.clone(), a))
            .collect();
        let mut changed = false;
        // What goes to the database, in one transaction; nothing when nothing changed.
        let mut writes: Vec<(&AppId, Option<Touch<'_>>, Vec<(PortRef, AddrFamily)>)> = Vec::new();

        for (id, l) in &live {
            let ports: Vec<(PortRef, AddrFamily)> = l.ports.iter().map(|(p, f)| (*p, *f)).collect();
            let Some(app) = known.get(id) else {
                info!("New app detected: {} ({id})", l.name);
                let app = App {
                    id: id.clone(),
                    name: l.name.clone(),
                    process_name: l.process_name.clone(),
                    exe_path: l.exe_path.clone(),
                    interpreter_arg: l.interpreter_arg.clone(),
                    identity_note: l.identity_note.clone(),
                    reviewed: false,
                    system: l.system,
                    first_seen: now,
                    last_seen: now,
                    ports: vec![],
                    addresses: vec![],
                };
                db.insert_app(&app).await?;
                self.tag_new_app(state, &app).await;
                self.record(
                    state,
                    NewActivity::new(
                        ActivityKind::AppDiscovered,
                        format!("New app {} is listening", l.name),
                    )
                    .app(id),
                )
                .await;
                self.emit(state, DaemonEvent::AppDiscovered(id.clone()));
                changed = true;
                writes.push((id, None, ports));
                continue;
            };
            let was_listening: BTreeSet<PortRef> = app
                .ports
                .iter()
                .filter(|p| p.listening)
                .map(AppPort::port_ref)
                .collect();
            let was_family: BTreeMap<PortRef, AddrFamily> = app
                .ports
                .iter()
                .filter(|p| p.listening)
                .map(|p| (p.port_ref(), p.family))
                .collect();
            let is_new_port = |p: &PortRef| !app.ports.iter().any(|k| k.port_ref() == *p);
            let ports_changed = ports.iter().any(|(p, _)| is_new_port(p))
                || was_listening != l.ports.keys().copied().collect::<BTreeSet<_>>()
                || was_family != l.ports;
            changed |= ports_changed;
            // A sighting that changes nothing is written only now and then, to keep
            // `last_seen` roughly current without a write on every poll.
            let fresh = |t| now - t < SIGHTING_REFRESH;
            let same_app = app.process_name == l.process_name
                && app.exe_path == l.exe_path
                && app.system == l.system
                && fresh(app.last_seen);
            let ports_fresh = app
                .ports
                .iter()
                .filter(|p| p.listening)
                .all(|p| fresh(p.last_seen));
            if same_app && !ports_changed && ports_fresh {
                continue;
            }
            writes.push((
                id,
                Some(Touch {
                    process_name: &l.process_name,
                    exe_path: l.exe_path.as_deref(),
                    system: l.system,
                }),
                ports,
            ));
        }

        // Apps that stopped listening keep their records, addresses and grants.
        for (id, app) in &known {
            if !live.contains_key(id) && app.ports.iter().any(|p| p.listening) {
                writes.push((id, None, Vec::new()));
                changed = true;
            }
        }
        let sightings: Vec<Sighting<'_>> = writes
            .iter()
            .map(|(id, touch, ports)| Sighting {
                app_id: id,
                touch: *touch,
                ports,
            })
            .collect();
        if !sightings.is_empty() {
            db.record_sightings(&sightings, now).await?;
        }
        Ok(changed)
    }
}
