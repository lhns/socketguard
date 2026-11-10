//! Live sockets to apps and ports.

use super::*;
use crate::api::DaemonEvent;
use crate::networks::{self};
use crate::state::NewActivity;
use crate::AppState;
use chrono::Utc;
use socketguard_core::config::ProcessFilter;
use socketguard_core::{app_identity, ActivityKind, App, AppId, AppIdentity, AppPort, PortRef};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use tracing::info;

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
            ports: BTreeSet<PortRef>,
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
                    ports: BTreeSet::new(),
                })
                .ports
                .insert(PortRef {
                    port: ls.port,
                    proto: ls.protocol,
                });
        }

        *self.binds.lock().unwrap() = binds;

        let db = &state.db;
        let now = Utc::now();
        let known: HashMap<AppId, App> = db
            .list_apps()
            .await?
            .into_iter()
            .map(|a| (a.id.clone(), a))
            .collect();
        let mut changed = false;

        for (id, l) in &live {
            let ports: Vec<PortRef> = l.ports.iter().copied().collect();
            if !known.contains_key(id) {
                info!("New app detected: {} ({id})", l.name);
                db.insert_app(&App {
                    id: id.clone(),
                    name: l.name.clone(),
                    process_name: l.process_name.clone(),
                    exe_path: l.exe_path.clone(),
                    interpreter_arg: l.interpreter_arg.clone(),
                    identity_note: l.identity_note.clone(),
                    reviewed: false,
                    first_seen: now,
                    last_seen: now,
                    ports: vec![],
                    addresses: vec![],
                })
                .await?;
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
            } else {
                db.touch_app(id, &l.process_name, l.exe_path.as_deref(), now)
                    .await?;
            }
            let was_listening: BTreeSet<PortRef> = known
                .get(id)
                .map(|a| {
                    a.ports
                        .iter()
                        .filter(|p| p.listening)
                        .map(AppPort::port_ref)
                        .collect()
                })
                .unwrap_or_default();
            let new_ports = db.sync_app_ports(id, &ports, now).await?;
            if !new_ports.is_empty() || was_listening != l.ports {
                changed = true;
            }
        }

        // Apps that stopped listening keep their records, addresses and grants.
        for (id, app) in &known {
            if !live.contains_key(id) && app.ports.iter().any(|p| p.listening) {
                db.sync_app_ports(id, &[], now).await?;
                changed = true;
            }
        }
        Ok(changed)
    }
}
