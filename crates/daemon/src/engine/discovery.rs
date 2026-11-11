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

/// An app, its new process details (if it was seen listening) and the ports it listens on.
type PendingSighting<'a> = (&'a AppId, Option<Touch<'a>>, Vec<(PortRef, AddrFamily)>);

/// How stale the last sighting of an unchanged app may get before a poll writes it again.
/// A commit can take over a second on a protected database file, so an idle host writes
/// nothing for minutes.
const SIGHTING_REFRESH: chrono::Duration = chrono::Duration::minutes(5);

/// How long a "does the executable still exist" answer is reused.
const EXE_CHECK_REFRESH: Duration = Duration::from_secs(180);

/// Whether each app's executable still exists, checked at poll time so that API reads
/// never touch the disk. Shared by all engines of the process, keyed by path; not stored.
#[derive(Default)]
struct ExeCache(HashMap<String, (bool, Instant)>);

static EXE_CACHE: Mutex<Option<ExeCache>> = Mutex::new(None);

impl ExeCache {
    /// Re-check the paths whose answer is unknown or older than `EXE_CHECK_REFRESH` (all of
    /// them with `force`). Returns whether any answer changed.
    fn refresh<'a>(
        &mut self,
        paths: impl Iterator<Item = &'a str>,
        now: Instant,
        force: bool,
        exists: impl Fn(&str) -> bool,
    ) -> bool {
        let mut flipped = false;
        for p in paths {
            let before = self.0.get(p).copied();
            let stale =
                force || before.is_none_or(|(_, at)| now.duration_since(at) >= EXE_CHECK_REFRESH);
            if stale {
                let missing = !exists(p);
                self.0.insert(p.to_string(), (missing, now));
                // A path seen for the first time that exists is not a change.
                flipped |= before.map_or(missing, |(m, _)| m != missing);
            }
        }
        flipped
    }

    fn missing(&self, path: &str) -> bool {
        self.0.get(path).is_some_and(|(m, _)| *m)
    }
}

/// A process in another mount namespace has a path this daemon cannot see.
fn path_is_checkable(app: &App) -> bool {
    app.exe_path.as_deref().is_some_and(|p| !p.is_empty())
        && !app
            .identity_note
            .as_deref()
            .is_some_and(|n| n.contains("foreign mount namespace"))
}

/// The cached answer for an app's executable: true only when a path is known and was found
/// missing at the last poll.
pub(super) fn exe_missing(app: &App) -> bool {
    let guard = EXE_CACHE.lock().unwrap();
    path_is_checkable(app)
        && app
            .exe_path
            .as_deref()
            .is_some_and(|p| guard.as_ref().is_some_and(|c| c.missing(p)))
}

impl Engine {
    /// Refresh the executable-exists cache for the known apps (a few minutes apart, and at
    /// once with `force`). Returns whether any answer changed.
    fn refresh_exe_cache(&self, apps: &HashMap<AppId, App>, force: bool) -> bool {
        let paths = apps
            .values()
            .filter(|a| path_is_checkable(a))
            .filter_map(|a| a.exe_path.as_deref());
        EXE_CACHE
            .lock()
            .unwrap()
            .get_or_insert_with(ExeCache::default)
            .refresh(paths, Instant::now(), force, |p| {
                std::path::Path::new(p).exists()
            })
    }

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
        // A new app is when "the old one moved" gets noticed: look again at every path then.
        let new_app = live.keys().any(|id| !known.contains_key(id));
        let mut changed = self.refresh_exe_cache(&known, new_app);
        // What goes to the database, in one transaction; nothing when nothing changed.
        let mut writes: Vec<PendingSighting<'_>> = Vec::new();

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
                    exe_missing: false,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_cache_rechecks_only_after_the_refresh_interval() {
        let t0 = Instant::now();
        let mut c = ExeCache::default();
        assert!(c.refresh(["/a"].into_iter(), t0, false, |_| false));
        assert!(c.missing("/a"));
        // The file comes back, but the answer is reused until it is stale or forced.
        let soon = t0 + Duration::from_secs(60);
        assert!(!c.refresh(["/a"].into_iter(), soon, false, |_| true));
        assert!(c.missing("/a"));
        assert!(c.refresh(["/a"].into_iter(), soon, true, |_| true));
        assert!(!c.missing("/a"));
        // Missing again after the interval: reported as a change.
        assert!(c.refresh(
            ["/a"].into_iter(),
            t0 + EXE_CHECK_REFRESH * 2,
            false,
            |_| false
        ));
        assert!(c.missing("/a"));
        assert!(!c.missing("/never-checked"));
    }
}
