//! Lock-order stress test (see the lock order on `AppState`): polls, mutations, network
//! add/remove (the engine's write lock), disable/enable and API reads run side by side on
//! the mock engine. A lock-order inversion, or a task awaiting `engine.read()` while
//! holding a lock with a writer queued, hangs; the timeout turns that into a failure that
//! names the workers that stopped.

mod common;

use axum::http::{Method, StatusCode};
use common::{call, listener};
use socketguard_core::config::{BackendConfig, BackendInstanceConfig, DaemonConfig};
use socketguard_core::{NewGrant, Scope, Subject, Target};
use socketguard_daemon::engine::Engine;
use socketguard_daemon::test_support::*;
use socketguard_daemon::{api, state::Database, AppState};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Iterations per worker (half for the network and disable workers): enough to interleave
/// every pair several times in a few seconds of a debug build.
const ROUNDS: usize = 4;
/// Far above the normal run time; reaching it means something is stuck.
const LIMIT: Duration = Duration::from_secs(60);

const WORKERS: [&str; 5] = [
    "poll",
    "mutations",
    "network add/remove",
    "disable/enable",
    "api reads",
];

fn ygg() -> BackendInstanceConfig {
    BackendInstanceConfig {
        id: "ygg".into(),
        backend: BackendConfig::yggdrasil(vec![]),
    }
}

/// Local and LAN networks over mocks, on a database file: the shared-cache in-memory one
/// reports "table is locked" under concurrent writers, which is not what this test is about.
async fn daemon(
    path: &std::path::Path,
) -> (
    Arc<AppState>,
    Arc<Mutex<Vec<socketguard_core::ListeningSocket>>>,
) {
    let monitor = MockSocketMonitor::new(vec![listener("nginx", 80)]);
    let sockets = monitor.sockets.clone();
    let mut backends = HashMap::new();
    let mut configs = Vec::new();
    for n in [local_net(), lan_net()] {
        let cfg = BackendInstanceConfig {
            id: n.id.to_string(),
            backend: n.config,
        };
        backends.insert(n.id.to_string(), ip_backend(cfg.clone(), Box::new(n.mock)));
        configs.push(cfg);
    }
    let engine = Engine::new_injectable(
        Box::new(monitor),
        Arc::new(MockFirewall::new(Arc::new(Mutex::new(vec![])))),
        Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
        backends,
    );
    let db = Database::new(path.to_str().unwrap()).await.unwrap();
    db.init_schema().await.unwrap();
    let state = Arc::new(AppState {
        config: tokio::sync::RwLock::new(DaemonConfig {
            backends: configs,
            ..DaemonConfig::default()
        }),
        config_path: None,
        db,
        engine: tokio::sync::RwLock::new(engine),
        firewall_lock: tokio::sync::Mutex::new(()),
        bundled: Default::default(),
        events: tokio::sync::broadcast::channel(64).0,
    });
    (state, sockets)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polls_mutations_network_changes_and_disable_never_hang() {
    let dir = std::env::temp_dir().join(format!("sg-locks-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let (state, sockets) = daemon(&dir.join("state.db")).await;
    state.engine.read().await.reconcile(&state).await.unwrap();
    let nginx = state.db.list_apps().await.unwrap()[0].id.clone();
    let progress: Arc<[AtomicUsize; 5]> = Arc::new(Default::default());

    let mut tasks = Vec::new();
    {
        // Polls, with an app that comes and goes so each pass has something to write.
        let (state, sockets, progress) = (state.clone(), sockets.clone(), progress.clone());
        tasks.push(tokio::spawn(async move {
            for i in 0..ROUNDS {
                {
                    let mut s = sockets.lock().unwrap();
                    if i % 2 == 0 {
                        s.push(listener("redis", 6379));
                    } else {
                        s.retain(|l| l.process_name != "redis");
                    }
                }
                let engine = state.engine.read().await;
                // A pass may meet a network that was just removed; it must not hang.
                let _ = engine.reconcile(&state).await;
                drop(engine);
                progress[0].fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    {
        // Grants (addresses, firewall), and forgetting the app that comes and goes.
        let (state, progress) = (state.clone(), progress.clone());
        let nginx = nginx.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..ROUNDS {
                let engine = state.engine.read().await;
                let grant = engine
                    .create_grant(
                        &state,
                        &NewGrant {
                            target: Target::App(nginx.clone()),
                            scope: Scope::All,
                            network_id: None,
                            subject: Subject::Anyone,
                            confirm_open: true,
                        },
                    )
                    .await;
                if let Ok(g) = grant {
                    let _ = engine.delete_grant(&state, &g.grant.id).await;
                }
                // Changes that take the change lock (ADR 0062) beside the polls and the rest.
                if let Ok(p) = engine.create_peer(&state, "", &[]).await {
                    let _ = engine.delete_peer(&state, &p.id).await;
                }
                if let Ok(t) = engine.create_tag(&state, "stress", &[], &[]).await {
                    let _ = engine.delete_tag(&state, &t.id, true).await;
                }
                let redis = state
                    .db
                    .list_apps()
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .find(|a| a.process_name == "redis");
                if let Some(redis) = redis {
                    let _ = engine.delete_app(&state, &redis.id).await;
                }
                drop(engine);
                progress[1].fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    {
        // The engine's write lock, as the API's network add and remove take it.
        let (state, progress) = (state.clone(), progress.clone());
        tasks.push(tokio::spawn(async move {
            for _ in 0..ROUNDS / 2 {
                {
                    let mut engine = state.engine.write().await;
                    add_ip_network(&mut engine, &state, &ygg(), Box::new(ygg_net().mock)).await;
                }
                tokio::task::yield_now().await;
                {
                    let mut engine = state.engine.write().await;
                    engine.remove_backend_instance(&state, "ygg").await;
                }
                progress[2].fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    {
        let (state, progress) = (state.clone(), progress.clone());
        tasks.push(tokio::spawn(async move {
            for _ in 0..ROUNDS / 2 {
                let _ = state.engine.read().await.disable(&state).await;
                tokio::task::yield_now().await;
                let _ = state.engine.read().await.enable(&state).await;
                progress[3].fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    {
        // Readers queue behind a pending writer: they must not be what a pass waits for.
        let (state, progress) = (state.clone(), progress.clone());
        let app = api::router(state.clone());
        tasks.push(tokio::spawn(async move {
            for _ in 0..ROUNDS {
                for path in ["/api/apps", "/api/status", "/api/networks"] {
                    let (s, body) = call(&app, Method::GET, path, None).await;
                    assert_eq!(s, StatusCode::OK, "{path}: {body}");
                }
                progress[4].fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    let work = async {
        for t in tasks {
            // A panic in a worker fails the test with its own message.
            t.await.unwrap();
        }
        // Settled: enabled, a pass succeeds, and the write lock is free.
        let engine = state.engine.read().await;
        engine.enable(&state).await.unwrap();
        engine.reconcile(&state).await.unwrap();
        drop(engine);
        drop(state.engine.write().await);
    };
    if tokio::time::timeout(LIMIT, work).await.is_err() {
        let stuck: Vec<String> = WORKERS
            .iter()
            .zip(progress.iter())
            .map(|(name, n)| format!("{name}: {}", n.load(Ordering::Relaxed)))
            .collect();
        panic!(
            "lock stress test hung for {LIMIT:?} (deadlock or lock-order inversion); \
             rounds done per worker: {}",
            stuck.join(", ")
        );
    }
    drop(state);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A grant to Anyone on a tag and an unconfirmed join of the tag run at once (ADR 0062).
/// This cannot tell a locked engine from an unlocked one (any interleaving ends in a serial
/// outcome; `change_lock.rs` tests the lock itself); it checks that the outcome is one: the join is refused and the
/// app is not a member, or it went first and the app is a member of the opened tag.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_anyone_grant_on_a_tag_and_an_unconfirmed_join_end_in_a_serial_order() {
    use socketguard_daemon::engine::EngineError;
    let dir = std::env::temp_dir().join(format!("sg-locks-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let (state, _sockets) = daemon(&dir.join("state.db")).await;
    state.engine.read().await.reconcile(&state).await.unwrap();
    let nginx = state.db.list_apps().await.unwrap()[0].id.clone();
    let (mut refused, mut joined) = (0, 0);
    for round in 0..12 {
        let engine = state.engine.read().await;
        let tag = engine
            .create_tag(&state, &format!("t{round}"), &[], &[])
            .await
            .unwrap();
        let grant = NewGrant {
            target: Target::Tag(tag.id.clone()),
            scope: Scope::All,
            network_id: None,
            subject: Subject::Anyone,
            confirm_open: true,
        };
        let (g, j) = tokio::join!(
            engine.create_grant(&state, &grant),
            engine.add_tag_member(&state, &tag.id, &nginx, Scope::All, false),
        );
        let g = g.unwrap();
        let member = engine
            .get_tag(&state, &tag.id)
            .await
            .unwrap()
            .members
            .iter()
            .any(|m| m.app_id == nginx);
        match j {
            Ok(_) => {
                assert!(member, "joined but not a member");
                joined += 1;
            }
            Err(EngineError::ConfirmationRequired) => {
                assert!(
                    !member,
                    "refused but a member: opened without a confirmation"
                );
                refused += 1;
            }
            Err(e) => panic!("unexpected: {e:?}"),
        }
        engine.delete_grant(&state, &g.grant.id).await.unwrap();
        engine.delete_tag(&state, &tag.id, true).await.unwrap();
    }
    eprintln!("joined first: {joined}, refused: {refused}");
    drop(state);
    let _ = std::fs::remove_dir_all(&dir);
}
