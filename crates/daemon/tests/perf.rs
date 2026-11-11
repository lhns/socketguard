//! Performance harness over a realistic state (ignored by default):
//!
//!     cargo test -p socketguard-daemon --test perf -- --ignored --nocapture
//!
//! 60 apps (30 flagged system), two IP networks that take grants, Local on loopback and a
//! Tor network, 20 peers, 4 peer groups, 8 tags, 4 port groups, 60 grants and 3
//! reservations. Prints the median wall-clock time of the main read and write paths and
//! the number of SQL statements each one issues.

mod common;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::{call, listener};
use serde_json::{json, Value};
use socketguard_core::config::{BackendConfig, BackendInstanceConfig, DaemonConfig, TorAuth};
use socketguard_core::{ListeningSocket, Protocol};
use socketguard_daemon::api;
use socketguard_daemon::engine::{ActiveBackend, Engine};
use socketguard_daemon::networks::tor::TorNetwork;
use socketguard_daemon::test_support::*;
use socketguard_daemon::AppState;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

/// Runs per operation (median reported); `PERF_RUNS` overrides it.
fn runs() -> usize {
    std::env::var("PERF_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
}
const YGG_KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";
const TOR_KEY: &str = "ZGBMJ4VIRNVUOQ5SJ2JXPSSWHB2R4YGTKPDGSMZ4HWCD5WLT2YKQ";

/// Counts the statements sqlx logs.
struct SqlCounter(Arc<AtomicUsize>);

impl<S: tracing::Subscriber> Layer<S> for SqlCounter {
    fn on_event(&self, ev: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if ev.metadata().target() == "sqlx::query" {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct Rig {
    state: Arc<AppState>,
    app: Router,
    _tor: MockTorControl,
}

fn system_socket(i: usize, port: u16) -> ListeningSocket {
    let name = format!("svc{i:02}");
    let mut s = listener(&name, port);
    if cfg!(windows) {
        s.process_name = format!("{name}.exe");
        s.exe_path = Some(format!("C:\\Windows\\System32\\{name}.exe"));
    } else {
        s.uid = Some("0".into());
        s.exe_path = Some(format!("/usr/sbin/{name}"));
    }
    s
}

fn sockets() -> Vec<ListeningSocket> {
    let mut out = Vec::new();
    for i in 0..60usize {
        let ports = 1 + i % 6;
        for j in 0..ports {
            let port = 10_000 + (i * 10 + j) as u16;
            let mut s = if i % 2 == 0 {
                system_socket(i, port)
            } else {
                listener(&format!("app{i:02}"), port)
            };
            if j == 1 {
                s.protocol = Protocol::Udp;
            }
            out.push(s);
        }
    }
    out
}

impl Rig {
    async fn build() -> (Self, Arc<Mutex<Vec<ListeningSocket>>>) {
        let tor = MockTorControl::start();
        let fw = Arc::new(MockFirewall::new(Arc::new(Mutex::new(vec![]))));
        let net = MockInterfaceManager::new(Arc::new(Mutex::new(vec![])));
        let monitor = MockSocketMonitor::new(sockets());
        let live = monitor.sockets.clone();

        let mut backends = HashMap::new();
        let mut configs = Vec::new();
        for n in [local_net(), lan_net(), ygg_net()] {
            let cfg = BackendInstanceConfig {
                id: n.id.to_string(),
                backend: n.config,
            };
            backends.insert(n.id.to_string(), ip_backend(cfg.clone(), Box::new(n.mock)));
            configs.push(cfg);
        }
        let tor_cfg = BackendInstanceConfig {
            id: "tor".into(),
            backend: BackendConfig::Tor {
                control: tor.addr(),
                auth: TorAuth::None,
                cookie_path: None,
                cookie_dir: None,
                expect_tor_uid: None,
                cookie_owner: None,
                allow_remote_control: false,
            },
        };
        backends.insert(
            "tor".to_string(),
            ActiveBackend {
                config: tor_cfg.clone(),
                network: Arc::new(TorNetwork::with_options(
                    &tor.addr(),
                    tor.auth_options(),
                    Duration::ZERO,
                )),
            },
        );
        configs.push(tor_cfg);
        let engine = Engine::new_injectable(Box::new(monitor), fw, Arc::new(net), backends);
        let state = test_app_state_at(
            engine,
            DaemonConfig {
                backends: configs,
                ..DaemonConfig::default()
            },
            None,
        )
        .await;
        let app = api::router(state.clone());
        (
            Self {
                state,
                app,
                _tor: tor,
            },
            live,
        )
    }

    async fn reconcile(&self) {
        let engine = self.state.engine.read().await;
        engine.reconcile(&self.state).await.unwrap();
    }

    async fn get(&self, path: &str) -> Value {
        let (s, body) = call(&self.app, Method::GET, path, None).await;
        assert_eq!(s, StatusCode::OK, "{path}: {body}");
        body
    }

    async fn send(&self, method: Method, path: &str, body: Value, want: StatusCode) -> Value {
        let (s, body) = call(&self.app, method, path, Some(body)).await;
        assert_eq!(s, want, "{path}: {body}");
        body
    }

    async fn create(&self, path: &str, body: Value) -> String {
        self.send(Method::POST, path, body, StatusCode::CREATED)
            .await["id"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

fn all() -> Value {
    json!({"kind": "all"})
}

fn port_scope(p: u64) -> Value {
    json!({"kind": "port", "port": p, "proto": "tcp"})
}

/// The state described in the module docs. Returns the ids the timings use.
struct Ids {
    apps: Vec<Value>,
    peers: Vec<String>,
}

async fn populate(r: &Rig) -> Ids {
    println!("first reconcile");
    r.reconcile().await;
    println!("reconciled");
    let apps = r.get("/api/apps").await.as_array().unwrap().clone();
    assert_eq!(apps.len(), 60);
    let system = apps.iter().filter(|a| a["system"] == true).count();
    assert_eq!(system, 30, "half of the apps are flagged system");
    let app_ids: Vec<String> = apps
        .iter()
        .map(|a| a["id"].as_str().unwrap().to_string())
        .collect();

    // Peers: one with a Yggdrasil key, one with a Tor key, the rest by address.
    let mut peers = Vec::new();
    for i in 0..20 {
        let creds = match i {
            0 => json!([{"kind": "ygg_key", "value": YGG_KEY}]),
            1 => json!([{"kind": "tor_client_key", "value": TOR_KEY}]),
            _ => json!([{"kind": "ip", "value": format!("2001:db8::{:x}", i + 1)}]),
        };
        peers.push(
            r.create(
                "/api/peers",
                json!({"label": format!("peer{i:02}"), "credentials": creds}),
            )
            .await,
        );
    }
    println!("peers done");
    let mut groups = Vec::new();
    for g in 0..4 {
        let members: Vec<&String> = peers.iter().skip(g * 3).take(5).collect();
        groups.push(
            r.create(
                "/api/peer-groups",
                json!({"label": format!("group{g}"), "members": members}),
            )
            .await,
        );
    }
    let mut tags = Vec::new();
    for t in 0..8 {
        let members: Vec<Value> = (0..6)
            .map(|k| json!({"app_id": app_ids[(t * 7 + k * 3) % 60], "scope": all()}))
            .collect();
        tags.push(
            r.create(
                "/api/tags",
                json!({"label": format!("tag{t}"), "members": members}),
            )
            .await,
        );
    }
    println!("tags done");
    let mut pgs = Vec::new();
    for g in 0..4u64 {
        let attach: Vec<&String> = app_ids
            .iter()
            .skip(g as usize * 5 + 1)
            .step_by(9)
            .take(6)
            .collect();
        pgs.push(
            r.create(
                "/api/port-groups",
                json!({"label": format!("pg{g}"),
                       "ports": [{"start": 50_000 + g * 1000, "end": 50_900 + g * 1000, "proto": "tcp"},
                                 {"start": 21, "end": 21, "proto": "tcp"}],
                       "apps": attach}),
            )
            .await,
        );
    }

    // 60 grants: direct, tag, group subjects, a few Anyone. Peer 19 stays free for the
    // dry-run and add/revoke measurements.
    let grant = |target: Value, scope: Value, subject: Value, open: bool| json!({"target": target, "scope": scope, "subject": subject, "confirm_open": open});
    let started = Instant::now();
    let mut n = 0;
    while n < 60 {
        let app = &app_ids[(n * 7) % 60];
        let peer = &peers[n % 19];
        let body = match n % 6 {
            0 | 1 => grant(
                json!({"kind": "app", "id": app}),
                all(),
                json!({"kind": "peer", "id": peer}),
                false,
            ),
            2 => grant(
                json!({"kind": "app", "id": app}),
                port_scope(apps[(n * 7) % 60]["ports"][0]["port"].as_u64().unwrap()),
                json!({"kind": "peer", "id": peer}),
                false,
            ),
            3 => grant(
                json!({"kind": "tag", "id": tags[n % 8]}),
                all(),
                json!({"kind": "group", "id": groups[n % 4]}),
                false,
            ),
            4 => grant(
                json!({"kind": "app", "id": app}),
                all(),
                json!({"kind": "group", "id": groups[n % 4]}),
                false,
            ),
            _ => grant(
                json!({"kind": "app", "id": app}),
                all(),
                json!({"kind": "anyone"}),
                true,
            ),
        };
        let (s, resp) = call(&r.app, Method::POST, "/api/grants", Some(body)).await;
        // A generated duplicate is skipped; the count below is what matters.
        assert!(
            s == StatusCode::CREATED || s == StatusCode::CONFLICT,
            "{s}: {resp}"
        );
        n += 1;
        if n % 10 == 0 {
            println!("  {n} grants after {:?}", started.elapsed());
        }
    }

    // 3 reservations with bindings, one of them granted.
    for k in 0..3usize {
        let id = r
            .create(
                "/api/reservations",
                json!({"label": format!("res{k}"), "bindings": [
                    {"kind": "app", "app_id": app_ids[50 + k], "scope": all()},
                    {"kind": "app", "app_id": app_ids[53 + k], "scope": all()},
                    {"kind": "tag", "tag_id": tags[k]},
                ]}),
            )
            .await;
        r.send(
            Method::POST,
            "/api/grants",
            grant(
                json!({"kind": "reservation", "id": id}),
                all(),
                json!({"kind": "peer", "id": peers[k]}),
                false,
            ),
            StatusCode::CREATED,
        )
        .await;
    }
    r.reconcile().await;
    Ids { apps, peers }
}

struct Report {
    rows: Vec<(String, Duration, f64)>,
    sql: Arc<AtomicUsize>,
}

impl Report {
    async fn measure<F, Fut>(&mut self, name: &str, mut op: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        op().await; // warm up
        let mut times = Vec::new();
        let before = self.sql.load(Ordering::Relaxed);
        for _ in 0..runs() {
            let t = Instant::now();
            op().await;
            times.push(t.elapsed());
        }
        let stmts = (self.sql.load(Ordering::Relaxed) - before) as f64 / runs() as f64;
        times.sort();
        self.rows.push((name.to_string(), times[runs() / 2], stmts));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "performance harness; run with --ignored --nocapture"]
async fn timings() {
    let sql = Arc::new(AtomicUsize::new(0));
    let _ = tracing_subscriber::registry()
        .with(
            SqlCounter(sql.clone())
                .with_filter(Targets::new().with_target("sqlx::query", tracing::Level::DEBUG)),
        )
        .try_init();

    let (r, _live) = Rig::build().await;
    let t = Instant::now();
    let ids = populate(&r).await;
    println!("setup took {:?}", t.elapsed());
    let db = &r.state.db;
    println!(
        "state: {} apps, {} peers, {} grants, {} tags, {} port groups, {} reservations, {} addresses",
        db.list_apps().await.unwrap().len(),
        db.list_peers().await.unwrap().len(),
        db.list_grants().await.unwrap().len(),
        db.list_tags().await.unwrap().len(),
        db.list_port_groups().await.unwrap().len(),
        db.list_reservations().await.unwrap().len(),
        db.list_addresses().await.unwrap().len(),
    );

    // An app with grants and several ports, and a tag with members.
    let busy = ids
        .apps
        .iter()
        .max_by_key(|a| a["ports"].as_array().unwrap().len())
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let free_app = ids.apps[59]["id"].as_str().unwrap().to_string();
    let free_peer = ids.peers[19].clone();
    let add = json!({"op": "add_grant", "target": {"kind": "app", "id": free_app},
        "subject": {"kind": "peer", "id": free_peer}, "scope": all()});

    let mut rep = Report {
        rows: Vec::new(),
        sql,
    };
    rep.measure("GET /api/apps", || async {
        r.get("/api/apps").await;
    })
    .await;
    rep.measure("GET /api/apps/{id}", || async {
        r.get(&format!("/api/apps/{busy}")).await;
    })
    .await;
    rep.measure("GET /api/grants", || async {
        r.get("/api/grants").await;
    })
    .await;
    rep.measure("GET /api/grants?app=", || async {
        r.get(&format!("/api/grants?app={busy}")).await;
    })
    .await;
    rep.measure("GET /api/addresses", || async {
        r.get("/api/addresses").await;
    })
    .await;
    rep.measure("GET /api/reservations", || async {
        r.get("/api/reservations").await;
    })
    .await;
    rep.measure("GET /api/tags", || async {
        r.get("/api/tags").await;
    })
    .await;
    rep.measure("GET /api/peers", || async {
        r.get("/api/peers").await;
    })
    .await;
    rep.measure("GET /api/port-groups", || async {
        r.get("/api/port-groups").await;
    })
    .await;
    rep.measure("POST /api/changes dry run (1 add_grant)", || async {
        r.send(
            Method::POST,
            "/api/changes",
            json!({"ops": [add.clone()], "dry_run": true}),
            StatusCode::OK,
        )
        .await;
    })
    .await;
    rep.measure("add_grant + revoke (2 requests)", || async {
        let g = r
            .create(
                "/api/grants",
                json!({"target": {"kind": "app", "id": free_app}, "scope": all(),
                       "subject": {"kind": "peer", "id": free_peer}}),
            )
            .await;
        r.send(
            Method::DELETE,
            &format!("/api/grants/{g}"),
            json!(null),
            StatusCode::NO_CONTENT,
        )
        .await;
    })
    .await;
    // A poll with nothing changed.
    let state = r.state.clone();
    rep.measure("reconcile, nothing changed", || async {
        let engine = state.engine.read().await;
        engine.reconcile(&state).await.unwrap();
    })
    .await;

    // Reads while a poll holds the write lock: the latency of a GET during reconcile.
    let mut during = Vec::new();
    for _ in 0..runs() {
        let poll = {
            let state = r.state.clone();
            tokio::spawn(async move {
                let engine = state.engine.read().await;
                engine.reconcile(&state).await.unwrap();
            })
        };
        tokio::task::yield_now().await;
        let t = Instant::now();
        r.get("/api/apps").await;
        during.push(t.elapsed());
        poll.await.unwrap();
    }
    during.sort();
    rep.rows.push((
        "GET /api/apps issued during a poll".into(),
        during[runs() / 2],
        0.0,
    ));

    println!("\n{:<44} {:>12} {:>10}", "operation", "median", "SQL stmts");
    for (name, d, n) in &rep.rows {
        println!("{name:<44} {:>9.2?} {:>10.0}", d, n);
    }
}
