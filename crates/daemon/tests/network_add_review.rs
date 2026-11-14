//! Adding a network lets the grants that already exist take effect on it, so it is reviewed
//! first (ADR 0066): a dry run lists the grants, and an add that would let Anyone in is
//! refused without `confirm_open`, before anything is created, written or started.

mod common;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::{call, listener, KEY};
use serde_json::{json, Value};
use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use socketguard_core::{new_id, Grant, Scope, Subject, Target};
use socketguard_daemon::api;
use socketguard_daemon::bundled::Bundled;
use socketguard_daemon::engine::Engine;
use socketguard_daemon::test_support::*;
use socketguard_daemon::AppState;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct Rig {
    state: Arc<AppState>,
    app: Router,
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

impl Rig {
    /// A daemon with `nets` as its networks, the files of Tor and Yggdrasil, and two apps
    /// (nginx, sshd) already seen.
    async fn new(nets: Vec<Net>) -> Self {
        let monitor = MockSocketMonitor::new(vec![listener("nginx", 80), listener("sshd", 22)]);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut backends = HashMap::new();
        let mut configs = Vec::new();
        for n in nets {
            let cfg = BackendInstanceConfig {
                id: n.id.to_string(),
                backend: n.config,
            };
            backends.insert(n.id.to_string(), ip_backend(cfg.clone(), Box::new(n.mock)));
            configs.push(cfg);
        }
        let engine = Engine::new_injectable(
            Box::new(monitor),
            Arc::new(MockFirewall::new(calls.clone())),
            Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(Vec::new())))),
            backends,
        );
        let dir = third_party_dir(
            &[
                &format!("tor/{}", exe("tor")),
                &format!("yggdrasil/{}", exe("yggdrasil")),
                "yggdrasil/wintun.dll",
            ],
            "tor 16.0.1\nyggdrasil v0.5.15 abc\n",
        );
        let state = test_app_state_with(
            engine,
            DaemonConfig {
                backends: configs,
                ..DaemonConfig::default()
            },
            None,
            Bundled::from_dir(&dir),
        )
        .await;
        let app = api::router(state.clone());
        state.engine.read().await.reconcile(&state).await.unwrap();
        Self { state, app }
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        call(&self.app, Method::GET, path, None).await
    }
    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        call(&self.app, Method::POST, path, Some(body)).await
    }
    async fn delete(&self, path: &str) -> (StatusCode, Value) {
        call(&self.app, Method::DELETE, path, None).await
    }

    async fn ok(&self, (s, b): (StatusCode, Value)) -> Value {
        assert!(s.is_success(), "{s} {b}");
        b
    }

    async fn app_id(&self, name: &str) -> String {
        let apps = self.ok(self.get("/api/apps").await).await;
        apps.as_array()
            .unwrap()
            .iter()
            .find(|a| a["process_name"] == name)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn peer(&self) -> String {
        let b = self
            .ok(self
                .post(
                    "/api/peers",
                    json!({"label": "alice", "credentials": [{"kind": "ygg_key", "value": KEY}]}),
                )
                .await)
            .await;
        b["id"].as_str().unwrap().to_string()
    }

    /// A grant of nginx (All ports) to `subject`, on `network` or on every network.
    async fn grant(&self, subject: Value, network: Option<&str>) -> String {
        let ng = self.app_id("nginx").await;
        let mut body = json!({
            "target": {"kind": "app", "id": ng},
            "subject": subject,
            "confirm_open": true,
        });
        if let Some(n) = network {
            body["network_id"] = json!(n);
        }
        let b = self.ok(self.post("/api/grants", body).await).await;
        b["id"]
            .as_str()
            .or_else(|| b["grant"]["id"].as_str())
            .unwrap()
            .to_string()
    }

    async fn network_ids(&self) -> Vec<String> {
        let n = self.ok(self.get("/api/networks").await).await;
        n.as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_str().unwrap().to_string())
            .collect()
    }

    async fn activity(&self) -> Vec<String> {
        let a = self.ok(self.get("/api/activity?limit=200").await).await;
        a.as_array()
            .unwrap()
            .iter()
            .map(|r| r["message"].as_str().unwrap().to_string())
            .collect()
    }

    /// What a refused or dry-run add must leave alone.
    async fn footprint(&self) -> (Vec<String>, usize, Vec<String>, Vec<String>) {
        let configured = self
            .state
            .engine
            .read()
            .await
            .backend_configs()
            .into_iter()
            .map(|b| b.id)
            .collect();
        let addresses = self.state.db.list_addresses().await.unwrap().len();
        (
            self.network_ids().await,
            addresses,
            self.activity().await,
            configured,
        )
    }

    /// The add of `body`, as a dry run and for real.
    async fn preview(&self, body: Value) -> Value {
        let mut body = body;
        body["dry_run"] = json!(true);
        let (s, b) = self.post("/api/networks", body).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        b
    }
}

fn tor() -> Value {
    json!({"type": "tor"})
}

fn ygg() -> Value {
    json!({"type": "yggdrasil"})
}

fn with_confirm(mut body: Value) -> Value {
    body["confirm_open"] = json!(true);
    body
}

fn refused(r: &(StatusCode, Value)) -> bool {
    r.0 == StatusCode::CONFLICT && r.1["code"] == "confirmation_required"
}

#[tokio::test]
async fn without_grants_nothing_is_listed_and_no_confirmation_is_needed() {
    let r = Rig::new(vec![local_net(), lan_net()]).await;
    let p = r.preview(ygg()).await;
    assert_eq!(p, json!({"gains": [], "confirm_open_required": false}));
    r.ok(r.post("/api/networks", ygg()).await).await;
    assert!(r.network_ids().await.contains(&"yggdrasil".to_string()));
}

#[tokio::test]
async fn a_peer_grant_is_listed_and_needs_no_confirmation() {
    let r = Rig::new(vec![local_net(), lan_net()]).await;
    let alice = r.peer().await;
    let gid = r.grant(json!({"kind": "peer", "id": alice}), None).await;
    let p = r.preview(ygg()).await;
    assert_eq!(p["confirm_open_required"], false, "{p}");
    let gains = p["gains"].as_array().unwrap();
    assert_eq!(gains.len(), 1, "{p}");
    assert_eq!(gains[0]["id"], gid);
    assert_eq!(gains[0]["name"], "alice to nginx");
    assert_eq!(gains[0]["opens_to_anyone"], false);
    assert_eq!(
        gains[0]["reach"],
        json!([{"network_id": "yggdrasil", "reach": "verified"}]),
        "only the reach on the new network"
    );
    // A Tor network does not verify a Yggdrasil key: nothing for that peer there.
    let p = r.preview(tor()).await;
    assert_eq!(p["gains"], json!([]), "{p}");
    r.ok(r.post("/api/networks", ygg()).await).await;
    let log = r.activity().await;
    assert!(
        log.iter()
            .any(|m| m.contains("1 existing grants take effect on it (0 to Anyone)")),
        "{log:?}"
    );
}

#[tokio::test]
async fn an_anyone_grant_without_a_network_needs_confirmation_and_the_refusal_changes_nothing() {
    let r = Rig::new(vec![local_net(), lan_net()]).await;
    r.grant(json!({"kind": "anyone"}), None).await;
    let before = r.footprint().await;

    let p = r.preview(ygg()).await;
    assert_eq!(p["confirm_open_required"], true, "{p}");
    assert_eq!(p["gains"][0]["opens_to_anyone"], true);
    assert_eq!(p["gains"][0]["name"], "Anyone to nginx");
    assert_eq!(r.footprint().await, before, "a dry run changes nothing");

    for body in [ygg(), tor()] {
        let res = r.post("/api/networks", body).await;
        assert!(refused(&res), "{res:?}");
        assert_eq!(
            r.footprint().await,
            before,
            "no network, no key, no address, no log line"
        );
    }

    r.ok(r.post("/api/networks", with_confirm(ygg())).await)
        .await;
    let log = r.activity().await;
    assert!(
        log.iter()
            .any(|m| m.contains("1 existing grants take effect on it (1 to Anyone)")),
        "{log:?}"
    );
}

#[tokio::test]
async fn a_grant_row_that_names_the_id_of_a_network_that_is_not_there_takes_effect_when_it_is_added(
) {
    let r = Rig::new(vec![local_net(), lan_net()]).await;
    let lan2 =
        json!({"id": "lan2", "type": "slaac", "interface": "eth9", "prefix": "2001:db8:9:9::/64"});
    r.ok(r.post("/api/networks", lan2.clone()).await).await;
    r.grant(json!({"kind": "anyone"}), Some("lan2")).await;
    r.ok(r.delete("/api/networks/lan2").await).await;
    let grants = r.ok(r.get("/api/grants").await).await;
    assert_eq!(
        grants,
        json!([]),
        "removing a network deletes the grants that name it"
    );

    // A row can still name an id nothing serves; adding the id lets it in.
    let ng = r.app_id("nginx").await;
    r.state
        .db
        .insert_grant(&Grant {
            id: new_id(),
            target: Target::App(ng),
            scope: Scope::All,
            network_id: Some("lan2".into()),
            subject: Subject::Anyone,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let before = r.footprint().await;

    // The grant does nothing on other networks, and takes effect on its id.
    let other = r.preview(ygg()).await;
    assert_eq!(other["gains"], json!([]), "{other}");
    let p = r.preview(lan2.clone()).await;
    assert_eq!(p["confirm_open_required"], true, "{p}");
    assert_eq!(p["gains"][0]["detail"], "on lan2");
    assert_eq!(
        p["gains"][0]["reach"],
        json!([{"network_id": "lan2", "reach": "open"}])
    );
    let res = r.post("/api/networks", lan2.clone()).await;
    assert!(refused(&res), "{res:?}");
    assert_eq!(r.footprint().await, before);
    r.ok(r.post("/api/networks", with_confirm(lan2)).await)
        .await;
}

#[tokio::test]
async fn local_takes_no_grants_so_it_never_asks_or_lists() {
    let r = Rig::new(vec![lan_net()]).await;
    r.grant(json!({"kind": "anyone"}), None).await;
    let local = json!({"type": "ula", "interface": "lo"});
    let p = r.preview(local.clone()).await;
    assert_eq!(p, json!({"gains": [], "confirm_open_required": false}));
    r.ok(r.post("/api/networks", local).await).await;
    assert!(
        !r.activity().await.iter().any(|m| m.contains("take effect")),
        "nothing took effect"
    );
}

#[tokio::test]
async fn a_row_bound_to_a_reservation_does_nothing_on_tor() {
    let r = Rig::new(vec![local_net(), lan_net()]).await;
    let ng = r.app_id("nginx").await;
    r.ok(r
        .post(
            "/api/reservations",
            json!({"label": "pub", "bindings": [{"kind": "app", "app_id": ng, "scope": {"kind": "all"}}]}),
        )
        .await)
        .await;
    r.grant(json!({"kind": "anyone"}), None).await;

    let p = r.preview(tor()).await;
    assert_eq!(
        p,
        json!({"gains": [], "confirm_open_required": false}),
        "{p}"
    );
    // The same grant does let Anyone in on Yggdrasil.
    let p = r.preview(ygg()).await;
    assert_eq!(p["confirm_open_required"], true, "{p}");

    r.ok(r.post("/api/networks", tor()).await).await;
}

#[tokio::test]
async fn a_dry_run_is_validated_like_the_real_add() {
    let r = Rig::new(vec![local_net(), lan_net()]).await;
    let (s, b) = r
        .post("/api/networks", json!({"type": "ula", "dry_run": true}))
        .await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );
    let (s, b) = r
        .post(
            "/api/networks",
            json!({"id": "lan", "type": "slaac", "interface": "eth9", "dry_run": true}),
        )
        .await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );
    let (s, b) = r
        .post(
            "/api/networks",
            json!({"type": "dhcpv6", "interface": "", "dry_run": true}),
        )
        .await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid"))
    );
}
