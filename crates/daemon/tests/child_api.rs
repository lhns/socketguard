//! ADR 0052 at the API: a Tor or Yggdrasil network is accepted from any caller when the
//! build ships the files, `/api/status` lists them, and a Yggdrasil's peers change
//! through `PUT /api/networks/{id}/peers`.

mod common;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::call;
use serde_json::{json, Value};
use socketguard_core::config::{BackendConfig, BackendInstanceConfig, DaemonConfig};
use socketguard_daemon::api;
use socketguard_daemon::bundled::Bundled;
use socketguard_daemon::test_support::*;
use std::sync::Arc;

fn third_party(files: &[&str]) -> std::path::PathBuf {
    third_party_dir(files, "tor 16.0.1\nyggdrasil v0.5.15 abc\n")
}

struct Fixture {
    state: Arc<socketguard_daemon::AppState>,
    app: Router,
}

impl Fixture {
    async fn new(bundled: Bundled) -> Self {
        let state =
            test_app_state_with(empty_engine(), DaemonConfig::default(), None, bundled).await;
        let app = api::router(state.clone());
        Self { state, app }
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        call(&self.app, method, path, body).await
    }

    /// A Yggdrasil network `ygg` over a mock allocator, without a child (the settings
    /// and the API are tested here; the child is in `child_ygg.rs`).
    async fn with_ygg_child(&self, peers: &[&str]) {
        let inst = BackendInstanceConfig {
            id: "ygg".into(),
            backend: BackendConfig::yggdrasil(peers.iter().map(|p| p.to_string()).collect()),
        };
        let mock = MockIpv6Backend::new("300:1:2:3::", 128, "ygg0");
        let mut engine = self.state.engine.write().await;
        add_ip_network(&mut engine, &self.state, &inst, Box::new(mock)).await;
    }
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

#[tokio::test]
async fn a_build_without_the_files_refuses_tor_and_yggdrasil_networks_and_says_so() {
    let f = Fixture::new(Bundled::none()).await;
    for body in [json!({"type": "tor"}), json!({"type": "yggdrasil"})] {
        let (s, e) = f.call(Method::POST, "/api/networks", Some(body)).await;
        assert_eq!(
            (s, e["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid"))
        );
        assert_eq!(e["message"], socketguard_core::setup::NOT_INCLUDED);
    }
    let (_, status) = f.call(Method::GET, "/api/status", None).await;
    assert!(status["bundled"].get("dir").is_none());
    assert_eq!(status["bundled"]["versions"], json!([]));
    let (_, setup) = f.call(Method::GET, "/api/networks/setup", None).await;
    assert_eq!(setup["tor"]["available"], false);
    assert_eq!(setup["tor"]["added"], false);
    assert_eq!(
        setup["yggdrasil"]["reason"],
        socketguard_core::setup::NOT_INCLUDED
    );
}

#[tokio::test]
async fn settings_are_checked_before_anything_else() {
    let f = Fixture::new(Bundled::none()).await;
    // The settings of a Tor the user runs are gone, as is the flag that told them apart.
    for key in ["control", "managed", "auth", "cookie_path"] {
        let (s, e) = f
            .call(
                Method::POST,
                "/api/networks",
                Some(json!({"type": "tor", key: "x"})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{key}");
        assert!(e["message"].as_str().unwrap().contains(key), "{e}");
    }
    let (s, _) = f
        .call(
            Method::POST,
            "/api/networks",
            Some(json!({"type": "yggdrasil", "peers": ["nonsense"]})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn complete_files_pass_the_checks_and_status_lists_them() {
    let dir = third_party(&[
        &format!("tor/{}", exe("tor")),
        &format!("yggdrasil/{}", exe("yggdrasil")),
        "yggdrasil/wintun.dll",
    ]);
    let f = Fixture::new(Bundled::from_dir(&dir)).await;
    let (_, status) = f.call(Method::GET, "/api/status", None).await;
    assert_eq!(status["bundled"]["dir"], dir.display().to_string());
    assert_eq!(status["bundled"]["versions"][0]["name"], "tor");
    let (_, setup) = f.call(Method::GET, "/api/networks/setup", None).await;
    assert_eq!(setup["tor"]["available"], true);
    assert_eq!(setup["tor"]["version"], "16.0.1");
    // The network is created; its child is not started by this engine (no state
    // directory), and the card says so instead of failing the request.
    let (s, n) = f
        .call(Method::POST, "/api/networks", Some(json!({"type": "tor"})))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{n}");
    assert_eq!(n["kind"], "tor");
    // (a daemon with no state directory has nowhere to keep Tor's data)
    assert_eq!(n["child"]["state"], "unavailable");
    assert_eq!(n["child"]["version"], "16.0.1");
    assert_eq!(n["status"]["state"], "down");
}

#[tokio::test]
async fn incomplete_files_are_refused_with_a_sentence() {
    let dir = third_party(&[&format!("yggdrasil/{}", exe("yggdrasil"))]);
    let f = Fixture::new(Bundled::from_dir(&dir)).await;
    let (s, e) = f
        .call(Method::POST, "/api/networks", Some(json!({"type": "tor"})))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        e["message"],
        "the Tor files of this build are incomplete: tor is missing"
    );
}

#[tokio::test]
async fn peers_are_replaced_validated_and_saved() {
    let f = Fixture::new(Bundled::none()).await;
    f.with_ygg_child(&["tls://a.example:1"]).await;
    let put = |peers: Value| {
        f.call(
            Method::PUT,
            "/api/networks/ygg/peers",
            Some(json!({"peers": peers})),
        )
    };

    let (s, n) = put(json!(["tls://b.example:2", "tcp://[2001:db8::1]:9"])).await;
    assert_eq!(s, StatusCode::OK, "{n}");
    assert_eq!(n["id"], "ygg");
    assert_eq!(
        n["child"]["peers"],
        json!(["tls://b.example:2", "tcp://[2001:db8::1]:9"])
    );
    let configs = f.state.engine.read().await.backend_configs();
    assert_eq!(configs[0].backend.peers().len(), 2);

    let (s, _) = put(json!(["tls://b.example:2", "tls://b.example:2"])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = put(json!(["not a uri"])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        f.state.engine.read().await.backend_configs()[0]
            .backend
            .peers()
            .len(),
        2,
        "a refused list changes nothing"
    );
    let (s, _) = put(json!([])).await;
    assert_eq!(s, StatusCode::OK);

    let (s, e) = f
        .call(
            Method::PUT,
            "/api/networks/nope/peers",
            Some(json!({"peers": []})),
        )
        .await;
    assert_eq!(
        (s, e["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
}

#[tokio::test]
async fn lan_discovery_is_off_and_turning_it_on_needs_confirmation() {
    let f = Fixture::new(Bundled::none()).await;
    f.with_ygg_child(&["tls://a.example:1"]).await;
    let put = |body: Value| f.call(Method::PUT, "/api/networks/ygg/lan-discovery", Some(body));
    let on = || async {
        f.state.engine.read().await.backend_configs()[0]
            .backend
            .lan_discovery()
    };
    let (_, n) = f.call(Method::GET, "/api/networks", None).await;
    assert_eq!(n[0]["child"]["lan_discovery"], false, "{n}");
    assert!(!on().await);

    // Turning it on opens the LAN to Yggdrasil nodes: refused without the confirmation.
    let (s, e) = put(json!({"enabled": true})).await;
    assert_eq!(
        (s, e["code"].as_str()),
        (StatusCode::CONFLICT, Some("confirmation_required")),
        "{e}"
    );
    assert!(!on().await);
    let (s, n) = put(json!({"enabled": true, "confirm_open": true})).await;
    assert_eq!(s, StatusCode::OK, "{n}");
    assert_eq!(n["child"]["lan_discovery"], true);
    assert!(on().await);
    // Changing the peers keeps it.
    let (s, n) = f
        .call(
            Method::PUT,
            "/api/networks/ygg/peers",
            Some(json!({"peers": []})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{n}");
    assert!(on().await);
    // Turning it off needs nothing.
    let (s, n) = put(json!({"enabled": false})).await;
    assert_eq!(s, StatusCode::OK, "{n}");
    assert_eq!(n["child"]["lan_discovery"], false);
    assert!(!on().await);

    let (s, e) = f
        .call(
            Method::PUT,
            "/api/networks/nope/lan-discovery",
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(
        (s, e["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
}

#[tokio::test]
async fn a_new_yggdrasil_network_cannot_be_added_with_lan_discovery_on() {
    let f = Fixture::new(Bundled::none()).await;
    let (s, e) = f
        .call(
            Method::POST,
            "/api/networks",
            Some(json!({"type": "yggdrasil", "lan_discovery": true})),
        )
        .await;
    // Refused before the files are even looked at.
    assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
    assert!(
        e["message"].as_str().unwrap().contains("LAN discovery"),
        "{e}"
    );
}
