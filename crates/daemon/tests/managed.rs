//! ADR 0052 at the API: the managed form of a network is accepted from any caller when the
//! build ships the files, `/api/status` lists them, and a managed Yggdrasil's peers change
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
    let d = std::env::temp_dir().join(format!("sg-managed-{}", uuid::Uuid::new_v4()));
    for f in files {
        let p = d.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }
    std::fs::write(d.join("VERSIONS"), "tor 16.0.1\nyggdrasil v0.5.15 abc\n").unwrap();
    d
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

    /// A managed Yggdrasil network `ygg` over a mock allocator, without a child (the settings
    /// and the API are tested here; the child is in `managed_ygg.rs`).
    async fn with_managed_ygg(&self, peers: &[&str]) {
        let inst = BackendInstanceConfig {
            id: "ygg".into(),
            backend: BackendConfig::managed_yggdrasil(
                peers.iter().map(|p| p.to_string()).collect(),
            ),
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
async fn a_build_without_the_files_refuses_managed_networks_and_says_so() {
    let f = Fixture::new(Bundled::none()).await;
    for body in [
        json!({"type": "tor", "managed": true}),
        json!({"type": "yggdrasil", "managed": true}),
    ] {
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
    assert_eq!(setup["tor"]["managed"]["available"], false);
    assert_eq!(setup["yggdrasil"]["existing"]["state"], "absent");
}

#[tokio::test]
async fn managed_settings_are_checked_before_anything_else() {
    let f = Fixture::new(Bundled::none()).await;
    let (s, e) = f
        .call(
            Method::POST,
            "/api/networks",
            Some(json!({"type": "tor", "managed": true, "control": "10.0.0.1:9051"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        e["message"].as_str().unwrap().contains("managed Tor"),
        "{e}"
    );
    let (s, _) = f
        .call(
            Method::POST,
            "/api/networks",
            Some(json!({"type": "yggdrasil", "managed": true, "peers": ["nonsense"]})),
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
    assert_eq!(setup["tor"]["managed"]["available"], true);
    assert_eq!(setup["tor"]["managed"]["version"], "16.0.1");
    // The network is created; its child is not started by this engine (no state
    // directory), and the card says so instead of failing the request.
    let (s, n) = f
        .call(
            Method::POST,
            "/api/networks",
            Some(json!({"type": "tor", "managed": true})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{n}");
    assert_eq!(n["kind"], "tor");
    // (a daemon with no state directory has nowhere to keep Tor's data)
    assert_eq!(n["managed"]["state"], "unavailable");
    assert_eq!(n["managed"]["version"], "16.0.1");
    assert_eq!(n["status"]["state"], "down");
}

#[tokio::test]
async fn incomplete_files_are_refused_with_a_sentence() {
    let dir = third_party(&[&format!("yggdrasil/{}", exe("yggdrasil"))]);
    let f = Fixture::new(Bundled::from_dir(&dir)).await;
    let (s, e) = f
        .call(
            Method::POST,
            "/api/networks",
            Some(json!({"type": "tor", "managed": true})),
        )
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
    f.with_managed_ygg(&["tls://a.example:1"]).await;
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
        n["managed"]["peers"],
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
async fn only_a_managed_yggdrasil_takes_peers() {
    let f = Fixture::new(Bundled::none()).await;
    let inst = BackendInstanceConfig {
        id: "ygg".into(),
        backend: BackendConfig::Yggdrasil {
            interface: Some("ygg0".into()),
            admin_endpoint: None,
            managed: false,
            peers: vec![],
        },
    };
    {
        let mut engine = f.state.engine.write().await;
        let mock = MockIpv6Backend::new("300:1:2:3::", 128, "ygg0");
        add_ip_network(&mut engine, &f.state, &inst, Box::new(mock)).await;
    }
    let (s, _) = f
        .call(
            Method::PUT,
            "/api/networks/ygg/peers",
            Some(json!({"peers": ["tls://a.example:1"]})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}
