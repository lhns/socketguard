//! ADR 0052 at the API: `PUT /api/networks/{id}/bridges` of a managed Tor network validates
//! every line against the one supported form, stores it in canonical form, and needs the
//! obfs4 helper of the build.

mod common;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::call;
use serde_json::{json, Value};
use socketguard_core::config::DaemonConfig;
use socketguard_daemon::api;
use socketguard_daemon::bundled::Bundled;
use socketguard_daemon::test_support::*;
use std::sync::Arc;

const FP: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
const CERT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn bridge(host: u8) -> String {
    format!("obfs4 192.0.2.{host}:443 {FP} cert={CERT} iat-mode=0")
}

struct Fixture {
    state: Arc<socketguard_daemon::AppState>,
    app: Router,
}

impl Fixture {
    /// A daemon whose build ships Tor, and the obfs4 helper when `helper`, with a managed
    /// Tor network `tor`.
    async fn new(helper: bool) -> Self {
        let f = Self::new_empty(helper).await;
        let (s, n) = f
            .call(
                Method::POST,
                "/api/networks",
                Some(json!({"type": "tor", "managed": true})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{n}");
        f
    }

    /// The same without a network.
    async fn new_empty(helper: bool) -> Self {
        let d = std::env::temp_dir().join(format!("sg-bridges-{}", uuid::Uuid::new_v4()));
        let mut files = vec![format!("tor/{}", exe("tor"))];
        if helper {
            files.push(format!("tor/pluggable_transports/{}", exe("lyrebird")));
        }
        for f in files {
            let p = d.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b"x").unwrap();
        }
        std::fs::write(d.join("VERSIONS"), "tor 16.0.1\n").unwrap();
        let state = test_app_state_with(
            empty_engine(),
            DaemonConfig::default(),
            None,
            Bundled::from_dir(&d),
        )
        .await;
        let app = api::router(state.clone());
        Self { state, app }
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        call(&self.app, method, path, body).await
    }

    async fn put(&self, bridges: Value) -> (StatusCode, Value) {
        self.call(
            Method::PUT,
            "/api/networks/tor/bridges",
            Some(json!({ "bridges": bridges })),
        )
        .await
    }

    async fn configured(&self) -> Vec<String> {
        self.state.engine.read().await.backend_configs()[0]
            .backend
            .bridges()
            .to_vec()
    }
}

#[tokio::test]
async fn bridges_are_validated_normalised_deduplicated_and_saved() {
    let f = Fixture::new(true).await;
    let lower = format!(
        "Bridge obfs4 192.0.2.1:443 {} cert={CERT} iat-mode=0",
        FP.to_lowercase()
    );
    let (s, n) = f.put(json!([lower, bridge(1), bridge(2)])).await;
    assert_eq!(s, StatusCode::OK, "{n}");
    assert_eq!(n["managed"]["bridges"], json!([bridge(1), bridge(2)]));
    assert!(n["managed"].get("bridges_unavailable").is_none());
    assert_eq!(f.configured().await, [bridge(1), bridge(2)]);

    for hostile in [
        format!("{}\nSocksPort 9050", bridge(3)),
        format!("{}\r\nControlPort 9051", bridge(3)),
        format!("{}\u{2028}SocksPort 1", bridge(3)),
        format!("{} SocksPort 1", bridge(3)),
        "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72".to_string(),
        "x".repeat(100_000),
    ] {
        let (s, e) = f.put(json!([bridge(3), hostile])).await;
        assert_eq!(
            (s, e["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid")),
            "{e}"
        );
    }
    assert_eq!(
        f.configured().await.len(),
        2,
        "a refused list changes nothing"
    );

    let (s, n) = f.put(json!([])).await;
    assert_eq!(s, StatusCode::OK, "{n}");
    assert!(n["managed"].get("bridges").is_none());
    assert!(f.configured().await.is_empty());

    let (s, e) = f
        .call(
            Method::PUT,
            "/api/networks/nope/bridges",
            Some(json!({"bridges": []})),
        )
        .await;
    assert_eq!(
        (s, e["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
}

#[tokio::test]
async fn without_the_helper_bridges_cannot_be_set_and_the_card_says_why() {
    let f = Fixture::new(false).await;
    let (s, e) = f.put(json!([bridge(1)])).await;
    assert_eq!(
        (s, e["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict")),
        "{e}"
    );
    assert!(
        e["message"].as_str().unwrap().contains("obfs4 helper"),
        "{e}"
    );
    assert!(f.configured().await.is_empty());
    // Turning bridges off is always possible.
    let (s, n) = f.put(json!([])).await;
    assert_eq!(s, StatusCode::OK, "{n}");
    assert!(n["managed"]["bridges_unavailable"]
        .as_str()
        .unwrap()
        .contains("obfs4 helper"));
}

#[tokio::test]
async fn bridges_in_a_new_network_follow_the_same_rules() {
    let body = |b: Value| json!({"type": "tor", "managed": true, "bridges": b});
    let f = Fixture::new_empty(true).await;
    let (s, e) = f
        .call(
            Method::POST,
            "/api/networks",
            Some(body(json!([format!("{} X", bridge(1))]))),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
    let (s, n) = f
        .call(
            Method::POST,
            "/api/networks",
            Some(body(json!([bridge(1)]))),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{n}");
    assert_eq!(n["managed"]["bridges"], json!([bridge(1)]));

    let f = Fixture::new_empty(false).await;
    let (s, e) = f
        .call(
            Method::POST,
            "/api/networks",
            Some(body(json!([bridge(1)]))),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
    assert!(
        e["message"].as_str().unwrap().contains("obfs4 helper"),
        "{e}"
    );
}

#[tokio::test]
async fn a_body_that_is_not_a_list_of_strings_is_refused() {
    let f = Fixture::new(true).await;
    let (s, _) = f
        .call(
            Method::PUT,
            "/api/networks/tor/bridges",
            Some(json!({"bridges": 5})),
        )
        .await;
    assert!(s.is_client_error());
}
