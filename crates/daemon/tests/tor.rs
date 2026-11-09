//! The Tor network through the engine, against a scripted control port (ADR 0037):
//! discovery, grants and revocation, the disable latch, Tor going away.

use socketguard_core::config::{BackendConfig, BackendInstanceConfig, DaemonConfig, TorAuth};
use socketguard_core::{
    CredentialKind, ListeningSocket, Locator, NetworkKind, NetworkStatus, NewCredential, NewGrant,
    Protocol, Subject,
};
use socketguard_daemon::engine::{ActiveBackend, Engine};
use socketguard_daemon::networks::tor::TorNetwork;
use socketguard_daemon::test_support::*;
use socketguard_daemon::AppState;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TOR_KEY: &str = "ZGBMJ4VIRNVUOQ5SJ2JXPSSWHB2R4YGTKPDGSMZ4HWCD5WLT2YKQ";

struct Harness {
    state: Arc<AppState>,
    tor: MockTorControl,
    fw: Arc<MockFirewall>,
}

fn socket(port: u16, protocol: Protocol, bind: &str) -> ListeningSocket {
    ListeningSocket {
        pid: 1,
        process_name: "webapp".into(),
        port,
        protocol,
        bind_address: bind.parse::<IpAddr>().unwrap(),
        exe_path: Some("/usr/bin/webapp".into()),
        cmdline: Some(vec!["webapp".into()]),
    }
}

impl Harness {
    async fn new(sockets: Vec<ListeningSocket>) -> Self {
        let tor = MockTorControl::start();
        let fw = Arc::new(MockFirewall::new(Arc::new(Mutex::new(vec![]))));
        let cfg = BackendInstanceConfig {
            id: "tor".into(),
            backend: BackendConfig::Tor {
                control: tor.addr(),
                auth: TorAuth::None,
                cookie_path: None,
                cookie_dir: None,
                expect_tor_uid: None,
            },
        };
        let mut backends = HashMap::new();
        backends.insert(
            "tor".to_string(),
            ActiveBackend {
                config: cfg.clone(),
                network: Arc::new(TorNetwork::with_options(
                    &tor.addr(),
                    tor.auth_options(),
                    Duration::ZERO,
                )),
            },
        );
        let engine = Engine::new_injectable(
            Box::new(MockSocketMonitor::new(sockets)),
            fw.clone(),
            Arc::new(MockNetworkInterface::new(Arc::new(Mutex::new(vec![])))),
            backends,
            vec!["tor".into()],
        );
        let state = test_app_state(
            engine,
            DaemonConfig {
                backends: vec![cfg],
                ..DaemonConfig::default()
            },
        )
        .await;
        Self { state, tor, fw }
    }

    async fn reconcile(&self) {
        let mut engine = self.state.engine.write().await;
        engine.reconcile(&self.state).await.unwrap();
    }

    async fn app(&self) -> socketguard_core::App {
        self.state.db.list_apps().await.unwrap().remove(0)
    }

    async fn peer(&self, key: &str) -> String {
        self.state
            .engine
            .read()
            .await
            .create_peer(
                &self.state,
                "bnode",
                &[NewCredential {
                    kind: CredentialKind::TorClientKey,
                    value: key.into(),
                    label: None,
                }],
            )
            .await
            .unwrap()
            .id
    }

    async fn grant(&self, subject: Subject) -> String {
        let app = self.app().await;
        self.state
            .engine
            .read()
            .await
            .create_grant(
                &self.state,
                &NewGrant {
                    app_id: app.id,
                    port: None,
                    network_id: None,
                    subject,
                    confirm_open: true,
                },
            )
            .await
            .unwrap()
            .grant
            .id
    }

    async fn revoke(&self, id: &str) {
        self.state
            .engine
            .read()
            .await
            .delete_grant(&self.state, id)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn discovery_grant_and_revoke_drive_the_control_port() {
    let h = Harness::new(vec![
        socket(8080, Protocol::Tcp, "0.0.0.0"),
        socket(5353, Protocol::Udp, "0.0.0.0"),
    ])
    .await;
    h.reconcile().await;

    // Discovery: an onion address with a stored key, and nothing published.
    let app = h.app().await;
    assert_eq!(app.addresses.len(), 1);
    assert_eq!(
        app.addresses[0].locator,
        Locator::Onion {
            hostname: "mocksvc1.onion".into()
        }
    );
    assert_eq!(
        h.state.db.onion_keys().await.unwrap()[&app.addresses[0].id],
        "ED25519-V3:mocksvc1"
    );
    assert!(h.tor.detached().is_empty(), "closed without a grant");
    let net = h.state.engine.read().await.networks().remove(0);
    assert_eq!(net.kind, NetworkKind::Tor);
    assert_eq!(net.interface, None);
    assert_eq!(net.status, NetworkStatus::Up);
    // Nothing for the firewall to do with it.
    assert!(applied(&h.fw.calls)
        .iter()
        .all(|r| r.rules.is_empty() && r.scopes.is_empty()));

    // A grant to a peer with a Tor key publishes the service for that key.
    let peer = h.peer(TOR_KEY).await;
    let grant = h.grant(Subject::Peer(peer)).await;
    assert_eq!(h.tor.detached(), ["mocksvc1"]);
    let add = h.tor.add_commands().pop().unwrap();
    assert!(
        add.starts_with("ADD_ONION ED25519-V3:mocksvc1 Flags=Detach,V3Auth"),
        "{add}"
    );
    assert!(add.contains("Port=8080,127.0.0.1:8080"), "{add}");
    assert!(!add.contains("5353"), "UDP is not served over Tor: {add}");
    assert!(add.contains(&format!("ClientAuthV3={TOR_KEY}")), "{add}");

    // Revoked: DEL_ONION, nothing left.
    h.revoke(&grant).await;
    assert!(h.tor.detached().is_empty());
    assert!(h.tor.commands().iter().any(|c| c == "DEL_ONION mocksvc1"));

    // The same name comes back (the stored key is reused) for Anyone, without client auth.
    h.grant(Subject::Anyone).await;
    assert_eq!(h.tor.detached(), ["mocksvc1"]);
    assert!(!h.tor.add_commands().pop().unwrap().contains("ClientAuthV3"));
}

#[tokio::test]
async fn targets_follow_the_listener_bind_address() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "192.168.1.5")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    let add = h.tor.add_commands().pop().unwrap();
    assert!(add.contains("Port=8080,192.168.1.5:8080"), "{add}");
}

#[tokio::test]
async fn disable_removes_services_and_nothing_comes_back_until_enable() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    assert_eq!(h.tor.detached().len(), 1);

    h.state.engine.read().await.disable(&h.state).await.unwrap();
    assert!(h.tor.detached().is_empty());
    h.reconcile().await;
    h.reconcile().await;
    assert!(h.tor.detached().is_empty(), "the latch holds");

    h.state.engine.read().await.enable(&h.state).await.unwrap();
    assert_eq!(h.tor.detached().len(), 1);
}

#[tokio::test]
async fn services_return_after_tor_restarts_and_tor_down_is_a_status() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    assert_eq!(h.tor.detached().len(), 1);

    h.tor.forget_services();
    h.reconcile().await;
    assert_eq!(h.tor.detached().len(), 1, "re-added by the next check");

    h.tor.set_down(true);
    h.reconcile().await;
    let net = h.state.engine.read().await.networks().remove(0);
    assert!(matches!(net.status, NetworkStatus::Down { .. }), "{net:?}");
    h.tor.set_down(false);
    h.tor.forget_services();
    h.reconcile().await;
    let net = h.state.engine.read().await.networks().remove(0);
    assert_eq!(net.status, NetworkStatus::Up);
    assert_eq!(h.tor.detached().len(), 1);
}

#[tokio::test]
async fn deleting_the_app_removes_its_service() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    let app = h.app().await;
    h.state
        .engine
        .read()
        .await
        .delete_app(&h.state, &app.id)
        .await
        .unwrap();
    assert!(h.tor.detached().is_empty());
    assert!(h.state.db.onion_keys().await.unwrap().is_empty());
}

#[tokio::test]
async fn an_unreachable_tor_creates_no_address_and_is_retried() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.tor.set_down(true);
    h.reconcile().await;
    assert!(h.app().await.addresses.is_empty());
    h.tor.set_down(false);
    h.reconcile().await;
    assert_eq!(h.app().await.addresses.len(), 1);
}

// ─── Revocation must not fail open ───────────────────────────────────────────

async fn ledger(h: &Harness) -> socketguard_daemon::networks::ledger::Ledger {
    socketguard_daemon::networks::ledger::load(&h.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn revoking_while_tor_is_down_completes_when_it_returns() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    let grant = h.grant(Subject::Anyone).await;
    assert_eq!(h.tor.detached().len(), 1);

    h.tor.set_down(true);
    h.revoke(&grant).await; // the grant is gone from the database ...
    assert!(h.state.db.list_grants().await.unwrap().is_empty());
    assert_eq!(h.tor.detached().len(), 1, "... but the service still runs");
    let pending = h.state.engine.read().await.enforcement_pending();
    assert!(pending.is_some(), "the caller is told");

    h.reconcile().await; // still down: still pending
    assert_eq!(h.tor.detached().len(), 1);
    h.tor.set_down(false);
    h.reconcile().await;
    assert!(h.tor.detached().is_empty(), "retried until it worked");
    assert!(h.state.engine.read().await.enforcement_pending().is_none());
}

#[tokio::test]
async fn an_app_deleted_while_tor_is_down_is_tombstoned_and_swept() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    let app = h.app().await;

    h.tor.set_down(true);
    h.state
        .engine
        .read()
        .await
        .delete_app(&h.state, &app.id)
        .await
        .unwrap();
    assert!(h.state.db.onion_keys().await.unwrap().is_empty());
    assert_eq!(h.tor.detached(), ["mocksvc1"], "still published");
    assert!(ledger(&h).await.tombstones.contains("mocksvc1"));

    h.tor.set_down(false);
    h.state
        .engine
        .write()
        .await
        .reconcile(&h.state)
        .await
        .unwrap();
    assert!(h.tor.detached().is_empty());
    let l = ledger(&h).await;
    assert!(l.tombstones.is_empty(), "{l:?}");
    assert!(!l.owned.contains("mocksvc1"), "{l:?}");
}

#[tokio::test]
async fn a_service_of_ours_whose_address_vanished_is_swept_but_foreign_ones_stay() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    h.tor.inject_service("someoneelse");
    let app = h.app().await;
    // The address disappears behind the daemon's back (deleted while it was down).
    h.state.db.delete_app(&app.id).await.unwrap();
    assert_eq!(h.tor.detached().len(), 2);

    h.reconcile().await;
    assert!(h.tor.detached().contains(&"someoneelse".to_string()));
    assert!(!h.tor.detached().contains(&"mocksvc1".to_string()));
    assert!(!ledger(&h).await.owned.contains("mocksvc1"));
}

// ─── The API says when enforcement is pending ────────────────────────────────

async fn call(
    h: &Harness,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    let body = match body {
        Some(b) => axum::body::Body::from(b.to_string()),
        None => axum::body::Body::empty(),
    };
    req = req.header("accept", "application/json");
    let resp = socketguard_daemon::api::router(h.state.clone())
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn mutations_answer_202_while_enforcement_is_pending() {
    use axum::http::StatusCode;
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    let app = h.app().await;
    let new_grant = serde_json::json!({
        "app_id": app.id, "subject": {"kind": "anyone"}, "confirm_open": true
    });

    // Healthy: the usual 201 and 204, no enforcement field.
    let (s, body) = call(&h, "POST", "/api/grants", Some(new_grant.clone())).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert!(body.get("enforcement").is_none());
    let id = body["id"].as_str().unwrap().to_string();

    // Tor down: the revocation is saved, the answer is 202 with the notice.
    h.tor.set_down(true);
    let (s, body) = call(&h, "DELETE", &format!("/api/grants/{id}"), None).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["enforcement"]["status"], "pending");
    assert!(body["enforcement"]["message"]
        .as_str()
        .unwrap()
        .contains("tor"));
    assert!(h.state.db.list_grants().await.unwrap().is_empty());

    // A create keeps its body and gains the field.
    let (s, body) = call(&h, "POST", "/api/grants", Some(new_grant)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    assert!(body["id"].is_string());
    assert_eq!(body["enforcement"]["status"], "pending");

    // Back up: after the retry, plain success again.
    h.tor.set_down(false);
    h.reconcile().await;
    let (s, _) = call(&h, "DELETE", "/api/peers/none", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let id = h.state.db.list_grants().await.unwrap().remove(0).id;
    let (s, body) = call(&h, "DELETE", &format!("/api/grants/{id}"), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
}
