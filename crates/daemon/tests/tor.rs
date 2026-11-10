//! The Tor network through the engine, against a scripted control port (ADR 0037):
//! discovery, grants and revocation, the disable latch, Tor going away.

use axum::http::StatusCode;
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
        uid: Some("1000".into()),
        foreign_mntns: false,
        cwd: None,
    }
}

impl Harness {
    async fn new(sockets: Vec<ListeningSocket>) -> Self {
        Self::new_at(sockets, None).await
    }

    /// With a config file that API-made network changes are saved to.
    async fn new_at(
        sockets: Vec<ListeningSocket>,
        config_path: Option<std::path::PathBuf>,
    ) -> Self {
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
                cookie_owner: None,
                allow_remote_control: false,
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
        let state = test_app_state_at(
            engine,
            DaemonConfig {
                backends: vec![cfg],
                ..DaemonConfig::default()
            },
            config_path,
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

    /// The service id of the app's onion address (derived from its stored key).
    async fn svc(&self) -> String {
        match self.app().await.addresses.remove(0).locator {
            Locator::Onion { hostname } => hostname.trim_end_matches(".onion").to_string(),
            other => panic!("not an onion locator: {other:?}"),
        }
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
    let svc = h.svc().await;
    let key = h.state.db.onion_keys().await.unwrap()[&app.addresses[0].id].clone();
    assert!(key.starts_with("ED25519-V3:"));
    assert_eq!(
        socketguard_daemon::networks::onion_key::service_id_of_secret(&key).unwrap(),
        svc,
        "the name is derived from the stored key"
    );
    assert!(
        h.tor.commands().iter().all(|c| !c.starts_with("ADD_ONION")),
        "creating the address does not touch Tor"
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
    assert_eq!(h.tor.detached(), [svc.as_str()]);
    let add = h.tor.add_commands().pop().unwrap();
    assert!(
        add.starts_with(&format!("ADD_ONION {key} Flags=Detach,V3Auth")),
        "{add}"
    );
    assert!(add.contains("Port=8080,127.0.0.1:8080"), "{add}");
    assert!(!add.contains("5353"), "UDP is not served over Tor: {add}");
    assert!(add.contains(&format!("ClientAuthV3={TOR_KEY}")), "{add}");

    // Revoked: DEL_ONION, nothing left.
    h.revoke(&grant).await;
    assert!(h.tor.detached().is_empty());
    assert!(h
        .tor
        .commands()
        .iter()
        .any(|c| c == &format!("DEL_ONION {svc}")));

    // The same name comes back (the stored key is reused) for Anyone, without client auth.
    h.grant(Subject::Anyone).await;
    assert_eq!(h.tor.detached(), [svc.as_str()]);
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
async fn disabling_while_tor_is_down_unpublishes_once_tor_returns() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    assert_eq!(h.tor.detached().len(), 1);

    h.tor.set_down(true);
    // The latch is set even though Tor could not be reached.
    let _ = h.state.engine.read().await.disable(&h.state).await;
    h.reconcile().await;
    h.tor.set_down(false);
    h.reconcile().await;
    assert!(
        h.tor.detached().is_empty(),
        "a disabled daemon must keep removing its services until Tor confirms"
    );
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
async fn an_unreachable_tor_still_gets_its_address_and_publishes_nothing() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.tor.set_down(true);
    h.reconcile().await;
    assert_eq!(h.app().await.addresses.len(), 1, "the key is local");
    h.tor.set_down(false);
    h.reconcile().await;
    assert_eq!(h.app().await.addresses.len(), 1);
    assert!(h.tor.detached().is_empty());
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
    let svc = h.svc().await;

    h.tor.set_down(true);
    h.state
        .engine
        .read()
        .await
        .delete_app(&h.state, &app.id)
        .await
        .unwrap();
    assert!(h.state.db.onion_keys().await.unwrap().is_empty());
    assert_eq!(h.tor.detached(), [svc.as_str()], "still published");
    assert!(ledger(&h).await.tombstones.contains(&svc));

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
    assert!(!l.owned.contains(&svc), "{l:?}");
}

#[tokio::test]
async fn a_service_of_ours_whose_address_vanished_is_swept_but_foreign_ones_stay() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    h.tor.inject_service("someoneelse");
    let app = h.app().await;
    let svc = h.svc().await;
    // The address disappears behind the daemon's back (deleted while it was down).
    h.state.db.delete_app(&app.id).await.unwrap();
    assert_eq!(h.tor.detached().len(), 2);

    h.reconcile().await;
    assert!(h.tor.detached().contains(&"someoneelse".to_string()));
    assert!(!h.tor.detached().contains(&svc));
    assert!(!ledger(&h).await.owned.contains(&svc));
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

    // A create that changes what Tor must publish keeps its body and gains the field.
    let peer = h.peer(TOR_KEY).await;
    let keyed = serde_json::json!({"app_id": app.id, "subject": {"kind": "peer", "id": peer}});
    let (s, body) = call(&h, "POST", "/api/grants", Some(keyed)).await;
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

#[tokio::test]
async fn tor_down_with_nothing_to_do_does_not_make_mutations_202() {
    use axum::http::StatusCode;
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    let peer = h.peer(TOR_KEY).await;
    h.tor.set_down(true);
    h.reconcile().await;
    assert!(matches!(
        h.state.engine.read().await.networks().remove(0).status,
        NetworkStatus::Down { .. }
    ));

    let cred = serde_json::json!({"kind": "tor_client_key", "value": "FDBSRGWHBKODXLW6IWZZSNGD5AXYI3X4SRXHPQ3GIGJO7OGEDMJQ"});
    let uri = format!("/api/peers/{peer}/credentials");
    let (s, body) = call(&h, "POST", &uri, Some(cred)).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert!(body.get("enforcement").is_none());
    let (s, body) = call(&h, "DELETE", &format!("/api/peers/{peer}"), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn services_from_before_the_ledger_are_adopted_and_swept() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    let svc = h.svc().await;
    // As before the ledger existed: the service runs, nothing recorded it.
    h.tor.inject_service(&svc);
    h.state
        .db
        .set_setting("tor_owned_services", "[]")
        .await
        .unwrap();
    assert!(ledger(&h).await.owned.is_empty());

    socketguard_daemon::networks::ledger::adopt_stored_keys(&h.state.db)
        .await
        .unwrap();
    socketguard_daemon::networks::ledger::adopt_stored_keys(&h.state.db)
        .await
        .unwrap();
    assert_eq!(ledger(&h).await.owned.len(), 1);
    assert!(ledger(&h).await.owned.contains(&svc));

    // Its address goes away behind the daemon's back: the service is swept.
    let app = h.app().await;
    h.state.db.delete_app(&app.id).await.unwrap();
    h.reconcile().await;
    assert!(h.tor.detached().is_empty());
}

// ─── Networks made through the API ───────────────────────────────────────────

fn tor_file(path: &std::path::Path) {
    let doc = serde_json::json!({"backends": [{
        "id": "tor", "type": "tor", "control": "127.0.0.1:19051",
        "cookie_path": "/var/lib/tor/control_auth_cookie"
    }]});
    std::fs::write(path, doc.to_string()).unwrap();
}

#[tokio::test]
async fn the_api_makes_a_tor_network_only_with_default_or_configured_settings() {
    let dir = std::env::temp_dir().join(format!("sg-tor-api-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("socketguard.json");
    tor_file(&file);
    let h = Harness::new_at(vec![], Some(file.clone())).await;
    let (s, body) = call(&h, "DELETE", "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    // The removal rewrote the file's list; the administrator puts the entry back.
    tor_file(&file);

    // A caller steering the control endpoint or its trust is refused ...
    for bad in [
        serde_json::json!({"type": "tor", "control": "unix:/tmp/x", "auth": "none"}),
        serde_json::json!({"type": "tor", "auth": "none"}),
        serde_json::json!({"type": "tor", "auth": "cookie_insecure"}),
        serde_json::json!({"type": "tor", "auth": {"password": "pw"}}),
        serde_json::json!({"type": "tor", "cookie_path": "/tmp/cookie"}),
        serde_json::json!({"type": "tor", "cookie_dir": "/tmp"}),
        serde_json::json!({"type": "tor", "control": "127.0.0.1:9999"}),
        serde_json::json!({"type": "tor", "expect_tor_uid": 0}),
        serde_json::json!({"type": "tor", "control": "10.0.0.1:9051", "allow_remote_control": true}),
        // The file's entry with one setting changed.
        serde_json::json!({"type": "tor", "control": "127.0.0.1:19051",
            "cookie_path": "/var/lib/tor/control_auth_cookie", "cookie_dir": "/tmp"}),
    ] {
        let (s, body) = call(&h, "POST", "/api/networks", Some(bad.clone())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert_eq!(body["code"], "invalid");
    }
    assert!(h.state.engine.read().await.networks().is_empty());

    // ... what the config file already has is accepted ...
    let configured = serde_json::json!({
        "type": "tor", "control": "127.0.0.1:19051",
        "cookie_path": "/var/lib/tor/control_auth_cookie"
    });
    let (s, body) = call(&h, "POST", "/api/networks", Some(configured)).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let (s, _) = call(&h, "DELETE", "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    // ... and so are the defaults.
    let default = serde_json::json!({"type": "tor"});
    let (s, body) = call(&h, "POST", "/api/networks", Some(default)).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    std::fs::remove_dir_all(dir).ok();

    // Without a config file only the defaults qualify.
    let h = Harness::new(vec![]).await;
    call(&h, "DELETE", "/api/networks/tor", None).await;
    let custom = serde_json::json!({"type": "tor", "control": "127.0.0.1:19051"});
    let (s, _) = call(&h, "POST", "/api/networks", Some(custom)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_remote_control_address_is_refused_when_the_network_is_made() {
    use socketguard_daemon::networks;
    let tor = |addr: &str, allow: bool| BackendConfig::Tor {
        control: addr.into(),
        auth: TorAuth::Cookie,
        cookie_path: None,
        cookie_dir: None,
        expect_tor_uid: None,
        cookie_owner: None,
        allow_remote_control: allow,
    };
    let net: Arc<dyn socketguard_daemon::network::NetworkInterface> =
        Arc::new(MockNetworkInterface::new(Arc::new(Mutex::new(vec![]))));
    let err = networks::create(&tor("10.0.0.1:9051", false), [0; 5], net.clone())
        .err()
        .unwrap();
    assert!(err.to_string().contains("allow_remote_control"), "{err:#}");
    assert!(networks::create(&tor("10.0.0.1:9051", true), [0; 5], net.clone()).is_ok());
    assert!(networks::create(&tor("localhost:9051", false), [0; 5], net).is_ok());
}

// ─── Removing the network ────────────────────────────────────────────────────

#[tokio::test]
async fn removing_the_network_removes_the_services_first() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    let svc = h.svc().await;
    assert_eq!(h.tor.detached(), [svc.as_str()]);

    let (s, body) = call(&h, "DELETE", "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert!(h.tor.detached().is_empty());
    assert!(h.tor.commands().contains(&format!("DEL_ONION {svc}")));
    assert!(h.state.engine.read().await.networks().is_empty());
    assert_eq!(ledger(&h).await, Default::default());
}

#[tokio::test]
async fn removing_the_network_while_tor_is_down_is_refused_unless_forced() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    h.tor.set_down(true);

    let (s, body) = call(&h, "DELETE", "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "conflict");
    assert!(
        body["message"].as_str().unwrap().contains("--force"),
        "{body}"
    );
    // Nothing was removed: the network, its address and the service are all still there.
    assert_eq!(h.state.engine.read().await.networks().len(), 1);
    assert_eq!(h.app().await.addresses.len(), 1);
    assert_eq!(h.tor.detached().len(), 1);
    assert!(!ledger(&h).await.owned.is_empty());

    // Retrying when Tor is back works.
    h.tor.set_down(false);
    let (s, body) = call(&h, "DELETE", "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert!(h.tor.detached().is_empty());
}

#[tokio::test]
async fn a_forced_removal_goes_ahead_without_tor() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    h.tor.set_down(true);
    let (s, body) = call(&h, "DELETE", "/api/networks/tor?force=true", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert!(h.state.engine.read().await.networks().is_empty());
}

#[tokio::test]
async fn pending_tombstones_block_a_removal_with_tor_down() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    h.tor.set_down(true);
    let id = h.app().await.id;
    let (s, _) = call(&h, "DELETE", &format!("/api/apps/{id}"), None).await;
    assert!(s.is_success());
    assert!(!ledger(&h).await.tombstones.is_empty());

    let (s, body) = call(&h, "DELETE", "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(!ledger(&h).await.tombstones.is_empty(), "still recorded");
    h.tor.set_down(false);
    let (s, body) = call(&h, "DELETE", "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert!(h.tor.detached().is_empty());
    assert!(ledger(&h).await.tombstones.is_empty());
}

#[tokio::test]
async fn removing_a_network_with_nothing_published_needs_no_tor() {
    let h = Harness::new(vec![]).await;
    h.tor.set_down(true);
    let (s, body) = call(&h, "DELETE", "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
}
