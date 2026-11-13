//! The Tor network through the engine, against a scripted control port (ADR 0037):
//! discovery, grants and revocation, the disable latch, Tor going away.

mod common;

use axum::http::{Method, StatusCode};
use socketguard_core::config::{BackendConfig, BackendInstanceConfig, DaemonConfig};
use socketguard_core::{
    CredentialKind, ListeningSocket, Locator, NetworkKind, NetworkStatus, NewCredential, NewGrant,
    Protocol, Scope, Subject, Target,
};
use socketguard_daemon::api;
use socketguard_daemon::engine::{ActiveBackend, Engine};
use socketguard_daemon::networks::tor::TorNetwork;
use socketguard_daemon::networks::tor_child::TorChild;
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
        protocol,
        bind_address: bind.parse::<IpAddr>().unwrap(),
        ..common::listener("webapp", port)
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
            backend: BackendConfig::tor(),
        };
        let mut backends = HashMap::new();
        backends.insert(
            "tor".to_string(),
            ActiveBackend {
                config: cfg.clone(),
                network: Arc::new(TorNetwork::new(
                    TorChild::with_control(tor.addr(), tor.auth_options()),
                    Duration::ZERO,
                )),
            },
        );
        let engine = Engine::new_injectable(
            Box::new(MockSocketMonitor::new(sockets)),
            fw.clone(),
            Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
            backends,
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
        let engine = self.state.engine.read().await;
        engine.reconcile(&self.state).await.unwrap();
    }

    async fn app(&self) -> socketguard_core::App {
        self.state.db.list_apps().await.unwrap().remove(0)
    }

    /// The service id of the app's onion address. An address exists only once a grant
    /// names the row, so this names it with a grant to an empty group, which lets nobody
    /// in and publishes nothing.
    async fn svc(&self) -> String {
        if self.state.db.list_addresses().await.unwrap().is_empty() {
            let group = self
                .state
                .engine
                .read()
                .await
                .create_group(&self.state, "ghosts", &[])
                .await
                .unwrap();
            self.grant(Subject::Group(group.id)).await;
        }
        match self
            .state
            .db
            .list_addresses()
            .await
            .unwrap()
            .remove(0)
            .locator
        {
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
                    target: Target::App(app.id),
                    scope: Scope::All,
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
    assert!(h.state.db.list_addresses().await.unwrap().is_empty());
    let svc = h.svc().await;
    let addresses = h.state.db.list_addresses().await.unwrap();
    assert_eq!(addresses.len(), 1, "named by a grant that lets nobody in");
    let key = h.state.db.onion_keys().await.unwrap()[&addresses[0].id].clone();
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
    // A few failed checks in a row before the network says down (the child is up).
    for _ in 0..4 {
        h.reconcile().await;
    }
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
    h.svc().await;
    assert_eq!(
        h.state.db.list_addresses().await.unwrap().len(),
        1,
        "the key is local"
    );
    h.tor.set_down(false);
    h.reconcile().await;
    assert_eq!(h.state.db.list_addresses().await.unwrap().len(), 1);
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

/// A request through the API router of the harness's daemon.
async fn call(
    h: &Harness,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    common::call(&api::router(h.state.clone()), method, uri, body).await
}

#[tokio::test]
async fn mutations_answer_202_while_enforcement_is_pending() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    let app = h.app().await;
    let new_grant = serde_json::json!({
        "target": {"kind": "app", "id": app.id}, "subject": {"kind": "anyone"}, "confirm_open": true
    });

    // Healthy: the usual 201 and 204, no enforcement field.
    let (s, body) = call(&h, Method::POST, "/api/grants", Some(new_grant.clone())).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert!(body.get("enforcement").is_none());
    let id = body["id"].as_str().unwrap().to_string();

    // Tor down: the revocation is saved, the answer is 202 with the notice.
    h.tor.set_down(true);
    let (s, body) = call(&h, Method::DELETE, &format!("/api/grants/{id}"), None).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["enforcement"]["status"], "pending");
    assert!(body["enforcement"]["message"]
        .as_str()
        .unwrap()
        .contains("tor"));
    assert!(h.state.db.list_grants().await.unwrap().is_empty());

    // A create that changes what Tor must publish keeps its body and gains the field.
    let peer = h.peer(TOR_KEY).await;
    let keyed = serde_json::json!({"target": {"kind": "app", "id": app.id}, "subject": {"kind": "peer", "id": peer}});
    let (s, body) = call(&h, Method::POST, "/api/grants", Some(keyed)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    assert!(body["id"].is_string());
    assert_eq!(body["enforcement"]["status"], "pending");

    // Back up: after the retry, plain success again.
    h.tor.set_down(false);
    h.reconcile().await;
    let (s, _) = call(&h, Method::DELETE, "/api/peers/none", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let id = h.state.db.list_grants().await.unwrap().remove(0).id;
    let (s, body) = call(&h, Method::DELETE, &format!("/api/grants/{id}"), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn tor_down_with_nothing_to_do_does_not_make_mutations_202() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    let peer = h.peer(TOR_KEY).await;
    h.tor.set_down(true);
    for _ in 0..4 {
        h.reconcile().await;
    }
    assert!(matches!(
        h.state.engine.read().await.networks().remove(0).status,
        NetworkStatus::Down { .. }
    ));

    let cred = serde_json::json!({"kind": "tor_client_key", "value": "FDBSRGWHBKODXLW6IWZZSNGD5AXYI3X4SRXHPQ3GIGJO7OGEDMJQ"});
    let uri = format!("/api/peers/{peer}/credentials");
    let (s, body) = call(&h, Method::POST, &uri, Some(cred)).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert!(body.get("enforcement").is_none());
    let (s, body) = call(&h, Method::DELETE, &format!("/api/peers/{peer}"), None).await;
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

// ─── Removing the network ────────────────────────────────────────────────────

#[tokio::test]
async fn removing_the_network_removes_the_services_first() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    let svc = h.svc().await;
    assert_eq!(h.tor.detached(), [svc.as_str()]);

    let (s, body) = call(&h, Method::DELETE, "/api/networks/tor", None).await;
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

    let (s, body) = call(&h, Method::DELETE, "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "conflict");
    assert!(
        body["message"].as_str().unwrap().contains("--force"),
        "{body}"
    );
    // Nothing was removed: the network, its address and the service are all still there.
    assert_eq!(h.state.engine.read().await.networks().len(), 1);
    assert_eq!(h.state.db.list_addresses().await.unwrap().len(), 1);
    assert_eq!(h.tor.detached().len(), 1);
    assert!(!ledger(&h).await.owned.is_empty());

    // Retrying when Tor is back works.
    h.tor.set_down(false);
    let (s, body) = call(&h, Method::DELETE, "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert!(h.tor.detached().is_empty());
}

#[tokio::test]
async fn a_forced_removal_goes_ahead_without_tor() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    h.grant(Subject::Anyone).await;
    h.tor.set_down(true);
    let (s, body) = call(&h, Method::DELETE, "/api/networks/tor?force=true", None).await;
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
    let (s, _) = call(&h, Method::DELETE, &format!("/api/apps/{id}"), None).await;
    assert!(s.is_success());
    assert!(!ledger(&h).await.tombstones.is_empty());

    let (s, body) = call(&h, Method::DELETE, "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(!ledger(&h).await.tombstones.is_empty(), "still recorded");
    h.tor.set_down(false);
    let (s, body) = call(&h, Method::DELETE, "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert!(h.tor.detached().is_empty());
    assert!(ledger(&h).await.tombstones.is_empty());
}

#[tokio::test]
async fn removing_a_network_with_nothing_published_needs_no_tor() {
    let h = Harness::new(vec![]).await;
    h.tor.set_down(true);
    let (s, body) = call(&h, Method::DELETE, "/api/networks/tor", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
}

// ─── Generated client keys and share (ADR 0045) ──────────────────────────────

#[tokio::test]
async fn a_generated_tor_key_authorizes_the_peer_and_share_hands_out_the_client_line() {
    let h = Harness::new(vec![socket(8080, Protocol::Tcp, "::")]).await;
    h.reconcile().await;
    let app = h.app().await;
    let svc = h.svc().await;
    // A peer with no credentials; pasted keys have no private half to share.
    let (s, peer) = call(
        &h,
        Method::POST,
        "/api/peers",
        Some(serde_json::json!({"label": "bnode"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{peer}");
    let peer_id = peer["id"].as_str().unwrap().to_string();
    let pasted = serde_json::json!({"kind": "tor_client_key", "value": TOR_KEY});
    call(
        &h,
        Method::POST,
        &format!("/api/peers/{peer_id}/credentials"),
        Some(pasted),
    )
    .await;

    let (s, key) = call(
        &h,
        Method::POST,
        &format!("/api/peers/{peer_id}/tor-key"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{key}");
    let public = key["credential"]["value"].as_str().unwrap().to_string();
    let private = key["private_key"].as_str().unwrap().to_string();
    assert_eq!((public.len(), private.len()), (52, 52));
    assert_eq!(key["credential"]["kind"], "tor_client_key");

    // Granted: the service is published for the generated key (and the pasted one).
    let peer_grant = h.grant(Subject::Peer(peer_id.clone())).await;
    h.reconcile().await;
    let add = h.tor.add_commands().join("\n");
    assert!(
        add.contains(&public),
        "the generated key is authorized: {add}"
    );

    // share: one line for the generated key, none for the pasted one.
    let (s, share) = call(
        &h,
        Method::GET,
        &format!("/api/apps/{}/share", app.id),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{share}");
    let tor = share["tor"].as_array().unwrap();
    assert_eq!(tor.len(), 1, "{share}");
    assert_eq!(
        tor[0]["auth_private"],
        format!("{svc}:descriptor:x25519:{private}")
    );
    assert_eq!(tor[0]["hostname"], format!("{svc}.onion"));
    assert_eq!(tor[0]["peer_label"], "bnode");

    // Regenerating replaces the key: the old one stops being authorized, the pasted stays.
    let (s, again) = call(
        &h,
        Method::POST,
        &format!("/api/peers/{peer_id}/tor-key"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_ne!(again["private_key"], key["private_key"]);
    let (_, peer) = call(&h, Method::GET, &format!("/api/peers/{peer_id}"), None).await;
    let values: Vec<_> = peer["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["value"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(values.len(), 2);
    assert!(values.contains(&TOR_KEY.to_string()));
    assert!(!values.contains(&public), "the old generated key is gone");
    let (_, share) = call(
        &h,
        Method::GET,
        &format!("/api/apps/{}/share", app.id),
        None,
    )
    .await;
    assert_eq!(
        share["tor"][0]["auth_private"],
        format!(
            "{svc}:descriptor:x25519:{}",
            again["private_key"].as_str().unwrap()
        )
    );

    // A peer without a grant gets no line; unknown peers and apps are 404.
    h.revoke(&peer_grant).await;
    let (_, share) = call(
        &h,
        Method::GET,
        &format!("/api/apps/{}/share", app.id),
        None,
    )
    .await;
    assert_eq!(share["tor"], serde_json::json!([]));
    let (s, _) = call(&h, Method::POST, "/api/peers/nope/tor-key", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&h, Method::GET, "/api/apps/nope/share", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// ─── Reservations on Tor (ADR 0047): opened as a whole ──────────────────────────

use socketguard_core::BindingTarget;
use socketguard_daemon::networks::tor_client_key;

struct Web {
    h: Harness,
    ssh: String,
    nginx: String,
    rid: String,
}

fn tcp_socket(name: &str, port: u16) -> ListeningSocket {
    ListeningSocket {
        bind_address: "0.0.0.0".parse().unwrap(),
        ..common::listener(name, port)
    }
}

/// A reservation "web" over sshd:22 and nginx:443, nothing granted yet.
async fn web() -> Web {
    let h = Harness::new(vec![tcp_socket("sshd", 22), tcp_socket("nginx", 443)]).await;
    h.reconcile().await;
    let apps = h.state.db.list_apps().await.unwrap();
    let id_of = |n: &str| {
        apps.iter()
            .find(|a| a.process_name == n)
            .unwrap()
            .id
            .clone()
    };
    let (ssh, nginx) = (id_of("sshd"), id_of("nginx"));
    let rid = h
        .state
        .engine
        .read()
        .await
        .create_reservation(
            &h.state,
            "web",
            vec![
                BindingTarget::App {
                    app_id: ssh.clone(),
                    scope: Scope::All,
                },
                BindingTarget::App {
                    app_id: nginx.clone(),
                    scope: Scope::All,
                },
            ],
            false,
        )
        .await
        .unwrap()
        .reservation
        .id;
    Web { h, ssh, nginx, rid }
}

impl Web {
    async fn peer(&self, label: &str) -> (String, String) {
        let key = tor_client_key::generate();
        let peer = self
            .h
            .state
            .engine
            .read()
            .await
            .create_peer(
                &self.h.state,
                label,
                &[NewCredential {
                    kind: CredentialKind::TorClientKey,
                    value: key.public.clone(),
                    label: None,
                }],
            )
            .await
            .unwrap();
        (peer.id, key.public)
    }

    async fn grant(&self, target: Target, scope: Scope, subject: Subject) -> String {
        self.h
            .state
            .engine
            .read()
            .await
            .create_grant(
                &self.h.state,
                &NewGrant {
                    target,
                    scope,
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

    /// The hostname of the reservation's onion address, if it has one.
    async fn reserved_onion(&self) -> Option<String> {
        self.h
            .state
            .db
            .list_addresses()
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.reservation_id.as_deref() == Some(self.rid.as_str()))
            .and_then(|a| match a.locator {
                Locator::Onion { hostname } => {
                    Some(hostname.trim_end_matches(".onion").to_string())
                }
                _ => None,
            })
    }

    async fn reach_note(&self, grant_id: &str) -> (socketguard_core::Reach, Option<String>) {
        let g = self
            .h
            .state
            .engine
            .read()
            .await
            .get_grant(&self.h.state, grant_id)
            .await
            .unwrap();
        let r = &g.reach[0];
        (r.reach, r.note.clone())
    }
}

#[tokio::test]
async fn a_client_granted_one_bound_row_is_not_admitted_on_tor() {
    let w = web().await;
    let (bob, _bob_key) = w.peer("bob").await;
    let g = w
        .grant(Target::App(w.nginx.clone()), Scope::All, Subject::Peer(bob))
        .await;
    // Nothing is published, no onion address of the reservation or of the row exists.
    assert!(w.h.tor.detached().is_empty());
    assert!(w.reserved_onion().await.is_none());
    let onions: Vec<_> =
        w.h.state
            .db
            .list_addresses()
            .await
            .unwrap()
            .into_iter()
            .filter(|a| matches!(a.locator, Locator::Onion { .. }))
            .collect();
    assert!(
        onions
            .iter()
            .all(|a| a.app_id.as_deref() != Some(w.nginx.as_str())),
        "a bound row has no onion of its own"
    );
    let (reach, note) = w.reach_note(&g).await;
    assert_eq!(reach, socketguard_core::Reach::NotReachable);
    assert_eq!(
        note.as_deref(),
        Some("bound to reservation web: on Tor grant the reservation as a whole")
    );
}

#[tokio::test]
async fn holding_every_row_through_row_grants_still_does_not_admit_on_tor() {
    let w = web().await;
    let (carol, _) = w.peer("carol").await;
    w.grant(
        Target::App(w.ssh.clone()),
        Scope::All,
        Subject::Peer(carol.clone()),
    )
    .await;
    w.grant(
        Target::App(w.nginx.clone()),
        Scope::All,
        Subject::Peer(carol),
    )
    .await;
    assert!(w.h.tor.detached().is_empty());
    assert!(w.reserved_onion().await.is_none());
}

#[tokio::test]
async fn a_grant_on_the_reservation_publishes_every_bound_port_for_its_client_only() {
    let w = web().await;
    let (alice, alice_key) = w.peer("alice").await;
    let (bob, bob_key) = w.peer("bob").await;
    w.grant(Target::App(w.nginx.clone()), Scope::All, Subject::Peer(bob))
        .await;
    w.grant(
        Target::Reservation(w.rid.clone()),
        Scope::All,
        Subject::Peer(alice),
    )
    .await;
    let svc = w
        .reserved_onion()
        .await
        .expect("the reservation has an onion address");
    assert_eq!(w.h.tor.detached(), [svc.as_str()]);
    let add = w.h.tor.add_commands().pop().unwrap();
    assert!(add.contains("Port=22,"), "{add}");
    assert!(add.contains("Port=443,"), "{add}");
    assert!(add.contains(&format!("ClientAuthV3={alice_key}")), "{add}");
    assert!(!add.contains(&bob_key), "a row grant does not count: {add}");
}

#[tokio::test]
async fn a_peer_group_granted_on_the_reservation_admits_every_member_key() {
    let w = web().await;
    let (a, a_key) = w.peer("a").await;
    let (b, b_key) = w.peer("b").await;
    let group =
        w.h.state
            .engine
            .read()
            .await
            .create_group(&w.h.state, "team", &[a, b])
            .await
            .unwrap();
    w.grant(
        Target::Reservation(w.rid.clone()),
        Scope::All,
        Subject::Group(group.id),
    )
    .await;
    let add = w.h.tor.add_commands().pop().unwrap();
    assert!(add.contains(&format!("ClientAuthV3={a_key}")), "{add}");
    assert!(add.contains(&format!("ClientAuthV3={b_key}")), "{add}");
}

#[tokio::test]
async fn an_unbound_row_keeps_its_own_onion_and_a_dangling_grant_publishes_nothing() {
    // An app outside any reservation: the grant names the row and the address exists, but
    // with nobody to admit nothing is published (`up` is false).
    let h = Harness::new(vec![tcp_socket("solo", 8080)]).await;
    h.reconcile().await;
    let app = h.app().await;
    let group = h
        .state
        .engine
        .read()
        .await
        .create_group(&h.state, "nobody", &[])
        .await
        .unwrap();
    h.grant(Subject::Group(group.id)).await;
    let addresses = h.state.db.list_addresses().await.unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].app_id.as_deref(), Some(app.id.as_str()));
    assert!(h.tor.detached().is_empty());
    let views = h
        .state
        .engine
        .read()
        .await
        .list_addresses(&h.state)
        .await
        .unwrap();
    assert!(!views[0].up, "not published, so not up");
}

// ─── Freeing a row from a reservation can open it to Anyone on Tor ──────────────

use socketguard_core::api_types::{ChangeOp, ChangesRequest, ChangesResponse};
use socketguard_core::Reach;
use socketguard_daemon::engine::EngineError;

fn confirmation_required<T>(r: &Result<T, EngineError>) -> bool {
    matches!(r, Err(EngineError::ConfirmationRequired))
}

impl Web {
    /// The reach the dry run of `op` reports, and whether it opens to Anyone.
    async fn dry_run(&self, op: ChangeOp) -> Result<ChangesResponse, EngineError> {
        let engine = self.h.state.engine.read().await;
        engine
            .apply_changes(
                &self.h.state,
                &ChangesRequest {
                    ops: vec![op],
                    dry_run: true,
                },
            )
            .await
    }

    async fn binding_of(&self, app: &str) -> String {
        let view = self
            .h
            .state
            .engine
            .read()
            .await
            .get_reservation(&self.h.state, &self.rid)
            .await
            .unwrap();
        view.reservation
            .bindings
            .into_iter()
            .find(|b| matches!(&b.target, BindingTarget::App { app_id, .. } if app_id == app))
            .unwrap()
            .id
    }
}

fn release_op(rid: &str, confirm_open: bool) -> ChangeOp {
    ChangeOp::ReleaseReservation {
        reservation_id: rid.to_string(),
        confirm_open,
    }
}

#[tokio::test]
async fn releasing_a_reservation_that_hides_an_anyone_grant_on_tor_needs_confirmation() {
    let w = web().await;
    // Inert on Tor while nginx is bound; releasing frees nginx and its own onion address
    // is published to Anyone.
    w.grant(Target::App(w.nginx.clone()), Scope::All, Subject::Anyone)
        .await;
    assert!(w.h.tor.add_commands().is_empty());
    let engine = w.h.state.engine.read().await;
    let refused = engine.release_reservation(&w.h.state, &w.rid, false).await;
    assert!(confirmation_required(&refused), "{refused:?}");
    assert!(w.h.tor.add_commands().is_empty(), "nothing was published");
    assert!(engine.get_reservation(&w.h.state, &w.rid).await.is_ok());
    drop(engine);

    // The preview says who gains access.
    let preview = w.dry_run(release_op(&w.rid, true)).await.unwrap();
    assert!(preview.changes_reach);
    let change = &preview.changes[0];
    assert!(change.change.opens_to_anyone);
    assert!(change.change.detail.as_deref().unwrap().contains("Anyone"));
    assert!(change
        .reach
        .iter()
        .any(|r| r.network_id == "tor" && r.reach != Reach::NotReachable));

    let engine = w.h.state.engine.read().await;
    engine
        .release_reservation(&w.h.state, &w.rid, true)
        .await
        .unwrap();
    assert_eq!(w.h.tor.add_commands().len(), 1, "nginx is published now");
}

#[tokio::test]
async fn removing_the_binding_that_hides_an_anyone_grant_on_tor_needs_confirmation() {
    let w = web().await;
    w.grant(Target::App(w.nginx.clone()), Scope::All, Subject::Anyone)
        .await;
    let binding = w.binding_of(&w.nginx).await;
    let engine = w.h.state.engine.read().await;
    let refused = engine
        .remove_binding(&w.h.state, &w.rid, &binding, false)
        .await;
    assert!(confirmation_required(&refused), "{refused:?}");
    assert!(w.h.tor.add_commands().is_empty());
    engine
        .remove_binding(&w.h.state, &w.rid, &binding, true)
        .await
        .unwrap();
    assert_eq!(w.h.tor.add_commands().len(), 1);
}

#[tokio::test]
async fn freeing_rows_for_a_named_peer_needs_no_confirmation_but_shows_the_reach() {
    let w = web().await;
    let (bob, _) = w.peer("bob").await;
    w.grant(Target::App(w.nginx.clone()), Scope::All, Subject::Peer(bob))
        .await;
    let preview = w.dry_run(release_op(&w.rid, false)).await.unwrap();
    assert!(preview.changes_reach, "bob gains access to nginx on Tor");
    assert!(!preview.changes[0].change.opens_to_anyone);
    assert!(!preview.changes[0].reach.is_empty());
    let engine = w.h.state.engine.read().await;
    engine
        .release_reservation(&w.h.state, &w.rid, false)
        .await
        .unwrap();
}

#[tokio::test]
async fn releasing_needs_no_confirmation_when_no_anyone_grant_becomes_live() {
    let w = web().await;
    // Anyone on the reservation itself goes with it: nothing is newly open.
    w.grant(
        Target::Reservation(w.rid.clone()),
        Scope::All,
        Subject::Anyone,
    )
    .await;
    let preview = w.dry_run(release_op(&w.rid, false)).await.unwrap();
    assert!(!preview.changes_reach);
    assert!(!preview.changes[0].change.opens_to_anyone);
    let engine = w.h.state.engine.read().await;
    engine
        .release_reservation(&w.h.state, &w.rid, false)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_tag_grant_that_was_live_through_other_members_gains_the_freed_one() {
    // Tag {nginx (bound), redis (free)}: the Anyone grant on the tag is reachable on Tor
    // through redis before and after, yet freeing nginx publishes nginx's own address.
    let h = Harness::new(vec![tcp_socket("nginx", 443), tcp_socket("redis", 6379)]).await;
    h.reconcile().await;
    let apps = h.state.db.list_apps().await.unwrap();
    let id_of = |n: &str| {
        apps.iter()
            .find(|a| a.process_name == n)
            .unwrap()
            .id
            .clone()
    };
    let (nginx, redis) = (id_of("nginx"), id_of("redis"));
    let engine = h.state.engine.read().await;
    let tag = engine
        .create_tag(
            &h.state,
            "pair",
            &[],
            &[
                socketguard_core::TagMember {
                    app_id: nginx.clone(),
                    scope: Scope::All,
                },
                socketguard_core::TagMember {
                    app_id: redis.clone(),
                    scope: Scope::All,
                },
            ],
        )
        .await
        .unwrap();
    let res = engine
        .create_reservation(
            &h.state,
            "web",
            vec![BindingTarget::App {
                app_id: nginx.clone(),
                scope: Scope::All,
            }],
            false,
        )
        .await
        .unwrap();
    engine
        .create_grant(
            &h.state,
            &NewGrant {
                target: Target::Tag(tag.id.clone()),
                scope: Scope::All,
                network_id: None,
                subject: Subject::Anyone,
                confirm_open: true,
            },
        )
        .await
        .unwrap();
    let published = h.tor.add_commands().len();
    let refused = engine
        .release_reservation(&h.state, &res.reservation.id, false)
        .await;
    assert!(confirmation_required(&refused), "{refused:?}");
    engine
        .release_reservation(&h.state, &res.reservation.id, true)
        .await
        .unwrap();
    assert!(h.tor.add_commands().len() > published);
}

/// Tag `bt` with sshd's All ports, bound to the reservation `bound`; an Anyone grant on
/// sshd's row directly (inert on Tor while the tag is bound). Returns (web, tag id).
async fn web_with_bound_tag() -> (Web, String) {
    let w = web().await;
    let engine = w.h.state.engine.read().await;
    // sshd leaves the reservation's direct binding and goes in through a tag.
    let binding = w.binding_of(&w.ssh).await;
    engine
        .remove_binding(&w.h.state, &w.rid, &binding, true)
        .await
        .unwrap();
    let tag = engine
        .create_tag(
            &w.h.state,
            "bt",
            &[],
            &[socketguard_core::TagMember {
                app_id: w.ssh.clone(),
                scope: Scope::All,
            }],
        )
        .await
        .unwrap();
    engine
        .add_binding(
            &w.h.state,
            &w.rid,
            BindingTarget::Tag {
                tag_id: tag.id.clone(),
            },
            false,
        )
        .await
        .unwrap();
    drop(engine);
    w.grant(Target::App(w.ssh.clone()), Scope::All, Subject::Anyone)
        .await;
    assert!(w.h.tor.add_commands().is_empty(), "inert while bound");
    (w, tag.id)
}

#[tokio::test]
async fn taking_a_member_out_of_a_bound_tag_that_hides_an_anyone_grant_needs_confirmation() {
    let (w, tag) = web_with_bound_tag().await;
    let engine = w.h.state.engine.read().await;
    let refused = engine
        .remove_tag_member(&w.h.state, &tag, &w.ssh, Scope::All, false)
        .await;
    assert!(confirmation_required(&refused), "{refused:?}");
    engine
        .remove_tag_member(&w.h.state, &tag, &w.ssh, Scope::All, true)
        .await
        .unwrap();
    assert_eq!(w.h.tor.add_commands().len(), 1);
}

#[tokio::test]
async fn deleting_a_bound_tag_that_hides_an_anyone_grant_needs_confirmation() {
    let (w, tag) = web_with_bound_tag().await;
    let engine = w.h.state.engine.read().await;
    let refused = engine.delete_tag(&w.h.state, &tag, false).await;
    assert!(confirmation_required(&refused), "{refused:?}");
    assert!(engine.get_tag(&w.h.state, &tag).await.is_ok());
    engine.delete_tag(&w.h.state, &tag, true).await.unwrap();
    assert_eq!(w.h.tor.add_commands().len(), 1);
}

// ─── Imports ask before freeing a row that hides an Anyone grant (ADR 0058, 0061) ───

use socketguard_core::api_types::{ApplyRequest, ExportBinding, ExportDocument};

impl Web {
    async fn export_text(&self) -> String {
        let engine = self.h.state.engine.read().await;
        let doc = socketguard_daemon::apply::export(&engine, &self.h.state)
            .await
            .unwrap();
        serde_json::to_string(&doc).unwrap()
    }

    /// Import `edit` of the current export: refused without the confirmation and nothing
    /// applied (a new peer comes first in the execution order); applied with it.
    async fn import_needs_confirmation(&self, edit: impl Fn(&mut ExportDocument)) {
        let engine = self.h.state.engine.read().await;
        let mut document = socketguard_daemon::apply::export(&engine, &self.h.state)
            .await
            .unwrap();
        edit(&mut document);
        document
            .peers
            .push(socketguard_core::api_types::ExportPeer {
                label: "zed".into(),
                credentials: vec![],
            });
        let request = |dry_run, confirm_open| ApplyRequest {
            document: document.clone(),
            dry_run,
            confirm_open,
        };
        let before = self.export_text().await;
        let preview =
            socketguard_daemon::apply::apply(&engine, &self.h.state, request(true, false))
                .await
                .unwrap();
        assert!(preview.confirm_open_required);
        let refused =
            socketguard_daemon::apply::apply(&engine, &self.h.state, request(false, false)).await;
        assert!(confirmation_required(&refused), "{refused:?}");
        assert_eq!(self.export_text().await, before, "nothing was applied");
        assert!(self.h.tor.add_commands().is_empty());
        socketguard_daemon::apply::apply(&engine, &self.h.state, request(false, true))
            .await
            .unwrap();
        assert_ne!(self.export_text().await, before);
        assert_eq!(self.h.tor.add_commands().len(), 1, "nginx is published now");
    }
}

#[tokio::test]
async fn an_import_that_removes_the_binding_hiding_an_anyone_grant_needs_confirmation() {
    let w = web().await;
    w.grant(Target::App(w.nginx.clone()), Scope::All, Subject::Anyone)
        .await;
    w.import_needs_confirmation(|doc| {
        doc.reservations[0]
            .bindings
            .retain(|b| !matches!(b, ExportBinding::App { app, .. } if app.id == w.nginx));
    })
    .await;
}

#[tokio::test]
async fn an_import_that_releases_the_reservation_hiding_an_anyone_grant_needs_confirmation() {
    let w = web().await;
    w.grant(Target::App(w.nginx.clone()), Scope::All, Subject::Anyone)
        .await;
    w.import_needs_confirmation(|doc| doc.reservations.clear())
        .await;
}

#[tokio::test]
async fn a_dry_run_of_deleting_a_bound_tag_shows_who_gains_access_and_changes_nothing() {
    let (w, tag) = web_with_bound_tag().await;
    let op = |confirm_open| ChangeOp::DeleteTag {
        tag_id: tag.clone(),
        confirm_open,
    };
    let refused = w.dry_run(op(false)).await;
    assert!(confirmation_required(&refused), "{refused:?}");
    let preview = w.dry_run(op(true)).await.unwrap();
    assert!(preview.changes_reach);
    let change = &preview.changes[0];
    assert!(change.change.opens_to_anyone);
    assert!(change
        .reach
        .iter()
        .any(|r| r.network_id == "tor" && r.reach != Reach::NotReachable));
    // A dry run deletes nothing and publishes nothing.
    let engine = w.h.state.engine.read().await;
    assert!(engine.get_tag(&w.h.state, &tag).await.is_ok());
    assert!(w.h.tor.add_commands().is_empty());
    // The batch applies it like the route does.
    engine
        .apply_changes(
            &w.h.state,
            &ChangesRequest {
                ops: vec![op(true)],
                dry_run: false,
            },
        )
        .await
        .unwrap();
    assert!(engine.get_tag(&w.h.state, &tag).await.is_err());
    assert_eq!(w.h.tor.add_commands().len(), 1);
}
