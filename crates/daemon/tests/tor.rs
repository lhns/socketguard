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
        uid: Some("1000".into()),
        foreign_mntns: false,
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
            },
        };
        let mut backends = HashMap::new();
        backends.insert(
            "tor".to_string(),
            ActiveBackend {
                config: cfg.clone(),
                network: Arc::new(TorNetwork::new(&tor.addr(), TorAuth::None, Duration::ZERO)),
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
