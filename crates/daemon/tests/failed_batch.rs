//! A batch write that fails has no side effects: the addresses it would retire stay active
//! and nothing is taken off an interface or network (ADR 0026, ADR 0062 note).

mod common;

use axum::http::{Method, StatusCode};
use common::{call, listener};
use serde_json::{json, Value};
use socketguard_daemon::api;
use socketguard_daemon::state::OwnedAddress;
use socketguard_daemon::test_support::*;

struct Rig {
    d: StandardDaemon,
    app: axum::Router,
    gid: String,
    app_id: String,
}

impl Rig {
    /// An app with a port group attached and the group's own address, owned and on its
    /// interface.
    async fn new() -> Self {
        let d = standard_daemon(vec![listener("nginx", 80)], None).await;
        let app = api::router(d.state.clone());
        {
            let engine = d.state.engine.read().await;
            engine.reconcile(&d.state).await.unwrap();
        }
        let mut r = Self {
            d,
            app,
            gid: String::new(),
            app_id: String::new(),
        };
        let (_, apps) = r.send(Method::GET, "/api/apps".into(), None).await;
        r.app_id = apps[0]["id"].as_str().unwrap().to_string();
        let (s, g) = r
            .send(
                Method::POST,
                "/api/port-groups".into(),
                Some(json!({"label": "pg", "ports": [{"start": 50000, "end": 50010, "proto": "tcp"}]})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{g}");
        r.gid = g["id"].as_str().unwrap().to_string();
        let (s, b) = r
            .send(
                Method::PUT,
                format!("/api/port-groups/{}/apps/{}", r.gid, r.app_id),
                Some(json!({})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        // A grant that names the group gives the group its own address; the grant can go
        // and leave the address in place.
        let (s, grant) = r
            .send(
                Method::POST,
                "/api/grants".into(),
                Some(json!({"target": {"kind": "app", "id": r.app_id},
                            "scope": {"kind": "group", "id": r.gid},
                            "subject": {"kind": "anyone"}, "confirm_open": true})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{grant}");
        r.send(
            Method::DELETE,
            format!("/api/grants/{}", grant["id"].as_str().unwrap()),
            None,
        )
        .await;
        let owned = r.d.state.db.list_owned_addresses().await.unwrap();
        assert!(!owned.is_empty(), "the group address is owned");
        assert!(owned.iter().all(|o| !o.retiring));
        assert!(r.on_iface(&owned) > 0);
        r
    }

    async fn send(&self, m: Method, p: String, b: Option<Value>) -> (StatusCode, Value) {
        call(&self.app, m, &p, b).await
    }

    fn on_iface(&self, owned: &[OwnedAddress]) -> usize {
        owned
            .iter()
            .filter(|o| self.d.net.addresses(&o.interface).contains(&o.addr))
            .count()
    }

    /// Detach the group while a trigger makes the write fail after the plan was accepted.
    async fn fail_detach(&self) {
        let db = &self.d.state.db;
        db.exec_raw(
            "CREATE TRIGGER boom BEFORE DELETE ON port_group_apps \
             BEGIN SELECT RAISE(ABORT, 'boom'); END",
        )
        .await
        .unwrap();
        let (s, b) = self
            .send(
                Method::DELETE,
                format!("/api/port-groups/{}/apps/{}", self.gid, self.app_id),
                None,
            )
            .await;
        assert_ne!(s, StatusCode::OK, "{b}");
        db.exec_raw("DROP TRIGGER boom").await.unwrap();
    }
}

#[tokio::test]
async fn a_failed_detach_leaves_its_address_active_and_on_the_interface() {
    let r = Rig::new().await;
    let before = r.on_iface(&r.d.state.db.list_owned_addresses().await.unwrap());
    r.fail_detach().await;
    let after = r.d.state.db.list_owned_addresses().await.unwrap();
    assert!(
        after.iter().all(|o| !o.retiring),
        "nothing is retiring after a failed write: {after:?}"
    );
    assert_eq!(r.on_iface(&after), before, "nothing left an interface");
}

/// What the stray `retiring` rows come to once the daemon carries on: the next reconcile
/// takes the address back (it is still wanted and still on its interface).
#[tokio::test]
async fn a_reconcile_after_a_failed_detach_finds_the_address_active_again() {
    let r = Rig::new().await;
    r.fail_detach().await;
    r.d.state
        .engine
        .read()
        .await
        .reconcile(&r.d.state)
        .await
        .unwrap();
    let owned = r.d.state.db.list_owned_addresses().await.unwrap();
    assert!(owned.iter().all(|o| !o.retiring), "{owned:?}");
    assert!(r.on_iface(&owned) > 0);
}
