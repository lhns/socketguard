//! An import asks before it changes what Anyone can reach (ADR 0061): one document per
//! engine confirmation site. Each is refused without `confirm_open` before anything is
//! applied (the export is byte-identical, though the document also adds a peer that comes
//! first in the execution order), and applied with it.

mod common;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::{call, listener};
use serde_json::{json, Value};
use socketguard_daemon::api;
use socketguard_daemon::test_support::*;

struct Rig {
    d: StandardDaemon,
    app: Router,
}

impl Rig {
    async fn new() -> Self {
        let d = standard_daemon(vec![listener("sshd", 22), listener("nginx", 443)], None).await;
        let app = api::router(d.state.clone());
        let r = Self { d, app };
        {
            let engine = r.d.state.engine.read().await;
            engine.reconcile(&r.d.state).await.unwrap();
        }
        r
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        call(&self.app, Method::GET, path, None).await
    }
    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        call(&self.app, Method::POST, path, Some(body)).await
    }
    async fn put(&self, path: &str, body: Value) -> (StatusCode, Value) {
        call(&self.app, Method::PUT, path, Some(body)).await
    }
    async fn delete(&self, path: &str) -> (StatusCode, Value) {
        call(&self.app, Method::DELETE, path, None).await
    }

    async fn ok(&self, (s, b): (StatusCode, Value)) -> Value {
        assert!(s.is_success(), "{s} {b}");
        b
    }

    async fn app_id(&self, name: &str) -> String {
        let (_, apps) = self.get("/api/apps").await;
        apps.as_array()
            .unwrap()
            .iter()
            .find(|a| a["process_name"] == name)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn export(&self) -> Value {
        self.ok(self.get("/api/export").await).await
    }

    async fn grant(&self, target: Value, subject: Value) -> String {
        let b = self
            .ok(self
                .post(
                    "/api/grants",
                    json!({"target": target, "subject": subject, "confirm_open": true}),
                )
                .await)
            .await;
        id(&b["grant"]).or_else(|| id(&b)).unwrap()
    }

    /// Reservation `pub` bound to sshd (All ports) with a grant to Anyone: the row's reach
    /// widens with a port group attached to sshd, or with a binding that joins.
    async fn open_reservation(&self) -> (String, String) {
        let ssh = self.app_id("sshd").await;
        let b = self
            .ok(self
                .post(
                    "/api/reservations",
                    json!({"label": "pub", "bindings": [bind(&ssh)]}),
                )
                .await)
            .await;
        let rid = id(&b).unwrap();
        self.grant(json!({"kind": "reservation", "id": rid}), anyone())
            .await;
        (ssh, rid)
    }

    async fn port_group(&self, ports: Value, apps: Value) -> String {
        let b = self
            .ok(self
                .post(
                    "/api/port-groups",
                    json!({"label": "extra", "ports": ports, "apps": apps, "confirm_open": true}),
                )
                .await)
            .await;
        id(&b).unwrap()
    }

    /// `doc` (an export of the state we want, plus a new peer that is applied first) is
    /// refused without the confirmation and leaves the state as it was; a dry run says why;
    /// with it, it is applied.
    async fn imports_only_when_confirmed(&self, mut doc: Value) {
        doc["peers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"label": "zed", "credentials": []}));
        let before = self.export().await.to_string();

        let preview = self
            .ok(self
                .post("/api/apply", json!({"document": doc, "dry_run": true}))
                .await)
            .await;
        assert_eq!(preview["confirm_open_required"], true, "{preview}");
        assert_eq!(
            self.export().await.to_string(),
            before,
            "a dry run changes nothing"
        );

        let (s, b) = self.post("/api/apply", json!({"document": doc})).await;
        assert_eq!(
            (s, b["code"].as_str()),
            (StatusCode::CONFLICT, Some("confirmation_required")),
            "{b}"
        );
        assert_eq!(
            self.export().await.to_string(),
            before,
            "nothing was applied before the refusal"
        );

        let done = self
            .ok(self
                .post("/api/apply", json!({"document": doc, "confirm_open": true}))
                .await)
            .await;
        assert_eq!(done["dry_run"], false);
        let after = self.export().await;
        assert_ne!(after.to_string(), before);
        assert!(after["peers"].to_string().contains("zed"), "{after}");
    }
}

fn id(v: &Value) -> Option<String> {
    v["id"].as_str().map(str::to_string)
}

fn anyone() -> Value {
    json!({"kind": "anyone"})
}

fn bind(app: &str) -> Value {
    json!({"kind": "app", "app_id": app, "scope": {"kind": "all"}})
}

fn ports(end: u16) -> Value {
    json!([{"start": 2200, "end": end, "proto": "tcp"}])
}

#[tokio::test]
async fn an_anyone_grant_on_an_app_needs_confirmation() {
    let r = Rig::new().await;
    let ng = r.app_id("nginx").await;
    let gid = r.grant(json!({"kind": "app", "id": ng}), anyone()).await;
    let doc = r.export().await;
    r.ok(r.delete(&format!("/api/grants/{gid}")).await).await;
    r.imports_only_when_confirmed(doc).await;
}

#[tokio::test]
async fn an_anyone_grant_on_a_reserved_address_needs_confirmation() {
    let r = Rig::new().await;
    let ssh = r.app_id("sshd").await;
    let b = r
        .ok(r
            .post(
                "/api/reservations",
                json!({"label": "pub", "bindings": [bind(&ssh)]}),
            )
            .await)
        .await;
    let rid = id(&b).unwrap();
    let gid = r
        .grant(json!({"kind": "reservation", "id": rid}), anyone())
        .await;
    let doc = r.export().await;
    r.ok(r.delete(&format!("/api/grants/{gid}")).await).await;
    r.imports_only_when_confirmed(doc).await;
}

#[tokio::test]
async fn a_new_port_group_that_widens_an_anyone_grant_needs_confirmation() {
    let r = Rig::new().await;
    let (ssh, _) = r.open_reservation().await;
    let gid = r.port_group(ports(2210), json!([ssh])).await;
    let doc = r.export().await;
    r.ok(r.delete(&format!("/api/port-groups/{gid}")).await)
        .await;
    r.imports_only_when_confirmed(doc).await;
}

#[tokio::test]
async fn growing_a_port_group_that_an_anyone_grant_covers_needs_confirmation() {
    let r = Rig::new().await;
    let (ssh, _) = r.open_reservation().await;
    let gid = r.port_group(ports(2210), json!([ssh])).await;
    r.ok(r
        .put(
            &format!("/api/port-groups/{gid}"),
            json!({"ports": ports(2300), "confirm_open": true}),
        )
        .await)
        .await;
    let doc = r.export().await;
    r.ok(r
        .put(
            &format!("/api/port-groups/{gid}"),
            json!({"ports": ports(2210)}),
        )
        .await)
        .await;
    r.imports_only_when_confirmed(doc).await;
}

#[tokio::test]
async fn attaching_a_port_group_that_an_anyone_grant_covers_needs_confirmation() {
    let r = Rig::new().await;
    let (ssh, _) = r.open_reservation().await;
    let gid = r.port_group(ports(2210), json!([])).await;
    r.ok(r
        .put(
            &format!("/api/port-groups/{gid}/apps/{ssh}"),
            json!({"confirm_open": true}),
        )
        .await)
        .await;
    let doc = r.export().await;
    r.ok(r
        .delete(&format!("/api/port-groups/{gid}/apps/{ssh}"))
        .await)
        .await;
    r.imports_only_when_confirmed(doc).await;
}

#[tokio::test]
async fn a_binding_that_joins_a_reservation_with_an_anyone_grant_needs_confirmation() {
    let r = Rig::new().await;
    let (_, rid) = r.open_reservation().await;
    let ng = r.app_id("nginx").await;
    let view = r
        .ok(r
            .post(
                &format!("/api/reservations/{rid}/bindings"),
                json!({"target": bind(&ng), "confirm_open": true}),
            )
            .await)
        .await;
    let doc = r.export().await;
    let binding = view["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["target"]["app_id"] == json!(ng))
        .and_then(id)
        .unwrap();
    r.ok(r
        .delete(&format!(
            "/api/reservations/{rid}/bindings/{binding}?confirm_open=true"
        ))
        .await)
        .await;
    r.imports_only_when_confirmed(doc).await;
}

#[tokio::test]
async fn an_import_that_touches_only_peers_needs_no_confirmation_beside_an_anyone_grant() {
    let r = Rig::new().await;
    let ng = r.app_id("nginx").await;
    r.grant(json!({"kind": "app", "id": ng}), anyone()).await;
    let mut doc = r.export().await;
    doc["peers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"label": "zed", "credentials": []}));
    let preview = r
        .ok(r
            .post("/api/apply", json!({"document": doc, "dry_run": true}))
            .await)
        .await;
    assert_eq!(preview["confirm_open_required"], false, "{preview}");
    r.ok(r.post("/api/apply", json!({"document": doc})).await)
        .await;
    assert!(r.export().await["peers"].to_string().contains("zed"));
}

/// Not an import, but the same rule (ADR 0066): adding a network lets the grants that
/// exist take effect on it, so it is refused without `confirm_open` when one is to Anyone,
/// before a network, a key or an address exists.
#[tokio::test]
async fn adding_a_network_that_an_anyone_grant_takes_effect_on_needs_confirmation() {
    let r = Rig::new().await;
    let ng = r.app_id("nginx").await;
    r.grant(json!({"kind": "app", "id": ng}), anyone()).await;
    let state = async {
        (
            r.get("/api/networks").await.1.to_string(),
            r.d.state.db.list_addresses().await.unwrap().len(),
            r.get("/api/activity?limit=200").await.1.to_string(),
            r.export().await.to_string(),
        )
    };
    let before = state.await;
    let net =
        json!({"id": "lan2", "type": "slaac", "interface": "eth9", "prefix": "2001:db8:9:9::/64"});

    let mut dry = net.clone();
    dry["dry_run"] = json!(true);
    let preview = r.ok(r.post("/api/networks", dry).await).await;
    assert_eq!(preview["confirm_open_required"], true, "{preview}");

    let (s, b) = r.post("/api/networks", net.clone()).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("confirmation_required")),
        "{b}"
    );
    let unchanged = async {
        (
            r.get("/api/networks").await.1.to_string(),
            r.d.state.db.list_addresses().await.unwrap().len(),
            r.get("/api/activity?limit=200").await.1.to_string(),
            r.export().await.to_string(),
        )
    };
    assert_eq!(
        unchanged.await,
        before,
        "the dry run and the refusal changed nothing"
    );

    let mut confirmed = net;
    confirmed["confirm_open"] = json!(true);
    let added = r.ok(r.post("/api/networks", confirmed).await).await;
    assert_eq!(added["id"], "lan2");
}
