//! Addresses on demand, reservations and `move_app` (ADR 0047) through the API, over mock
//! firewall, interfaces and networks.

mod common;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::{call, listener};
use serde_json::{json, Value};
use socketguard_core::ListeningSocket;
use socketguard_daemon::api;
use socketguard_daemon::firewall::{Dst, ScopeMatch};
use socketguard_daemon::test_support::*;
use std::net::IpAddr;
use std::sync::Arc;

const KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";

struct Rig {
    d: StandardDaemon,
    app: Router,
}

fn iface_of(network: &str) -> &'static str {
    match network {
        "local" => "lo",
        "lan" => "eth0",
        "ygg" => "ygg0",
        other => panic!("unknown network {other}"),
    }
}

fn sock(name: &str, port: u16) -> ListeningSocket {
    listener(name, port)
}

impl Rig {
    async fn new(sockets: Vec<ListeningSocket>) -> Self {
        let d = standard_daemon(sockets, None).await;
        let app = api::router(d.state.clone());
        let r = Self { d, app };
        r.reconcile().await;
        r
    }

    async fn reconcile(&self) {
        let mut engine = self.d.state.engine.write().await;
        engine.reconcile(&self.d.state).await.unwrap();
    }

    fn set_sockets(&self, sockets: Vec<ListeningSocket>) {
        *self.d.sockets.lock().unwrap() = sockets;
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

    async fn app_id(&self, name: &str) -> String {
        let (_, apps) = self.get("/api/apps").await;
        apps.as_array()
            .unwrap()
            .iter()
            .find(|a| a["process_name"] == name)
            .unwrap_or_else(|| panic!("no app {name}: {apps}"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn peer(&self, label: &str) -> String {
        let (s, body) = self
            .post(
                "/api/peers",
                json!({"label": label, "credentials": [{"kind": "ygg_key", "value": KEY}]}),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        body["id"].as_str().unwrap().to_string()
    }

    async fn empty_peer(&self, label: &str) -> String {
        let (s, body) = self
            .post("/api/peers", json!({"label": label, "credentials": []}))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        body["id"].as_str().unwrap().to_string()
    }

    /// POST a grant; the body fields are given as JSON.
    async fn grant(&self, target: Value, scope: Value, subject: Value) -> Value {
        let (s, body) = self
            .post(
                "/api/grants",
                json!({"target": target, "scope": scope, "subject": subject, "confirm_open": true}),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        body
    }

    async fn grant_app(&self, app: &str, subject: Value) -> Value {
        self.grant(json!({"kind": "app", "id": app}), all(), subject)
            .await
    }

    async fn addresses(&self) -> Vec<Value> {
        let (s, body) = self.get("/api/addresses").await;
        assert_eq!(s, StatusCode::OK, "{body}");
        body.as_array().unwrap().clone()
    }

    /// The addresses of an app's rows on `network`.
    async fn of_app(&self, app: &str, network: &str) -> Vec<Value> {
        self.addresses()
            .await
            .into_iter()
            .filter(|a| a["app_id"] == app && a["network_id"] == network)
            .collect()
    }

    async fn of_reservation(&self, id: &str, network: &str) -> Vec<Value> {
        self.addresses()
            .await
            .into_iter()
            .filter(|a| a["reservation_id"] == id && a["network_id"] == network)
            .collect()
    }

    fn on_interface(&self, network: &str, addr: &Value) -> bool {
        let ip = addr["locator"]["addr"].as_str().unwrap().parse().unwrap();
        self.d.net.addresses(iface_of(network)).contains(&ip)
    }

    fn managed(&self) -> Vec<IpAddr> {
        let rs = applied(&self.d.fw_calls).pop().expect("a ruleset");
        rs.scopes
            .iter()
            .find(|s| s.id == "managed")
            .map(|s| match &s.matcher {
                ScopeMatch::Destinations(d) => d.clone(),
                _ => vec![],
            })
            .unwrap_or_default()
    }

    /// The (port, grant id) of every rule towards `addr` in the last ruleset.
    fn rules_to(&self, addr: &Value) -> Vec<(u16, String)> {
        let ip: IpAddr = addr["locator"]["addr"].as_str().unwrap().parse().unwrap();
        let rs = applied(&self.d.fw_calls).pop().expect("a ruleset");
        let mut out: Vec<(u16, String)> = rs
            .rules
            .iter()
            .filter(|r| matches!(r.dst, Dst::Addr(a) if a == ip))
            .map(|r| (r.ports.start, r.id.split(':').nth(4).unwrap().to_string()))
            .collect();
        out.sort();
        out
    }

    async fn create_reservation(&self, label: &str, bindings: Value) -> Value {
        let (s, body) = self
            .post(
                "/api/reservations",
                json!({"label": label, "bindings": bindings}),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        body
    }
}

fn all() -> Value {
    json!({"kind": "all"})
}

fn port(p: u16) -> Value {
    json!({"kind": "port", "port": p, "proto": "tcp"})
}

fn anyone() -> Value {
    json!({"kind": "anyone"})
}

fn bind(app: &str, scope: Value) -> Value {
    json!({"kind": "app", "app_id": app, "scope": scope})
}

fn res_target(id: &str) -> Value {
    json!({"kind": "reservation", "id": id})
}

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap()
}

fn two_apps() -> Vec<ListeningSocket> {
    vec![sock("sshd", 22), sock("nginx", 443)]
}

// ─── Addresses on demand ─────────────────────────────────────────────────────

#[tokio::test]
async fn an_app_without_grants_has_no_address_except_on_loopback() {
    let r = Rig::new(two_apps()).await;
    let ssh = r.app_id("sshd").await;
    assert!(r.of_app(&ssh, "lan").await.is_empty());
    assert!(r.of_app(&ssh, "ygg").await.is_empty());
    let local = r.of_app(&ssh, "local").await;
    assert_eq!(local.len(), 1, "loopback keeps an address for every app");
    assert_eq!(local[0]["up"], true);
    assert!(r.on_interface("local", &local[0]));
}

#[tokio::test]
async fn a_grant_on_a_port_gives_only_that_port_an_address() {
    let r = Rig::new(vec![sock("nginx", 80), sock("nginx", 443)]).await;
    let ng = r.app_id("nginx").await;
    r.grant(json!({"kind": "app", "id": ng}), port(443), anyone())
        .await;
    for net in ["lan", "ygg"] {
        let a = r.of_app(&ng, net).await;
        assert_eq!(a.len(), 1, "{net}: {a:?}");
        assert_eq!(a[0]["scope"], port(443));
        assert_eq!(a[0]["up"], true);
        assert!(r.on_interface(net, &a[0]));
    }
}

#[tokio::test]
async fn an_all_ports_grant_gives_one_address_and_the_port_rows_none() {
    let r = Rig::new(vec![sock("nginx", 80), sock("nginx", 443)]).await;
    let ng = r.app_id("nginx").await;
    r.grant_app(&ng, anyone()).await;
    for net in ["lan", "ygg"] {
        let a = r.of_app(&ng, net).await;
        assert_eq!(a.len(), 1, "{net}: {a:?}");
        assert_eq!(a[0]["scope"], all());
    }
}

#[tokio::test]
async fn a_tag_grant_names_the_rows_of_its_members() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let (s, tag) = r
        .post(
            "/api/tags",
            json!({"label": "web", "members": [
                {"app_id": ssh, "scope": all()},
                {"app_id": ng, "scope": port(443)}
            ]}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{tag}");
    // The grant's own port limits what is let in; it names no other row.
    r.grant(json!({"kind": "tag", "id": id(&tag)}), port(443), anyone())
        .await;
    assert_eq!(r.of_app(&ssh, "lan").await[0]["scope"], all());
    let n = r.of_app(&ng, "lan").await;
    assert_eq!(n.len(), 1);
    assert_eq!(n[0]["scope"], port(443));
}

#[tokio::test]
async fn revoking_makes_the_address_dormant_and_a_new_grant_brings_it_back() {
    let r = Rig::new(two_apps()).await;
    let ssh = r.app_id("sshd").await;
    let g = r.grant_app(&ssh, anyone()).await;
    let first = r.of_app(&ssh, "ygg").await.remove(0);
    let ip: IpAddr = first["locator"]["addr"].as_str().unwrap().parse().unwrap();
    assert!(r.on_interface("ygg", &first));
    assert!(r.managed().contains(&ip));
    assert!(!r.rules_to(&first).is_empty());

    let (s, _) = r.delete(&format!("/api/grants/{}", id(&g))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let dormant = r.of_app(&ssh, "ygg").await.remove(0);
    assert_eq!(dormant["id"], first["id"], "the row stays");
    assert_eq!(dormant["up"], false);
    assert!(!r.on_interface("ygg", &first), "off the interface");
    assert!(!r.managed().contains(&ip), "not in the ruleset");
    assert!(r.rules_to(&first).is_empty());

    r.grant_app(&ssh, anyone()).await;
    let back = r.of_app(&ssh, "ygg").await.remove(0);
    assert_eq!(back["locator"], first["locator"], "the same locator");
    assert_eq!(back["up"], true);
    assert!(r.on_interface("ygg", &back));
}

#[tokio::test]
async fn changing_a_peer_group_or_credential_never_creates_or_deletes_an_address() {
    let r = Rig::new(two_apps()).await;
    let ssh = r.app_id("sshd").await;
    let (s, group) = r
        .post("/api/peer-groups", json!({"label": "empty", "members": []}))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{group}");
    // A grant to an empty group still names the row.
    r.grant_app(&ssh, json!({"kind": "group", "id": id(&group)}))
        .await;
    let ids = |v: Vec<Value>| -> Vec<String> { v.iter().map(id).collect() };
    let before = ids(r.addresses().await);
    assert_eq!(r.of_app(&ssh, "ygg").await.len(), 1);

    let peer = r.peer("alice").await;
    let (s, _) = r
        .put(
            &format!("/api/peer-groups/{}/members", id(&group)),
            json!({"peer_ids": [peer]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ids(r.addresses().await), before);
    let (s, _) = r
        .post(
            &format!("/api/peers/{peer}/credentials"),
            json!({"kind": "ip", "value": "fd00::9"}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(ids(r.addresses().await), before);
    r.put(
        &format!("/api/peer-groups/{}/members", id(&group)),
        json!({"peer_ids": []}),
    )
    .await;
    let (s, _) = r.delete(&format!("/api/peers/{peer}")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(ids(r.addresses().await), before);
}

// ─── Reservations ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_reservation_gets_its_address_with_the_first_covering_grant_and_keeps_it() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let res = r
        .create_reservation("web", json!([bind(&ssh, all()), bind(&ng, all())]))
        .await;
    let rid = id(&res);
    assert!(
        r.of_reservation(&rid, "ygg").await.is_empty(),
        "no grant yet"
    );

    r.grant(res_target(&rid), all(), anyone()).await;
    let on_ygg = r.of_reservation(&rid, "ygg").await;
    assert_eq!(on_ygg.len(), 1);
    assert_eq!(on_ygg[0]["up"], true);
    assert!(r.on_interface("ygg", &on_ygg[0]));
    assert_eq!(r.of_reservation(&rid, "lan").await.len(), 1);
    // The bound rows have no automatic address on networks with grants.
    assert!(r.of_app(&ssh, "ygg").await.is_empty());
    assert!(r.of_app(&ng, "lan").await.is_empty());
    // Both ports are served on the one address.
    let ports: Vec<u16> = r.rules_to(&on_ygg[0]).iter().map(|x| x.0).collect();
    assert_eq!(ports, [22, 443]);

    // Revoking closes it but keeps it, and forgetting an app leaves it.
    let (_, grants) = r.get(&format!("/api/grants?reservation={rid}")).await;
    let gid = id(&grants[0]);
    r.delete(&format!("/api/grants/{gid}")).await;
    let closed = r.of_reservation(&rid, "ygg").await.remove(0);
    assert_eq!(closed["up"], false);
    assert!(!r.on_interface("ygg", &closed));
    let (s, _) = r.delete(&format!("/api/apps/{ssh}")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let kept = r.of_reservation(&rid, "ygg").await.remove(0);
    assert_eq!(kept["locator"], on_ygg[0]["locator"], "never re-allocated");
    let (_, view) = r.get(&format!("/api/reservations/{rid}")).await;
    assert_eq!(
        view["bindings"].as_array().unwrap().len(),
        1,
        "its binding went"
    );
    // And it comes back with a grant.
    r.grant(res_target(&rid), all(), anyone()).await;
    let again = r.of_reservation(&rid, "ygg").await.remove(0);
    assert_eq!(again["locator"], on_ygg[0]["locator"]);
    assert_eq!(again["up"], true);
}

#[tokio::test]
async fn a_grant_on_one_bound_row_is_enough_to_create_the_address_on_ip_networks() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let rid = id(&r
        .create_reservation("web", json!([bind(&ssh, all()), bind(&ng, all())]))
        .await);
    let bob = r.peer("bob").await;
    r.grant_app(&ng, json!({"kind": "peer", "id": bob})).await;
    let a = r.of_reservation(&rid, "ygg").await;
    assert_eq!(a.len(), 1);
    // bob is let in on 443 only; ssh has no rule.
    let rules = r.rules_to(&a[0]);
    assert_eq!(rules.iter().map(|x| x.0).collect::<Vec<_>>(), [443]);
}

#[tokio::test]
async fn grants_per_app_are_respected_in_a_shared_reservation() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let rid = id(&r
        .create_reservation("web", json!([bind(&ssh, all()), bind(&ng, all())]))
        .await);
    let (alice, bob) = (r.peer("alice").await, r.empty_peer("bob").await);
    let ga = id(&r
        .grant_app(&ssh, json!({"kind": "peer", "id": alice}))
        .await);
    let gb = id(&r.grant_app(&ng, json!({"kind": "anyone"})).await);
    let _ = bob;
    let a = r.of_reservation(&rid, "ygg").await.remove(0);
    assert_eq!(
        r.rules_to(&a),
        [(22, ga.clone()), (443, gb.clone())],
        "each grant only on its own app's port"
    );
}

#[tokio::test]
async fn conflicts_are_reported_with_the_app_that_is_served() {
    let r = Rig::new(vec![sock("a", 80), sock("b", 443)]).await;
    let (a, b) = (r.app_id("a").await, r.app_id("b").await);
    let (s, group) = r
        .post(
            "/api/port-groups",
            json!({"label": "web", "ports": [
                {"start": 80, "end": 80, "proto": "tcp"},
                {"start": 443, "end": 443, "proto": "tcp"},
                {"start": 9000, "end": 9001, "proto": "tcp"}],
                "apps": [a, b]}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{group}");
    let gscope = json!({"kind": "group", "id": id(&group)});
    let res = r
        .create_reservation(
            "shared",
            json!([bind(&a, gscope.clone()), bind(&b, gscope)]),
        )
        .await;
    let conflicts = res["conflicts"].as_array().unwrap();
    // 80 and 443 are listened by one app each; 9000-9001 are listened by none.
    let served: Vec<(String, Option<String>)> = conflicts
        .iter()
        .map(|c| {
            (
                format!("{}-{}", c["ports"]["start"], c["ports"]["end"]),
                c["served_app"].as_str().map(String::from),
            )
        })
        .collect();
    assert_eq!(
        served,
        [
            ("80-80".to_string(), Some(a.clone())),
            ("443-443".to_string(), Some(b.clone())),
            ("9000-9001".to_string(), None)
        ]
    );
    assert_eq!(conflicts[0]["bindings"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn excluded_ports_are_reported_on_the_address() {
    let r = Rig::new(vec![sock("a", 22), sock("b", 80)]).await;
    let (a, _b) = (r.app_id("a").await, r.app_id("b").await);
    let (_, group) = r
        .post(
            "/api/port-groups",
            json!({"label": "range", "ports": [{"start": 70, "end": 90, "proto": "tcp"}],
                   "apps": [a]}),
        )
        .await;
    r.grant(
        json!({"kind": "app", "id": a}),
        json!({"kind": "group", "id": id(&group)}),
        anyone(),
    )
    .await;
    let addr = r.of_app(&a, "ygg").await.remove(0);
    // b listens on 80, which a's range covers but a does not own.
    assert_eq!(
        addr["excluded"],
        json!([{"start": 80, "end": 80, "proto": "tcp"}])
    );
}

#[tokio::test]
async fn reserving_an_automatic_address_keeps_its_locator() {
    let r = Rig::new(two_apps()).await;
    let ssh = r.app_id("sshd").await;
    r.grant_app(&ssh, anyone()).await;
    let auto = r.of_app(&ssh, "ygg").await.remove(0);
    let (s, res) = r
        .post(
            &format!("/api/addresses/{}/reserve", id(&auto)),
            json!({"label": "my ssh"}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{res}");
    assert_eq!(res["label"], "my ssh");
    assert_eq!(res["bindings"][0]["target"]["app_id"], json!(ssh));
    let addr = &res["addresses"][0];
    assert_eq!(addr["locator"], auto["locator"]);
    assert_eq!(addr["network_id"], "ygg");
    assert_eq!(addr["id"], auto["id"]);
    assert_eq!(addr["up"], true);
    // The row has no automatic address any more; the other networks' ones go dormant.
    assert!(r.of_app(&ssh, "ygg").await.is_empty());
    let (s, b) = r
        .post(
            &format!("/api/addresses/{}/reserve", id(&auto)),
            json!({"label": "again"}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::BAD_REQUEST, "invalid"));
}

#[tokio::test]
async fn releasing_a_reservation_gives_its_rows_automatic_addresses_where_granted() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let rid = id(&r
        .create_reservation("web", json!([bind(&ssh, all()), bind(&ng, all())]))
        .await);
    r.grant_app(&ssh, anyone()).await;
    assert!(r.of_app(&ssh, "ygg").await.is_empty());
    let on = r.of_reservation(&rid, "ygg").await.remove(0);
    assert!(r.on_interface("ygg", &on));

    let (s, _) = r.delete(&format!("/api/reservations/{rid}")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(r.of_reservation(&rid, "ygg").await.is_empty());
    assert!(
        !r.on_interface("ygg", &on),
        "the reservation's address left"
    );
    let fresh = r.of_app(&ssh, "ygg").await;
    assert_eq!(fresh.len(), 1, "named by the grant");
    assert_ne!(fresh[0]["locator"], on["locator"]);
    assert!(r.of_app(&ng, "ygg").await.is_empty(), "nobody named nginx");
}

#[tokio::test]
async fn bindings_are_validated() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let rid = id(&r.create_reservation("a", json!([bind(&ssh, all())])).await);
    // A row is bound once.
    let (s, b) = r
        .post(
            "/api/reservations",
            json!({"label": "b", "bindings": [bind(&ssh, all())]}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::CONFLICT, "conflict"));
    let (s, b) = r
        .post(
            &format!("/api/reservations/{rid}/bindings"),
            json!({"target": bind(&ssh, all())}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::CONFLICT, "conflict"));
    // Labels are unique; a group has to be attached; a port has to exist.
    let (s, b) = r
        .post("/api/reservations", json!({"label": "a", "bindings": []}))
        .await;
    assert_eq!((s, code(&b)), (StatusCode::CONFLICT, "conflict"));
    let (_, group) = r
        .post(
            "/api/port-groups",
            json!({"label": "g", "ports": [{"start": 5, "end": 6, "proto": "tcp"}]}),
        )
        .await;
    let (s, b) = r
        .post(
            &format!("/api/reservations/{rid}/bindings"),
            json!({"target": bind(&ng, json!({"kind": "group", "id": id(&group)}))}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::BAD_REQUEST, "invalid"));
    let (s, b) = r
        .post(
            &format!("/api/reservations/{rid}/bindings"),
            json!({"target": bind(&ng, port(9))}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::BAD_REQUEST, "invalid"));
    // Rename and the binding removal work.
    let (s, v) = r
        .put(
            &format!("/api/reservations/{rid}"),
            json!({"label": "renamed"}),
        )
        .await;
    assert_eq!((s, v["label"].as_str()), (StatusCode::OK, Some("renamed")));
    let bid = v["bindings"][0]["id"].as_str().unwrap().to_string();
    let (s, v) = r
        .delete(&format!("/api/reservations/{rid}/bindings/{bid}"))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["bindings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_grant_on_a_reservation_needs_scope_all_and_follows_its_bindings() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let rid = id(&r
        .create_reservation("web", json!([bind(&ssh, all())]))
        .await);
    let (s, b) = r
        .post(
            "/api/grants",
            json!({"target": res_target(&rid), "scope": port(22), "subject": anyone(),
                   "confirm_open": true}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::BAD_REQUEST, "invalid"));

    let alice = r.peer("alice").await;
    r.grant(
        res_target(&rid),
        all(),
        json!({"kind": "peer", "id": alice}),
    )
    .await;
    let a = r.of_reservation(&rid, "ygg").await.remove(0);
    assert_eq!(r.rules_to(&a).iter().map(|x| x.0).collect::<Vec<_>>(), [22]);
    // A new binding is covered by the grant on the reservation.
    let (s, _) = r
        .post(
            &format!("/api/reservations/{rid}/bindings"),
            json!({"target": bind(&ng, all())}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(
        r.rules_to(&a).iter().map(|x| x.0).collect::<Vec<_>>(),
        [22, 443]
    );
    // The app's access lists the reservation as the origin.
    let (_, detail) = r.get(&format!("/api/apps/{ng}")).await;
    assert_eq!(detail["access"][0]["origin"]["kind"], "reservation");
    assert_eq!(detail["access"][0]["origin"]["reservation_id"], json!(rid));
}

#[tokio::test]
async fn binding_to_a_reservation_granted_to_anyone_needs_confirmation() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let rid = id(&r
        .create_reservation("web", json!([bind(&ssh, all())]))
        .await);
    r.grant(res_target(&rid), all(), anyone()).await;
    let (s, b) = r
        .post(
            &format!("/api/reservations/{rid}/bindings"),
            json!({"target": bind(&ng, all())}),
        )
        .await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::CONFLICT, "confirmation_required")
    );
    // The batch shows the reach in a dry run.
    let (s, b) = r
        .post(
            "/api/changes",
            json!({"dry_run": true, "ops": [{
                "op": "add_binding", "reservation_id": rid,
                "target": bind(&ng, all()), "confirm_open": true}]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["changes_reach"], true);
    assert_eq!(b["changes"][0]["opens_to_anyone"], true);
    assert!(!b["changes"][0]["reach"].as_array().unwrap().is_empty());
    let (s, _) = r
        .post(
            &format!("/api/reservations/{rid}/bindings"),
            json!({"target": bind(&ng, all()), "confirm_open": true}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn a_batch_creates_a_reservation_binds_and_grants_with_refs() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let body = json!({"ops": [
        {"op": "create_reservation", "ref": "$r", "label": "web",
         "bindings": [bind(&ssh, all())]},
        {"op": "add_binding", "reservation_id": "$r", "target": bind(&ng, all())},
        {"op": "add_grant", "target": res_target("$r"), "subject": anyone(),
         "confirm_open": true},
    ]});
    let mut dry = body.clone();
    dry["dry_run"] = json!(true);
    let (s, d) = r.post("/api/changes", dry).await;
    assert_eq!(s, StatusCode::OK, "{d}");
    assert_eq!(d["changes"].as_array().unwrap().len(), 3);
    assert!(
        r.get("/api/reservations")
            .await
            .1
            .as_array()
            .unwrap()
            .is_empty(),
        "a dry run saves nothing"
    );
    let (s, b) = r.post("/api/changes", body).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let rid = b["refs"]["$r"].as_str().unwrap().to_string();
    let (_, view) = r.get(&format!("/api/reservations/{rid}")).await;
    assert_eq!(view["bindings"].as_array().unwrap().len(), 2);
    assert_eq!(view["grants"].as_array().unwrap().len(), 1);
    assert_eq!(
        view["addresses"].as_array().unwrap().len(),
        2,
        "lan and ygg"
    );
    // The batch can also reserve and release.
    let ssh_auto_free = r.of_app(&ssh, "lan").await;
    assert!(ssh_auto_free.is_empty());
    let (s, b) = r
        .post(
            "/api/changes",
            json!({"ops": [{"op": "release_reservation", "reservation_id": rid}]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(r
        .get("/api/reservations")
        .await
        .1
        .as_array()
        .unwrap()
        .is_empty());
}

// ─── move_app ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn move_app_carries_grants_tags_addresses_and_bindings() {
    let r = Rig::new(vec![sock("old", 8080), sock("new", 8080)]).await;
    // Two apps cannot listen on the same port: give the new one its own.
    r.set_sockets(vec![sock("old", 8080), sock("new", 9090)]);
    r.reconcile().await;
    let (old, new) = (r.app_id("old").await, r.app_id("new").await);
    let (alice, bob) = (r.peer("alice").await, r.empty_peer("bob").await);
    r.grant_app(&old, json!({"kind": "peer", "id": alice}))
        .await;
    r.grant_app(&old, json!({"kind": "peer", "id": bob})).await;
    // The target has one of them already.
    r.grant_app(&new, json!({"kind": "peer", "id": alice}))
        .await;
    let (_, group) = r
        .post(
            "/api/port-groups",
            json!({"label": "extra", "ports": [{"start": 5000, "end": 5001, "proto": "tcp"}],
                   "apps": [old]}),
        )
        .await;
    let gscope = json!({"kind": "group", "id": id(&group)});
    r.grant(
        json!({"kind": "app", "id": old}),
        gscope.clone(),
        json!({"kind": "peer", "id": bob}),
    )
    .await;
    let (_, tag) = r
        .post(
            "/api/tags",
            json!({"label": "t", "members": [{"app_id": old, "scope": all()}]}),
        )
        .await;
    let old_addr = r.of_app(&old, "ygg").await;
    let all_addr = old_addr
        .iter()
        .find(|a| a["scope"] == all())
        .unwrap()
        .clone();
    let new_addr_before = r.of_app(&new, "ygg").await.remove(0);
    let res = r
        .create_reservation("res", json!([bind(&old, port(8080))]))
        .await;

    let (s, _) = r
        .post(&format!("/api/apps/{old}/move"), json!({"to": old}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "FROM == TO is invalid");
    let (s, _) = r
        .post(&format!("/api/apps/{old}/move"), json!({"to": new}))
        .await;
    assert_eq!(s, StatusCode::OK);

    // Grants: the duplicate is skipped, the others moved; FROM is left bare.
    let (_, grants) = r.get(&format!("/api/grants?app={new}")).await;
    assert_eq!(grants.as_array().unwrap().len(), 3);
    assert!(r
        .get(&format!("/api/grants?app={old}"))
        .await
        .1
        .as_array()
        .unwrap()
        .is_empty());
    // The group the moved grant uses is attached to the target.
    let (_, g) = r.get(&format!("/api/port-groups/{}", id(&group))).await;
    assert!(g["apps"].as_array().unwrap().contains(&json!(new)));
    // The tag membership moved.
    let (_, t) = r.get(&format!("/api/tags/{}", id(&tag))).await;
    assert_eq!(t["members"][0]["app_id"], json!(new));
    // The All address moved with its locator; the target's own was replaced by it.
    let moved = r.of_app(&new, "ygg").await;
    let carried = moved.iter().find(|a| a["scope"] == all()).unwrap();
    assert_eq!(carried["locator"], all_addr["locator"]);
    assert_ne!(carried["locator"], new_addr_before["locator"]);
    assert!(r.of_app(&old, "ygg").await.is_empty());
    // The binding was re-pointed.
    let (_, v) = r.get(&format!("/api/reservations/{}", id(&res))).await;
    assert_eq!(v["bindings"][0]["target"]["app_id"], json!(new));
}

#[tokio::test]
async fn moving_an_anyone_grant_needs_confirmation() {
    let r = Rig::new(vec![sock("old", 8080), sock("new", 9090)]).await;
    let (old, new) = (r.app_id("old").await, r.app_id("new").await);
    r.grant_app(&old, anyone()).await;
    let (s, b) = r
        .post(&format!("/api/apps/{old}/move"), json!({"to": new}))
        .await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::CONFLICT, "confirmation_required")
    );
    // The dry run shows the reach and that someone gains access.
    let (s, b) = r
        .post(
            "/api/changes",
            json!({"dry_run": true, "ops": [{"op": "move_app", "from": old, "to": new,
                                              "confirm_open": true}]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["changes_reach"], true);
    let (s, _) = r
        .post(
            &format!("/api/apps/{old}/move"),
            json!({"to": new, "confirm_open": true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r.of_app(&new, "ygg").await.len(), 1);
}

#[allow(dead_code)]
fn unused(_: Arc<()>) {}

// ─── Migration of v7 addresses ───────────────────────────────────────────────

#[tokio::test]
async fn existing_addresses_become_automatic_reservation_or_dormant() {
    use socketguard_core::{Address, Locator, Scope};
    let r = Rig::new(two_apps()).await;
    let ssh = r.app_id("sshd").await;
    // A grant on port 22 names that row only.
    r.grant(json!({"kind": "app", "id": ssh}), port(22), anyone())
        .await;
    let db = &r.d.state.db;
    let loc = |s: &str| Locator::Ipv6 {
        addr: s.parse().unwrap(),
    };
    // What the v7 schema left: an All address that the port grant covers without naming
    // it, and a port address nothing covers.
    let covered = Address::automatic(&ssh, Scope::All, "ygg", loc("300:1:2:3::777"));
    let idle = Address::automatic(
        &ssh,
        Scope::Port {
            port: 2222,
            proto: socketguard_core::Protocol::Tcp,
        },
        "ygg",
        loc("300:1:2:3::778"),
    );
    db.insert_address(&covered).await.unwrap();
    db.insert_address(&idle).await.unwrap();
    db.set_setting("classify_addresses", "pending")
        .await
        .unwrap();

    let n =
        r.d.state
            .engine
            .read()
            .await
            .classify_legacy_addresses(&r.d.state)
            .await
            .unwrap();
    assert_eq!(n, 1);
    let all = db.list_addresses().await.unwrap();
    let by_id = |id: &str| all.iter().find(|a| a.id == id).unwrap();
    // Covered but not named: the address of a new reservation with the row bound.
    let c = by_id(&covered.id);
    assert_eq!(c.app_id, None);
    let res = db.list_reservations().await.unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].label, "sshd All ports");
    assert_eq!(res[0].bindings.len(), 1);
    assert_eq!(c.reservation_id.as_deref(), Some(res[0].id.as_str()));
    assert_eq!(c.locator, covered.locator, "no address in use changes");
    // Nothing covers the idle one: it is remembered, dormant.
    assert_eq!(by_id(&idle.id).app_id.as_deref(), Some(ssh.as_str()));
    // The named one and the loopback one stay automatic.
    assert!(all
        .iter()
        .any(|a| a.app_id.as_deref() == Some(ssh.as_str()) && a.network_id == "local"));
    assert!(all.iter().any(|a| a.app_id.as_deref() == Some(ssh.as_str())
        && a.network_id == "lan"
        && a.scope
            == Scope::Port {
                port: 22,
                proto: socketguard_core::Protocol::Tcp
            }));
    // Done once.
    let again =
        r.d.state
            .engine
            .read()
            .await
            .classify_legacy_addresses(&r.d.state)
            .await
            .unwrap();
    assert_eq!(again, 0);
}

// ─── Export and apply ────────────────────────────────────────────────────────

#[tokio::test]
async fn reservations_with_bindings_and_grants_export_and_apply() {
    let r = Rig::new(two_apps()).await;
    let (ssh, ng) = (r.app_id("sshd").await, r.app_id("nginx").await);
    let alice = r.peer("alice").await;
    let rid = id(&r
        .create_reservation("web", json!([bind(&ssh, all()), bind(&ng, port(443))]))
        .await);
    r.grant(
        res_target(&rid),
        all(),
        json!({"kind": "peer", "id": alice}),
    )
    .await;

    let (s, doc) = r.get("/api/export").await;
    assert_eq!(s, StatusCode::OK);
    let res = &doc["reservations"][0];
    assert_eq!(res["label"], "web");
    assert_eq!(res["bindings"].as_array().unwrap().len(), 2);
    assert_eq!(res["grants"][0]["subject"], json!({"peer": "alice"}));

    // Applying the same document changes nothing.
    let (s, b) = r
        .post("/api/apply", json!({"document": doc, "dry_run": true}))
        .await;
    assert_eq!((s, &b["changes"]), (StatusCode::OK, &json!([])), "{b}");

    // Release it, and applying the document brings it back with its grant.
    r.delete(&format!("/api/reservations/{rid}")).await;
    assert!(r
        .get("/api/reservations")
        .await
        .1
        .as_array()
        .unwrap()
        .is_empty());
    let (s, b) = r
        .post("/api/apply", json!({"document": doc, "dry_run": false}))
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (_, list) = r.get("/api/reservations").await;
    assert_eq!(list[0]["label"], "web");
    assert_eq!(list[0]["bindings"].as_array().unwrap().len(), 2);
    assert_eq!(list[0]["grants"].as_array().unwrap().len(), 1);
    assert_eq!(
        list[0]["addresses"].as_array().unwrap().len(),
        2,
        "lan and ygg"
    );
    let (_, again) = r.get("/api/export").await;
    assert_eq!(again["reservations"], doc["reservations"]);
}
