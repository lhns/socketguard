//! ADR 0051: a Yggdrasil network is closed from the moment it is added, whatever its node does,
//! and leaving it says what stays reachable.

mod common;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::{call, listener};
use serde_json::{json, Value};
use socketguard_core::config::DaemonConfig;
use socketguard_daemon::api;
use socketguard_daemon::firewall::{DesiredRuleset, ScopeMatch};
use socketguard_daemon::networks::ip::yggdrasil::NOT_RUNNING;
use socketguard_daemon::test_support::*;

const ADDR: &str = "200:1:2:3::5";
const SUBNET: &str = "300:1:2:3::/64";

struct Fixture {
    d: StandardDaemon,
    app: Router,
}

impl Fixture {
    async fn new(nets: Vec<Net>, config_path: Option<std::path::PathBuf>) -> Self {
        let d = daemon_with(
            nets,
            vec![listener("nginx", 80)],
            DaemonConfig::default(),
            config_path,
        )
        .await;
        let app = api::router(d.state.clone());
        let f = Self { d, app };
        f.reconcile().await;
        f
    }

    async fn reconcile(&self) {
        let engine = self.d.state.engine.read().await;
        engine.reconcile(&self.d.state).await.unwrap();
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        call(&self.app, Method::GET, path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        call(&self.app, Method::POST, path, Some(body)).await
    }

    async fn delete(&self, path: &str) -> (StatusCode, Value) {
        call(&self.app, Method::DELETE, path, None).await
    }

    fn last(&self) -> DesiredRuleset {
        applied(&self.d.fw_calls)
            .pop()
            .expect("a ruleset was applied")
    }

    fn net_scopes(&self) -> Vec<(String, String)> {
        self.last()
            .scopes
            .iter()
            .filter_map(|s| match &s.matcher {
                ScopeMatch::DestinationNet(n) => Some((s.id.clone(), n.to_string())),
                _ => None,
            })
            .collect()
    }

    fn has_interface_scope(&self, name: &str) -> bool {
        self.last()
            .scopes
            .iter()
            .any(|s| matches!(&s.matcher, ScopeMatch::Interface { name: n, .. } if n == name))
    }
}

fn with_ygg() -> Vec<Net> {
    vec![local_net(), lan_net(), ygg_net()]
}

fn range_scope() -> Vec<(String, String)> {
    vec![("overlay:ygg:range".to_string(), "200::/7".to_string())]
}

#[tokio::test]
async fn an_existing_node_is_closed_by_the_whole_range_whatever_it_does() {
    let f = Fixture::new(with_ygg(), None).await;
    // Never seen: the range is there already, beside the configured interface.
    assert_eq!(f.net_scopes(), range_scope());
    assert!(f.has_interface_scope("ygg0"));
    let (_, setup) = f.get("/api/networks/setup").await;
    let block = &setup["yggdrasil_block"];
    assert_eq!(block["closed"], true);
    assert_eq!(block["address_blocked"], true);
    assert_eq!(block["interface_blocked"], true);
    assert!(block.get("reason").is_none(), "{block}");

    // The node answers: the same scope, and nothing is remembered about it.
    f.d.nets["ygg"].set_node(ADDR, SUBNET);
    f.reconcile().await;
    assert_eq!(f.net_scopes(), range_scope());
    assert_eq!(
        f.d.state.db.get_setting("ygg_node:ygg").await.unwrap(),
        None
    );

    // It stops, and its adapter is gone: still closed.
    f.d.nets["ygg"].clear_node();
    f.d.nets["ygg"].set_problem(Some(NOT_RUNNING));
    f.d.net.set_interface_missing("ygg0", true);
    f.reconcile().await;
    assert_eq!(f.net_scopes(), range_scope());
    let (_, setup) = f.get("/api/networks/setup").await;
    assert_eq!(setup["yggdrasil_block"]["closed"], true);
}

#[tokio::test]
async fn an_address_of_another_node_on_the_host_is_inside_the_range() {
    let f = Fixture::new(with_ygg(), None).await;
    let theirs: std::net::IpAddr = "200:9:9:9::7".parse().unwrap();
    let range = f
        .last()
        .scopes
        .into_iter()
        .find_map(|s| match s.matcher {
            ScopeMatch::DestinationNet(n) if s.id == "overlay:ygg:range" => Some(n),
            _ => None,
        })
        .expect("the range scope");
    assert!(range.contains(&theirs));
}

#[tokio::test]
async fn an_existing_node_that_does_not_answer_cannot_be_added() {
    // No Yggdrasil yet; the one named answers nothing.
    let f = Fixture::new(vec![local_net(), lan_net()], None).await;
    let (s, body) = f
        .post(
            "/api/networks",
            json!({"type": "yggdrasil", "interface": "Yggdrasil", "admin_endpoint": "tcp://127.0.0.1:1"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("does not answer"),
        "{body}"
    );
    assert_eq!(f.get("/api/networks").await.1.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn the_exposure_lists_listeners_on_all_addresses() {
    let dir = std::env::temp_dir().join(format!("sg-exp-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("socketguard.json");
    let f = Fixture::new(with_ygg(), Some(config)).await;
    let (s, e) = f.get("/api/exposure?without=ygg").await;
    assert_eq!(s, StatusCode::OK, "{e}");
    let n = &e["networks"][0];
    assert_eq!(n["network"], "ygg");
    assert_eq!(n["kind"], "yggdrasil");
    assert_eq!(n["interface"], "ygg0");
    assert_eq!(n["node_running"], true);
    assert_eq!(
        n["listeners"],
        json!([{"app": "nginx", "port": 80, "proto": "tcp"}])
    );
    // Without a name, or `all`, every Yggdrasil network; other networks are not in it.
    for q in ["/api/exposure", "/api/exposure?without=all"] {
        let (s, e) = f.get(q).await;
        assert_eq!(
            (s, e["networks"].as_array().unwrap().len()),
            (StatusCode::OK, 1)
        );
    }
    let (_, e) = f.get("/api/exposure?without=lan").await;
    assert!(e["networks"].as_array().unwrap().is_empty());
    assert_eq!(
        f.get("/api/exposure?without=nope").await.0,
        StatusCode::NOT_FOUND
    );

    // A node that does not run exposes nothing.
    f.d.nets["ygg"].set_problem(Some(NOT_RUNNING));
    let (_, e) = f.get("/api/exposure?without=ygg").await;
    assert_eq!(e["networks"][0]["node_running"], false);
    assert_eq!(e["networks"][0]["listeners"], json!([]));
}

#[tokio::test]
async fn removing_a_network_whose_node_runs_needs_confirm_exposed() {
    let f = Fixture::new(with_ygg(), None).await;
    let (s, body) = f.delete("/api/networks/ygg").await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "confirmation_required");
    assert_eq!(body["details"]["networks"][0]["node_running"], true);
    assert_eq!(
        body["details"]["networks"][0]["listeners"][0]["app"],
        "nginx"
    );
    assert_eq!(f.get("/api/networks").await.1.as_array().unwrap().len(), 3);

    let (s, body) = f.delete("/api/networks/ygg?confirm_exposed=true").await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(f.get("/api/networks").await.1.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn removing_a_network_whose_node_is_down_needs_no_confirmation() {
    let f = Fixture::new(with_ygg(), None).await;
    f.d.nets["ygg"].set_problem(Some(NOT_RUNNING));
    let (s, body) = f.delete("/api/networks/ygg").await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn removing_the_network_removes_its_range_scope() {
    let f = Fixture::new(with_ygg(), None).await;
    assert_eq!(f.net_scopes(), range_scope());
    let (s, _) = f.delete("/api/networks/ygg?confirm_exposed=true").await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(f.net_scopes().is_empty());
}

#[tokio::test]
async fn where_an_interface_rule_needs_the_adapter_it_is_not_counted_until_the_adapter_exists() {
    // WFP cannot make a filter for an adapter that is not there: the desired ruleset names
    // it, but nothing is enforced, so setup must not start the service on that basis.
    let f = Fixture::new(with_ygg(), None).await;
    f.d.fw.set_blocks_absent_interfaces(false);
    let (_, setup) = f.get("/api/networks/setup").await;
    let block = &setup["yggdrasil_block"];
    assert_eq!(block["interface_blocked"], false, "{block}");
    // The range scope closes the node without the adapter.
    assert_eq!(block["closed"], true, "{block}");

    f.d.net.add_interface("ygg0");
    let (_, setup) = f.get("/api/networks/setup").await;
    assert_eq!(setup["yggdrasil_block"]["interface_blocked"], true);

    // Where interface rules hold for absent adapters (nftables, pf) the scope counts.
    f.d.net.set_interface_missing("ygg0", true);
    f.d.fw.set_blocks_absent_interfaces(true);
    let (_, setup) = f.get("/api/networks/setup").await;
    assert_eq!(setup["yggdrasil_block"]["interface_blocked"], true);
}

#[tokio::test]
async fn a_port_also_bound_on_loopback_is_still_listed_as_exposed() {
    let f = Fixture::new(with_ygg(), None).await;
    let mut local = listener("nginx", 80);
    local.bind_address = "127.0.0.1".parse().unwrap();
    f.d.sockets.lock().unwrap().push(local);
    f.d.sockets.lock().unwrap().push(listener("dnsmasq", 53));
    let (_, e) = f.get("/api/exposure?without=ygg").await;
    assert_eq!(
        e["networks"][0]["listeners"],
        json!([
            {"app": "dnsmasq", "port": 53, "proto": "tcp"},
            {"app": "nginx", "port": 80, "proto": "tcp"}
        ])
    );
}
