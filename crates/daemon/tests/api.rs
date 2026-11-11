//! API v1 through the router (no transport): every route, the error mappings, the
//! confirmation and protect-host rules, export and apply, events and trace propagation.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::*;
use serde_json::{json, Value};
use socketguard_core::api_types::{ApplyRequest, ApplyResponse, ChangeKind, ExportDocument};
use tower::ServiceExt;

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap()
}

// ─── Status, fallback, malformed requests ────────────────────────────────────

#[tokio::test]
async fn status_reports_networks_and_counts() {
    let d = Daemon::new().await;
    let (s, body) = d.get("/api/status").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body["version"].is_string());
    assert_eq!(body["networks"].as_array().unwrap().len(), 3);
    assert_eq!(body["counts"]["apps"], 1);
    assert_eq!(body["counts"]["pending_apps"], 1);
    assert_eq!(
        body["counts"]["addresses"], 1,
        "only loopback until a grant"
    );
    assert_eq!(body["protect_host_interfaces"], json!([]));
}

#[tokio::test]
async fn errors_have_code_and_message() {
    let d = Daemon::new().await;
    let (s, body) = d.get("/api/nope").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "not_found");
    assert!(body["message"].is_string());
    assert!(body.get("details").is_none());

    // Malformed JSON, wrong field type and a bad query value are all 400 `invalid`.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/peers")
        .header("content-type", "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let resp = d.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let (s, body) = d.post("/api/peers", json!({"label": 5})).await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "invalid"));
    let (s, body) = d.get("/api/apps?pending=maybe").await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "invalid"));
}

// ─── Apps ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn apps_list_get_review_and_pending_filter() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;

    let (s, body) = d.get("/api/apps").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(
        d.get("/api/apps?pending=true")
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let (s, body) = d.get(&format!("/api/apps/{app_id}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["name"], "nginx");
    assert_eq!(body["grants"], json!([]));
    assert_eq!(body["counters"], json!([]));
    assert_eq!(body["addresses"].as_array().unwrap().len(), 1);

    let (s, body) = d
        .post(
            &format!("/api/apps/{app_id}/review"),
            json!({"reviewed": true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["reviewed"], true);
    assert_eq!(d.get("/api/apps?pending=true").await.1, json!([]));

    let (s, body) = d.get("/api/apps/nope").await;
    assert_eq!((s, code(&body)), (StatusCode::NOT_FOUND, "not_found"));
    let (s, _) = d
        .post("/api/apps/nope/review", json!({"reviewed": true}))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deleting_an_app_forgets_it_until_it_listens_again() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let (s, _) = d.delete(&format!("/api/apps/{app_id}")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        d.get(&format!("/api/apps/{app_id}")).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        d.delete(&format!("/api/apps/{app_id}")).await.0,
        StatusCode::NOT_FOUND
    );

    d.reconcile().await;
    let (_, body) = d.get("/api/apps?pending=true").await;
    assert_eq!(
        body.as_array().unwrap().len(),
        1,
        "it listens, so it is pending again"
    );
}

// ─── Peers and groups ────────────────────────────────────────────────────────

#[tokio::test]
async fn peers_crud_and_credentials() {
    let d = Daemon::new().await;
    let pid = d.ygg_peer("alice").await;

    let (s, body) = d.get("/api/peers").await;
    assert_eq!((s, body.as_array().unwrap().len()), (StatusCode::OK, 1));
    let (s, body) = d.get(&format!("/api/peers/{pid}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["label"], "alice");
    assert_eq!(body["credentials"][0]["kind"], "ygg_key");

    let (s, body) = d.post("/api/peers", json!({"label": "alice"})).await;
    assert_eq!((s, code(&body)), (StatusCode::CONFLICT, "conflict"));
    let (s, body) = d
        .post(
            "/api/peers",
            json!({"label": "bad", "credentials": [{"kind": "ygg_key", "value": "zz"}]}),
        )
        .await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "invalid"));
    let (s, body) = d
        .post(
            "/api/peers",
            json!({"label": "bob", "credentials": [{"kind": "ygg_key", "value": KEY}]}),
        )
        .await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "conflict"),
        "credentials are unique"
    );

    let (s, body) = d
        .send(
            Method::PATCH,
            &format!("/api/peers/{pid}"),
            json!({"label": "alicia"}),
        )
        .await;
    assert_eq!(
        (s, body["label"].as_str()),
        (StatusCode::OK, Some("alicia"))
    );
    let (s, _) = d
        .send(Method::PATCH, "/api/peers/nope", json!({"label": "x"}))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, cred) = d
        .post(
            &format!("/api/peers/{pid}/credentials"),
            json!({"kind": "ip", "value": "fd00::5", "label": "laptop"}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{cred}");
    assert_eq!(cred["value"], "fd00::5/128", "normalized");
    let (s, _) = d
        .post(
            &format!("/api/peers/{pid}/credentials"),
            json!({"kind": "ip", "value": "fd00::5"}),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let cid = id(&cred);
    assert_eq!(
        d.delete(&format!("/api/peers/{pid}/credentials/{cid}"))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        d.delete(&format!("/api/peers/{pid}/credentials/{cid}"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        d.delete(&format!("/api/peers/{pid}")).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        d.delete(&format!("/api/peers/{pid}")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn groups_crud_and_members() {
    let d = Daemon::new().await;
    let alice = d.ygg_peer("alice").await;
    let (_, bob) = d.post("/api/peers", json!({"label": "bob"})).await;
    let bob = id(&bob);

    let (s, g) = d
        .post(
            "/api/peer-groups",
            json!({"label": "team", "members": [alice]}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    let gid = id(&g);
    assert_eq!(g["members"], json!([alice]));
    assert_eq!(
        d.get("/api/peer-groups").await.1.as_array().unwrap().len(),
        1
    );
    assert_eq!(
        d.get(&format!("/api/peer-groups/{gid}")).await.1["label"],
        "team"
    );

    let (s, body) = d.post("/api/peer-groups", json!({"label": "team"})).await;
    assert_eq!((s, code(&body)), (StatusCode::CONFLICT, "conflict"));
    let (s, body) = d
        .post(
            "/api/peer-groups",
            json!({"label": "x", "members": ["nope"]}),
        )
        .await;
    assert_eq!((s, code(&body)), (StatusCode::NOT_FOUND, "not_found"));

    let (s, g) = d
        .send(
            Method::PATCH,
            &format!("/api/peer-groups/{gid}"),
            json!({"label": "crew"}),
        )
        .await;
    assert_eq!((s, g["label"].as_str()), (StatusCode::OK, Some("crew")));
    let (s, g) = d
        .send(
            Method::PUT,
            &format!("/api/peer-groups/{gid}/members"),
            json!({"peer_ids": [alice, bob]}),
        )
        .await;
    assert_eq!(
        (s, g["members"].as_array().unwrap().len()),
        (StatusCode::OK, 2)
    );
    let (s, _) = d
        .send(
            Method::PUT,
            &format!("/api/peer-groups/{gid}/members"),
            json!({"peer_ids": ["nope"]}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    assert_eq!(
        d.delete(&format!("/api/peer-groups/{gid}")).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        d.get(&format!("/api/peer-groups/{gid}")).await.0,
        StatusCode::NOT_FOUND
    );
}

// ─── Grants ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn grants_with_reach_filters_and_errors() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let alice = d.ygg_peer("alice").await;
    let (_, g) = d
        .post(
            "/api/peer-groups",
            json!({"label": "team", "members": [alice]}),
        )
        .await;
    let gid = id(&g);

    let (s, grant) = d
        .post(
            "/api/grants",
            json!({"target": {"kind": "app", "id": app_id}, "subject": {"kind": "peer", "id": alice}}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{grant}");
    let reach: Vec<_> = grant["reach"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["network_id"].as_str().unwrap(),
                r["reach"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(reach.contains(&("ygg", "verified")) && reach.contains(&("lan", "not_reachable")));
    assert!(
        !reach.iter().any(|(n, _)| *n == "local"),
        "Local takes no grants"
    );
    let grant_id = id(&grant);

    let (s, _) = d
        .post(
            "/api/grants",
            json!({"target": {"kind": "app", "id": app_id}, "subject": {"kind": "group", "id": gid}}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);

    assert_eq!(d.get("/api/grants").await.1.as_array().unwrap().len(), 2);
    assert_eq!(
        d.get(&format!("/api/grants?app={app_id}"))
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(d.get("/api/grants?app=other").await.1, json!([]));
    assert_eq!(
        d.get(&format!("/api/grants?peer={alice}"))
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        2,
        "directly and through the group"
    );
    assert_eq!(
        d.get(&format!("/api/grants?group={gid}"))
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Errors.
    let (s, body) = d
        .post(
            "/api/grants",
            json!({"target": {"kind": "app", "id": app_id}, "subject": {"kind": "peer", "id": alice}}),
        )
        .await;
    assert_eq!((s, code(&body)), (StatusCode::CONFLICT, "conflict"));
    let (s, body) = d
        .post(
            "/api/grants",
            json!({"target": {"kind": "app", "id": "nope"}, "subject": {"kind": "anyone"}, "confirm_open": true}),
        )
        .await;
    assert_eq!((s, code(&body)), (StatusCode::NOT_FOUND, "not_found"));
    let (s, body) = d
        .post("/api/grants", json!({"target": {"kind": "app", "id": app_id}, "scope": {"kind": "port", "port": 9, "proto": "tcp"}, "subject": {"kind": "peer", "id": alice}}))
        .await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "invalid"));
    let (s, body) = d
        .post("/api/grants", json!({"target": {"kind": "app", "id": app_id}, "network_id": "local", "subject": {"kind": "peer", "id": alice}}))
        .await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "local_network"));
    assert_eq!(body["message"], "Local is this machine only");

    assert_eq!(
        d.delete(&format!("/api/grants/{grant_id}")).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        d.delete(&format!("/api/grants/{grant_id}")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_grant_to_anyone_needs_confirmation() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let (s, body) = d
        .post(
            "/api/grants",
            json!({"target": {"kind": "app", "id": app_id}, "subject": {"kind": "anyone"}}),
        )
        .await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "confirmation_required")
    );
    assert_eq!(d.get("/api/grants").await.1, json!([]));

    let (s, grant) = d
        .post(
            "/api/grants",
            json!({"target": {"kind": "app", "id": app_id}, "subject": {"kind": "anyone"}, "confirm_open": true}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{grant}");
    assert!(grant["reach"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["reach"] == "open"));
}

// ─── Networks ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn networks_list_add_and_remove() {
    let d = Daemon::new().await;
    let (s, body) = d.get("/api/networks").await;
    assert_eq!((s, body.as_array().unwrap().len()), (StatusCode::OK, 3));

    let (s, body) = d.post("/api/networks", json!({"type": "ula"})).await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "conflict"),
        "one ULA network only"
    );
    let (s, body) = d
        .post("/api/networks", json!({"type": "dhcpv6", "interface": ""}))
        .await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "invalid"));
    let (s, body) = d
        .post("/api/networks", json!({"type": "carrier-pigeon"}))
        .await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "invalid"));

    let (s, net) = d
        .post(
            "/api/networks",
            json!({"id": "lan2", "type": "slaac", "interface": "eth9", "prefix": "2001:db8:9:9::/64"}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{net}");
    assert_eq!(net["id"], "lan2");
    assert_eq!(net["kind"], "lan");
    assert!(d
        .state
        .engine
        .read()
        .await
        .backend_configs()
        .iter()
        .any(|b| b.id == "lan2"));
    let (s, body) = d
        .post("/api/networks", json!({"id": "lan2", "type": "slaac", "interface": "eth9", "prefix": "2001:db8:9:9::/64"}))
        .await;
    assert_eq!((s, code(&body)), (StatusCode::CONFLICT, "conflict"));

    // A reconcile pass leaves the new network alone.
    d.reconcile().await;
    assert_eq!(d.get("/api/networks").await.1.as_array().unwrap().len(), 4);

    assert_eq!(
        d.delete("/api/networks/lan2").await.0,
        StatusCode::NO_CONTENT
    );
    assert!(!d
        .state
        .engine
        .read()
        .await
        .backend_configs()
        .iter()
        .any(|b| b.id == "lan2"));
    assert_eq!(d.get("/api/networks").await.1.as_array().unwrap().len(), 3);
    assert_eq!(
        d.delete("/api/networks/lan2").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn hostile_interface_names_are_refused() {
    let d = Daemon::new().await;
    let nl = char::from(10u8);
    let hostile = [
        format!("eth0\"{nl} flush ruleset"),
        format!("a{nl}b"),
        "x\";accept".to_string(),
        "x".repeat(65),
    ];
    for name in hostile {
        let (s, body) = d
            .post(
                "/api/networks",
                json!({"type": "dhcpv6", "interface": name}),
            )
            .await;
        assert_eq!(
            (s, code(&body)),
            (StatusCode::BAD_REQUEST, "invalid"),
            "{name:?}"
        );
        let (s, body) = d
            .send(
                Method::PUT,
                "/api/settings/protect-host",
                json!({"interfaces": [name]}),
            )
            .await;
        assert_eq!(
            (s, code(&body)),
            (StatusCode::BAD_REQUEST, "invalid"),
            "{name:?}"
        );
    }
    assert_eq!(d.get("/api/networks").await.1.as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn networks_are_saved_to_the_config_file() {
    let dir = std::env::temp_dir().join(format!("sg-cfg-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("socketguard.json");
    let backends = |path: &std::path::Path| -> Vec<String> {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["backends"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["id"].as_str().unwrap().to_string())
            .collect()
    };
    let add = |id: &str, iface: &str, prefix: &str| json!({"id": id, "type": "slaac", "interface": iface, "prefix": prefix});

    // No file yet: the first change creates it, with the daemon's whole config.
    let d = Daemon::new_at(Some(path.clone())).await;
    assert!(!path.exists());
    let (s, _) = d
        .post("/api/networks", add("lan2", "eth9", "2001:db8:9:9::/64"))
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(backends(&path), ["lan", "lan2", "local", "ygg"]);

    // An existing file keeps its other keys; nothing is left behind.
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    v["poll_interval_secs"] = json!(17);
    v["something_else"] = json!({"kept": true});
    std::fs::write(&path, v.to_string()).unwrap();
    assert_eq!(
        d.delete("/api/networks/lan2").await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(backends(&path), ["lan", "local", "ygg"]);
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(v["poll_interval_secs"], 17);
    assert_eq!(v["something_else"], json!({"kept": true}));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no temp file");

    // The file loads back as a config.
    let loaded: socketguard_core::config::DaemonConfig =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(loaded.backends.len(), 3);

    // A file that is not an object is not overwritten; the change still happens.
    std::fs::write(&path, "[1]").unwrap();
    let (s, _) = d
        .post("/api/networks", add("lan3", "eth8", "2001:db8:8:8::/64"))
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[1]");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn concurrent_network_changes_are_all_saved() {
    let dir = std::env::temp_dir().join(format!("sg-cfg-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("socketguard.json");
    let d = Daemon::new_at(Some(path.clone())).await;
    let add = |id: &str, iface: &str, prefix: &str| json!({"id": id, "type": "slaac", "interface": iface, "prefix": prefix});
    let ((s1, _), (s2, _), (s3, _)) = tokio::join!(
        d.post("/api/networks", add("lan2", "eth7", "2001:db8:7:7::/64")),
        d.post("/api/networks", add("lan3", "eth8", "2001:db8:8:8::/64")),
        d.post("/api/networks", add("lan4", "eth9", "2001:db8:9:9::/64")),
    );
    assert_eq!(
        (s1, s2, s3),
        (
            StatusCode::CREATED,
            StatusCode::CREATED,
            StatusCode::CREATED
        )
    );
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let ids: Vec<&str> = saved["backends"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["lan", "lan2", "lan3", "lan4", "local", "ygg"]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Settings, protect-host ──────────────────────────────────────────────────

#[tokio::test]
async fn settings_have_only_protect_host() {
    let d = Daemon::new().await;
    let (s, body) = d.get("/api/settings").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["protect_host_interfaces"], json!([]));
    assert!(body.get("address_mode").is_none());
    let (s, _) = d.send(Method::PUT, "/api/settings", json!({})).await;
    assert_eq!(
        s,
        StatusCode::METHOD_NOT_ALLOWED,
        "the address mode setting is gone"
    );
}

#[tokio::test]
async fn protect_host_is_refused_with_the_risks_unless_forced() {
    let d = Daemon::new().await;
    d.sockets.lock().unwrap().push(listener("sshd", 22));
    d.reconcile().await;

    let (s, body) = d
        .send(
            Method::PUT,
            "/api/settings/protect-host",
            json!({"interfaces": ["eth0"]}),
        )
        .await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "protect_host_refused"),
        "{body}"
    );
    let risks = body["details"].as_array().unwrap();
    assert_eq!(risks[0]["process_name"], "sshd");
    assert_eq!(risks[0]["port"], 22);
    assert_eq!(
        d.get("/api/settings").await.1["protect_host_interfaces"],
        json!([])
    );

    let (s, body) = d
        .send(
            Method::PUT,
            "/api/settings/protect-host",
            json!({"interfaces": ["eth0"], "force": true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["settings"]["protect_host_interfaces"], json!(["eth0"]));
    assert_eq!(body["overridden"][0]["process_name"], "sshd");

    let (s, body) = d
        .send(
            Method::PUT,
            "/api/settings/protect-host",
            json!({"interfaces": []}),
        )
        .await;
    assert_eq!(
        (s, body["settings"]["protect_host_interfaces"].clone()),
        (StatusCode::OK, json!([]))
    );
}

// ─── Activity and disable ────────────────────────────────────────────────────

#[tokio::test]
async fn activity_is_filterable() {
    let d = Daemon::new().await;
    let alice = d.ygg_peer("alice").await;
    let (s, all) = d.get("/api/activity").await;
    assert_eq!(s, StatusCode::OK);
    let kinds: Vec<&str> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"app_discovered") && kinds.contains(&"peer_added"));

    let (_, only) = d.get("/api/activity?kind=peer_added").await;
    assert_eq!(only.as_array().unwrap().len(), 1);
    assert_eq!(
        d.get("/api/activity?limit=1")
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let first = all[0]["id"].as_i64().unwrap();
    let (_, older) = d.get(&format!("/api/activity?before={first}")).await;
    assert_eq!(
        older.as_array().unwrap().len(),
        all.as_array().unwrap().len() - 1
    );
    assert_eq!(
        d.get("/api/activity?since=2999-01-01T00:00:00Z").await.1,
        json!([])
    );
    // The query string is `ActivityQuery`: `peer_id` and `app_id` select by id.
    let (_, mine) = d.get(&format!("/api/activity?peer_id={alice}")).await;
    let mine = mine.as_array().unwrap();
    assert!(!mine.is_empty() && mine.iter().all(|r| r["peer_id"] == alice.as_str()));
    assert!(mine.len() < all.as_array().unwrap().len());
    assert_eq!(d.get("/api/activity?peer_id=nobody").await.1, json!([]));
    assert_eq!(d.get("/api/activity?app_id=nobody").await.1, json!([]));
    let (s, body) = d.get("/api/activity?kind=nonsense").await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "invalid"));
}

#[tokio::test]
async fn disable_needs_confirmation() {
    use socketguard_daemon::test_support::FirewallCall;
    let d = Daemon::new().await;
    let (s, body) = d.post("/api/disable", json!({"confirm": false})).await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "confirmation_required")
    );
    assert_eq!(d.get("/api/status").await.1["disabled"], false);
    let (s, _) = d.post("/api/disable", json!({"confirm": true})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(d.get("/api/status").await.1["disabled"], true);
    assert!(d
        .fw
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| matches!(c, FirewallCall::Disable)));
}

#[tokio::test]
async fn enable_clears_the_latch_and_reapplies() {
    use socketguard_daemon::test_support::FirewallCall;
    let d = Daemon::new().await;
    d.post("/api/disable", json!({"confirm": true})).await;
    d.fw.calls.lock().unwrap().clear();

    // A reconcile while disabled applies nothing.
    d.reconcile().await;
    assert!(d.fw.calls.lock().unwrap().is_empty());

    let (s, _) = d.post("/api/enable", json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(d.get("/api/status").await.1["disabled"], false);
    assert!(d
        .fw
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| matches!(c, FirewallCall::Apply(_))));
}

// ─── Events ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn events_stream_pushes_named_events() {
    use http_body_util::BodyExt;
    let d = Daemon::new().await;
    let req = Request::builder()
        .uri("/api/events")
        .body(Body::empty())
        .unwrap();
    let resp = d.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut body = resp.into_body();

    d.ygg_peer("alice").await;
    let mut seen = String::new();
    let wait = async {
        while !(seen.contains("event: peers_changed") && seen.contains("event: activity")) {
            let frame = body.frame().await.unwrap().unwrap();
            if let Some(data) = frame.data_ref() {
                seen.push_str(&String::from_utf8_lossy(data));
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), wait)
        .await
        .unwrap_or_else(|_| panic!("events not pushed, got: {seen:?}"));
}

// ─── Export and apply ────────────────────────────────────────────────────────

async fn export(d: &Daemon) -> ExportDocument {
    let (s, body) = d.get("/api/export").await;
    assert_eq!(s, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

async fn apply(d: &Daemon, document: &ExportDocument, dry_run: bool) -> (StatusCode, Value) {
    d.post(
        "/api/apply",
        serde_json::to_value(ApplyRequest {
            document: document.clone(),
            dry_run,
        })
        .unwrap(),
    )
    .await
}

async fn apply_ok(d: &Daemon, document: &ExportDocument, dry_run: bool) -> ApplyResponse {
    let (s, body) = apply(d, document, dry_run).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

/// alice (ygg key + ip), bob, group team = {alice, bob}, nginx granted to alice and to
/// team, and to Anyone on ygg.
async fn populated() -> Daemon {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let alice = d.ygg_peer("alice").await;
    d.post(
        &format!("/api/peers/{alice}/credentials"),
        json!({"kind": "ip", "value": "fd00::5", "label": "laptop"}),
    )
    .await;
    let (_, bob) = d.post("/api/peers", json!({"label": "bob"})).await;
    let (_, team) = d
        .post(
            "/api/peer-groups",
            json!({"label": "team", "members": [alice, id(&bob)]}),
        )
        .await;
    for subject in [
        json!({"kind": "peer", "id": alice}),
        json!({"kind": "group", "id": id(&team)}),
    ] {
        let (s, b) = d
            .post(
                "/api/grants",
                json!({"target": {"kind": "app", "id": app_id}, "subject": subject}),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
    }
    let (s, b) = d
        .post("/api/grants", json!({"target": {"kind": "app", "id": app_id}, "network_id": "ygg", "scope": {"kind": "port", "port": 80, "proto": "tcp"}, "subject": {"kind": "anyone"}, "confirm_open": true}))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    d
}

#[tokio::test]
async fn export_has_the_documented_shape() {
    let d = populated().await;
    let (s, body) = d.get("/api/export").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["version"], 1);
    assert!(body["settings"].get("address_mode").is_none());
    assert_eq!(body["peers"][0]["label"], "alice");
    assert_eq!(body["peers"][0]["credentials"][0]["kind"], "ip");
    assert_eq!(
        body["groups"][0],
        json!({"label": "team", "members": ["alice", "bob"]})
    );
    let grants = body["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 3);
    assert!(grants
        .iter()
        .any(|g| g["subject"] == "anyone" && g["network"] == "ygg" && g["app"]["name"] == "nginx"));
    assert!(grants
        .iter()
        .any(|g| g["subject"] == json!({"peer": "alice"})));
    assert!(grants
        .iter()
        .any(|g| g["subject"] == json!({"group": "team"})));
}

#[tokio::test]
async fn export_then_apply_is_an_empty_diff() {
    let d = populated().await;
    let doc = export(&d).await;
    for dry_run in [true, false] {
        let r = apply_ok(&d, &doc, dry_run).await;
        assert!(r.is_empty(), "{r:?}");
        assert_eq!(r.dry_run, dry_run);
    }
    assert_eq!(export(&d).await, doc);
}

#[tokio::test]
async fn apply_dry_run_reports_and_changes_nothing() {
    let d = populated().await;
    let app = d.state.db.list_apps().await.unwrap().remove(0);
    let before = export(&d).await;
    let mut doc = before.clone();
    doc.settings.protect_host_interfaces = vec!["eth0".into()];
    doc.peers.retain(|p| p.label != "bob");
    doc.peers.push(
        serde_json::from_value(
            json!({"label": "carol", "credentials": [{"kind": "ip", "value": "fd00::9"}]}),
        )
        .unwrap(),
    );
    doc.groups[0].members = vec!["alice".into(), "carol".into()];
    doc.grants.retain(|g| {
        g.subject
            != serde_json::from_value::<socketguard_core::api_types::ExportSubject>(json!("anyone"))
                .unwrap()
    });
    doc.grants.push(
        serde_json::from_value(
            json!({"app": {"id": app.id, "name": "nginx"}, "network": "lan", "subject": "anyone"}),
        )
        .unwrap(),
    );

    let r = apply_ok(&d, &doc, true).await;
    assert!(r.dry_run);
    let summary: Vec<String> = r
        .changes
        .iter()
        .map(|c| format!("{:?} {:?} {}", c.kind, c.item, c.name))
        .collect();
    let has = |s: &str| assert!(summary.iter().any(|x| x.contains(s)), "{s} in {summary:#?}");
    has("Update Setting protect_host_interfaces");
    has("Create Peer carol");
    has("Delete Peer bob");
    has("Update Group team");
    has("Delete Grant nginx 80/tcp on ygg to Anyone");
    has("Create Grant nginx on lan to Anyone");
    assert!(
        r.changes.iter().filter(|c| c.opens_to_anyone).count() == 2,
        "both Anyone changes are marked"
    );
    assert!(r
        .changes
        .iter()
        .all(|c| c.kind != ChangeKind::Update || c.detail.is_some()));
    assert_eq!(export(&d).await, before, "a dry run changes nothing");
}

#[tokio::test]
async fn apply_accepts_and_ignores_the_address_mode_of_an_old_document() {
    let d = populated().await;
    let mut doc = serde_json::to_value(export(&d).await).unwrap();
    doc["settings"]["address_mode"] = json!("per_port");
    let (s, body) = d
        .post("/api/apply", json!({"document": doc, "dry_run": false}))
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["changes"], json!([]), "the field changes nothing");
    let settings = d.get("/api/settings").await.1;
    assert!(settings.get("address_mode").is_none());
}

#[tokio::test]
async fn apply_makes_the_state_match_the_document() {
    let d = populated().await;
    let app = d.state.db.list_apps().await.unwrap().remove(0);
    let mut doc = export(&d).await;
    // alice loses her laptop; carol gets it (a credential moves between peers); bob goes.
    doc.peers.retain(|p| p.label != "bob");
    doc.peers[0]
        .credentials
        .retain(|c| c.value != "fd00::5/128");
    doc.peers.push(serde_json::from_value(json!({"label": "carol", "credentials": [{"kind": "ip", "value": "fd00::5", "label": "laptop"}]})).unwrap());
    doc.groups[0].members = vec!["alice".into(), "carol".into()];
    doc.grants.clear();
    doc.grants.push(
        serde_json::from_value(
            json!({"app": {"id": app.id, "name": "x"}, "subject": {"group": "team"}}),
        )
        .unwrap(),
    );
    doc.grants.push(serde_json::from_value(json!({"app": {"id": app.id, "name": "x"}, "scope": {"kind": "port", "port": 80, "proto": "tcp"}, "subject": "anyone"})).unwrap());

    let r = apply_ok(&d, &doc, false).await;
    assert!(!r.is_empty() && !r.dry_run);

    // Converged: the same document is now an empty diff.
    let again = apply_ok(&d, &doc, true).await;
    assert!(again.is_empty(), "{again:?}");
    let now = export(&d).await;
    assert_eq!(
        now.peers
            .iter()
            .map(|p| p.label.as_str())
            .collect::<Vec<_>>(),
        ["alice", "carol"]
    );
    assert_eq!(now.grants.len(), 2);
    // The Anyone grant in the file counted as confirmed, and is in force.
    let grants = d.get("/api/grants").await.1;
    assert!(grants
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["subject"]["kind"] == "anyone"));
}

#[tokio::test]
async fn apply_rejects_documents_that_cannot_be_applied() {
    let d = populated().await;
    let good = export(&d).await;
    let bad = |f: &dyn Fn(&mut ExportDocument)| {
        let mut doc = good.clone();
        f(&mut doc);
        doc
    };
    let docs = [
        bad(&|d| d.version = 2),
        bad(&|d| d.groups[0].members.push("nobody".into())),
        bad(&|d| d.peers.push(d.peers[0].clone())),
        bad(&|d| d.grants[0].app.id = "nope".into()),
        bad(&|d| d.grants[0].subject = serde_json::from_value(json!({"peer": "nobody"})).unwrap()),
        bad(&|d| d.grants[0].network = Some("nope".into())),
        bad(&|d| d.peers[0].credentials[0].value = "not an address".into()),
    ];
    for doc in docs {
        let (s, body) = apply(&d, &doc, false).await;
        assert_eq!(
            (s, code(&body)),
            (StatusCode::BAD_REQUEST, "invalid"),
            "{body}"
        );
    }
    let (s, body) = apply(
        &d,
        &bad(&|d| d.grants[0].network = Some("local".into())),
        false,
    )
    .await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "local_network"));
    assert_eq!(export(&d).await, good, "nothing was applied");
}
