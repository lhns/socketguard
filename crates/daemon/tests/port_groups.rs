//! Port groups (ADR 0047) through the API: their lifecycle, attachment, use as a scope
//! in grants, tag members and addresses, the refusals while they are used, the batch
//! operations and export/apply.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{json, Value};
use socketguard_daemon::test_support::applied;

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap()
}

fn rule_ids(d: &Daemon) -> Vec<String> {
    applied(&d.fw.calls)
        .last()
        .map(|r| r.rules.iter().map(|r| r.id.clone()).collect())
        .unwrap_or_default()
}

fn app_target(app_id: &str) -> Value {
    json!({"kind": "app", "id": app_id})
}

async fn create_group(d: &Daemon, label: &str, ports: Value) -> String {
    let (s, body) = d
        .post("/api/port-groups", json!({"label": label, "ports": ports}))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    id(&body)
}

fn passive() -> Value {
    json!([{"start": 50000, "end": 50010, "proto": "tcp"}, {"start": 21, "end": 21, "proto": "tcp"}])
}

async fn attach(d: &Daemon, gid: &str, app_id: &str, confirm: bool) -> (StatusCode, Value) {
    d.send(
        Method::PUT,
        &format!("/api/port-groups/{gid}/apps/{app_id}"),
        json!({"confirm_open": confirm}),
    )
    .await
}

fn group_scope(gid: &str) -> Value {
    json!({"kind": "group", "id": gid})
}

#[tokio::test]
async fn groups_are_created_listed_changed_and_validated() {
    let d = Daemon::new().await;
    let gid = create_group(&d, "passive", passive()).await;

    // Ports are normalized: sorted.
    let (_, g) = d.get(&format!("/api/port-groups/{gid}")).await;
    assert_eq!(g["label"], "passive");
    assert_eq!(g["ports"][0]["start"], 21);
    assert_eq!(g["ports"][1]["end"], 50010);
    assert_eq!(g["apps"], json!([]));
    assert_eq!(
        d.get("/api/port-groups").await.1.as_array().unwrap().len(),
        1
    );

    // Labels are unique; ports are needed and valid.
    let (s, b) = d
        .post(
            "/api/port-groups",
            json!({"label": "passive", "ports": passive()}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::CONFLICT, "conflict"));
    let (s, b) = d
        .post("/api/port-groups", json!({"label": "x", "ports": []}))
        .await;
    assert_eq!((s, code(&b)), (StatusCode::BAD_REQUEST, "invalid"));
    let (s, b) = d
        .post(
            "/api/port-groups",
            json!({"label": "x", "ports": [{"start": 9, "end": 5, "proto": "tcp"}]}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::BAD_REQUEST, "invalid"));

    // PUT changes the label and/or ports.
    let (s, g) = d
        .send(
            Method::PUT,
            &format!("/api/port-groups/{gid}"),
            json!({"label": "ftp", "ports": [{"start": 2121, "end": 2121, "proto": "tcp"}]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{g}");
    assert_eq!(
        (g["label"].as_str(), g["ports"].as_array().unwrap().len()),
        (Some("ftp"), 1)
    );
    let (s, _) = d
        .send(Method::PUT, "/api/port-groups/nope", json!({"label": "z"}))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    assert_eq!(
        d.delete(&format!("/api/port-groups/{gid}")).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        d.get(&format!("/api/port-groups/{gid}")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn attached_groups_show_in_the_app_and_give_range_rules() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let peer = d.ygg_peer("alice").await;
    let gid = create_group(&d, "passive", passive()).await;

    // A group scope needs the group attached to the app.
    let grant = json!({"target": app_target(&app_id), "scope": group_scope(&gid),
                       "subject": {"kind": "peer", "id": peer}});
    let (s, b) = d.post("/api/grants", grant.clone()).await;
    assert_eq!((s, code(&b)), (StatusCode::BAD_REQUEST, "invalid"), "{b}");

    let (s, g) = attach(&d, &gid, &app_id, false).await;
    assert_eq!(s, StatusCode::OK, "{g}");
    assert_eq!(g["apps"], json!([app_id]));
    // Attaching again changes nothing.
    assert_eq!(attach(&d, &gid, &app_id, false).await.0, StatusCode::OK);
    let (_, detail) = d.get(&format!("/api/apps/{app_id}")).await;
    assert_eq!(detail["port_groups"][0]["label"], "passive");

    let (s, b) = d.post("/api/grants", grant).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(b["scope"], group_scope(&gid));
    let ids = rule_ids(&d);
    assert!(
        ids.iter().any(|r| r.contains(":50000-50010:tcp:")),
        "{ids:?}"
    );
    assert!(ids.iter().any(|r| r.contains(":21:tcp:")), "{ids:?}");
    assert!(
        ids.iter().all(|r| !r.contains(":80:tcp:")),
        "only the group is granted"
    );

    // A tag member by group needs the attachment too.
    let (_, tag) = d.post("/api/tags", json!({"label": "ftp"})).await;
    let other = create_group(
        &d,
        "other",
        json!([{"start": 7000, "end": 7001, "proto": "udp"}]),
    )
    .await;
    let (s, _) = d
        .post(
            &format!("/api/tags/{}/members", id(&tag)),
            json!({"app_id": app_id, "scope": group_scope(&other)}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, t) = d
        .post(
            &format!("/api/tags/{}/members", id(&tag)),
            json!({"app_id": app_id, "scope": group_scope(&gid)}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{t}");
    assert_eq!(t["members"][0]["scope"], group_scope(&gid));
}

#[tokio::test]
async fn a_group_in_use_cannot_be_detached_or_deleted_and_the_message_says_why() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let peer = d.ygg_peer("alice").await;
    let gid = create_group(&d, "passive", passive()).await;
    attach(&d, &gid, &app_id, false).await;
    let (_, grant) = d
        .post(
            "/api/grants",
            json!({"target": app_target(&app_id), "scope": group_scope(&gid),
                   "subject": {"kind": "peer", "id": peer}}),
        )
        .await;
    let (_, tag) = d.post("/api/tags", json!({"label": "ftp"})).await;
    d.post(
        &format!("/api/tags/{}/members", id(&tag)),
        json!({"app_id": app_id, "scope": group_scope(&gid)}),
    )
    .await;

    let (s, b) = d
        .delete(&format!("/api/port-groups/{gid}/apps/{app_id}"))
        .await;
    assert_eq!((s, code(&b)), (StatusCode::CONFLICT, "conflict"));
    let msg = b["message"].as_str().unwrap();
    assert!(msg.contains("grant to alice on nginx"), "{msg}");
    assert!(msg.contains("nginx in tag ftp"), "{msg}");
    let (s, b) = d.delete(&format!("/api/port-groups/{gid}")).await;
    assert_eq!((s, code(&b)), (StatusCode::CONFLICT, "conflict"));
    assert!(b["message"].as_str().unwrap().contains("tag ftp"));

    // A grant on a tag with the group scope blocks a delete, not a detach.
    d.delete(&format!("/api/grants/{}", id(&grant))).await;
    d.delete(&format!(
        "/api/tags/{}/members/{app_id}?group={gid}",
        id(&tag)
    ))
    .await;
    let (_, tag_grant) = d
        .post(
            "/api/grants",
            json!({"target": {"kind": "tag", "id": id(&tag)}, "scope": group_scope(&gid),
                   "subject": {"kind": "peer", "id": peer}}),
        )
        .await;
    assert_eq!(tag_grant["scope"], group_scope(&gid));
    let (s, b) = d.delete(&format!("/api/port-groups/{gid}")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    let (s, b) = d
        .delete(&format!("/api/port-groups/{gid}/apps/{app_id}"))
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["apps"], json!([]));
    d.delete(&format!("/api/grants/{}", id(&tag_grant))).await;
    assert_eq!(
        d.delete(&format!("/api/port-groups/{gid}")).await.0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn an_address_for_a_group_goes_when_the_group_is_detached() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let gid = create_group(&d, "passive", passive()).await;
    attach(&d, &gid, &app_id, false).await;
    // A grant that names the group gives the group its own address.
    let (s, g) = d
        .post(
            "/api/grants",
            json!({"target": app_target(&app_id), "scope": group_scope(&gid),
                   "subject": {"kind": "anyone"}, "confirm_open": true}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    let addrs = d.get("/api/addresses").await.1;
    let a = addrs
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["network_id"] == "ygg" && a["scope"] == group_scope(&gid))
        .expect("the group has an address")
        .clone();
    let ip: std::net::Ipv6Addr = a["locator"]["addr"].as_str().unwrap().parse().unwrap();
    // Detaching is refused while the grant uses the group there, and allowed after.
    let (s, b) = d
        .delete(&format!("/api/port-groups/{gid}/apps/{app_id}"))
        .await;
    assert_eq!((s, code(&b)), (StatusCode::CONFLICT, "conflict"));
    d.delete(&format!("/api/grants/{}", g["id"].as_str().unwrap()))
        .await;
    assert!(d
        .state
        .db
        .list_addresses()
        .await
        .unwrap()
        .iter()
        .any(|x| x.locator.ipv6() == Some(ip)));

    let (s, b) = d
        .delete(&format!("/api/port-groups/{gid}/apps/{app_id}"))
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let left = d.state.db.list_addresses().await.unwrap();
    assert!(
        left.iter().all(|x| x.locator.ipv6() != Some(ip)),
        "the group address went"
    );
    // The ruleset no longer names it as a managed destination.
    let rs = applied(&d.fw.calls).last().cloned().unwrap();
    assert!(rs.scopes.iter().all(|s| !matches!(
        &s.matcher,
        socketguard_daemon::firewall::ScopeMatch::Destinations(d)
            if d.contains(&std::net::IpAddr::V6(ip))
    )));
}

#[tokio::test]
async fn attaching_or_widening_under_a_grant_to_anyone_needs_confirm_open() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let gid = create_group(&d, "passive", passive()).await;
    d.post(
        "/api/grants",
        json!({"target": app_target(&app_id), "subject": {"kind": "anyone"}, "confirm_open": true}),
    )
    .await;
    let before = rule_ids(&d);

    let (s, b) = attach(&d, &gid, &app_id, false).await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::CONFLICT, "confirmation_required"),
        "{b}"
    );
    assert_eq!(rule_ids(&d), before, "nothing changed");
    let (s, b) = attach(&d, &gid, &app_id, true).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(rule_ids(&d).iter().any(|r| r.contains(":50000-50010:tcp:")));

    // New ports of an attached group widen the grant too.
    let (s, b) = d
        .send(
            Method::PUT,
            &format!("/api/port-groups/{gid}"),
            json!({"ports": [{"start": 60000, "end": 60010, "proto": "tcp"}]}),
        )
        .await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::CONFLICT, "confirmation_required")
    );
    let (s, _) = d
        .send(
            Method::PUT,
            &format!("/api/port-groups/{gid}"),
            json!({"confirm_open": true, "ports": [{"start": 60000, "end": 60010, "proto": "tcp"}]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let ids = rule_ids(&d);
    assert!(ids.iter().any(|r| r.contains(":60000-60010:tcp:")));
    assert!(
        ids.iter().all(|r| !r.contains(":50000-50010:tcp:")),
        "the old range is gone"
    );

    // Creating a group with an app to attach to is the same.
    let (s, b) = d
        .post(
            "/api/port-groups",
            json!({"label": "more", "ports": [{"start": 1, "end": 2, "proto": "udp"}], "apps": [app_id]}),
        )
        .await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::CONFLICT, "confirmation_required")
    );
}

#[tokio::test]
async fn batch_operations_chain_refs_report_reach_and_are_atomic() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let alice = d.ygg_peer("alice").await;

    // A dry run shows the diff and that attaching widens a whole-app grant's reach.
    d.post(
        "/api/grants",
        json!({"target": app_target(&app_id), "subject": {"kind": "peer", "id": alice}}),
    )
    .await;
    let ops = json!([
        {"op": "create_port_group", "ref": "$g", "label": "passive", "ports": passive()},
        {"op": "attach_port_group", "group_id": "$g", "app_id": app_id},
        {"op": "add_grant", "target": app_target(&app_id),
         "scope": {"kind": "group", "id": "$g"}, "network_id": "ygg",
         "subject": {"kind": "peer", "id": "$other"}},
    ]);
    let (s, b) = d
        .post(
            "/api/changes",
            json!({"dry_run": true, "ops": [ops[0], ops[1]]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["changes_reach"], true, "{b}");
    assert_eq!(b["changes"][0]["item"], "port_group");
    assert_eq!(b["changes"][1]["kind"], "update");
    assert!(!b["changes"][1]["reach"].as_array().unwrap().is_empty());
    assert_eq!(
        d.state.db.list_port_groups().await.unwrap().len(),
        0,
        "a dry run saves nothing"
    );

    // The real batch, with a grant that uses the new group by ref.
    let (s, b) = d
        .post(
            "/api/changes",
            json!({"ops": [ops[0], ops[1], {
                "op": "add_grant", "target": app_target(&app_id),
                "scope": {"kind": "group", "id": "$g"}, "network_id": "ygg",
                "subject": {"kind": "peer", "id": alice}
            }]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let gid = b["refs"]["$g"].as_str().unwrap().to_string();
    let g = d.state.db.get_port_group(&gid).await.unwrap().unwrap();
    assert_eq!(g.apps, std::slice::from_ref(&app_id));

    // Detaching is refused while the grant uses it; the whole batch changes nothing.
    let (s, b) = d
        .post(
            "/api/changes",
            json!({"ops": [
                {"op": "update_port_group", "group_id": gid, "label": "renamed"},
                {"op": "detach_port_group", "group_id": gid, "app_id": app_id}
            ]}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::CONFLICT, "conflict"), "{b}");
    assert!(b["message"].as_str().unwrap().contains("operation 1"));
    assert_eq!(
        d.state
            .db
            .get_port_group(&gid)
            .await
            .unwrap()
            .unwrap()
            .label,
        "passive"
    );

    // Removing the grant first in the same batch makes the detach legal; deleting follows.
    let grant_id = d
        .state
        .db
        .list_grants()
        .await
        .unwrap()
        .last()
        .unwrap()
        .id
        .clone();
    let (s, b) = d
        .post(
            "/api/changes",
            json!({"ops": [
                {"op": "remove_grant", "grant_id": grant_id},
                {"op": "detach_port_group", "group_id": gid, "app_id": app_id},
                {"op": "delete_port_group", "group_id": gid}
            ]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(d.state.db.list_port_groups().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_batch_attach_under_a_grant_to_anyone_needs_confirm_open() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let gid = create_group(&d, "passive", passive()).await;
    d.post(
        "/api/grants",
        json!({"target": app_target(&app_id), "subject": {"kind": "anyone"}, "confirm_open": true}),
    )
    .await;
    let op = |confirm: bool| {
        json!({"dry_run": true, "ops": [{"op": "attach_port_group", "group_id": gid,
                                         "app_id": app_id, "confirm_open": confirm}]})
    };
    let (s, b) = d.post("/api/changes", op(false)).await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::CONFLICT, "confirmation_required"),
        "{b}"
    );
    let (s, b) = d.post("/api/changes", op(true)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["changes_reach"], true);
    assert_eq!(b["changes"][0]["opens_to_anyone"], true);
}

#[tokio::test]
async fn export_and_apply_carry_port_groups_by_label() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let alice = d.ygg_peer("alice").await;
    let gid = create_group(&d, "passive", passive()).await;
    attach(&d, &gid, &app_id, false).await;
    d.post(
        "/api/grants",
        json!({"target": app_target(&app_id), "scope": group_scope(&gid),
               "subject": {"kind": "peer", "id": alice}}),
    )
    .await;

    let (s, doc) = d.get("/api/export").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(doc["port_groups"][0]["label"], "passive");
    assert_eq!(doc["port_groups"][0]["apps"][0]["id"], app_id);
    assert_eq!(
        doc["grants"][0]["scope"],
        json!({"kind": "group", "label": "passive"})
    );
    // Applying the export again is an empty diff.
    let (s, r) = d
        .post("/api/apply", json!({"document": doc, "dry_run": true}))
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["changes"], json!([]));

    // A document with another group and port set changes the state to match.
    let mut want = doc.clone();
    want["port_groups"][0]["ports"] = json!([{"start": 4000, "end": 4005, "proto": "tcp"}]);
    want["port_groups"].as_array_mut().unwrap().push(json!({
        "label": "dns", "ports": [{"start": 53, "end": 53, "proto": "udp"}], "apps": []
    }));
    let (s, r) = d
        .post("/api/apply", json!({"document": want, "dry_run": false}))
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let groups = d.state.db.list_port_groups().await.unwrap();
    assert_eq!(groups.len(), 2);
    assert!(rule_ids(&d).iter().any(|r| r.contains(":4000-4005:tcp:")));

    // A grant naming a group the document does not attach is invalid.
    let mut bad = want.clone();
    bad["port_groups"][1]["apps"] = json!([]);
    bad["grants"][0]["scope"] = json!({"kind": "group", "label": "dns"});
    let (s, r) = d
        .post("/api/apply", json!({"document": bad, "dry_run": true}))
        .await;
    assert_eq!((s, code(&r)), (StatusCode::BAD_REQUEST, "invalid"), "{r}");

    // Dropping the group and its grant from the document removes both.
    let mut gone = want.clone();
    gone["port_groups"] = json!([]);
    gone["grants"] = json!([]);
    let (s, r) = d
        .post("/api/apply", json!({"document": gone, "dry_run": false}))
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert!(d.state.db.list_port_groups().await.unwrap().is_empty());
    assert!(d.state.db.list_grants().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_tag_open_to_anyone_makes_attaching_and_widening_a_confirmed_change() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let gid = create_group(&d, "passive", passive()).await;
    // The app is a member (All sockets) of a tag that has a grant to Anyone.
    let (_, tag) = d.post("/api/tags", json!({"label": "open"})).await;
    d.post(
        &format!("/api/tags/{}/members", id(&tag)),
        json!({"app_id": app_id}),
    )
    .await;
    d.post(
        "/api/grants",
        json!({"target": {"kind": "tag", "id": id(&tag)}, "subject": {"kind": "anyone"},
               "confirm_open": true}),
    )
    .await;
    let (s, b) = attach(&d, &gid, &app_id, false).await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::CONFLICT, "confirmation_required"),
        "{b}"
    );
    // The dry run of the batch lists the reach and says it opens to Anyone.
    let (s, b) = d
        .post(
            "/api/changes",
            json!({"dry_run": true, "ops": [
                {"op": "attach_port_group", "group_id": gid, "app_id": app_id, "confirm_open": true}]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["changes_reach"], true);
    assert_eq!(b["changes"][0]["opens_to_anyone"], true);
    assert!(!b["changes"][0]["reach"].as_array().unwrap().is_empty());
    assert_eq!(attach(&d, &gid, &app_id, true).await.0, StatusCode::OK);
}

#[tokio::test]
async fn one_batch_creates_a_group_attaches_it_and_uses_it_by_ref() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let alice = d.ygg_peer("alice").await;
    let (_, tag) = d.post("/api/tags", json!({"label": "ftp"})).await;
    let (s, b) = d
        .post(
            "/api/changes",
            json!({"ops": [
                {"op": "create_port_group", "ref": "$g", "label": "passive", "ports": passive()},
                {"op": "attach_port_group", "group_id": "$g", "app_id": app_id},
                {"op": "add_tag_member", "tag_id": id(&tag), "app_id": app_id,
                 "scope": {"kind": "group", "id": "$g"}},
                {"op": "add_grant", "target": app_target(&app_id),
                 "scope": {"kind": "group", "id": "$g"},
                 "subject": {"kind": "peer", "id": alice}}
            ]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let gid = b["refs"]["$g"].as_str().unwrap().to_string();
    let t = d.state.db.get_tag(&id(&tag)).await.unwrap().unwrap();
    assert_eq!(t.members[0].scope.group_id(), Some(gid.as_str()));
    assert_eq!(
        d.state.db.list_grants().await.unwrap()[0].scope.group_id(),
        Some(gid.as_str())
    );
}

#[tokio::test]
async fn unidentified_apps_take_no_port_groups() {
    let d = Daemon::new().await;
    let mut sock = listener("mystery", 9999);
    sock.unidentified = true;
    d.sockets.lock().unwrap().push(sock);
    d.reconcile().await;
    let apps = d.state.db.list_apps().await.unwrap();
    let unknown = apps.iter().find(|a| a.name == "unknown:tcp/9999").unwrap();
    let gid = create_group(&d, "passive", passive()).await;
    let (s, b) = attach(&d, &gid, &unknown.id, true).await;
    assert_eq!((s, code(&b)), (StatusCode::BAD_REQUEST, "invalid"), "{b}");
    let (s, b) = d
        .post(
            "/api/port-groups",
            json!({"label": "other", "ports": passive(), "apps": [unknown.id]}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::BAD_REQUEST, "invalid"), "{b}");
    assert!(d
        .state
        .db
        .get_port_group(&gid)
        .await
        .unwrap()
        .unwrap()
        .apps
        .is_empty());
}

#[tokio::test]
async fn an_unnamed_port_group_is_named_after_its_ports() {
    let d = Daemon::new().await;
    let tcp = |p: u16| json!({"start": p, "end": p, "proto": "tcp"});
    let (s, g) = d
        .post(
            "/api/port-groups",
            json!({"ports": [tcp(443), tcp(80), {"start": 50000, "end": 51000, "proto": "tcp"}]}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    assert_eq!(g["label"], "80/tcp, 443/tcp, 50000-51000/tcp");

    // A blank label counts as missing; a clash gets a suffix, again and again.
    for (label, want) in [
        (json!(null), "80/tcp"),
        (json!("  "), "80/tcp (2)"),
        (json!(""), "80/tcp (3)"),
    ] {
        let (s, g) = d
            .post(
                "/api/port-groups",
                json!({"label": label, "ports": [tcp(80)]}),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{g}");
        assert_eq!(g["label"], want);
    }

    // An explicit label that is taken stays a conflict.
    let (s, b) = d
        .post(
            "/api/port-groups",
            json!({"label": "80/tcp", "ports": [tcp(8080)]}),
        )
        .await;
    assert_eq!((s, code(&b)), (StatusCode::CONFLICT, "conflict"));

    // The batch names them too, and sees the groups made earlier in it.
    let (s, b) = d
        .post(
            "/api/changes",
            json!({"ops": [
                {"op": "create_port_group", "ref": "$a", "ports": [tcp(25)]},
                {"op": "create_port_group", "ref": "$b", "ports": [tcp(25)]}
            ]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let names: Vec<String> = b["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["25/tcp", "25/tcp (2)"]);
}
