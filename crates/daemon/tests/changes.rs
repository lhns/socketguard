//! Tags (ADR 0043) and batch changes (ADR 0045) through the API: expansion of tag grants
//! into rules, auto-membership, and the atomicity, refs, dry run and confirmation of
//! `POST /api/changes`.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::{json, Value};
use socketguard_daemon::test_support::{applied, FirewallCall};

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap()
}

/// How many rulesets the firewall has been given.
fn applies(d: &Daemon) -> usize {
    d.fw.calls
        .lock()
        .unwrap()
        .iter()
        .filter(|c| matches!(c, FirewallCall::Apply(_)))
        .count()
}

/// The ids of the rules of the last applied ruleset.
fn rule_ids(d: &Daemon) -> Vec<String> {
    applied(&d.fw.calls)
        .last()
        .map(|r| r.rules.iter().map(|r| r.id.clone()).collect())
        .unwrap_or_default()
}

fn app_target(app_id: &str) -> Value {
    json!({"kind": "app", "id": app_id})
}

fn tag_target(tag_id: &str) -> Value {
    json!({"kind": "tag", "id": tag_id})
}

// ─── Tags ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_tag_grant_gives_each_member_access_with_its_origin() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let peer = d.ygg_peer("alice").await;

    let (s, tag) = d
        .post("/api/tags", json!({"label": "dev", "patterns": []}))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{tag}");
    let tag_id = id(&tag);
    let (s, body) = d
        .post(
            "/api/grants",
            json!({"target": tag_target(&tag_id), "subject": {"kind": "peer", "id": peer}}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let grant_id = id(&body);
    assert_eq!(body["target"], tag_target(&tag_id));
    assert!(
        rule_ids(&d).iter().all(|r| !r.contains(&grant_id)),
        "an empty tag grants nothing"
    );

    let (s, _) = d
        .post(
            &format!("/api/tags/{tag_id}/members"),
            json!({"app_id": app_id}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        rule_ids(&d).iter().any(|r| r.contains(&grant_id)),
        "the member is reachable: {:?}",
        rule_ids(&d)
    );

    let (_, detail) = d.get(&format!("/api/apps/{app_id}")).await;
    assert_eq!(detail["grants"], json!([]), "no grant on the app itself");
    assert_eq!(detail["tags"], json!([tag_id]));
    let access = detail["access"].as_array().unwrap();
    assert_eq!(access.len(), 1);
    assert_eq!(
        access[0]["origin"],
        json!({"kind": "tag", "tag_id": tag_id})
    );
    assert_eq!(access[0]["grant_id"], json!(grant_id));

    // Listing the tag's grants and the reach of the tag grant.
    let (_, grants) = d.get(&format!("/api/grants?tag={tag_id}")).await;
    assert_eq!(grants.as_array().unwrap().len(), 1);
    assert!(grants[0]["reach"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["network_id"] == "ygg" && r["reach"] == "verified"));

    // Removing the member removes the access.
    let (s, _) = d
        .delete(&format!("/api/tags/{tag_id}/members/{app_id}"))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(rule_ids(&d).iter().all(|r| !r.contains(&grant_id)));
    let (s, body) = d
        .delete(&format!("/api/tags/{tag_id}/members/{app_id}"))
        .await;
    assert_eq!((s, code(&body)), (StatusCode::NOT_FOUND, "not_found"));
}

#[tokio::test]
async fn member_port_and_grant_port_narrow_each_other() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let peer = d.ygg_peer("alice").await;
    let (_, tag) = d.post("/api/tags", json!({"label": "web"})).await;
    let tag_id = id(&tag);
    let p80 = json!({"port": 80, "proto": "tcp"});
    let p81 = json!({"port": 81, "proto": "tcp"});
    d.post(
        &format!("/api/tags/{tag_id}/members"),
        json!({"app_id": app_id, "port": p80}),
    )
    .await;
    // A member port the app does not have is refused.
    let (s, _) = d
        .post(
            &format!("/api/tags/{tag_id}/members"),
            json!({"app_id": app_id, "port": p81}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let subject = json!({"kind": "peer", "id": peer});
    let (_, whole) = d
        .post(
            "/api/grants",
            json!({"target": tag_target(&tag_id), "subject": subject}),
        )
        .await;
    let (_, access) = d.get(&format!("/api/apps/{app_id}")).await;
    assert_eq!(access["access"][0]["port"], p80, "the member port narrows");

    // Same port on the grant: still port 80. A different port: nothing.
    let (_, same) = d
        .post(
            "/api/grants",
            json!({"target": tag_target(&tag_id), "port": p80, "subject": subject}),
        )
        .await;
    let (_, other) = d
        .post(
            "/api/grants",
            json!({"target": tag_target(&tag_id), "port": p81, "subject": subject}),
        )
        .await;
    let rules = rule_ids(&d);
    assert!(rules.iter().any(|r| r.contains(&id(&whole))));
    assert!(rules.iter().any(|r| r.contains(&id(&same))));
    assert!(
        rules.iter().all(|r| !r.contains(&id(&other))),
        "both set and different covers nothing"
    );
}

#[tokio::test]
async fn deleting_a_tag_or_an_app_takes_its_grants_and_rules_with_it() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let (_, tag) = d
        .post(
            "/api/tags",
            json!({"label": "all", "members": [{"app_id": app_id}]}),
        )
        .await;
    let tag_id = id(&tag);
    let (s, g) = d
        .post(
            "/api/grants",
            json!({"target": tag_target(&tag_id), "subject": {"kind": "anyone"}, "confirm_open": true}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    assert!(rule_ids(&d).iter().any(|r| r.contains(&id(&g))));
    let (s, _) = d.delete(&format!("/api/tags/{tag_id}")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(rule_ids(&d).iter().all(|r| !r.contains(&id(&g))));
    assert_eq!(d.get("/api/grants").await.1, json!([]));
    assert_eq!(
        d.get(&format!("/api/tags/{tag_id}")).await.0,
        StatusCode::NOT_FOUND
    );

    // A grant on the app goes with the app.
    let (_, g) = d
        .post(
            "/api/grants",
            json!({"target": app_target(&app_id), "subject": {"kind": "anyone"}, "confirm_open": true}),
        )
        .await;
    assert!(!id(&g).is_empty());
    assert_eq!(
        d.delete(&format!("/api/apps/{app_id}")).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(d.get("/api/grants").await.1, json!([]));
}

#[tokio::test]
async fn tag_labels_are_unique_and_unknown_things_are_not_found() {
    let d = Daemon::new().await;
    assert_eq!(
        d.post("/api/tags", json!({"label": "dev"})).await.0,
        StatusCode::CREATED
    );
    let (s, body) = d.post("/api/tags", json!({"label": "dev"})).await;
    assert_eq!((s, code(&body)), (StatusCode::CONFLICT, "conflict"));
    let (s, body) = d.post("/api/tags", json!({"label": "  "})).await;
    assert_eq!((s, code(&body)), (StatusCode::BAD_REQUEST, "invalid"));
    let (s, _) = d
        .post(
            "/api/tags",
            json!({"label": "x", "members": [{"app_id": "nope"}]}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = d
        .post(
            "/api/grants",
            json!({"target": tag_target("nope"), "subject": {"kind": "anyone"}, "confirm_open": true}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn patterns_add_matching_apps_now_and_new_ones_later_but_not_excluded_ones() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    // The existing nginx matches at creation.
    let (_, tag) = d
        .post(
            "/api/tags",
            json!({"label": "web", "patterns": ["ngi*", " ", "ngi*"]}),
        )
        .await;
    let tag_id = id(&tag);
    assert_eq!(tag["patterns"], json!(["ngi*"]));
    assert_eq!(tag["members"], json!([{"app_id": app_id, "port": null}]));

    // A grant on the tag, then a new matching listener starts: covered from its first
    // reconcile, with no request in between.
    let (_, g) = d
        .post(
            "/api/grants",
            json!({"target": tag_target(&tag_id), "subject": {"kind": "anyone"}, "confirm_open": true}),
        )
        .await;
    let grant_id = id(&g);
    d.sockets.lock().unwrap().push(listener("nginx-two", 8081));
    d.reconcile().await;
    let tag = d.get(&format!("/api/tags/{tag_id}")).await.1;
    assert_eq!(tag["members"].as_array().unwrap().len(), 2, "{tag}");
    let apps = d.state.db.list_apps().await.unwrap();
    let new_app = apps.iter().find(|a| a.id != app_id).unwrap();
    let with_rule = rule_ids(&d)
        .into_iter()
        .filter(|r| r.contains(&grant_id))
        .count();
    assert!(with_rule >= 2, "both apps have rules");
    assert!(new_app.addresses.len() == 3);

    // Removing a matched app is remembered: a later pass does not add it back, and it is
    // not added by a pattern change either.
    let (s, tag) = d
        .delete(&format!("/api/tags/{tag_id}/members/{}", new_app.id))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(tag["excluded"], json!([new_app.id]));
    d.reconcile().await;
    let (s, tag) = d
        .send(
            axum::http::Method::PATCH,
            &format!("/api/tags/{tag_id}"),
            json!({"patterns": ["ngi*", "nginx*"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{tag}");
    assert_eq!(tag["members"].as_array().unwrap().len(), 1, "{tag}");
    // Adding it by hand clears the exclusion.
    let (_, tag) = d
        .post(
            &format!("/api/tags/{tag_id}/members"),
            json!({"app_id": new_app.id, "confirm_open": true}),
        )
        .await;
    assert_eq!(tag["excluded"], json!([]));
    assert_eq!(tag["members"].as_array().unwrap().len(), 2);
}

// ─── Batch changes ───────────────────────────────────────────────────────────

#[tokio::test]
async fn a_batch_is_one_transaction_and_one_firewall_update() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let before = applies(&d);
    let (s, body) = d
        .post(
            "/api/changes",
            json!({"ops": [
                {"op": "create_peer", "ref": "$alice", "label": "alice",
                 "credentials": [{"kind": "ygg_key", "value": KEY}]},
                {"op": "create_tag", "ref": "$dev", "label": "dev"},
                {"op": "add_tag_member", "tag_id": "$dev", "app_id": app_id},
                {"op": "add_grant", "target": tag_target("$dev"),
                 "subject": {"kind": "peer", "id": "$alice"}},
                {"op": "add_grant", "target": app_target(&app_id), "network_id": "ygg",
                 "port": {"port": 80, "proto": "tcp"},
                 "subject": {"kind": "peer", "id": "$alice"}},
                {"op": "review", "app_id": app_id, "reviewed": true}
            ]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(applies(&d) - before, 1, "one reconcile for the whole batch");

    // The refs map to the real ids.
    let alice = body["refs"]["$alice"].as_str().unwrap();
    let dev = body["refs"]["$dev"].as_str().unwrap();
    let peers = d.state.db.list_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].id, alice);
    assert_eq!(d.state.db.list_tags().await.unwrap()[0].id, dev);
    let grants = d.state.db.list_grants().await.unwrap();
    assert_eq!(grants.len(), 2);
    assert!(d.state.db.get_app(&app_id).await.unwrap().unwrap().reviewed);

    // The diff lists every change, with reach for the grants.
    let changes = body["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 6);
    assert_eq!(changes[0]["item"], "peer");
    assert_eq!(changes[0]["id"], alice);
    let grant_changes: Vec<_> = changes.iter().filter(|c| c["item"] == "grant").collect();
    assert_eq!(grant_changes.len(), 2);
    assert!(grant_changes[1]["reach"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["network_id"] == "ygg" && r["reach"] == "verified"));
    assert!(rule_ids(&d).len() >= 2);
}

#[tokio::test]
async fn a_failing_operation_rolls_back_every_other() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let before = applies(&d);
    let (s, body) = d
        .post(
            "/api/changes",
            json!({"ops": [
                {"op": "create_peer", "label": "alice"},
                {"op": "create_tag", "label": "dev"},
                {"op": "add_grant", "target": app_target("no-such-app"),
                 "subject": {"kind": "anyone"}, "confirm_open": true}
            ]}),
        )
        .await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::NOT_FOUND, "not_found"),
        "{body}"
    );
    assert!(body["message"].as_str().unwrap().contains("operation 2"));
    assert!(d.state.db.list_peers().await.unwrap().is_empty());
    assert!(d.state.db.list_tags().await.unwrap().is_empty());
    assert_eq!(applies(&d), before, "nothing was applied");

    // A duplicate inside the batch, and against a stored grant, refuses everything.
    let grant = json!({"op": "add_grant", "target": app_target(&app_id),
                       "subject": {"kind": "anyone"}, "confirm_open": true});
    let (s, body) = d
        .post(
            "/api/changes",
            json!({"ops": [{"op": "create_peer", "label": "bob"}, grant, grant]}),
        )
        .await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "conflict"),
        "{body}"
    );
    assert!(d.state.db.list_peers().await.unwrap().is_empty());
    assert!(d.state.db.list_grants().await.unwrap().is_empty());
    let (s, _) = d.post("/api/changes", json!({"ops": [grant]})).await;
    assert_eq!(s, StatusCode::OK);
    let (s, body) = d
        .post(
            "/api/changes",
            json!({"ops": [{"op": "create_peer", "label": "carol"}, grant]}),
        )
        .await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "conflict"),
        "{body}"
    );
    assert!(d.state.db.list_peers().await.unwrap().is_empty());

    // Unknown refs, reused refs and refs without the $ are refused too.
    for ops in [
        json!([{"op": "add_tag_member", "tag_id": "$nope", "app_id": app_id}]),
        json!([{"op": "create_peer", "ref": "$a", "label": "x"},
               {"op": "create_peer", "ref": "$a", "label": "y"}]),
        json!([{"op": "create_peer", "ref": "plain", "label": "x"}]),
    ] {
        let (s, body) = d.post("/api/changes", json!({"ops": ops})).await;
        assert_eq!(
            (s, code(&body)),
            (StatusCode::BAD_REQUEST, "invalid"),
            "{body}"
        );
    }
    assert!(d.state.db.list_peers().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_grant_to_anyone_needs_confirm_open_or_the_whole_batch_is_refused() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let before = applies(&d);
    let ops = |confirm: bool| {
        json!({"ops": [
            {"op": "create_peer", "label": "alice"},
            {"op": "add_grant", "target": app_target(&app_id),
             "subject": {"kind": "anyone"}, "confirm_open": confirm}
        ]})
    };
    let (s, body) = d.post("/api/changes", ops(false)).await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "confirmation_required"),
        "{body}"
    );
    assert!(d.state.db.list_peers().await.unwrap().is_empty());
    assert_eq!(applies(&d), before);
    let (s, body) = d.post("/api/changes", ops(true)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(d.state.db.list_peers().await.unwrap().len(), 1);
    let changes = body["changes"].as_array().unwrap();
    assert_eq!(changes[1]["opens_to_anyone"], true);
}

#[tokio::test]
async fn a_dry_run_reports_the_diff_and_reach_and_changes_nothing() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let peer = d.ygg_peer("alice").await;
    let (_, existing) = d
        .post(
            "/api/grants",
            json!({"target": app_target(&app_id), "network_id": "ygg",
                   "subject": {"kind": "peer", "id": peer}}),
        )
        .await;
    let before = applies(&d);
    let (s, body) = d
        .post(
            "/api/changes",
            json!({"dry_run": true, "ops": [
                {"op": "create_peer", "ref": "$p", "label": "bob",
                 "credentials": [{"kind": "ygg_key", "value": "00".repeat(32)}]},
                {"op": "add_grant", "target": app_target(&app_id),
                 "subject": {"kind": "peer", "id": "$p"}},
                {"op": "remove_grant", "grant_id": id(&existing)}
            ]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["dry_run"], true);
    let changes = body["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 3);
    assert_eq!(changes[1]["kind"], "create");
    assert!(changes[1]["reach"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["network_id"] == "ygg" && r["reach"] == "verified"));
    assert_eq!(
        changes[2]["kind"], "delete",
        "removing shows the reach lost"
    );
    assert!(!changes[2]["reach"].as_array().unwrap().is_empty());
    assert!(body["refs"]["$p"].is_string());

    // Nothing was written or applied.
    assert_eq!(d.state.db.list_peers().await.unwrap().len(), 1);
    assert_eq!(d.state.db.list_grants().await.unwrap().len(), 1);
    assert_eq!(applies(&d), before);

    // The real constraints still decide: a dry run reports the conflict too.
    let (s, body) = d
        .post(
            "/api/changes",
            json!({"dry_run": true, "ops": [
                {"op": "create_peer", "label": "bob2",
                 "credentials": [{"kind": "ygg_key", "value": KEY}]}]}),
        )
        .await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "conflict"),
        "{body}"
    );
}

#[tokio::test]
async fn batch_tag_member_operations_and_removal_of_grants() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let (_, tag) = d
        .post("/api/tags", json!({"label": "dev", "patterns": ["ngi*"]}))
        .await;
    let tag_id = id(&tag);
    let (_, g) = d
        .post(
            "/api/grants",
            json!({"target": tag_target(&tag_id), "subject": {"kind": "anyone"}, "confirm_open": true}),
        )
        .await;
    let (s, body) = d
        .post(
            "/api/changes",
            json!({"ops": [
                {"op": "remove_tag_member", "tag_id": tag_id, "app_id": app_id},
                {"op": "remove_grant", "grant_id": id(&g)}
            ]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let tag = d.get(&format!("/api/tags/{tag_id}")).await.1;
    assert_eq!(tag["members"], json!([]));
    assert_eq!(tag["excluded"], json!([app_id]), "a matched app stays out");
    assert!(d.state.db.list_grants().await.unwrap().is_empty());

    let (s, body) = d
        .post(
            "/api/changes",
            json!({"ops": [{"op": "remove_grant", "grant_id": "nope"}]}),
        )
        .await;
    assert_eq!((s, code(&body)), (StatusCode::NOT_FOUND, "not_found"));
}

// ─── Joining a tag that is open to anyone ────────────────────────────────────

/// A tag with a grant to Anyone, and a second app that is not in it.
async fn open_tag_and_spare_app(d: &Daemon) -> (String, String) {
    let (_, tag) = d.post("/api/tags", json!({"label": "web"})).await;
    let tag_id = id(&tag);
    let (s, g) = d
        .post(
            "/api/grants",
            json!({"target": tag_target(&tag_id), "subject": {"kind": "anyone"}, "confirm_open": true}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    (tag_id, d.app_id().await)
}

#[tokio::test]
async fn adding_a_member_to_a_tag_open_to_anyone_needs_confirm_open() {
    let d = Daemon::new().await;
    let (tag_id, app_id) = open_tag_and_spare_app(&d).await;
    let path = format!("/api/tags/{tag_id}/members");

    let (s, body) = d.post(&path, json!({"app_id": app_id})).await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "confirmation_required"),
        "{body}"
    );
    assert!(d.get(&format!("/api/tags/{tag_id}")).await.1["members"]
        .as_array()
        .unwrap()
        .is_empty());

    let (s, body) = d
        .post(&path, json!({"app_id": app_id, "confirm_open": true}))
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["members"].as_array().unwrap().len(), 1);

    // Already a member: nothing opens, so nothing to confirm.
    let (s, body) = d.post(&path, json!({"app_id": app_id})).await;
    assert_eq!(s, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_tag_without_an_anyone_grant_takes_members_unconfirmed() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let peer = d.ygg_peer("alice").await;
    let (_, tag) = d.post("/api/tags", json!({"label": "web"})).await;
    let tag_id = id(&tag);
    d.post(
        "/api/grants",
        json!({"target": tag_target(&tag_id), "subject": {"kind": "peer", "id": peer}}),
    )
    .await;
    let (s, body) = d
        .post(
            &format!("/api/tags/{tag_id}/members"),
            json!({"app_id": app_id}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_batch_member_of_an_open_tag_needs_confirm_open_and_says_so_in_a_dry_run() {
    let d = Daemon::new().await;
    let (tag_id, app_id) = open_tag_and_spare_app(&d).await;
    let op = |confirm: bool| {
        json!({"ops": [{"op": "add_tag_member", "tag_id": tag_id, "app_id": app_id,
                        "confirm_open": confirm}]})
    };

    // Without the confirmation the batch is refused, a dry run included.
    let (s, body) = d.post("/api/changes", op(false)).await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "confirmation_required"),
        "{body}"
    );
    let mut dry = op(true);
    dry["dry_run"] = json!(true);
    let (s, body) = d.post("/api/changes", dry).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["changes_reach"], true);
    let change = &body["changes"][0];
    assert_eq!(change["item"], "tag_member");
    assert_eq!(change["opens_to_anyone"], true);
    assert!(change["detail"].as_str().unwrap().contains("Anyone"));
    assert!(!change["reach"].as_array().unwrap().is_empty());
    assert!(d.state.db.list_tags().await.unwrap()[0].members.is_empty());

    let (s, body) = d.post("/api/changes", op(true)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(d.state.db.list_tags().await.unwrap()[0].members.len(), 1);
}

#[tokio::test]
async fn new_patterns_that_add_apps_to_an_open_tag_need_confirm_open() {
    let d = Daemon::new().await;
    let (tag_id, app_id) = open_tag_and_spare_app(&d).await;
    let path = format!("/api/tags/{tag_id}");
    let patch = |body: Value| d.send(axum::http::Method::PATCH, &path, body);

    // A rename adds nobody; a pattern nothing matches adds nobody.
    let (s, body) = patch(json!({"label": "web2", "patterns": ["zzz*"]})).await;
    assert_eq!(s, StatusCode::OK, "{body}");

    let (s, body) = patch(json!({"patterns": ["ngi*"]})).await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "confirmation_required"),
        "{body}"
    );
    assert!(d.get(&path).await.1["members"]
        .as_array()
        .unwrap()
        .is_empty());

    let (s, body) = patch(json!({"patterns": ["ngi*"], "confirm_open": true})).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["members"], json!([{"app_id": app_id, "port": null}]));
}

#[tokio::test]
async fn changes_reach_is_set_by_opening_edits_only() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let peer = d.ygg_peer("alice").await;
    let dry = |ops: Value| json!({"dry_run": true, "ops": ops});

    // Granting a verified peer widens reach.
    let grant = json!({"op": "add_grant", "target": app_target(&app_id),
                       "subject": {"kind": "peer", "id": peer}});
    let (_, body) = d.post("/api/changes", dry(json!([grant.clone()]))).await;
    assert_eq!(body["changes_reach"], true, "{body}");

    // A tag without grants gains a member: nobody gains access.
    let (_, tag) = d.post("/api/tags", json!({"label": "plain"})).await;
    let (_, body) = d
        .post(
            "/api/changes",
            dry(json!([{"op": "add_tag_member", "tag_id": id(&tag), "app_id": app_id}])),
        )
        .await;
    assert_eq!(body["changes_reach"], false, "{body}");

    // A member of a tag granted to a verified peer: the peer gains access.
    let (_, shared) = d.post("/api/tags", json!({"label": "shared"})).await;
    d.post(
        "/api/grants",
        json!({"target": tag_target(&id(&shared)), "subject": {"kind": "peer", "id": peer}}),
    )
    .await;
    let (_, body) = d
        .post(
            "/api/changes",
            dry(json!([{"op": "add_tag_member", "tag_id": id(&shared), "app_id": app_id}])),
        )
        .await;
    assert_eq!(body["changes_reach"], true, "{body}");
    assert!(body["changes"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("alice"));

    // Removing and reviewing never widen it.
    let (_, created) = d
        .post("/api/grants", {
            let mut g = grant.clone();
            g.as_object_mut().unwrap().remove("op");
            g
        })
        .await;
    let (_, body) = d
        .post(
            "/api/changes",
            dry(json!([{"op": "remove_grant", "grant_id": id(&created)},
                       {"op": "review", "app_id": app_id, "reviewed": true}])),
        )
        .await;
    assert_eq!(body["changes_reach"], false, "{body}");
}

#[tokio::test]
async fn a_new_tag_has_no_grants_so_only_the_anyone_grant_itself_is_confirmed() {
    let d = Daemon::new().await;
    let app_id = d.app_id().await;
    let ops = |confirm: bool| {
        json!({"ops": [
            {"op": "create_tag", "ref": "$t", "label": "web", "patterns": ["ngi*"]},
            {"op": "add_grant", "target": tag_target("$t"),
             "subject": {"kind": "anyone"}, "confirm_open": confirm}
        ]})
    };
    let (s, body) = d.post("/api/changes", ops(false)).await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "confirmation_required"),
        "{body}"
    );
    assert!(d.state.db.list_tags().await.unwrap().is_empty());
    let (s, body) = d.post("/api/changes", ops(true)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let tags = d.state.db.list_tags().await.unwrap();
    assert_eq!(tags[0].members[0].app_id, app_id);
}

// ─── Unnamed peers and groups in a batch ─────────────────────────────────────

fn sibling_key(last: &str) -> String {
    format!("{}{last}", &KEY[..62])
}

#[tokio::test]
async fn an_unnamed_peer_is_named_after_its_first_credential() {
    let d = Daemon::new().await;
    let (s, p) = d
        .post(
            "/api/peers",
            json!({"credentials": [{"kind": "ip", "value": "fd00::1/128"}]}),
        )
        .await;
    assert_eq!(
        (s, p["label"].as_str()),
        (StatusCode::CREATED, Some("fd00::1"))
    );
    let (_, p) = d
        .post(
            "/api/peers",
            json!({"credentials": [{"kind": "ip", "value": "10.0.0.5"}]}),
        )
        .await;
    assert_eq!(p["label"], "10.0.0.5");
    // A blank name counts as none, and a key is shortened.
    let (s, p) = d
        .post(
            "/api/peers",
            json!({"label": "  ", "credentials": [{"kind": "ygg_key", "value": KEY}]}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{p}");
    let short = &KEY[..12];
    assert_eq!(p["label"], format!("{short}…"));
    // The same name again gets a suffix, then the next number.
    for (last, name) in [
        ("00", format!("{short}… (2)")),
        ("01", format!("{short}… (3)")),
    ] {
        let (_, p) = d
            .post(
                "/api/peers",
                json!({"credentials": [{"kind": "ygg_key", "value": sibling_key(last)}]}),
            )
            .await;
        assert_eq!(p["label"], name);
    }
}

#[tokio::test]
async fn a_peer_with_neither_name_nor_credential_is_refused_and_a_given_name_still_clashes() {
    let d = Daemon::new().await;
    let (s, body) = d.post("/api/peers", json!({})).await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::BAD_REQUEST, "invalid"),
        "{body}"
    );
    let (s, body) = d
        .post("/api/changes", json!({"ops": [{"op": "create_peer"}]}))
        .await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::BAD_REQUEST, "invalid"),
        "{body}"
    );
    d.post("/api/peers", json!({"label": "alice"})).await;
    let (s, body) = d.post("/api/peers", json!({"label": "alice"})).await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "conflict"),
        "{body}"
    );
    let (s, body) = d
        .post(
            "/api/changes",
            json!({"ops": [{"op": "create_peer", "label": "alice"}]}),
        )
        .await;
    assert_eq!(
        (s, code(&body)),
        (StatusCode::CONFLICT, "conflict"),
        "{body}"
    );
}

#[tokio::test]
async fn a_batch_names_unnamed_peers_and_groups_them_by_ref() {
    let d = Daemon::new().await;
    let (s, body) = d
        .post(
            "/api/changes",
            json!({"ops": [
                {"op": "create_peer", "ref": "$a",
                 "credentials": [{"kind": "ygg_key", "value": KEY}]},
                {"op": "create_peer", "ref": "$b",
                 "credentials": [{"kind": "ygg_key", "value": sibling_key("00")}]},
                {"op": "create_peer", "ref": "$c",
                 "credentials": [{"kind": "ip", "value": "10.0.0.5/32"}]},
                {"op": "create_group", "ref": "$g", "label": "ops", "members": ["$a", "$b", "$c"]}
            ]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let names: Vec<String> = body["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            format!(
                "{} {}",
                c["item"].as_str().unwrap(),
                c["name"].as_str().unwrap()
            )
        })
        .collect();
    let short = &KEY[..12];
    assert_eq!(
        names,
        [
            format!("peer {short}…"),
            format!("peer {short}… (2)"),
            "peer 10.0.0.5".to_string(),
            "group ops".to_string(),
        ]
    );
    let groups = d.state.db.list_groups().await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, body["refs"]["$g"]);
    assert_eq!(groups[0].members.len(), 3);
    let peers = d.state.db.list_peers().await.unwrap();
    assert!(peers.iter().all(|p| p.groups == [groups[0].id.clone()]));
}

#[tokio::test]
async fn a_batch_group_refuses_unknown_members_and_clashing_names_and_rolls_back() {
    let d = Daemon::new().await;
    let (s, _) = d.post("/api/peer-groups", json!({"label": "ops"})).await;
    assert_eq!(s, StatusCode::CREATED);
    for ops in [
        json!([{"op": "create_peer", "label": "x"},
               {"op": "create_group", "label": "ops"}]),
        json!([{"op": "create_peer", "label": "x"},
               {"op": "create_group", "label": "new", "members": ["$nope"]}]),
        json!([{"op": "create_group", "label": "new", "members": ["no-such-peer"]}]),
    ] {
        let (s, body) = d.post("/api/changes", json!({"ops": ops})).await;
        assert!(s.is_client_error(), "{body}");
    }
    assert!(d.state.db.list_peers().await.unwrap().is_empty());
    assert_eq!(d.state.db.list_groups().await.unwrap().len(), 1);
}
