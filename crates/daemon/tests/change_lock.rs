//! Every change that ADR 0062 lists waits for `Engine::change_lock`: with the lock held the
//! call does not finish and writes nothing; once it is released the call finishes.

mod common;

use common::listener;
use socketguard_core::api_types::{ChangeOp, ChangesRequest};
use socketguard_core::{
    CredentialKind, NewCredential, NewGrant, PortRange, Protocol, Scope, Subject, TagMember, Target,
};
use socketguard_daemon::engine::Engine;
use socketguard_daemon::test_support::*;
use socketguard_daemon::AppState;
use std::time::Duration;

struct Ids {
    app: String,
    peer: String,
    cred: String,
    group: String,
    grant: String,
    tag: String,
    pg: String,
    pg_attached: String,
}

fn range(start: u16) -> PortRange {
    PortRange {
        start,
        end: start + 5,
        proto: Protocol::Tcp,
    }
}

/// An app, a peer with a credential, a group, a grant, a tag, and two port groups (one
/// attached to the app).
async fn fixture(engine: &Engine, state: &AppState) -> Ids {
    let app = state.db.list_apps().await.unwrap()[0].id.clone();
    let peer = engine
        .create_peer(
            state,
            "p0",
            &[NewCredential {
                kind: CredentialKind::Ip,
                value: "fd00::5".into(),
                label: None,
            }],
        )
        .await
        .unwrap();
    let group = engine
        .create_group(state, "g0", std::slice::from_ref(&peer.id))
        .await
        .unwrap();
    let grant = engine
        .create_grant(
            state,
            &NewGrant {
                target: Target::App(app.clone()),
                scope: Scope::All,
                network_id: None,
                subject: Subject::Peer(peer.id.clone()),
                confirm_open: false,
            },
        )
        .await
        .unwrap();
    let tag = engine.create_tag(state, "t0", &[], &[]).await.unwrap();
    let pg = engine
        .create_port_group(state, Some("pg0"), &[range(50000)], &[], false)
        .await
        .unwrap();
    let pg_attached = engine
        .create_port_group(
            state,
            Some("pg1"),
            &[range(51000)],
            std::slice::from_ref(&app),
            false,
        )
        .await
        .unwrap();
    Ids {
        cred: peer.credentials[0].id.clone(),
        peer: peer.id,
        group: group.id,
        grant: grant.grant.id,
        tag: tag.id,
        pg: pg.id,
        pg_attached: pg_attached.id,
        app,
    }
}

const CASES: &[&str] = &[
    "apply_changes",
    "add_tag_member",
    "create_peer",
    "update_peer_label",
    "delete_peer",
    "add_credential",
    "remove_credential",
    "create_group",
    "rename_group",
    "delete_group",
    "set_group_members",
    "create_grant",
    "delete_grant",
    "create_tag",
    "update_tag",
    "delete_tag",
    "create_port_group",
    "update_port_group",
    "delete_port_group",
    "attach_port_group",
    "detach_port_group",
    "generate_tor_key",
    "set_protect_host",
    "delete_app",
];

/// One call of the named method, on the fixture. Results are not looked at: the test is
/// about when the call finishes.
async fn call(name: &str, e: &Engine, s: &AppState, i: &Ids) {
    match name {
        "apply_changes" => {
            let _ = e
                .apply_changes(
                    s,
                    &ChangesRequest {
                        ops: vec![ChangeOp::CreatePeer {
                            ref_: None,
                            label: Some("batch".into()),
                            credentials: vec![],
                        }],
                        dry_run: false,
                    },
                )
                .await;
        }
        "add_tag_member" => {
            let _ = e.add_tag_member(s, &i.tag, &i.app, Scope::All, false).await;
        }
        "create_peer" => {
            let _ = e.create_peer(s, "p1", &[]).await;
        }
        "update_peer_label" => {
            let _ = e.update_peer_label(s, &i.peer, "renamed").await;
        }
        "delete_peer" => {
            let _ = e.delete_peer(s, &i.peer).await;
        }
        "add_credential" => {
            let _ = e
                .add_credential(
                    s,
                    &i.peer,
                    &NewCredential {
                        kind: CredentialKind::Ip,
                        value: "fd00::6".into(),
                        label: None,
                    },
                )
                .await;
        }
        "remove_credential" => {
            let _ = e.remove_credential(s, &i.peer, &i.cred).await;
        }
        "create_group" => {
            let _ = e.create_group(s, "g1", &[]).await;
        }
        "rename_group" => {
            let _ = e.rename_group(s, &i.group, "g-renamed").await;
        }
        "delete_group" => {
            let _ = e.delete_group(s, &i.group).await;
        }
        "set_group_members" => {
            let _ = e.set_group_members(s, &i.group, &[]).await;
        }
        "create_grant" => {
            let _ = e
                .create_grant(
                    s,
                    &NewGrant {
                        target: Target::App(i.app.clone()),
                        scope: Scope::All,
                        network_id: None,
                        subject: Subject::Group(i.group.clone()),
                        confirm_open: false,
                    },
                )
                .await;
        }
        "delete_grant" => {
            let _ = e.delete_grant(s, &i.grant).await;
        }
        "create_tag" => {
            let _ = e
                .create_tag(
                    s,
                    "t1",
                    &[],
                    &[TagMember {
                        app_id: i.app.clone(),
                        scope: Scope::All,
                    }],
                )
                .await;
        }
        "update_tag" => {
            let _ = e
                .update_tag(s, &i.tag, Some("t-renamed"), None, false)
                .await;
        }
        "delete_tag" => {
            let _ = e.delete_tag(s, &i.tag, false).await;
        }
        "create_port_group" => {
            let _ = e
                .create_port_group(s, Some("pg2"), &[range(52000)], &[], false)
                .await;
        }
        "update_port_group" => {
            let _ = e
                .update_port_group(s, &i.pg, None, Some(&[range(50100)]), false)
                .await;
        }
        "delete_port_group" => {
            let _ = e.delete_port_group(s, &i.pg).await;
        }
        "attach_port_group" => {
            let _ = e.attach_port_group(s, &i.pg, &i.app, false).await;
        }
        "detach_port_group" => {
            let _ = e.detach_port_group(s, &i.pg_attached, &i.app).await;
        }
        "generate_tor_key" => {
            let _ = e.generate_tor_key(s, &i.peer).await;
        }
        "set_protect_host" => {
            let _ = e.set_protect_host(s, vec![], false).await;
        }
        "delete_app" => {
            let _ = e.delete_app(s, &i.app).await;
        }
        other => panic!("no call for {other}"),
    }
}

#[tokio::test]
async fn every_change_waits_for_the_change_lock_and_finishes_after_it() {
    let mut failures = Vec::new();
    for name in CASES {
        let d = standard_daemon(vec![listener("nginx", 80)], None).await;
        let state = d.state.clone();
        let engine = state.engine.read().await;
        engine.reconcile(&state).await.unwrap();
        let ids = fixture(&engine, &state).await;
        let before = format!("{:?}", state.db.read_catalog().await.unwrap());

        let guard = engine.hold_change_lock().await;
        let mut fut = Box::pin(call(name, &engine, &state, &ids));
        let early = tokio::time::timeout(Duration::from_millis(150), &mut fut).await;
        if early.is_ok() {
            failures.push(format!("{name}: finished while the lock was held"));
            continue;
        }
        let during = format!("{:?}", state.db.read_catalog().await.unwrap());
        if during != before {
            failures.push(format!("{name}: wrote while the lock was held"));
        }
        drop(guard);
        if tokio::time::timeout(Duration::from_secs(20), &mut fut)
            .await
            .is_err()
        {
            failures.push(format!(
                "{name}: did not finish after the lock was released"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
