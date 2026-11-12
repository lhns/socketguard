//! The Yggdrasil network (ADR 0052) in the engine, over the fake supervisor: the
//! node's key and addresses exist before anything runs, the child starts only after the
//! ruleset that closes its addresses is in force and no other node runs on the host, and
//! its state is what the network card shows.

use socketguard_core::config::{BackendConfig, BackendInstanceConfig, DaemonConfig};
use socketguard_core::{ChildState, Network, NetworkStatus};
use socketguard_daemon::networks::ygg_child::OTHER_NODE;
use socketguard_daemon::networks::ygg_key::YggKey;
use socketguard_daemon::test_support::*;
use socketguard_daemon::AppState;
use std::sync::Arc;
use std::time::Duration;

const ID: &str = "ygg";
const ADAPTER: &str = if cfg!(windows) {
    "SocketGuard"
} else {
    "sgygg0"
};

fn ygg_instance(peers: &[&str]) -> BackendInstanceConfig {
    BackendInstanceConfig {
        id: ID.into(),
        backend: BackendConfig::yggdrasil(peers.iter().map(|p| p.to_string()).collect()),
    }
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..500 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Long enough for a pass of the supervisor to have started a child, if it would.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

async fn network(state: &AppState) -> Network {
    let engine = state.engine.read().await;
    engine
        .networks()
        .into_iter()
        .find(|n| n.id == ID)
        .expect("the network")
}

async fn add(h: &ChildHarness, peers: &[&str]) -> (Arc<AppState>, anyhow::Result<()>) {
    let state = h.app_state(DaemonConfig::default()).await;
    let (_, applied) = state
        .engine
        .write()
        .await
        .add_network(&state, ygg_instance(peers))
        .await
        .unwrap();
    (state, applied)
}

async fn reconcile(state: &AppState) {
    state.engine.read().await.reconcile(state).await.unwrap();
}

fn key(h: &ChildHarness) -> YggKey {
    h.ctx.keys.get(ID).expect("the key of the network")
}

fn overlay_scopes(h: &ChildHarness) -> Vec<String> {
    applied(&h.fw_calls)
        .last()
        .map(|r| r.scopes.iter().map(|s| s.id.clone()).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn the_key_and_the_remembered_node_exist_when_the_network_is_added() {
    let h = ChildHarness::new();
    let (state, applied) = add(&h, &[]).await;
    applied.unwrap();
    let key = key(&h);

    let stored = state.db.get_setting("ygg_key:ygg").await.unwrap().unwrap();
    assert_eq!(YggKey::from_private_hex(&stored).unwrap(), key);
    let node = state.db.get_setting("ygg_node:ygg").await.unwrap().unwrap();
    assert_eq!(node, serde_json::to_string(&key.node()).unwrap());

    // The first ruleset that was applied already closes the node's address and /64.
    let first = &applied_rulesets(&h)[0];
    let scopes: Vec<&str> = first.scopes.iter().map(|s| s.id.as_str()).collect();
    assert!(scopes.contains(&"overlay:ygg:addr"), "{scopes:?}");
    assert!(scopes.contains(&"overlay:ygg:subnet"), "{scopes:?}");
}

fn applied_rulesets(h: &ChildHarness) -> Vec<socketguard_daemon::firewall::DesiredRuleset> {
    applied(&h.fw_calls)
}

#[tokio::test]
async fn the_private_key_is_not_in_the_export() {
    let h = ChildHarness::new();
    let (state, applied) = add(&h, &[]).await;
    applied.unwrap();
    let engine = state.engine.read().await;
    let doc = socketguard_daemon::apply::export(&engine, &state)
        .await
        .map_err(|e| format!("{e:?}"))
        .unwrap();
    let text = serde_json::to_string(&doc).unwrap();
    let private = key(&h).private_hex();
    let seed = &private[..64];
    assert!(!text.contains(seed), "the seed is not exported");
}

#[tokio::test]
async fn the_child_starts_after_the_ruleset_with_the_adr_command_line_and_a_private_conf() {
    let h = ChildHarness::new();
    let (state, applied) = add(&h, &["tcp://192.0.2.1:9001"]).await;
    applied.unwrap();
    wait_until("the child to start", || h.spawner.started() == 1).await;
    assert!(overlay_scopes(&h).contains(&"overlay:ygg:addr".to_string()));

    let spec = h.spawner.proc(0).spec;
    assert_eq!(spec.name, "yggdrasil");
    assert_eq!(spec.args[0], "-useconffile");
    assert!(spec.args[1].ends_with("yggdrasil.conf"));
    if cfg!(unix) {
        assert_eq!(&spec.args[2..], ["-user", "socketguard-net"]);
    }
    let conf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&spec.args[1]).unwrap()).unwrap();
    assert_eq!(conf["PrivateKey"], key(&h).private_hex());
    assert_eq!(conf["Peers"][0], "tcp://192.0.2.1:9001");
    assert_eq!(
        conf["IfName"],
        if cfg!(target_os = "macos") {
            "auto"
        } else {
            ADAPTER
        }
    );
    assert_eq!(conf["Listen"], serde_json::json!([]));
    assert_eq!(conf["NodeInfoPrivacy"], true);
    assert!(conf.get("MulticastInterfaces").is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&spec.args[1])
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // The card: starting, the node's address from the key, the configured peers.
    let n = network(&state).await;
    assert_eq!(
        n.status,
        NetworkStatus::Down {
            reason: "Yggdrasil is starting".into()
        }
    );
    if !cfg!(target_os = "macos") {
        assert_eq!(n.interface.as_deref(), Some(ADAPTER));
    }
    let m = n.child.expect("child info");
    assert_eq!(m.state, ChildState::Starting);
    assert_eq!(m.address, Some(key(&h).node().address.to_string()));
    assert_eq!(m.peers, ["tcp://192.0.2.1:9001"]);
    assert_eq!(m.peers_connected, None);
    assert_eq!(m.version.as_deref(), Some("0.5.15"));
    let account = if cfg!(windows) {
        "the daemon's account (creating the network adapter needs the daemon's rights)"
    } else {
        "socketguard-net"
    };
    assert_eq!(m.runs_as.as_deref(), Some(account));
    // The network's /64 is the key's, known without the node.
    assert_eq!(
        n.prefix,
        Some(key(&h).node().subnet.network()),
        "allocation works before the node does"
    );
}

#[tokio::test]
async fn a_failed_apply_keeps_the_child_unstarted_and_the_status_says_why() {
    let h = ChildHarness::new();
    h.fw.set_failing(true);
    let (state, applied) = add(&h, &[]).await;
    assert!(applied.is_err());
    settle().await;
    assert_eq!(
        h.spawner.started(),
        0,
        "nothing runs before the block is in force"
    );
    // The ruleset was tried, and it did have the scopes.
    assert!(overlay_scopes(&h).contains(&"overlay:ygg:addr".to_string()));

    let n = network(&state).await;
    let m = n.child.expect("child info");
    assert_eq!(m.state, ChildState::Waiting);
    let detail = m.detail.expect("a reason");
    assert!(
        detail.starts_with("waiting for the firewall rules that close the node"),
        "{detail}"
    );
    assert!(detail.contains("failed"), "{detail}");
    assert_eq!(n.status, NetworkStatus::Down { reason: detail });

    // The next pass applies for real and the child starts.
    h.fw.set_failing(false);
    reconcile(&state).await;
    wait_until("the child to start", || h.spawner.started() == 1).await;
    assert_eq!(
        network(&state).await.child.unwrap().state,
        ChildState::Starting
    );
}

#[tokio::test]
async fn another_node_on_the_host_holds_it_back_until_it_is_gone() {
    let h = ChildHarness::new();
    h.ifaces.add_interface("ygg0");
    h.ifaces
        .plant_address("ygg0", "200:1111:2222::1".parse().unwrap());
    let (state, applied) = add(&h, &[]).await;
    applied.unwrap();
    settle().await;
    assert_eq!(h.spawner.started(), 0);
    let n = network(&state).await;
    let m = n.child.unwrap();
    assert_eq!(m.state, ChildState::Waiting);
    assert_eq!(m.detail.as_deref(), Some(OTHER_NODE));
    assert_eq!(
        OTHER_NODE,
        "Another Yggdrasil node is running on this computer. SocketGuard's Yggdrasil cannot run next to it."
    );
    assert_eq!(
        n.status,
        NetworkStatus::Down {
            reason: OTHER_NODE.into()
        }
    );

    // Still there on the next pass; gone on the one after.
    reconcile(&state).await;
    settle().await;
    assert_eq!(h.spawner.started(), 0);
    h.ifaces
        .drop_address("ygg0", "200:1111:2222::1".parse().unwrap());
    reconcile(&state).await;
    wait_until("the child to start", || h.spawner.started() == 1).await;
}

#[tokio::test]
async fn our_own_adapter_does_not_count_as_another_node() {
    let h = ChildHarness::new();
    let (state, applied) = add(&h, &[]).await;
    applied.unwrap();
    wait_until("the child to start", || h.spawner.started() == 1).await;
    // The node is up: its adapter holds its address (and later the apps' addresses).
    h.ifaces.add_interface(ADAPTER);
    h.ifaces.plant_address(ADAPTER, key(&h).node().address);
    reconcile(&state).await;
    settle().await;
    assert_eq!(h.spawner.started(), 1, "not restarted, not held");
    assert_ne!(
        network(&state).await.child.unwrap().state,
        ChildState::Waiting
    );
}

#[tokio::test]
async fn the_node_is_up_when_its_admin_socket_answers_and_the_adapter_has_the_address() {
    use socketguard_daemon::networks::ip::ygg_admin::fake::*;
    let h = ChildHarness::new();
    let (state, applied) = add(&h, &["tcp://192.0.2.1:9001"]).await;
    applied.unwrap();
    wait_until("the child to start", || h.spawner.started() == 1).await;

    let node = key(&h).node();
    let own = format!(
        r#"{{"status":"success","response":{{"key":"{}","address":"{}","subnet":"{}"}}}}"#,
        key(&h).public_hex(),
        node.address,
        node.subnet
    );
    let admin_path = h.state_dir.join("yggdrasil").join("run").join("admin.sock");
    let _admin = FakeAdmin::start_at(
        &admin_path,
        vec![("getself", own), ("getpeers", GET_PEERS_ANSWER.to_string())],
    );
    // The admin answers, but the adapter has no address yet: not up.
    settle().await;
    assert_ne!(network(&state).await.child.unwrap().state, ChildState::Up);

    h.ifaces.add_interface(ADAPTER);
    h.ifaces.plant_address(ADAPTER, node.address);
    let st = h.ctx.children.clone();
    // The health check runs once a second.
    for _ in 0..300 {
        if st.status(ID).state == ChildState::Up {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(st.status(ID).state, ChildState::Up);
    let n = network(&state).await;
    assert_eq!(n.status, NetworkStatus::Up);
    let m = n.child.unwrap();
    assert_eq!(m.state, ChildState::Up);
    assert_eq!(m.peers_connected, Some(1), "one of the two peers is up");
}

#[tokio::test]
async fn new_peers_restart_the_child_with_a_new_conf() {
    let h = ChildHarness::new();
    let (state, applied) = add(&h, &["tcp://192.0.2.1:9001"]).await;
    applied.unwrap();
    wait_until("the child to start", || h.spawner.started() == 1).await;
    let conf_path = h.spawner.proc(0).spec.args[1].clone();

    state
        .engine
        .write()
        .await
        .set_peers(&state, ID, vec!["tls://example.org:443".into()])
        .await
        .unwrap();
    wait_until("the restart", || h.spawner.started() == 2).await;
    assert_eq!(h.spawner.proc(0).signals(), ["term"]);
    let conf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&conf_path).unwrap()).unwrap();
    assert_eq!(conf["Peers"], serde_json::json!(["tls://example.org:443"]));
    assert_eq!(
        network(&state).await.child.unwrap().peers,
        ["tls://example.org:443"]
    );
}

#[tokio::test]
async fn turning_socketguard_off_stops_the_child_and_on_starts_it_again() {
    let h = ChildHarness::new();
    let (state, applied) = add(&h, &[]).await;
    applied.unwrap();
    wait_until("the child to start", || h.spawner.started() == 1).await;

    state.engine.read().await.disable(&state).await.unwrap();
    assert!(
        h.spawner.running().is_empty(),
        "disable waits for the child"
    );
    let n = network(&state).await;
    assert_eq!(n.child.as_ref().unwrap().state, ChildState::Stopped);
    assert_eq!(
        n.status,
        NetworkStatus::Down {
            reason: "SocketGuard is turned off".into()
        }
    );
    settle().await;
    reconcile(&state).await;
    settle().await;
    assert_eq!(h.spawner.started(), 1, "a pass does not start it again");

    state.engine.read().await.enable(&state).await.unwrap();
    wait_until("the child to start again", || h.spawner.started() == 2).await;
}

#[tokio::test]
async fn removing_the_network_stops_the_child_and_deletes_the_key() {
    let h = ChildHarness::new();
    let (state, applied) = add(&h, &[]).await;
    applied.unwrap();
    wait_until("the child to start", || h.spawner.started() == 1).await;
    let old = key(&h);

    state
        .engine
        .write()
        .await
        .remove_network(&state, ID, false)
        .await
        .unwrap();
    assert!(h.spawner.running().is_empty());
    assert_eq!(state.db.get_setting("ygg_key:ygg").await.unwrap(), None);
    assert_eq!(state.db.get_setting("ygg_node:ygg").await.unwrap(), None);
    assert!(h.ctx.keys.get(ID).is_none());
    assert!(
        !h.state_dir.join("yggdrasil").exists(),
        "the configuration with the key goes too"
    );

    // The same name again is a new node.
    let (_, applied) = {
        let (_, a) = state
            .engine
            .write()
            .await
            .add_network(&state, ygg_instance(&[]))
            .await
            .unwrap();
        ((), a)
    };
    applied.unwrap();
    assert_ne!(key(&h), old);
}

#[tokio::test]
async fn the_key_survives_a_restart_of_the_daemon() {
    let h = ChildHarness::new();
    let (state, applied) = add(&h, &[]).await;
    applied.unwrap();
    let before = key(&h);
    // As after a restart: the network exists, the key ring is empty, the database has the key.
    h.ctx.keys.remove(ID);
    state.engine.read().await.startup_reconcile(&state).await;
    assert_eq!(key(&h), before, "the stored key is loaded, not replaced");
}
