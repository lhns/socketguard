//! The Tor network (ADR 0052) in the engine, over the fake supervisor: the child is
//! declared when the network exists and SocketGuard is on, stopped when it is turned off or
//! the network goes, and its state is what the network card shows.

use socketguard_core::config::{BackendConfig, BackendInstanceConfig, DaemonConfig};
use socketguard_core::{ChildState, Network, NetworkStatus};
use socketguard_daemon::children::{ChildHealth, ChildSpec, HealthCheck, RunAs};
use socketguard_daemon::networks::tor::TorNetwork;
use socketguard_daemon::networks::tor_child::TorChild;
use socketguard_daemon::networks::Network as _;
use socketguard_daemon::test_support::*;
use socketguard_daemon::AppState;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ID: &str = "tor";

fn tor_instance() -> BackendInstanceConfig {
    BackendInstanceConfig {
        id: ID.into(),
        backend: BackendConfig::tor(),
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

async fn network(state: &AppState) -> Network {
    let engine = state.engine.read().await;
    engine
        .networks()
        .into_iter()
        .find(|n| n.id == ID)
        .expect("the network")
}

async fn add(h: &ChildHarness) -> Arc<AppState> {
    let state = h.app_state(DaemonConfig::default()).await;
    let (_, applied) = state
        .engine
        .write()
        .await
        .add_network(&state, tor_instance())
        .await
        .unwrap();
    applied.unwrap();
    state
}

#[tokio::test]
async fn adding_a_tor_network_starts_its_child_with_the_adr_command_line() {
    let h = ChildHarness::new();
    let state = add(&h).await;
    wait_until("the child to start", || h.spawner.started() == 1).await;

    let proc = h.spawner.proc(0);
    assert_eq!(proc.spec.name, "tor");
    assert_eq!(proc.spec.args[0], "-f");
    assert_eq!(proc.spec.args[2], "--__OwningControllerProcess");
    assert_eq!(proc.spec.args[3], std::process::id().to_string());
    assert!(proc.spec.args[1].ends_with("torrc"));
    assert!(proc.spec.data_dir.ends_with("tor"));

    // Not bootstrapped: the network is down and says why, on the card too.
    let n = network(&state).await;
    assert_eq!(
        n.status,
        NetworkStatus::Down {
            reason: "Tor is starting".into()
        }
    );
    let m = n.child.expect("child info");
    assert_eq!(m.state, ChildState::Starting);
    let account = if cfg!(windows) {
        "LocalService"
    } else {
        "socketguard-net"
    };
    assert_eq!(m.runs_as.as_deref(), Some(account));
    assert_eq!(m.version.as_deref(), Some("16.0.1"));
}

#[cfg(unix)]
#[tokio::test]
async fn without_the_account_it_runs_as_the_daemon_and_says_so() {
    let h = ChildHarness::with(socketguard_daemon::account::FakeAccounts::absent());
    let state = add(&h).await;
    wait_until("the child to start", || h.spawner.started() == 1).await;
    let m = network(&state).await.child.unwrap();
    assert_eq!(
        m.runs_as.as_deref(),
        Some("the daemon's account (socketguard-net does not exist)")
    );
}

#[tokio::test]
async fn the_last_log_line_is_the_reason_when_tor_exits() {
    let h = ChildHarness::new();
    let state = add(&h).await;
    wait_until("the child to start", || h.spawner.started() == 1).await;
    h.spawner
        .proc(0)
        .print("[warn] Could not bind to the control socket");
    h.spawner.proc(0).exit("exit code 1");
    wait_until("the exit to show", || {
        h.ctx.children.status(ID).state == ChildState::Exited
    })
    .await;
    let n = network(&state).await;
    assert_eq!(
        n.status,
        NetworkStatus::Down {
            reason: "Tor exited: [warn] Could not bind to the control socket".into()
        }
    );
    assert_eq!(n.child.unwrap().state, ChildState::Exited);
}

#[tokio::test]
async fn turning_socketguard_off_stops_the_child_and_on_starts_it_again() {
    let h = ChildHarness::new();
    let state = add(&h).await;
    wait_until("the child to start", || h.spawner.started() == 1).await;

    state.engine.read().await.disable(&state).await.unwrap();
    assert!(
        h.spawner.running().is_empty(),
        "disable waits for the child"
    );
    assert_eq!(h.spawner.proc(0).signals(), ["term"]);
    let n = network(&state).await;
    assert_eq!(n.child.as_ref().unwrap().state, ChildState::Stopped);
    assert_eq!(
        n.status,
        NetworkStatus::Down {
            reason: "SocketGuard is turned off".into()
        }
    );

    // A pass while off does not bring it back.
    state.engine.read().await.reconcile(&state).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.spawner.started(), 1);

    state.engine.read().await.enable(&state).await.unwrap();
    wait_until("the child to start again", || h.spawner.started() == 2).await;
    assert_eq!(h.spawner.running().len(), 1);
}

#[tokio::test]
async fn removing_the_network_stops_the_child_before_it_disappears() {
    let h = ChildHarness::new();
    let state = add(&h).await;
    wait_until("the child to start", || h.spawner.started() == 1).await;

    state
        .engine
        .write()
        .await
        .remove_network(&state, ID, false)
        .await
        .unwrap();
    assert!(h.spawner.running().is_empty());
    assert_eq!(h.spawner.proc(0).signals(), ["term"]);
    assert!(state.engine.read().await.networks().is_empty());
    assert_eq!(h.ctx.children.status(ID).state, ChildState::Stopped);
}

#[tokio::test]
async fn a_pass_with_an_unchanged_wish_restarts_nothing() {
    let h = ChildHarness::new();
    let state = add(&h).await;
    wait_until("the child to start", || h.spawner.started() == 1).await;
    for _ in 0..3 {
        state.engine.read().await.reconcile(&state).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.spawner.started(), 1, "an unchanged wish is no restart");
}

/// Health that reports each of `steps` once, then `Up`.
struct Script(Mutex<VecDeque<ChildHealth>>);

impl HealthCheck for Script {
    fn check(&self) -> ChildHealth {
        self.0
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(ChildHealth::Up)
    }
}

fn scripted_child(health: Option<Arc<dyn HealthCheck>>) -> ChildSpec {
    ChildSpec {
        name: "tor".into(),
        program: "tor".into(),
        args: vec![],
        env: vec![],
        cwd: None,
        run_as: RunAs::Daemon { note: None },
        data_dir: "tor".into(),
        pid_file: None,
        guarded: false,
        quiet_patterns: vec![],
        health,
        before_start: None,
        on_exit: None,
        start_deadline: None,
        on_deadline: None,
        stall_limit: None,
        config_tag: String::new(),
    }
}

/// How far a status is: starting, bootstrapping (any percent), up.
fn rank(s: &NetworkStatus) -> u8 {
    match s {
        NetworkStatus::Down { reason } if reason == "Tor is starting" => 0,
        NetworkStatus::Down { reason } if reason.starts_with("bootstrapping ") => 1,
        NetworkStatus::Up => 2,
        other => panic!("not a start-up state: {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn the_status_only_moves_forward_through_start_up_and_never_reads_not_connected() {
    let h = ChildHarness::new();
    let steps = [
        ChildHealth::Starting,
        ChildHealth::Bootstrapping(10),
        ChildHealth::Bootstrapping(60),
    ];
    let health: Arc<dyn HealthCheck> = Arc::new(Script(Mutex::new(steps.into())));
    h.ctx.children.set("t", Some(scripted_child(Some(health))));
    let net = TorNetwork::new(TorChild::new("t", &h.ctx), Duration::from_secs(60));

    let mut seen = vec![];
    for _ in 0..8 {
        seen.push(rank(&net.status().0));
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(seen.windows(2).all(|w| w[0] <= w[1]), "{seen:?}");
    assert_eq!(seen.first(), Some(&0), "{seen:?}");
    assert_eq!(seen.last(), Some(&2), "{seen:?}");
    assert!(seen.contains(&1), "{seen:?}");
}

#[tokio::test(start_paused = true)]
async fn one_failed_control_check_keeps_the_last_good_state_and_three_in_a_row_do_not() {
    let h = ChildHarness::new();
    h.ctx.children.set("t", Some(scripted_child(None)));
    let net = TorNetwork::new(TorChild::new("t", &h.ctx), Duration::from_secs(60));
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The child is up and nothing was checked over the control port yet: not "not connected".
    assert_eq!(net.status().0, NetworkStatus::Up);

    // No Tor answers (no socket, no port file): every check fails.
    assert!(net.disable(&[]).is_err());
    assert_eq!(net.status().0, NetworkStatus::Up, "one failure");
    assert!(net.disable(&[]).is_err());
    assert_eq!(net.status().0, NetworkStatus::Up, "two failures");
    assert!(net.disable(&[]).is_err());
    assert!(
        matches!(net.status().0, NetworkStatus::Down { .. }),
        "three"
    );

    // The child going away resets the count.
    h.ctx.children.set("t", None);
    h.ctx.children.wait_stopped("t").await;
    assert!(matches!(net.status().0, NetworkStatus::Down { .. }));
}

#[tokio::test]
async fn a_build_without_the_files_shows_the_network_as_unavailable() {
    let h = ChildHarness::new();
    // The engine knows files that are then removed from disk.
    let state = h.app_state(DaemonConfig::default()).await;
    std::fs::remove_dir_all(h.ctx.bundled.dir().unwrap().join("tor")).unwrap();
    let (_, applied) = state
        .engine
        .write()
        .await
        .add_network(&state, tor_instance())
        .await
        .unwrap();
    applied.unwrap();
    assert_eq!(h.spawner.started(), 0);
    let n = network(&state).await;
    assert_eq!(n.child.unwrap().state, ChildState::Unavailable);
    assert!(matches!(n.status, NetworkStatus::Down { .. }));
}
