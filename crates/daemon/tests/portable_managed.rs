//! Managed Tor and Yggdrasil (ADR 0052) under the portable teardown (ADR 0054): the one place
//! portable mode ends the run is `portable::teardown`, and when it has returned no child of
//! SocketGuard is left running.

use socketguard_core::config::{BackendConfig, BackendInstanceConfig, DaemonConfig};
use socketguard_core::ChildState;
use socketguard_daemon::portable;
use socketguard_daemon::test_support::*;
use std::time::Duration;

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..500 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn the_teardown_waits_for_a_managed_tor_and_a_managed_yggdrasil_to_be_gone() {
    let h = ManagedHarness::new();
    let state = h.app_state(DaemonConfig::default()).await;
    for inst in [
        BackendInstanceConfig {
            id: "tor".into(),
            backend: BackendConfig::managed_tor(),
        },
        BackendInstanceConfig {
            id: "ygg".into(),
            backend: BackendConfig::managed_yggdrasil(vec![]),
        },
    ] {
        let (_, applied) = state
            .engine
            .write()
            .await
            .add_network(&state, inst)
            .await
            .unwrap();
        applied.unwrap();
    }
    wait_until("both children to start", || h.spawner.running().len() == 2).await;
    let names: Vec<String> = h
        .spawner
        .running()
        .iter()
        .map(|p| p.spec.name.clone())
        .collect();
    assert!(
        names.contains(&"tor".to_string()) && names.contains(&"yggdrasil".to_string()),
        "{names:?}"
    );

    // The teardown alone, without the supervisor shutdown `run` does first: `mark_done`
    // follows only after it returns, so the children must be gone by then either way.
    let left = portable::teardown(&state).await;
    assert!(left.is_empty(), "{left:?}");
    assert!(
        h.spawner.running().is_empty(),
        "no child runs once the teardown has returned"
    );
    for id in ["tor", "ygg"] {
        assert_eq!(h.ctx.children.status(id).state, ChildState::Stopped, "{id}");
    }
    // Asked politely first (Tor and Yggdrasil flush their state on SIGTERM).
    for n in 0..2 {
        assert_eq!(h.spawner.proc(n).signals(), ["term"]);
    }
    // The on/off setting is back as it was: the networks, not the teardown, decide again.
    assert!(!state.db.disabled().await);

    // Closing the supervisor afterwards is a no-op for what has already ended.
    h.ctx.children.shutdown().await;
    assert!(h.spawner.running().is_empty());
}

/// The order `run` uses: the supervisor is shut down first, then the teardown runs. It must
/// not hang on children that are already gone, and nothing is left.
#[tokio::test]
async fn the_teardown_after_the_supervisor_shutdown_returns_with_nothing_left() {
    let h = ManagedHarness::new();
    let state = h.app_state(DaemonConfig::default()).await;
    let (_, applied) = state
        .engine
        .write()
        .await
        .add_network(
            &state,
            BackendInstanceConfig {
                id: "tor".into(),
                backend: BackendConfig::managed_tor(),
            },
        )
        .await
        .unwrap();
    applied.unwrap();
    wait_until("the child to start", || h.spawner.running().len() == 1).await;
    h.ctx.children.shutdown().await;
    assert!(h.spawner.running().is_empty());
    let left = tokio::time::timeout(Duration::from_secs(10), portable::teardown(&state))
        .await
        .expect("the teardown does not hang");
    assert!(left.is_empty(), "{left:?}");
    assert!(h.spawner.running().is_empty());
}
