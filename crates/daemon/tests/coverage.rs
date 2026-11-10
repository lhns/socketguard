//! Every route of the API has a client method, and the client has no method for a route
//! that does not exist (ADR 0033). Phase 7a extends this to CLI commands.

use socketguard_client::CLIENT_ROUTES;
use socketguard_daemon::api::ROUTES;
use std::collections::BTreeSet;

fn set(routes: &[(http::Method, &str)]) -> BTreeSet<(String, String)> {
    routes
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect()
}

#[test]
fn every_route_has_a_client_method_and_vice_versa() {
    let api = set(ROUTES);
    let client = set(CLIENT_ROUTES);
    assert_eq!(api.len(), ROUTES.len(), "duplicate route in ROUTES");
    let missing: Vec<_> = api.difference(&client).collect();
    let extra: Vec<_> = client.difference(&api).collect();
    assert!(
        missing.is_empty(),
        "routes without a client method: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "client methods for unknown routes: {extra:?}"
    );
}

#[test]
fn the_router_serves_every_route() {
    // Building the router panics if a route has no handler or two routes collide.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let state = socketguard_daemon::test_support::test_app_state(
            socketguard_daemon::engine::Engine::new_injectable(
                Box::new(socketguard_daemon::test_support::MockSocketMonitor::new(
                    vec![],
                )),
                std::sync::Arc::new(socketguard_daemon::test_support::MockFirewall::new(
                    Default::default(),
                )),
                std::sync::Arc::new(socketguard_daemon::test_support::MockNetworkInterface::new(
                    Default::default(),
                )),
                Default::default(),
            ),
            Default::default(),
        )
        .await;
        let _ = socketguard_daemon::api::router(state);
    });
}
