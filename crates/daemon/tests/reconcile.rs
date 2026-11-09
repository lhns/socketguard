// Scenarios are being rewritten for the new model; allow the old test style meanwhile.
#![allow(clippy::len_zero, clippy::await_holding_lock)]

use socketguard_core::config::{
    BackendConfig, BackendInstanceConfig, DaemonConfig, FilterMode, ProcessFilter,
};
use socketguard_core::{
    socket_id, BackendType, ListeningSocket, ManagedSocket, Policy, Protocol, SocketAddress,
};
use socketguard_daemon::engine::Engine;
use socketguard_daemon::firewall::{ScopeMatch, Sources};
use socketguard_daemon::test_support::*;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

/// Helper: build a DaemonConfig with one ULA-like backend.
fn single_backend_config() -> DaemonConfig {
    DaemonConfig {
        backends: vec![BackendInstanceConfig {
            id: "mock-ula".to_string(),
            backend: BackendConfig::Ula {
                interface: "lo".to_string(),
            },
        }],
        ..DaemonConfig::default()
    }
}

/// Helper: build a test engine with mock deps and a single mock backend.
fn build_test_engine(
    monitor: MockSocketMonitor,
    fw_calls: Arc<Mutex<Vec<FirewallCall>>>,
    net_calls: Arc<Mutex<Vec<NetworkCall>>>,
) -> Engine {
    let firewall = Arc::new(MockFirewall::new(fw_calls));
    let network = Arc::new(MockNetworkInterface::new(net_calls));

    let mock_backend = MockIpv6Backend::new("fd00::", 128, "lo");
    let mut backends = HashMap::new();
    backends.insert(
        "mock-ula".to_string(),
        socketguard_daemon::engine::ActiveBackend {
            config: BackendInstanceConfig {
                id: "mock-ula".to_string(),
                backend: BackendConfig::Ula {
                    interface: "lo".to_string(),
                },
            },
            backend: Box::new(mock_backend),
        },
    );

    Engine::new_injectable(
        Box::new(monitor),
        firewall,
        network,
        backends,
        vec!["mock-ula".to_string()],
    )
}

/// `Sources::Nets` with exactly one network.
fn only_source(net: &str) -> Sources {
    Sources::Nets(vec![net.parse().unwrap()])
}

/// Helper: create a listening socket.
fn listening_socket(name: &str, port: u16, protocol: Protocol) -> ListeningSocket {
    ListeningSocket {
        pid: 1000,
        process_name: name.to_string(),
        port,
        protocol,
        bind_address: IpAddr::V6("::".parse().unwrap()),
        exe_path: Some(format!("/usr/bin/{name}")),
        cmdline: Some(name.to_string()),
    }
}

// ─── Test 1: New socket provisioning ─────────────────────────────────────────

#[tokio::test]
async fn new_socket_gets_address_and_firewall() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Run reconcile
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    // DB should have the socket with an address
    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(sockets.len(), 1);
    assert_eq!(sockets[0].process_name, "nginx");
    assert_eq!(sockets[0].port, 80);
    assert_eq!(sockets[0].addresses.len(), 1);
    assert_eq!(sockets[0].addresses[0].backend_id, "mock-ula");

    // MockNetwork should have received add_address
    let net = net_calls.lock().unwrap();
    assert_eq!(net.len(), 1);
    assert!(
        matches!(&net[0], NetworkCall::AddAddress { iface, prefix, .. } if iface == "lo" && *prefix == 128)
    );

    // One ruleset: closed with no ACL has no rule, but the address is in the managed
    // scope, i.e. denied (not "inactive").
    let fw = applied(&fw_calls);
    assert_eq!(fw.len(), 1);
    assert!(fw[0].rules.is_empty());
    assert_eq!(fw[0].scopes.len(), 1);
    assert_eq!(fw[0].scopes[0].id, "managed");
    let ScopeMatch::Destinations(dsts) = &fw[0].scopes[0].matcher else {
        panic!("managed scope matches destinations");
    };
    assert_eq!(dsts, &vec![IpAddr::V6(sockets[0].addresses[0].address)]);
}

// ─── Test 2: Closed policy with ACL entries ──────────────────────────────────

#[tokio::test]
async fn closed_policy_with_acl_applies_allowed_ips() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // First reconcile: provisions the socket
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    // Add an ACL entry
    let sockets = state.db.list_sockets().await.unwrap();
    let socket = &sockets[0];
    state
        .db
        .add_acl_entry(&socket.id, "mock-ula", "fd00::100", Some("peer1"))
        .await
        .unwrap();

    // Clear call logs
    fw_calls.lock().unwrap().clear();
    net_calls.lock().unwrap().clear();

    // Second reconcile: should apply ACL with allowed IP
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let fw = applied(&fw_calls);
    assert_eq!(fw.len(), 1);
    assert_eq!(fw[0].rules.len(), 1);
    assert_eq!(fw[0].rules[0].port, 80);
    assert_eq!(fw[0].rules[0].sources, only_source("fd00::100/128"));
}

// ─── Test 3: Open policy ─────────────────────────────────────────────────────

#[tokio::test]
async fn open_policy_removes_acl() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // First reconcile: provisions the socket (closed by default)
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    // Change policy to open
    let sockets = state.db.list_sockets().await.unwrap();
    let socket = &sockets[0];
    state
        .db
        .update_address_policy(&socket.id, "mock-ula", Policy::Open)
        .await
        .unwrap();

    // Clear call logs
    fw_calls.lock().unwrap().clear();

    // Second reconcile
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let fw = applied(&fw_calls);
    assert_eq!(fw.len(), 1);
    assert_eq!(fw[0].rules.len(), 1);
    assert_eq!(fw[0].rules[0].sources, Sources::Any);
    // The address stays inside the managed scope; the rule is what lets traffic through.
    assert_eq!(fw[0].scopes[0].id, "managed");
}

// ─── Test 4: Policy change closed→open ───────────────────────────────────────

#[tokio::test]
async fn policy_change_closed_to_open_updates_firewall() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Reconcile 1: new socket, closed with no ACL: denied by the managed scope
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let sockets = state.db.list_sockets().await.unwrap();
    let socket = &sockets[0];

    // Verify initial state is closed
    assert_eq!(socket.addresses[0].policy, Policy::Closed);

    // Change to open
    state
        .db
        .update_address_policy(&socket.id, "mock-ula", Policy::Open)
        .await
        .unwrap();

    fw_calls.lock().unwrap().clear();

    // Reconcile 2: open policy gives an any-source rule
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let fw = applied(&fw_calls);
    assert_eq!(fw.len(), 1);
    assert_eq!(fw[0].rules.len(), 1);
    assert_eq!(fw[0].rules[0].sources, Sources::Any);
}

// ─── Test 5: Stale socket cleanup ────────────────────────────────────────────

#[tokio::test]
async fn stale_socket_gets_cleaned_up() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    // Monitor returns empty — the socket is gone
    let monitor = MockSocketMonitor::new(vec![]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Pre-populate DB with a stale socket (old last_seen)
    let stale_time = chrono::Utc::now() - chrono::Duration::seconds(3600);
    let addr = SocketAddress {
        backend_id: "mock-ula".to_string(),
        backend_type: BackendType::Ula,
        address: "fd00::99".parse().unwrap(),
        interface: "lo".to_string(),
        prefix_len: 128,
        policy: Policy::Closed,
    };
    let socket = ManagedSocket {
        id: "tcp:stale-proc:8080".to_string(),
        pid: 999,
        process_name: "stale-proc".to_string(),
        port: 8080,
        protocol: Protocol::Tcp,
        addresses: vec![addr.clone()],
        policy: Policy::Closed,
        exe_path: None,
        cmdline: None,
        first_seen: stale_time,
        last_seen: stale_time,
        acl_group_id: None,
        socket_group_ids: vec![],
    };
    state.db.upsert_socket(&socket).await.unwrap();
    state
        .db
        .upsert_socket_address(&socket.id, &addr)
        .await
        .unwrap();

    // Reconcile: socket not in monitor + stale last_seen → cleanup
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    // Socket should be removed from DB
    let sockets = state.db.list_sockets().await.unwrap();
    assert!(sockets.is_empty());

    // The last applied ruleset no longer mentions the address
    let fw = applied(&fw_calls);
    assert!(fw.last().unwrap().scopes.is_empty());
    assert!(fw.last().unwrap().rules.is_empty());

    // Network should have address removed
    let net = net_calls.lock().unwrap();
    assert!(net.iter().any(|c| matches!(c, NetworkCall::RemoveAddress { addr, .. } if *addr == "fd00::99".parse::<Ipv6Addr>().unwrap())));
}

// ─── Test 6: Multi-backend provisioning ──────────────────────────────────────

#[tokio::test]
async fn multi_backend_provisions_multiple_addresses() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let firewall = Arc::new(MockFirewall::new(fw_calls.clone()));
    let network = Arc::new(MockNetworkInterface::new(net_calls.clone()));

    let mock_ula = MockIpv6Backend::new("fd00::", 128, "lo");
    let mock_slaac = MockIpv6Backend::new("2001:db8::", 64, "eth0");

    let mut backends = HashMap::new();
    backends.insert(
        "mock-ula".to_string(),
        socketguard_daemon::engine::ActiveBackend {
            config: BackendInstanceConfig {
                id: "mock-ula".to_string(),
                backend: BackendConfig::Ula {
                    interface: "lo".to_string(),
                },
            },
            backend: Box::new(mock_ula),
        },
    );
    backends.insert(
        "mock-slaac".to_string(),
        socketguard_daemon::engine::ActiveBackend {
            config: BackendInstanceConfig {
                id: "mock-slaac".to_string(),
                backend: BackendConfig::Ula {
                    interface: "eth0".to_string(),
                },
            },
            backend: Box::new(mock_slaac),
        },
    );

    let engine = Engine::new_injectable(
        Box::new(monitor),
        firewall,
        network,
        backends,
        vec!["mock-ula".to_string(), "mock-slaac".to_string()],
    );

    let config = DaemonConfig {
        backends: vec![
            BackendInstanceConfig {
                id: "mock-ula".to_string(),
                backend: BackendConfig::Ula {
                    interface: "lo".to_string(),
                },
            },
            BackendInstanceConfig {
                id: "mock-slaac".to_string(),
                backend: BackendConfig::Ula {
                    interface: "eth0".to_string(),
                },
            },
        ],
        ..DaemonConfig::default()
    };
    let state = test_app_state(engine, config).await;

    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(sockets.len(), 1);
    assert_eq!(sockets[0].addresses.len(), 2);

    // Each address was added to its interface
    let net = net_calls.lock().unwrap();
    assert_eq!(net.len(), 2);

    // One ruleset covering both addresses in the managed scope, no rules (closed)
    let fw = applied(&fw_calls);
    assert_eq!(fw.len(), 1);
    assert!(fw[0].rules.is_empty());
    let ScopeMatch::Destinations(dsts) = &fw[0].scopes[0].matcher else {
        panic!("managed scope matches destinations");
    };
    assert_eq!(dsts.len(), 2);
}

// ─── Test 7: ACL group inheritance ───────────────────────────────────────────

#[tokio::test]
async fn acl_group_inheritance_applies_group_acl() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Reconcile to provision the socket
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let sockets = state.db.list_sockets().await.unwrap();
    let socket = &sockets[0];

    // Create ACL group with an entry
    let group = state.db.create_acl_group("webservers").await.unwrap();
    state
        .db
        .add_acl_group_entry(&group.id, "mock-ula", "fd00::200", Some("trusted"))
        .await
        .unwrap();

    // Add socket to group and set policy to Group
    state
        .db
        .add_to_acl_group(&group.id, &socket.id)
        .await
        .unwrap();
    state
        .db
        .update_address_policy(&socket.id, "mock-ula", Policy::Group)
        .await
        .unwrap();

    fw_calls.lock().unwrap().clear();

    // Reconcile: should resolve Group → Closed (group default) and apply group's ACL
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let fw = applied(&fw_calls);
    assert_eq!(
        fw.last().unwrap().rules[0].sources,
        only_source("fd00::200/128")
    );
}

// ─── Test 8: Process filter ──────────────────────────────────────────────────

#[tokio::test]
async fn process_filter_ignores_non_matching() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![
        listening_socket("nginx", 80, Protocol::Tcp),
        listening_socket("sshd", 22, Protocol::Tcp),
    ]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = DaemonConfig {
        backends: vec![BackendInstanceConfig {
            id: "mock-ula".to_string(),
            backend: BackendConfig::Ula {
                interface: "lo".to_string(),
            },
        }],
        process_filter: ProcessFilter {
            mode: FilterMode::Allowlist,
            patterns: vec!["nginx".to_string()],
        },
        ..DaemonConfig::default()
    };
    let state = test_app_state(engine, config).await;

    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    // Only nginx should be provisioned
    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(sockets.len(), 1);
    assert_eq!(sockets[0].process_name, "nginx");
}

// ─── Test 9: Startup reconcile ───────────────────────────────────────────────

#[tokio::test]
async fn startup_reconcile_restores_state() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Pre-populate DB with a socket that has an ACL entry (simulating previous run)
    let addr = SocketAddress {
        backend_id: "mock-ula".to_string(),
        backend_type: BackendType::Ula,
        address: "fd00::42".parse().unwrap(),
        interface: "lo".to_string(),
        prefix_len: 128,
        policy: Policy::Closed,
    };
    let socket = ManagedSocket {
        id: "tcp:nginx:80".to_string(),
        pid: 1000,
        process_name: "nginx".to_string(),
        port: 80,
        protocol: Protocol::Tcp,
        addresses: vec![addr.clone()],
        policy: Policy::Closed,
        exe_path: None,
        cmdline: None,
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        acl_group_id: None,
        socket_group_ids: vec![],
    };
    state.db.upsert_socket(&socket).await.unwrap();
    state
        .db
        .upsert_socket_address(&socket.id, &addr)
        .await
        .unwrap();
    state
        .db
        .add_acl_entry(&socket.id, "mock-ula", "fd00::100", Some("peer1"))
        .await
        .unwrap();

    // Run startup reconcile
    {
        let engine = state.engine.read().await;
        engine.startup_reconcile(&state).await;
    }

    // Startup applies the desired state straight away: no cleanup or disable first
    // (the frozen ruleset is replaced atomically, ADR 0026/0029).
    let fw = fw_calls.lock().unwrap();
    assert_eq!(fw.len(), 1);
    let FirewallCall::Apply(rs) = &fw[0] else {
        panic!("startup must apply, not flush: {:?}", fw[0]);
    };
    assert_eq!(rs.rules[0].sources, only_source("fd00::100/128"));

    // Should have re-added the address
    let net = net_calls.lock().unwrap();
    assert!(net.iter().any(|c| matches!(c, NetworkCall::AddAddress { addr, .. } if *addr == "fd00::42".parse::<Ipv6Addr>().unwrap())));
}

// ─── Test 10: Shutdown freezes state ─────────────────────────────────────────

#[tokio::test]
async fn shutdown_removes_nothing() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Pre-populate DB with two sockets
    for (name, port, ip_suffix) in [("nginx", 80u16, "42"), ("redis", 6379u16, "43")] {
        let addr = SocketAddress {
            backend_id: "mock-ula".to_string(),
            backend_type: BackendType::Ula,
            address: format!("fd00::{ip_suffix}").parse().unwrap(),
            interface: "lo".to_string(),
            prefix_len: 128,
            policy: Policy::Closed,
        };
        let socket = ManagedSocket {
            id: format!("tcp:{name}:{port}"),
            pid: 1000,
            process_name: name.to_string(),
            port,
            protocol: Protocol::Tcp,
            addresses: vec![addr.clone()],
            policy: Policy::Closed,
            exe_path: None,
            cmdline: None,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            acl_group_id: None,
            socket_group_ids: vec![],
        };
        state.db.upsert_socket(&socket).await.unwrap();
        state
            .db
            .upsert_socket_address(&socket.id, &addr)
            .await
            .unwrap();
    }

    {
        let engine = state.engine.read().await;
        engine.shutdown().await;
    }

    // Rules and addresses stay (ADR 0026): no firewall call, no address removal.
    assert!(fw_calls.lock().unwrap().is_empty());
    assert!(net_calls.lock().unwrap().is_empty());
}

// ─── Test 10b: disable removes everything ────────────────────────────────────

#[tokio::test]
async fn disable_removes_rules_and_addresses() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let engine = build_test_engine(
        MockSocketMonitor::new(vec![]),
        fw_calls.clone(),
        net_calls.clone(),
    );
    let state = test_app_state(engine, single_backend_config()).await;

    for (name, port, ip_suffix) in [("nginx", 80u16, "42"), ("redis", 6379u16, "43")] {
        let addr = SocketAddress {
            backend_id: "mock-ula".to_string(),
            backend_type: BackendType::Ula,
            address: format!("fd00::{ip_suffix}").parse().unwrap(),
            interface: "lo".to_string(),
            prefix_len: 128,
            policy: Policy::Closed,
        };
        let socket = ManagedSocket {
            id: format!("tcp:{name}:{port}"),
            pid: 1000,
            process_name: name.to_string(),
            port,
            protocol: Protocol::Tcp,
            addresses: vec![addr.clone()],
            policy: Policy::Closed,
            exe_path: None,
            cmdline: None,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            acl_group_id: None,
            socket_group_ids: vec![],
        };
        state.db.upsert_socket(&socket).await.unwrap();
        state
            .db
            .upsert_socket_address(&socket.id, &addr)
            .await
            .unwrap();
    }
    // A socket group address counts too.
    let group = state.db.create_socket_group("web", "nginx").await.unwrap();
    state
        .db
        .upsert_socket_group_address(&socketguard_core::SocketGroupAddress {
            group_id: group.id,
            backend_id: "mock-ula".into(),
            address: "fd00::44".parse().unwrap(),
            interface: "lo".into(),
            prefix_len: 128,
            policy: Policy::Closed,
        })
        .await
        .unwrap();

    {
        let engine = state.engine.read().await;
        engine.disable(&state).await.unwrap();
    }

    assert_eq!(*fw_calls.lock().unwrap(), vec![FirewallCall::Disable]);
    let net = net_calls.lock().unwrap();
    let removed: Vec<_> = net
        .iter()
        .filter_map(|c| match c {
            NetworkCall::RemoveAddress { addr, .. } => Some(*addr),
            _ => None,
        })
        .collect();
    assert_eq!(removed.len(), 3);
    assert!(removed.contains(&"fd00::44".parse().unwrap()));
}

// ─── Test 11: Error resilience — add_address fails for one backend ────────

#[tokio::test]
async fn error_resilience_partial_backend_failure() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let firewall = Arc::new(MockFirewall::new(fw_calls.clone()));
    // FailingNetworkInterface fails add_address on "eth0" but succeeds on "lo"
    let network = Arc::new(FailingNetworkInterface::new(net_calls.clone(), "eth0"));

    let mock_ula = MockIpv6Backend::new("fd00::", 128, "lo");
    let mock_slaac = MockIpv6Backend::new("2001:db8::", 64, "eth0");

    let mut backends = HashMap::new();
    backends.insert(
        "mock-ula".to_string(),
        socketguard_daemon::engine::ActiveBackend {
            config: BackendInstanceConfig {
                id: "mock-ula".to_string(),
                backend: BackendConfig::Ula {
                    interface: "lo".to_string(),
                },
            },
            backend: Box::new(mock_ula),
        },
    );
    backends.insert(
        "mock-slaac".to_string(),
        socketguard_daemon::engine::ActiveBackend {
            config: BackendInstanceConfig {
                id: "mock-slaac".to_string(),
                backend: BackendConfig::Ula {
                    interface: "eth0".to_string(),
                },
            },
            backend: Box::new(mock_slaac),
        },
    );

    let engine = Engine::new_injectable(
        Box::new(monitor),
        firewall,
        network,
        backends,
        vec!["mock-ula".to_string(), "mock-slaac".to_string()],
    );

    let config = DaemonConfig {
        backends: vec![
            BackendInstanceConfig {
                id: "mock-ula".to_string(),
                backend: BackendConfig::Ula {
                    interface: "lo".to_string(),
                },
            },
            BackendInstanceConfig {
                id: "mock-slaac".to_string(),
                backend: BackendConfig::Ula {
                    interface: "eth0".to_string(),
                },
            },
        ],
        ..DaemonConfig::default()
    };
    let state = test_app_state(engine, config).await;

    // Reconcile should succeed overall even though eth0 add_address fails
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    // DB should still have the socket with both addresses allocated
    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(sockets.len(), 1);
    assert_eq!(
        sockets[0].addresses.len(),
        2,
        "both addresses should be in DB even if one failed to add"
    );

    // Network mock should have attempted both add_address calls
    let net = net_calls.lock().unwrap();
    let add_count = net
        .iter()
        .filter(|c| matches!(c, NetworkCall::AddAddress { .. }))
        .count();
    assert_eq!(add_count, 2, "both add_address should have been attempted");

    // The ruleset covers both addresses regardless: the failed one is simply not on the
    // interface yet, so it is unreachable, and the scope is ready when it appears.
    let fw = applied(&fw_calls);
    assert_eq!(fw.len(), 1);
    let ScopeMatch::Destinations(dsts) = &fw[0].scopes[0].matcher else {
        panic!("managed scope matches destinations");
    };
    assert_eq!(dsts.len(), 2);
}

// ─── Test 11b: no ruleset in place, no addresses ─────────────────────────

#[tokio::test]
async fn failed_apply_keeps_addresses_off_interfaces() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));
    let firewall = Arc::new(MockFirewall::new(fw_calls.clone()));
    firewall.set_failing(true);
    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);
    let mut backends = HashMap::new();
    backends.insert(
        "mock-ula".to_string(),
        socketguard_daemon::engine::ActiveBackend {
            config: BackendInstanceConfig {
                id: "mock-ula".to_string(),
                backend: BackendConfig::Ula {
                    interface: "lo".to_string(),
                },
            },
            backend: Box::new(MockIpv6Backend::new("fd00::", 128, "lo")),
        },
    );
    let engine = Engine::new_injectable(
        Box::new(monitor),
        firewall.clone(),
        Arc::new(MockNetworkInterface::new(net_calls.clone())),
        backends,
        vec!["mock-ula".to_string()],
    );
    let state = test_app_state(engine, single_backend_config()).await;

    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }
    assert!(
        net_calls.lock().unwrap().is_empty(),
        "an address nothing denies must not be added"
    );

    // Once the firewall works again the next pass applies and adds the address.
    firewall.set_failing(false);
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }
    assert_eq!(net_calls.lock().unwrap().len(), 1);
}

// ─── Test 12: Backend add/remove ─────────────────────────────────────────

#[tokio::test]
async fn backend_add_and_remove() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // First reconcile: provisions nginx with mock-ula backend
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(sockets[0].addresses.len(), 1);
    assert_eq!(sockets[0].addresses[0].backend_id, "mock-ula");

    fw_calls.lock().unwrap().clear();
    net_calls.lock().unwrap().clear();

    // Add a new backend directly (bypassing check_config_change which calls create_backend)
    let new_inst = BackendInstanceConfig {
        id: "mock-slaac".to_string(),
        backend: BackendConfig::Ula {
            interface: "eth0".to_string(),
        },
    };
    {
        let mut engine = state.engine.write().await;
        engine.add_backend_instance(&state, &new_inst).await;
    }

    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(
        sockets[0].addresses.len(),
        2,
        "new backend should have allocated an address"
    );

    // Network should have added the new address on eth0
    let net = net_calls.lock().unwrap();
    assert!(net
        .iter()
        .any(|c| matches!(c, NetworkCall::AddAddress { iface, .. } if iface == "eth0")));
    drop(net);

    net_calls.lock().unwrap().clear();

    // Remove the original backend
    {
        let mut engine = state.engine.write().await;
        engine.remove_backend_instance(&state, "mock-ula").await;
    }

    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(
        sockets[0].addresses.len(),
        1,
        "removed backend's address should be gone"
    );
    assert_eq!(sockets[0].addresses[0].backend_id, "mock-slaac");

    // Network should have removed the old address from lo
    let net = net_calls.lock().unwrap();
    assert!(net
        .iter()
        .any(|c| matches!(c, NetworkCall::RemoveAddress { iface, .. } if iface == "lo")));
}

// ─── Test 13: Socket group provisioning + ACL ────────────────────────────

#[tokio::test]
async fn socket_group_provisioning_and_acl() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![
        listening_socket("nginx", 80, Protocol::Tcp),
        listening_socket("nginx", 443, Protocol::Tcp),
    ]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Reconcile: provisions both sockets
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(sockets.len(), 2);

    // Create a socket group and add both members
    let group = state.db.create_socket_group("web", "nginx").await.unwrap();
    state
        .db
        .add_socket_to_group(&group.id, &sockets[0].id)
        .await
        .unwrap();
    state
        .db
        .add_socket_to_group(&group.id, &sockets[1].id)
        .await
        .unwrap();

    net_calls.lock().unwrap().clear();

    // Reconcile again: ensure_socket_group_addresses should allocate addresses for the group
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    // Socket group should have an address allocated
    let sg_addrs = state
        .db
        .get_socket_group_addresses(&group.id)
        .await
        .unwrap();
    assert_eq!(
        sg_addrs.len(),
        1,
        "group should have one address from mock-ula backend"
    );
    assert_eq!(sg_addrs[0].backend_id, "mock-ula");

    // Network should have added the group address
    let net = net_calls.lock().unwrap();
    assert!(net
        .iter()
        .any(|c| matches!(c, NetworkCall::AddAddress { .. })));

    // Add an ACL entry to the socket group
    state
        .db
        .add_socket_group_acl_entry(&group.id, "mock-ula", "fd00::300", Some("trusted"))
        .await
        .unwrap();

    fw_calls.lock().unwrap().clear();

    // Apply socket group ACL
    {
        let engine = state.engine.read().await;
        engine
            .apply_socket_group_acl(&state, &group.id)
            .await
            .unwrap();
    }

    // One rule per member (443 and 80) for the group's address, with the ACL source
    let fw = applied(&fw_calls);
    let rs = fw.last().unwrap();
    let group_rules: Vec<_> = rs.rules.iter().filter(|r| r.id.starts_with("g:")).collect();
    let mut ports: Vec<_> = group_rules.iter().map(|r| r.port).collect();
    ports.sort();
    assert_eq!(ports, [80, 443]);
    assert!(group_rules
        .iter()
        .all(|r| r.dst == IpAddr::V6(sg_addrs[0].address)
            && r.sources == only_source("fd00::300/128")));
}

// ─── Test 14: Idempotency — reconcile 3x with no state changes ──────────

#[tokio::test]
async fn idempotent_reconcile_no_duplicate_calls() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Reconcile 1: provisions socket
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let sockets_after_1 = state.db.list_sockets().await.unwrap();
    assert_eq!(sockets_after_1.len(), 1);
    assert_eq!(sockets_after_1[0].addresses.len(), 1);

    // Record initial call counts
    let initial_net_count = net_calls.lock().unwrap().len(); // 1 add_address
    let initial_fw_count = fw_calls.lock().unwrap().len(); // 1 ruleset

    // Reconcile 2 and 3: no new sockets, same state
    for _ in 0..2 {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    // DB should still have exactly 1 socket with 1 address
    let sockets_after_3 = state.db.list_sockets().await.unwrap();
    assert_eq!(sockets_after_3.len(), 1);
    assert_eq!(sockets_after_3[0].addresses.len(), 1);

    // Network add_address should NOT have grown — existing sockets don't get re-added
    let final_net_count = net_calls.lock().unwrap().len();
    assert_eq!(
        final_net_count, initial_net_count,
        "no new add_address calls on idempotent reconciles"
    );

    // An unchanged ruleset is not re-sent.
    let final_fw_count = fw_calls.lock().unwrap().len();
    assert_eq!(
        final_fw_count, initial_fw_count,
        "unchanged state must not re-apply the ruleset"
    );
}

// ─── Test 15: PID change — same process/port, different PID ──────────────

#[tokio::test]
async fn pid_change_updates_metadata_not_duplicated() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Reconcile 1: provisions nginx PID 1000
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(sockets.len(), 1);
    assert_eq!(sockets[0].pid, 1000);
    let original_addr = sockets[0].addresses[0].address;
    let original_id = sockets[0].id.clone();

    // The socket_id is deterministic based on (process_name, port, protocol),
    // so a new PID with same name/port maps to the same socket ID.
    let expected_id = socket_id("nginx", 80, Protocol::Tcp);
    assert_eq!(
        original_id, expected_id,
        "socket ID should be based on name/port/proto, not PID"
    );

    // Manually update the DB socket's PID to simulate what would happen
    // if monitor returned a different PID — the reconcile logic uses get_socket(sid)
    // which matches on socket_id, then updates pid/process_name/exe_path/cmdline.
    // Since we can't change the mock monitor's output, verify the identity property:
    // running reconcile again with same monitor output doesn't create a duplicate.

    net_calls.lock().unwrap().clear();

    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let sockets = state.db.list_sockets().await.unwrap();
    assert_eq!(
        sockets.len(),
        1,
        "same process/port should not create a duplicate socket"
    );
    assert_eq!(sockets[0].id, original_id);
    assert_eq!(
        sockets[0].addresses[0].address, original_addr,
        "address should be stable across reconciles"
    );

    // No new add_address calls — the socket already exists
    let net = net_calls.lock().unwrap();
    assert!(
        net.is_empty(),
        "existing socket should not trigger new add_address"
    );
}

// ─── Test 16: Event emission on socket changes ──────────────────────────

#[tokio::test]
async fn event_emission_on_new_and_stale_sockets() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));

    let monitor = MockSocketMonitor::new(vec![listening_socket("nginx", 80, Protocol::Tcp)]);

    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls.clone());
    let config = single_backend_config();
    let state = test_app_state(engine, config).await;

    // Subscribe to events BEFORE reconcile
    let mut rx = state.events.subscribe();

    // Reconcile 1: new socket detected → should emit SocketsChanged
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    // Check event was emitted
    let event = rx.try_recv();
    assert!(
        event.is_ok(),
        "SocketsChanged event should be emitted when new sockets are provisioned"
    );

    // Reconcile 2: no changes → no event expected
    // Drain any remaining events first
    while rx.try_recv().is_ok() {}

    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let event2 = rx.try_recv();
    assert!(
        event2.is_err(),
        "no event should be emitted when nothing changed"
    );

    // Now create a stale socket and reconcile to trigger cleanup → event
    let stale_time = chrono::Utc::now() - chrono::Duration::seconds(3600);
    let addr = SocketAddress {
        backend_id: "mock-ula".to_string(),
        backend_type: BackendType::Ula,
        address: "fd00::99".parse().unwrap(),
        interface: "lo".to_string(),
        prefix_len: 128,
        policy: Policy::Closed,
    };
    let stale_socket = ManagedSocket {
        id: "tcp:stale:9999".to_string(),
        pid: 9999,
        process_name: "stale".to_string(),
        port: 9999,
        protocol: Protocol::Tcp,
        addresses: vec![addr.clone()],
        policy: Policy::Closed,
        exe_path: None,
        cmdline: None,
        first_seen: stale_time,
        last_seen: stale_time,
        acl_group_id: None,
        socket_group_ids: vec![],
    };
    state.db.upsert_socket(&stale_socket).await.unwrap();
    state
        .db
        .upsert_socket_address(&stale_socket.id, &addr)
        .await
        .unwrap();

    // Drain events
    while rx.try_recv().is_ok() {}

    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let event3 = rx.try_recv();
    assert!(
        event3.is_ok(),
        "SocketsChanged event should be emitted when stale sockets are cleaned up"
    );
}

// ─── Phase 3: address stability ──────────────────────────────────────────────

/// Engine with one prefix-tracking mock backend ("ygg0") that tests can steer through
/// the returned handles.
struct PrefixHarness {
    state: Arc<socketguard_daemon::AppState>,
    backend: MockIpv6Backend,
    net: MockNetworkInterface,
    fw_calls: Arc<Mutex<Vec<FirewallCall>>>,
}

async fn prefix_harness(sockets: Vec<ListeningSocket>) -> PrefixHarness {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net = MockNetworkInterface::new(Arc::new(Mutex::new(Vec::new())));
    let backend = MockIpv6Backend::new("300:1:2:3::", 128, "ygg0");
    backend.set_prefix("300:1:2:3::");
    let monitor = MockSocketMonitor::new(sockets);

    let cfg = BackendInstanceConfig {
        id: "ygg".to_string(),
        backend: BackendConfig::Yggdrasil {
            interface: "ygg0".to_string(),
            admin_endpoint: None,
        },
    };
    let mut backends = HashMap::new();
    backends.insert(
        "ygg".to_string(),
        socketguard_daemon::engine::ActiveBackend {
            config: cfg.clone(),
            backend: Box::new(backend.clone()),
        },
    );
    let engine = Engine::new_injectable(
        Box::new(monitor),
        Arc::new(MockFirewall::new(fw_calls.clone())),
        Arc::new(net.clone()),
        backends,
        vec!["ygg".to_string()],
    );
    let state = test_app_state(
        engine,
        DaemonConfig {
            backends: vec![cfg],
            ..DaemonConfig::default()
        },
    )
    .await;
    PrefixHarness {
        state,
        backend,
        net,
        fw_calls,
    }
}

impl PrefixHarness {
    async fn reconcile(&self) {
        let mut engine = self.state.engine.write().await;
        engine.reconcile(&self.state).await.unwrap();
    }
}

fn addr(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

#[tokio::test]
async fn prefix_change_rehomes_socket_address_keeping_iid() {
    let h = prefix_harness(vec![listening_socket("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;

    let sockets = h.state.db.list_sockets().await.unwrap();
    let sid = sockets[0].id.clone();
    let old = sockets[0].addresses[0].address;
    assert_eq!(old, addr("300:1:2:3::1"));
    assert!(h.net.addresses("ygg0").contains(&old));
    h.state
        .db
        .update_address_policy(&sid, "ygg", Policy::Open)
        .await
        .unwrap();
    h.fw_calls.lock().unwrap().clear();

    h.backend.set_prefix("300:9:9:9::");
    h.reconcile().await;

    let new = h.state.db.list_sockets().await.unwrap()[0].addresses[0].address;
    assert_eq!(new, addr("300:9:9:9::1"), "same interface ID, new prefix");
    let on_iface = h.net.addresses("ygg0");
    assert!(on_iface.contains(&new));
    assert!(!on_iface.contains(&old));

    // The ruleset follows the address: open rule and managed scope now name the new one.
    let fw = applied(&h.fw_calls);
    let last = fw.last().unwrap();
    assert_eq!(last.rules.len(), 1);
    assert_eq!(last.rules[0].dst, IpAddr::V6(new));
    let ScopeMatch::Destinations(dsts) = &last.scopes[0].matcher else {
        panic!("managed scope matches destinations");
    };
    assert_eq!(dsts, &vec![IpAddr::V6(new)]);
}

#[tokio::test]
async fn prefix_change_rehomes_socket_group_address() {
    let h = prefix_harness(vec![
        listening_socket("nginx", 80, Protocol::Tcp),
        listening_socket("nginx", 443, Protocol::Tcp),
    ])
    .await;
    h.reconcile().await;
    let sockets = h.state.db.list_sockets().await.unwrap();
    let group = h
        .state
        .db
        .create_socket_group("web", "nginx")
        .await
        .unwrap();
    for s in &sockets {
        h.state
            .db
            .add_socket_to_group(&group.id, &s.id)
            .await
            .unwrap();
    }
    h.reconcile().await;
    let old = h
        .state
        .db
        .get_socket_group_addresses(&group.id)
        .await
        .unwrap()[0]
        .address;
    assert!(h.net.addresses("ygg0").contains(&old));

    h.backend.set_prefix("300:9:9:9::");
    h.reconcile().await;

    let new = h
        .state
        .db
        .get_socket_group_addresses(&group.id)
        .await
        .unwrap()[0]
        .address;
    assert_eq!(socketguard_daemon::backend::iid_of(new), 3);
    assert!(socketguard_daemon::backend::same_prefix64(
        new,
        addr("300:9:9:9::")
    ));
    assert!(h.net.addresses("ygg0").contains(&new));
    assert!(!h.net.addresses("ygg0").contains(&old));
}

#[tokio::test]
async fn missing_address_is_re_added() {
    let h = prefix_harness(vec![listening_socket("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    let sid = h.state.db.list_sockets().await.unwrap()[0].id.clone();
    let a = h.state.db.list_sockets().await.unwrap()[0].addresses[0].address;
    // Closed addresses are on the interface too (denied by the ruleset, not absent).
    h.net.drop_address("ygg0", a);
    h.reconcile().await;
    assert!(
        h.net.addresses("ygg0").contains(&a),
        "closed address is restored"
    );

    h.state
        .db
        .update_address_policy(&sid, "ygg", Policy::Open)
        .await
        .unwrap();
    h.net.drop_address("ygg0", a);
    h.reconcile().await;
    assert!(
        h.net.addresses("ygg0").contains(&a),
        "open address is restored"
    );
}

#[tokio::test]
async fn missing_interface_is_skipped_then_recovers() {
    let h = prefix_harness(vec![listening_socket("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    let sid = h.state.db.list_sockets().await.unwrap()[0].id.clone();
    h.state
        .db
        .update_address_policy(&sid, "ygg", Policy::Open)
        .await
        .unwrap();
    let a = h.state.db.list_sockets().await.unwrap()[0].addresses[0].address;

    // Yggdrasil is down: the tun is gone. Reconcile must not fail.
    h.net.set_interface_missing("ygg0", true);
    h.reconcile().await;
    assert!(h.net.addresses("ygg0").is_empty());

    // Yggdrasil is back with a fresh tun.
    h.net.set_interface_missing("ygg0", false);
    h.reconcile().await;
    assert!(h.net.addresses("ygg0").contains(&a));
}

#[tokio::test]
async fn ula_global_id_survives_restart() {
    let path = std::env::temp_dir().join(format!("sg-ula-{}.db", uuid::Uuid::new_v4()));
    let path_str = path.to_str().unwrap();
    let ula = BackendConfig::Ula {
        interface: "lo".to_string(),
    };

    let first = {
        let db = socketguard_daemon::state::Database::new(path_str)
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let id = db.ula_global_id().await.unwrap();
        let b = socketguard_daemon::backend::create_backend(&ula, id).unwrap();
        (id, b.allocate(None).unwrap().address.octets())
    };

    // "Restart": reopen the same DB and rebuild the backend.
    let db = socketguard_daemon::state::Database::new(path_str)
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let id = db.ula_global_id().await.unwrap();
    assert_eq!(id, first.0);
    let b = socketguard_daemon::backend::create_backend(&ula, id).unwrap();
    assert_eq!(
        b.allocate(None).unwrap().address.octets()[..6],
        first.1[..6]
    );

    drop(db);
    let _ = std::fs::remove_file(&path);
}

// ─── Whole-host protection and the lockout guard ─────────────────────────────

fn sshd_listener() -> ListeningSocket {
    listening_socket("sshd", 22, Protocol::Tcp)
}

#[tokio::test]
async fn protect_host_is_refused_when_it_would_lock_out_sshd() {
    use socketguard_daemon::engine::ProtectHostError;
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));
    let monitor = MockSocketMonitor::new(vec![sshd_listener()]);
    let engine = build_test_engine(monitor, fw_calls.clone(), net_calls);
    let state = test_app_state(engine, single_backend_config()).await;
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }
    fw_calls.lock().unwrap().clear();

    // sshd is closed with no grant: refused, nothing stored, nothing applied.
    let err = {
        let engine = state.engine.read().await;
        engine
            .set_protect_host(&state, vec!["eth0".into()], false)
            .await
            .unwrap_err()
    };
    assert!(matches!(&err, ProtectHostError::Lockout(r) if r.len() == 1 && r[0].port == 22));
    assert!(state
        .db
        .get_setting("protect_host_interfaces")
        .await
        .unwrap()
        .is_none());
    assert!(fw_calls.lock().unwrap().is_empty());

    // Force overrides, reports the risk, stores the setting and applies the scope.
    let risks = {
        let engine = state.engine.read().await;
        engine
            .set_protect_host(&state, vec!["eth0".into()], true)
            .await
            .unwrap()
    };
    assert_eq!(risks.len(), 1);
    assert_eq!(
        state
            .db
            .get_setting("protect_host_interfaces")
            .await
            .unwrap()
            .as_deref(),
        Some(r#"["eth0"]"#)
    );
    let rs = applied(&fw_calls).pop().unwrap();
    assert!(rs.scopes.iter().any(|s| s.id == "host:eth0"));

    // An empty list switches it off again, without any check.
    {
        let engine = state.engine.read().await;
        engine
            .set_protect_host(&state, vec![], false)
            .await
            .unwrap();
    }
    let rs = applied(&fw_calls).pop().unwrap();
    assert!(!rs.scopes.iter().any(|s| s.id == "host:eth0"));
}

#[tokio::test]
async fn protect_host_is_allowed_once_sshd_is_granted() {
    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let monitor = MockSocketMonitor::new(vec![sshd_listener()]);
    let engine = build_test_engine(monitor, fw_calls, Arc::new(Mutex::new(Vec::new())));
    let state = test_app_state(engine, single_backend_config()).await;
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }
    let sid = state.db.list_sockets().await.unwrap()[0].id.clone();
    state
        .db
        .update_address_policy(&sid, "mock-ula", Policy::Open)
        .await
        .unwrap();

    let engine = state.engine.read().await;
    let risks = engine
        .set_protect_host(&state, vec!["lo".into()], false)
        .await
        .unwrap();
    assert!(risks.is_empty());
}
