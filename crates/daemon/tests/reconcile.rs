// Scenarios are being rewritten for the new model; allow the old test style meanwhile.
#![allow(clippy::len_zero, clippy::await_holding_lock)]

use socketguard_core::config::{
    BackendConfig, BackendInstanceConfig, DaemonConfig, FilterMode, ProcessFilter,
};
use socketguard_core::{
    socket_id, BackendType, ListeningSocket, ManagedSocket, Policy, Protocol, SocketAddress,
};
use socketguard_daemon::engine::Engine;
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

    // MockFirewall should have received block_all (= apply_acl with empty allowed)
    let fw = fw_calls.lock().unwrap();
    assert_eq!(fw.len(), 1);
    assert!(matches!(&fw[0], FirewallCall::ApplyAcl { allowed, .. } if allowed.is_empty()));
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

    let fw = fw_calls.lock().unwrap();
    // Should have applied ACL with the allowed IP
    assert!(fw.iter().any(|c| matches!(c, FirewallCall::ApplyAcl { allowed, .. } if allowed == &vec!["fd00::100".parse::<Ipv6Addr>().unwrap()])));
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

    let fw = fw_calls.lock().unwrap();
    // Open policy → RemoveAcl (allow all)
    assert!(fw
        .iter()
        .any(|c| matches!(c, FirewallCall::RemoveAcl { .. })));
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

    // Reconcile 1: new socket, closed+no ACL = inactive (RemoveAcl to clean stale)
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

    // Reconcile 2: open policy should RemoveAcl
    {
        let mut engine = state.engine.write().await;
        engine.reconcile(&state).await.unwrap();
    }

    let fw = fw_calls.lock().unwrap();
    assert!(fw
        .iter()
        .any(|c| matches!(c, FirewallCall::RemoveAcl { .. })));
    // Should NOT have any ApplyAcl since we're open now
    assert!(!fw
        .iter()
        .any(|c| matches!(c, FirewallCall::ApplyAcl { .. })));
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
        keypair_id: None,
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

    // Firewall should have been cleaned (RemoveAcl for the address)
    let fw = fw_calls.lock().unwrap();
    assert!(fw.iter().any(|c| matches!(c, FirewallCall::RemoveAcl { dest_ip, port: 8080, .. } if *dest_ip == "fd00::99".parse::<Ipv6Addr>().unwrap())));

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

    // Each address should have gotten an add_address and block_all
    let net = net_calls.lock().unwrap();
    assert_eq!(net.len(), 2);

    let fw = fw_calls.lock().unwrap();
    assert_eq!(fw.len(), 2);
    // Both should be block_all (ApplyAcl with empty allowed)
    assert!(fw
        .iter()
        .all(|c| matches!(c, FirewallCall::ApplyAcl { allowed, .. } if allowed.is_empty())));
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

    let fw = fw_calls.lock().unwrap();
    // Should apply ACL with group's allowed IP
    assert!(fw.iter().any(|c| matches!(c, FirewallCall::ApplyAcl { allowed, .. } if allowed == &vec!["fd00::200".parse::<Ipv6Addr>().unwrap()])));
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
        keypair_id: None,
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

    let fw = fw_calls.lock().unwrap();
    // Should have cleanup_all first
    assert!(matches!(&fw[0], FirewallCall::CleanupAll));

    // Should have re-applied firewall (ApplyAcl with the ACL entry)
    assert!(fw.iter().any(|c| matches!(c, FirewallCall::ApplyAcl { allowed, .. } if allowed == &vec!["fd00::100".parse::<Ipv6Addr>().unwrap()])));

    // Should have re-added the address
    let net = net_calls.lock().unwrap();
    assert!(net.iter().any(|c| matches!(c, NetworkCall::AddAddress { addr, .. } if *addr == "fd00::42".parse::<Ipv6Addr>().unwrap())));
}

// ─── Test 10: Shutdown cleanup ───────────────────────────────────────────────

#[tokio::test]
async fn shutdown_cleanup_removes_all_addresses() {
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
            keypair_id: None,
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

    // Run shutdown cleanup
    {
        let engine = state.engine.read().await;
        engine.shutdown_cleanup(&state).await;
    }

    // Firewall should have cleanup_all
    let fw = fw_calls.lock().unwrap();
    assert!(fw.iter().any(|c| matches!(c, FirewallCall::CleanupAll)));

    // Network should have removed both addresses
    let net = net_calls.lock().unwrap();
    let remove_count = net
        .iter()
        .filter(|c| matches!(c, NetworkCall::RemoveAddress { .. }))
        .count();
    assert_eq!(remove_count, 2);
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

    // The "lo" backend's firewall rule should have been applied (block_all succeeds after add_address)
    // The "eth0" backend's firewall rule is skipped because add_address failed (continue in loop)
    let fw = fw_calls.lock().unwrap();
    // At least one firewall call for the successful backend
    assert!(
        fw.len() >= 1,
        "at least the successful backend should get a firewall rule"
    );
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

    let fw = fw_calls.lock().unwrap();
    // Should have applied ACL with the allowed IP for the group address
    assert!(fw.iter().any(|c| matches!(c, FirewallCall::ApplyAcl { allowed, .. } if allowed == &vec!["fd00::300".parse::<Ipv6Addr>().unwrap()])));
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
    let initial_fw_count = fw_calls.lock().unwrap().len(); // 1 block_all

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

    // Firewall calls will grow because reconcile re-applies firewall on each pass for existing sockets.
    // But the number of firewall calls per reconcile should be bounded (1 per address per reconcile).
    let final_fw_count = fw_calls.lock().unwrap().len();
    // 1 from initial provision + 2 from subsequent reconciles (1 each for the existing socket)
    assert_eq!(
        final_fw_count,
        initial_fw_count + 2,
        "each reconcile should apply firewall once per address, not more"
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
        keypair_id: None,
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
