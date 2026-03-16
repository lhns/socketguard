use crate::backend::Ipv6Backend;
use crate::firewall::Firewall;
use crate::monitor::SocketMonitor;
use crate::network::NetworkInterface;
use crate::AppState;
use anyhow::Result;
use socketguard_core::config::DaemonConfig;
use socketguard_core::{AllocatedAddress, BackendType, ListeningSocket, Protocol};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

// ─── MockFirewall ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum FirewallCall {
    ApplyAcl {
        dest_ip: Ipv6Addr,
        port: u16,
        protocol: Protocol,
        allowed: Vec<Ipv6Addr>,
    },
    RemoveAcl {
        dest_ip: Ipv6Addr,
        port: u16,
        protocol: Protocol,
    },
    CleanupAll,
}

pub struct MockFirewall {
    pub calls: Arc<Mutex<Vec<FirewallCall>>>,
}

impl MockFirewall {
    pub fn new(calls: Arc<Mutex<Vec<FirewallCall>>>) -> Self {
        Self { calls }
    }
}

impl Firewall for MockFirewall {
    fn apply_acl(
        &self,
        dest_ip: Ipv6Addr,
        dest_port: u16,
        protocol: Protocol,
        allowed: &[Ipv6Addr],
    ) -> Result<()> {
        self.calls.lock().unwrap().push(FirewallCall::ApplyAcl {
            dest_ip,
            port: dest_port,
            protocol,
            allowed: allowed.to_vec(),
        });
        Ok(())
    }

    fn remove_acl(
        &self,
        dest_ip: Ipv6Addr,
        dest_port: u16,
        protocol: Protocol,
    ) -> Result<()> {
        self.calls.lock().unwrap().push(FirewallCall::RemoveAcl {
            dest_ip,
            port: dest_port,
            protocol,
        });
        Ok(())
    }

    fn cleanup_all_rules(&self) -> Result<()> {
        self.calls.lock().unwrap().push(FirewallCall::CleanupAll);
        Ok(())
    }
}

// ─── MockNetworkInterface ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkCall {
    AddAddress {
        iface: String,
        addr: Ipv6Addr,
        prefix: u8,
    },
    RemoveAddress {
        iface: String,
        addr: Ipv6Addr,
    },
}

pub struct MockNetworkInterface {
    pub calls: Arc<Mutex<Vec<NetworkCall>>>,
}

impl MockNetworkInterface {
    pub fn new(calls: Arc<Mutex<Vec<NetworkCall>>>) -> Self {
        Self { calls }
    }
}

impl NetworkInterface for MockNetworkInterface {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        self.calls.lock().unwrap().push(NetworkCall::AddAddress {
            iface: iface.to_string(),
            addr,
            prefix,
        });
        Ok(())
    }

    fn remove_address(&self, iface: &str, addr: Ipv6Addr) -> Result<()> {
        self.calls.lock().unwrap().push(NetworkCall::RemoveAddress {
            iface: iface.to_string(),
            addr,
        });
        Ok(())
    }

    fn list_interfaces(&self) -> Result<Vec<String>> {
        Ok(vec!["lo".to_string()])
    }
}

// ─── MockSocketMonitor ───────────────────────────────────────────────────────

pub struct MockSocketMonitor {
    pub sockets: Arc<Mutex<Vec<ListeningSocket>>>,
}

impl MockSocketMonitor {
    pub fn new(sockets: Vec<ListeningSocket>) -> Self {
        Self {
            sockets: Arc::new(Mutex::new(sockets)),
        }
    }
}

impl SocketMonitor for MockSocketMonitor {
    fn list_listening_sockets(&self) -> Result<Vec<ListeningSocket>> {
        Ok(self.sockets.lock().unwrap().clone())
    }
}

// ─── MockIpv6Backend ─────────────────────────────────────────────────────────

pub struct MockIpv6Backend {
    counter: std::sync::atomic::AtomicU64,
    prefix: u128,
    prefix_len: u8,
    interface: String,
}

impl MockIpv6Backend {
    pub fn new(prefix: &str, prefix_len: u8, interface: &str) -> Self {
        let addr: Ipv6Addr = prefix.parse().unwrap();
        Self {
            counter: std::sync::atomic::AtomicU64::new(1),
            prefix: u128::from(addr),
            prefix_len,
            interface: interface.to_string(),
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

impl Ipv6Backend for MockIpv6Backend {
    fn allocate_address(&self) -> Result<AllocatedAddress> {
        let n = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let addr = Ipv6Addr::from(self.prefix | n as u128);
        Ok(AllocatedAddress {
            address: addr,
            prefix_len: self.prefix_len,
            backend: BackendType::Ula,
            keypair: None,
        })
    }

    fn release_address(&self, _addr: &Ipv6Addr) -> Result<()> {
        Ok(())
    }
}

// ─── FailingNetworkInterface ─────────────────────────────────────────────────

/// A network interface mock that fails `add_address` for a specific interface name.
/// Used to test error resilience when one backend's network op fails.
pub struct FailingNetworkInterface {
    pub calls: Arc<Mutex<Vec<NetworkCall>>>,
    /// Interface name that should trigger failures on `add_address`.
    pub fail_iface: String,
}

impl FailingNetworkInterface {
    pub fn new(calls: Arc<Mutex<Vec<NetworkCall>>>, fail_iface: &str) -> Self {
        Self {
            calls,
            fail_iface: fail_iface.to_string(),
        }
    }
}

impl NetworkInterface for FailingNetworkInterface {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        self.calls.lock().unwrap().push(NetworkCall::AddAddress {
            iface: iface.to_string(),
            addr,
            prefix,
        });
        if iface == self.fail_iface {
            anyhow::bail!("simulated add_address failure on {}", iface);
        }
        Ok(())
    }

    fn remove_address(&self, iface: &str, addr: Ipv6Addr) -> Result<()> {
        self.calls.lock().unwrap().push(NetworkCall::RemoveAddress {
            iface: iface.to_string(),
            addr,
        });
        Ok(())
    }

    fn list_interfaces(&self) -> Result<Vec<String>> {
        Ok(vec!["lo".to_string()])
    }
}

// ─── Test helpers ────────────────────────────────────────────────────────────

pub async fn test_app_state(
    engine: crate::engine::Engine,
    config: DaemonConfig,
) -> Arc<AppState> {
    let db = crate::state::Database::new(":memory:").await.unwrap();
    db.migrate().await.unwrap();

    let (events_tx, _) = tokio::sync::broadcast::channel(64);

    Arc::new(AppState {
        config: tokio::sync::RwLock::new(config),
        db,
        engine: tokio::sync::RwLock::new(engine),
        firewall_lock: tokio::sync::Mutex::new(()),
        events: events_tx,
        api_token: "test-token".to_string(),
    })
}
