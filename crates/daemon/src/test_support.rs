use crate::backend::yggdrasil::{NodeInfo, YggdrasilNode};
use crate::backend::{with_prefix64, Ipv6Backend, Prefix};
use crate::firewall::Firewall;
use crate::monitor::SocketMonitor;
use crate::network::NetworkInterface;
use crate::AppState;
use anyhow::Result;
use socketguard_core::config::DaemonConfig;
use socketguard_core::{AllocatedAddress, BackendType, ListeningSocket, Protocol};
use std::collections::{HashMap, HashSet};
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

    fn remove_acl(&self, dest_ip: Ipv6Addr, dest_port: u16, protocol: Protocol) -> Result<()> {
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

/// Records calls and tracks which addresses are configured on which interface.
/// Cloning shares the state, so a test can keep a handle after boxing the mock.
#[derive(Clone)]
pub struct MockNetworkInterface {
    pub calls: Arc<Mutex<Vec<NetworkCall>>>,
    addrs: Arc<Mutex<HashMap<String, HashSet<Ipv6Addr>>>>,
    missing_ifaces: Arc<Mutex<HashSet<String>>>,
}

impl MockNetworkInterface {
    pub fn new(calls: Arc<Mutex<Vec<NetworkCall>>>) -> Self {
        Self {
            calls,
            addrs: Arc::default(),
            missing_ifaces: Arc::default(),
        }
    }

    /// Addresses currently configured on `iface`.
    pub fn addresses(&self, iface: &str) -> HashSet<Ipv6Addr> {
        self.addrs
            .lock()
            .unwrap()
            .get(iface)
            .cloned()
            .unwrap_or_default()
    }

    /// Make an address vanish without a recorded call (e.g. the tun was recreated).
    pub fn drop_address(&self, iface: &str, addr: Ipv6Addr) {
        if let Some(set) = self.addrs.lock().unwrap().get_mut(iface) {
            set.remove(&addr);
        }
    }

    /// Simulate an interface that does not exist (removing it also clears its addresses).
    pub fn set_interface_missing(&self, iface: &str, missing: bool) {
        let mut m = self.missing_ifaces.lock().unwrap();
        if missing {
            m.insert(iface.to_string());
            self.addrs.lock().unwrap().remove(iface);
        } else {
            m.remove(iface);
        }
    }
}

impl NetworkInterface for MockNetworkInterface {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        self.calls.lock().unwrap().push(NetworkCall::AddAddress {
            iface: iface.to_string(),
            addr,
            prefix,
        });
        if self.missing_ifaces.lock().unwrap().contains(iface) {
            anyhow::bail!("interface {iface} does not exist");
        }
        self.addrs
            .lock()
            .unwrap()
            .entry(iface.to_string())
            .or_default()
            .insert(addr);
        Ok(())
    }

    fn remove_address(&self, iface: &str, addr: Ipv6Addr) -> Result<()> {
        self.calls.lock().unwrap().push(NetworkCall::RemoveAddress {
            iface: iface.to_string(),
            addr,
        });
        if let Some(set) = self.addrs.lock().unwrap().get_mut(iface) {
            set.remove(&addr);
        }
        Ok(())
    }

    fn list_interfaces(&self) -> Result<Vec<String>> {
        Ok(vec!["lo".to_string()])
    }

    fn list_addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>> {
        if self.missing_ifaces.lock().unwrap().contains(iface) {
            anyhow::bail!("interface {iface} does not exist");
        }
        Ok(self.addresses(iface).into_iter().collect())
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

/// Mock backend. Cloning shares state, so tests can change the prefix after boxing it.
///
/// By default it reports no prefix (like ULA); `set_prefix` makes it behave like a
/// /64-based backend whose prefix can change.
#[derive(Clone)]
pub struct MockIpv6Backend {
    inner: Arc<Mutex<MockBackendInner>>,
    prefix_len: u8,
    interface: String,
}

struct MockBackendInner {
    counter: u64,
    base: Ipv6Addr,
    prefix: Option<Prefix>,
}

impl MockIpv6Backend {
    pub fn new(prefix: &str, prefix_len: u8, interface: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockBackendInner {
                counter: 1,
                base: prefix.parse().unwrap(),
                prefix: None,
            })),
            prefix_len,
            interface: interface.to_string(),
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Start (or change) reporting a /64 prefix; later allocations use it.
    pub fn set_prefix(&self, prefix: &str) {
        let addr: Ipv6Addr = prefix.parse().unwrap();
        let mut inner = self.inner.lock().unwrap();
        inner.base = addr;
        inner.prefix = Some(Prefix::new(addr, 64));
    }
}

impl Ipv6Backend for MockIpv6Backend {
    fn current_prefix(&self) -> Result<Option<Prefix>> {
        Ok(self.inner.lock().unwrap().prefix)
    }

    fn allocate(&self, iid: Option<u64>) -> Result<AllocatedAddress> {
        let mut inner = self.inner.lock().unwrap();
        let n = iid.unwrap_or_else(|| {
            let n = inner.counter;
            inner.counter += 1;
            n
        });
        Ok(AllocatedAddress {
            address: with_prefix64(inner.base, n),
            prefix_len: self.prefix_len,
            backend: BackendType::Ula,
        })
    }

    fn release_address(&self, _addr: &Ipv6Addr) -> Result<()> {
        Ok(())
    }
}

// ─── MockYggdrasilNode ───────────────────────────────────────────────────────

/// Fake `yggdrasilctl getSelf`. Cloning shares state.
#[derive(Clone)]
pub struct MockYggdrasilNode {
    state: Arc<Mutex<MockNodeState>>,
}

struct MockNodeState {
    info: NodeInfo,
    failing: bool,
    calls: usize,
}

impl MockYggdrasilNode {
    /// `subnet` like "300:1:2:3::/64".
    pub fn new(subnet: &str) -> Self {
        let node = Self {
            state: Arc::new(Mutex::new(MockNodeState {
                info: NodeInfo {
                    key: "00".repeat(32),
                    address: "200::1".parse().unwrap(),
                    subnet: Prefix::new(Ipv6Addr::UNSPECIFIED, 64),
                },
                failing: false,
                calls: 0,
            })),
        };
        node.set_subnet(subnet);
        node
    }

    pub fn set_subnet(&self, subnet: &str) {
        let (net, len) = subnet.split_once('/').unwrap();
        self.state.lock().unwrap().info.subnet =
            Prefix::new(net.parse().unwrap(), len.parse().unwrap());
    }

    pub fn set_failing(&self, failing: bool) {
        self.state.lock().unwrap().failing = failing;
    }

    /// Number of `get_self` calls so far.
    pub fn calls(&self) -> usize {
        self.state.lock().unwrap().calls
    }
}

impl YggdrasilNode for MockYggdrasilNode {
    fn get_self(&self) -> Result<NodeInfo> {
        let mut st = self.state.lock().unwrap();
        st.calls += 1;
        if st.failing {
            anyhow::bail!("yggdrasil is not running");
        }
        Ok(st.info.clone())
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

    fn list_addresses(&self, _iface: &str) -> Result<Vec<Ipv6Addr>> {
        Ok(Vec::new())
    }
}

// ─── Test helpers ────────────────────────────────────────────────────────────

pub async fn test_app_state(engine: crate::engine::Engine, config: DaemonConfig) -> Arc<AppState> {
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
