use crate::firewall::{Counter, DesiredRuleset, DropEvent, DropSink, Firewall, Revocation};
use crate::iface::{InterfaceInfo, InterfaceManager};
use crate::monitor::SocketMonitor;
use crate::networks::ip::{with_prefix64, AllocatedAddress, Ipv6Backend, Prefix};
use crate::AppState;
use anyhow::Result;
use ipnet::Ipv4Net;
use socketguard_core::config::DaemonConfig;
use socketguard_core::{BackendType, ListeningSocket};
use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// ─── MockFirewall ────────────────────────────────────────────────────────────

/// What the engine asked the firewall to do.
#[derive(Debug, Clone, PartialEq)]
pub enum FirewallCall {
    /// A full ruleset was applied.
    Apply(DesiredRuleset),
    Disable,
}

pub struct MockFirewall {
    pub calls: Arc<Mutex<Vec<FirewallCall>>>,
    fail_apply: AtomicBool,
    /// Interface rules hold for adapters that do not exist yet (nftables, pf; not WFP).
    absent_ok: AtomicBool,
    /// SocketGuard's ruleset is installed (applied, or planted by a test).
    installed: AtomicBool,
    /// The next `verify` reports the installed state as gone.
    drifted: AtomicBool,
    verifies: AtomicUsize,
    revoked: Mutex<Vec<Revocation>>,
    drop_sink: Mutex<Option<DropSink>>,
    counters: Mutex<Vec<Counter>>,
}

impl MockFirewall {
    pub fn new(calls: Arc<Mutex<Vec<FirewallCall>>>) -> Self {
        Self {
            calls,
            fail_apply: AtomicBool::new(false),
            absent_ok: AtomicBool::new(true),
            installed: AtomicBool::new(false),
            drifted: AtomicBool::new(false),
            verifies: AtomicUsize::new(0),
            revoked: Mutex::new(Vec::new()),
            drop_sink: Mutex::new(None),
            counters: Mutex::new(Vec::new()),
        }
    }

    /// What `counters()` reports from now on.
    pub fn set_counters(&self, counters: Vec<Counter>) {
        *self.counters.lock().unwrap() = counters;
    }

    /// Deliver a drop event to the engine, as the platform would. Returns false if the
    /// engine has not subscribed (yet).
    pub fn emit_drop(&self, ev: DropEvent) -> bool {
        match self.drop_sink.lock().unwrap().as_ref() {
            Some(sink) => {
                sink(ev);
                true
            }
            None => false,
        }
    }

    /// Make the next `verify` report that the installed rules disappeared.
    pub fn simulate_drift(&self) {
        self.drifted.store(true, Ordering::Relaxed);
    }

    /// How many times the engine called `verify`.
    pub fn verify_count(&self) -> usize {
        self.verifies.load(Ordering::Relaxed)
    }

    /// Every connection revocation the engine asked for, oldest first.
    pub fn revoked(&self) -> Vec<Revocation> {
        self.revoked.lock().unwrap().clone()
    }

    /// Pretend a SocketGuard ruleset is (or is not) already installed, as after a restart
    /// or with a lost database.
    pub fn set_installed(&self, installed: bool) {
        self.installed.store(installed, Ordering::Relaxed);
    }

    /// Act like WFP: an interface rule cannot be made for an adapter that is not there.
    pub fn set_blocks_absent_interfaces(&self, holds: bool) {
        self.absent_ok.store(holds, Ordering::Relaxed);
    }

    /// Make `apply` fail (the call is still recorded).
    pub fn set_failing(&self, failing: bool) {
        self.fail_apply.store(failing, Ordering::Relaxed);
    }
}

/// The rulesets applied so far, oldest first.
pub fn applied(calls: &Mutex<Vec<FirewallCall>>) -> Vec<DesiredRuleset> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter_map(|c| match c {
            FirewallCall::Apply(r) => Some(r.clone()),
            FirewallCall::Disable => None,
        })
        .collect()
}

impl Firewall for MockFirewall {
    fn blocks_absent_interfaces(&self) -> bool {
        self.absent_ok.load(Ordering::Relaxed)
    }

    fn apply(&self, desired: &DesiredRuleset) -> Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(FirewallCall::Apply(desired.clone()));
        if self.fail_apply.load(Ordering::Relaxed) {
            anyhow::bail!("simulated apply failure");
        }
        self.installed.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn verify(&self) -> Result<bool> {
        self.verifies.fetch_add(1, Ordering::Relaxed);
        let drifted = self.drifted.swap(false, Ordering::Relaxed);
        Ok(self.installed.load(Ordering::Relaxed) && !drifted)
    }

    fn revoke(&self, revoked: &[Revocation]) -> Result<()> {
        self.revoked.lock().unwrap().extend_from_slice(revoked);
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        self.calls.lock().unwrap().push(FirewallCall::Disable);
        self.installed.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn counters(&self) -> Result<Vec<Counter>> {
        Ok(self.counters.lock().unwrap().clone())
    }

    fn subscribe_drops(&self, sink: DropSink) -> Result<()> {
        *self.drop_sink.lock().unwrap() = Some(sink);
        Ok(())
    }
}

// ─── MockInterfaceManager ────────────────────────────────────────────────────

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
pub struct MockInterfaceManager {
    pub calls: Arc<Mutex<Vec<NetworkCall>>>,
    addrs: Arc<Mutex<HashMap<String, HashSet<Ipv6Addr>>>>,
    missing_ifaces: Arc<Mutex<HashSet<String>>>,
    remove_failing: Arc<Mutex<bool>>,
    ipv4: Arc<Mutex<HashMap<String, Vec<Ipv4Net>>>>,
    vlans: Arc<Mutex<HashMap<String, u16>>>,
    extra: Arc<Mutex<HashSet<String>>>,
}

impl MockInterfaceManager {
    pub fn new(calls: Arc<Mutex<Vec<NetworkCall>>>) -> Self {
        Self {
            calls,
            addrs: Arc::default(),
            missing_ifaces: Arc::default(),
            remove_failing: Arc::default(),
            ipv4: Arc::default(),
            vlans: Arc::default(),
            extra: Arc::default(),
        }
    }

    /// Make `iface` show up in `list_interfaces` (only `lo` and VLANs do by default).
    pub fn add_interface(&self, iface: &str) {
        self.extra.lock().unwrap().insert(iface.to_string());
    }

    /// Give `iface` the IPv4 subnets `nets` (e.g. "192.168.1.0/24"); empty clears them.
    pub fn set_ipv4_subnets(&self, iface: &str, nets: &[&str]) {
        self.ipv4.lock().unwrap().insert(
            iface.to_string(),
            nets.iter().map(|n| n.parse().unwrap()).collect(),
        );
    }

    /// Make `iface` a VLAN subinterface with this id.
    pub fn set_vlan(&self, iface: &str, id: u16) {
        self.vlans.lock().unwrap().insert(iface.to_string(), id);
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

    /// Make `remove_address` fail (and leave the address in place) while set.
    pub fn set_remove_failing(&self, failing: bool) {
        *self.remove_failing.lock().unwrap() = failing;
    }

    /// Put an address on an interface without a recorded call (a leftover of a crash).
    pub fn plant_address(&self, iface: &str, addr: Ipv6Addr) {
        self.addrs
            .lock()
            .unwrap()
            .entry(iface.to_string())
            .or_default()
            .insert(addr);
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

impl InterfaceManager for MockInterfaceManager {
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

    fn remove_address(&self, iface: &str, addr: Ipv6Addr, _prefix: u8) -> Result<()> {
        self.calls.lock().unwrap().push(NetworkCall::RemoveAddress {
            iface: iface.to_string(),
            addr,
        });
        if *self.remove_failing.lock().unwrap() {
            anyhow::bail!("simulated remove_address failure on {iface}");
        }
        if let Some(set) = self.addrs.lock().unwrap().get_mut(iface) {
            set.remove(&addr);
        }
        Ok(())
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        let vlans = self.vlans.lock().unwrap();
        let mut names: Vec<String> = vec!["lo".to_string()];
        names.extend(vlans.keys().cloned());
        names.extend(self.extra.lock().unwrap().iter().cloned());
        names.retain(|n| !self.missing_ifaces.lock().unwrap().contains(n));
        names.sort();
        Ok(names
            .into_iter()
            .map(|name| InterfaceInfo {
                vlan_id: vlans.get(&name).copied(),
                name,
            })
            .collect())
    }

    fn list_ipv4_subnets(&self, iface: &str) -> Result<Vec<Ipv4Net>> {
        if self.missing_ifaces.lock().unwrap().contains(iface) {
            anyhow::bail!("interface {iface} does not exist");
        }
        Ok(self
            .ipv4
            .lock()
            .unwrap()
            .get(iface)
            .cloned()
            .unwrap_or_default())
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
    failing: bool,
    /// The node's addresses, when the mock stands in for a Yggdrasil node that answers.
    node: Option<crate::ruleset::OverlayNode>,
    /// Why the network is down, like a status reason of the real backend.
    problem: Option<String>,
}

impl MockIpv6Backend {
    pub fn new(prefix: &str, prefix_len: u8, interface: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockBackendInner {
                counter: 1,
                base: prefix.parse().unwrap(),
                prefix: None,
                failing: false,
                node: None,
                problem: None,
            })),
            prefix_len,
            interface: interface.to_string(),
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Make `allocate` fail (e.g. Yggdrasil is down).
    pub fn set_failing(&self, failing: bool) {
        self.inner.lock().unwrap().failing = failing;
    }

    /// Report the node's addresses (`node()`), or none: the node does not answer.
    pub fn set_node(&self, address: &str, subnet: &str) {
        self.inner.lock().unwrap().node = Some(crate::ruleset::OverlayNode {
            address: address.parse().unwrap(),
            subnet: subnet.parse().unwrap(),
        });
    }

    pub fn clear_node(&self) {
        self.inner.lock().unwrap().node = None;
    }

    /// Make the network report itself down with `reason`, or up again.
    pub fn set_problem(&self, reason: Option<&str>) {
        self.inner.lock().unwrap().problem = reason.map(str::to_string);
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
    /// A Yggdrasil config names no interface: the node's adapter is found at runtime, which
    /// the mock stands in for.
    fn interface(&self) -> Option<String> {
        Some(self.interface.clone())
    }

    fn node(&self) -> Option<crate::ruleset::OverlayNode> {
        self.inner.lock().unwrap().node
    }

    fn problem(&self) -> Option<String> {
        self.inner.lock().unwrap().problem.clone()
    }

    fn current_prefix(&self) -> Result<Option<Prefix>> {
        Ok(self.inner.lock().unwrap().prefix)
    }

    fn allocate(&self, iid: Option<u64>) -> Result<AllocatedAddress> {
        let mut inner = self.inner.lock().unwrap();
        if inner.failing {
            anyhow::bail!("simulated allocation failure");
        }
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
}

// ─── ManualClock ─────────────────────────────────────────────────────────────

/// A clock that only moves when told to, for the engine's verify cadence.
pub struct ManualClock(Mutex<std::time::Instant>);

impl ManualClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(std::time::Instant::now())))
    }

    pub fn advance(&self, by: std::time::Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl crate::engine::Clock for ManualClock {
    fn now(&self) -> std::time::Instant {
        *self.0.lock().unwrap()
    }
}

// ─── Test helpers ────────────────────────────────────────────────────────────

/// An IP network over an already built allocator (a mock stands in for the real one).
pub fn ip_backend(
    config: socketguard_core::config::BackendInstanceConfig,
    backend: Box<dyn Ipv6Backend>,
) -> crate::engine::ActiveBackend {
    let network = Arc::new(crate::networks::ip::IpNetwork::for_config(
        &config.backend,
        backend,
    ));
    crate::engine::ActiveBackend { config, network }
}

/// Add an IP network with a mock allocator to a running engine.
pub async fn add_ip_network(
    engine: &mut crate::engine::Engine,
    state: &AppState,
    inst: &socketguard_core::config::BackendInstanceConfig,
    backend: Box<dyn Ipv6Backend>,
) {
    let network = Arc::new(crate::networks::ip::IpNetwork::for_config(
        &inst.backend,
        backend,
    ));
    let _ = engine.add_network_instance(state, inst, network).await;
}

pub async fn test_app_state(engine: crate::engine::Engine, config: DaemonConfig) -> Arc<AppState> {
    test_app_state_at(engine, config, None).await
}

/// [`test_app_state`] with a config file path that API-made network changes are saved to.
pub async fn test_app_state_at(
    engine: crate::engine::Engine,
    config: DaemonConfig,
    config_path: Option<std::path::PathBuf>,
) -> Arc<AppState> {
    test_app_state_with(engine, config, config_path, crate::bundled::Bundled::none()).await
}

/// [`test_app_state_at`] with a `third_party` directory (see `Bundled::from_dir`).
pub async fn test_app_state_with(
    mut engine: crate::engine::Engine,
    config: DaemonConfig,
    config_path: Option<std::path::PathBuf>,
    bundled: crate::bundled::Bundled,
) -> Arc<AppState> {
    let db = crate::state::Database::new(":memory:").await.unwrap();
    db.migrate().await.unwrap();

    let (events_tx, _) = tokio::sync::broadcast::channel(64);
    // The engine builds Tor and Yggdrasil networks from the same files the API checks.
    let bundled = Arc::new(bundled);
    engine.set_bundled(bundled.clone());

    Arc::new(AppState {
        config: tokio::sync::RwLock::new(config),
        config_path,
        db,
        engine: tokio::sync::RwLock::new(engine),
        firewall_lock: tokio::sync::Mutex::new(()),
        bundled,
        events: events_tx,
    })
}

/// The pieces of a Tor or Yggdrasil network test: the fake processes, a state directory in a temp
/// directory and the accounts, with the supervisor's pauses shortened to milliseconds.
pub struct ChildHarness {
    pub spawner: crate::children::fake::FakeSpawner,
    pub state_dir: std::path::PathBuf,
    pub ctx: crate::networks::ChildCtx,
    /// The firewall and the interfaces of the engines it builds.
    pub fw: Arc<MockFirewall>,
    pub fw_calls: Arc<Mutex<Vec<FirewallCall>>>,
    pub ifaces: MockInterfaceManager,
}

impl ChildHarness {
    /// `third_party` has a Tor and a Yggdrasil; the account `socketguard-net` exists (with
    /// the ids of the test process, so preparing the directories works without root).
    pub fn new() -> Self {
        Self::with(crate::account::FakeAccounts::own())
    }

    pub fn with(accounts: crate::account::FakeAccounts) -> Self {
        let root =
            std::env::temp_dir().join(format!("sg-m-{}", &uuid::Uuid::new_v4().to_string()[..8]));
        let third = root.join("third_party");
        let tor = third.join("tor");
        std::fs::create_dir_all(&tor).unwrap();
        std::fs::write(
            tor.join(if cfg!(windows) { "tor.exe" } else { "tor" }),
            b"x",
        )
        .unwrap();
        let ygg = third.join("yggdrasil");
        std::fs::create_dir_all(&ygg).unwrap();
        std::fs::write(
            ygg.join(if cfg!(windows) {
                "yggdrasil.exe"
            } else {
                "yggdrasil"
            }),
            b"x",
        )
        .unwrap();
        std::fs::write(ygg.join("wintun.dll"), b"x").unwrap();
        std::fs::write(third.join("VERSIONS"), "tor 16.0.1\nyggdrasil 0.5.15\n").unwrap();
        let state_dir = root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let spawner = crate::children::fake::FakeSpawner::default();
        let ctx = crate::networks::ChildCtx::new(
            Arc::new(crate::bundled::Bundled::from_dir(third)),
            Some(state_dir.clone()),
            Arc::new(crate::children::Supervisor::new(Arc::new(spawner.clone()))),
            Arc::new(accounts),
        );
        let fw_calls = Arc::new(Mutex::new(vec![]));
        Self {
            spawner,
            state_dir,
            ctx,
            fw: Arc::new(MockFirewall::new(fw_calls.clone())),
            fw_calls,
            ifaces: MockInterfaceManager::new(Arc::new(Mutex::new(vec![]))),
        }
    }

    /// An engine over mocks with no networks that runs Tor and Yggdrasil networks on this harness.
    pub fn engine(&self) -> crate::engine::Engine {
        let mut engine = crate::engine::Engine::new_injectable(
            Box::new(MockSocketMonitor::new(vec![])),
            self.fw.clone(),
            Arc::new(self.ifaces.clone()),
            HashMap::new(),
        );
        engine.set_child_ctx(self.ctx.clone());
        engine
    }

    /// A daemon state over [`ChildHarness::engine`] that knows the same shipped files.
    pub async fn app_state(&self, config: DaemonConfig) -> Arc<AppState> {
        test_app_state_with(self.engine(), config, None, (*self.ctx.bundled).clone()).await
    }
}

impl Default for ChildHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// A mock network: its config and the mock allocator behind it.
pub struct Net {
    pub id: &'static str,
    pub config: socketguard_core::config::BackendConfig,
    pub mock: MockIpv6Backend,
}

/// Local (ULA) network on `lo`: no prefix, grants have no effect.
pub fn local_net() -> Net {
    Net {
        id: "local",
        config: socketguard_core::config::BackendConfig::Ula {
            interface: "lo".into(),
        },
        mock: MockIpv6Backend::new("fd00:1:2:3::", 128, "lo"),
    }
}

/// LAN network on `eth0` with a /64.
pub fn lan_net() -> Net {
    let mock = MockIpv6Backend::new("2001:db8:1:2::", 128, "eth0");
    mock.set_prefix("2001:db8:1:2::");
    Net {
        id: "lan",
        config: socketguard_core::config::BackendConfig::Slaac {
            interface: "eth0".into(),
            prefix: None,
        },
        mock,
    }
}

/// Yggdrasil network on `ygg0`.
pub fn ygg_net() -> Net {
    let mock = MockIpv6Backend::new("300:1:2:3::", 128, "ygg0");
    mock.set_prefix("300:1:2:3::");
    Net {
        id: "ygg",
        config: socketguard_core::config::BackendConfig::yggdrasil(vec![]),
        mock,
    }
}

/// An engine over mocks with no networks and no sockets.
pub fn empty_engine() -> crate::engine::Engine {
    crate::engine::Engine::new_injectable(
        Box::new(MockSocketMonitor::new(vec![])),
        Arc::new(MockFirewall::new(Arc::new(Mutex::new(vec![])))),
        Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
        HashMap::new(),
    )
}

/// An in-memory daemon over mocks, with handles to all of them.
pub struct StandardDaemon {
    pub state: Arc<AppState>,
    pub sockets: Arc<Mutex<Vec<ListeningSocket>>>,
    pub fw: Arc<MockFirewall>,
    /// What the engine asked the firewall to do.
    pub fw_calls: Arc<Mutex<Vec<FirewallCall>>>,
    pub net: MockInterfaceManager,
    /// What the engine asked the interfaces to do.
    pub net_calls: Arc<Mutex<Vec<NetworkCall>>>,
    /// The allocator behind each network.
    pub nets: HashMap<&'static str, MockIpv6Backend>,
}

/// A daemon with the given mock networks and a monitor that reports `initial` listening
/// sockets. `config` supplies the settings (its `backends` are replaced by `nets`). Nothing
/// is reconciled yet.
pub async fn daemon_with(
    nets: Vec<Net>,
    initial: Vec<ListeningSocket>,
    config: DaemonConfig,
    config_path: Option<std::path::PathBuf>,
) -> StandardDaemon {
    use crate::engine::Engine;
    use socketguard_core::config::BackendInstanceConfig;

    let fw_calls = Arc::new(Mutex::new(Vec::new()));
    let net_calls = Arc::new(Mutex::new(Vec::new()));
    let fw = Arc::new(MockFirewall::new(fw_calls.clone()));
    let net = MockInterfaceManager::new(net_calls.clone());
    let monitor = MockSocketMonitor::new(initial);
    let sockets = monitor.sockets.clone();

    let mut backends = HashMap::new();
    let mut configs = Vec::new();
    let mut mocks = HashMap::new();
    for n in nets {
        let cfg = BackendInstanceConfig {
            id: n.id.to_string(),
            backend: n.config,
        };
        mocks.insert(n.id, n.mock.clone());
        backends.insert(n.id.to_string(), ip_backend(cfg.clone(), Box::new(n.mock)));
        configs.push(cfg);
    }
    let engine = Engine::new_injectable(
        Box::new(monitor),
        fw.clone(),
        Arc::new(net.clone()),
        backends,
    );
    let state = test_app_state_at(
        engine,
        DaemonConfig {
            backends: configs,
            ..config
        },
        config_path,
    )
    .await;
    StandardDaemon {
        state,
        sockets,
        fw,
        fw_calls,
        net,
        net_calls,
        nets: mocks,
    }
}

/// Networks `local` (lo, ULA), `lan` (eth0, SLAAC) and `ygg` (ygg0, Yggdrasil), all mocks,
/// and a monitor that reports `initial` listening sockets. Nothing is reconciled yet.
pub async fn standard_daemon(
    initial: Vec<ListeningSocket>,
    config_path: Option<std::path::PathBuf>,
) -> StandardDaemon {
    daemon_with(
        vec![local_net(), lan_net(), ygg_net()],
        initial,
        DaemonConfig::default(),
        config_path,
    )
    .await
}

// ─── MockTorControl ──────────────────────────────────────────────────────────

/// How the mock control port authenticates its clients.
#[derive(Clone)]
pub enum MockAuth {
    /// SAFECOOKIE and COOKIE with this cookie, reported at `cookie_path`. With
    /// `wrong_server_hash` the server cannot prove it knows the cookie (a rogue one).
    SafeCookie {
        cookie: [u8; 32],
        cookie_path: String,
        wrong_server_hash: bool,
    },
    /// Only plain COOKIE.
    CookieOnly {
        cookie: [u8; 32],
        cookie_path: String,
    },
}

/// Per-connection authentication progress.
#[derive(Default)]
struct MockConn {
    authed: bool,
    client_nonce: Vec<u8>,
    server_nonce: Vec<u8>,
}

struct MockTorState {
    auth: MockAuth,
    commands: Vec<String>,
    /// Running onion services: id -> the ADD_ONION command that created it.
    services: std::collections::BTreeMap<String, String>,
    created: u32,
    down: bool,
}

impl MockTorState {
    fn new(auth: MockAuth) -> Self {
        Self {
            auth,
            commands: Vec::new(),
            services: Default::default(),
            created: 0,
            down: false,
        }
    }
}

/// A scripted Tor control port on 127.0.0.1 that authenticates with SAFECOOKIE (a fresh
/// cookie file of its own, unless given a [`MockAuth`]). It records every command and keeps the set of detached onion services like Tor would. `ADD_ONION` with
/// `NEW:ED25519-V3` creates service `mocksvc<N>` with key `ED25519-V3:mocksvc<N>`; a
/// given key `ED25519-V3:<name>` runs service `<name>`.
pub struct MockTorControl {
    addr: std::net::SocketAddr,
    state: Arc<Mutex<MockTorState>>,
    /// The scratch directory of the cookie `start` made.
    dir: Option<std::path::PathBuf>,
}

impl Drop for MockTorControl {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            std::fs::remove_dir_all(dir).ok();
        }
    }
}

impl MockTorControl {
    pub fn start() -> Self {
        let dir =
            std::env::temp_dir().join(format!("sg-mock-tor-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control_auth_cookie");
        let cookie = [0x5a; 32];
        std::fs::write(&path, cookie).unwrap();
        // Explicit modes: a permissive umask would make the file writable by others,
        // which the cookie check refuses.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut mock = Self::start_with(MockAuth::SafeCookie {
            cookie,
            cookie_path: path.to_string_lossy().into_owned(),
            wrong_server_hash: false,
        });
        mock.dir = Some(dir);
        mock
    }

    pub fn start_with(auth: MockAuth) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(MockTorState::new(auth)));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let state = shared.clone();
                std::thread::spawn(move || Self::serve(stream, state));
            }
        });
        Self {
            addr,
            state,
            dir: None,
        }
    }

    /// The control address to configure (`host:port`).
    pub fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// Client options that fit this mock: the cookie file it reports, owned by the account
    /// running the test.
    pub fn auth_options(&self) -> crate::networks::tor_control::AuthOptions {
        use crate::networks::tor_control::AuthOptions;
        let (MockAuth::SafeCookie { cookie_path, .. } | MockAuth::CookieOnly { cookie_path, .. }) =
            &self.state.lock().unwrap().auth;
        AuthOptions {
            cookie_path: Some(cookie_path.clone()),
            // The test's cookie file belongs to the account running the test.
            #[cfg(windows)]
            cookie_owner: socketguard_core::winsid::current_user_sid(),
            ..AuthOptions::default()
        }
    }

    /// Every command received, oldest first (including AUTHENTICATE and QUIT).
    pub fn commands(&self) -> Vec<String> {
        self.state.lock().unwrap().commands.clone()
    }

    pub fn add_commands(&self) -> Vec<String> {
        self.commands()
            .into_iter()
            .filter(|c| c.starts_with("ADD_ONION"))
            .collect()
    }

    /// Ids of the running services.
    pub fn detached(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .services
            .keys()
            .cloned()
            .collect()
    }

    /// A service some other program runs on this Tor.
    pub fn inject_service(&self, id: &str) {
        self.state
            .lock()
            .unwrap()
            .services
            .insert(id.to_string(), "ADD_ONION (foreign)".to_string());
    }

    /// Tor restarted: every service is gone.
    pub fn forget_services(&self) {
        self.state.lock().unwrap().services.clear();
    }

    /// Refuse (drop) new connections.
    pub fn set_down(&self, down: bool) {
        self.state.lock().unwrap().down = down;
    }

    fn serve(stream: std::net::TcpStream, state: Arc<Mutex<MockTorState>>) {
        use std::io::{BufRead, BufReader, Write};
        if state.lock().unwrap().down {
            return;
        }
        let mut writer = stream.try_clone().unwrap();
        let reader = BufReader::new(stream);
        let mut conn = MockConn::default();
        for line in reader.lines() {
            let Ok(line) = line else { return };
            let reply = {
                let mut st = state.lock().unwrap();
                st.commands.push(line.clone());
                Self::reply(&mut st, &mut conn, &line)
            };
            if writer.write_all(reply.as_bytes()).is_err() || line == "QUIT" {
                return;
            }
        }
    }

    fn reply(st: &mut MockTorState, conn: &mut MockConn, line: &str) -> String {
        use crate::networks::tor_control::{
            hex, safecookie_hash, CONTROLLER_TO_SERVER, SERVER_TO_CONTROLLER,
        };
        let (cmd, rest) = line.split_once(' ').unwrap_or((line, ""));
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len() / 2)
                .filter_map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
                .collect()
        };
        let info = |methods: &str, path: Option<&String>| {
            // A control-spec quoted string escapes backslashes (Windows paths) and quotes.
            let file = path.map_or(String::new(), |p| {
                format!(
                    " COOKIEFILE=\"{}\"",
                    p.replace('\\', "\\\\").replace('"', "\\\"")
                )
            });
            format!("250-PROTOCOLINFO 1\r\n250-AUTH METHODS={methods}{file}\r\n250-VERSION Tor=\"0.4.8.0\"\r\n250 OK\r\n")
        };
        match (&st.auth, cmd) {
            (MockAuth::SafeCookie { cookie_path, .. }, "PROTOCOLINFO") => {
                info("COOKIE,SAFECOOKIE", Some(cookie_path))
            }
            (MockAuth::CookieOnly { cookie_path, .. }, "PROTOCOLINFO") => {
                info("COOKIE", Some(cookie_path))
            }
            (
                MockAuth::SafeCookie {
                    cookie,
                    wrong_server_hash,
                    ..
                },
                "AUTHCHALLENGE",
            ) => {
                conn.client_nonce = unhex(rest.strip_prefix("SAFECOOKIE ").unwrap_or_default());
                conn.server_nonce = vec![7u8; 32];
                let mut hash = safecookie_hash(
                    SERVER_TO_CONTROLLER,
                    cookie,
                    &conn.client_nonce,
                    &conn.server_nonce,
                );
                if *wrong_server_hash {
                    hash[0] ^= 1;
                }
                format!(
                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                    hex(&hash),
                    hex(&conn.server_nonce)
                )
            }
            (MockAuth::SafeCookie { cookie, .. }, "AUTHENTICATE") => {
                let want = safecookie_hash(
                    CONTROLLER_TO_SERVER,
                    cookie,
                    &conn.client_nonce,
                    &conn.server_nonce,
                );
                conn.authed = unhex(rest) == want;
                if conn.authed {
                    "250 OK\r\n".into()
                } else {
                    "515 Authentication failed: bad hash\r\n".into()
                }
            }
            (MockAuth::CookieOnly { cookie, .. }, "AUTHENTICATE") => {
                conn.authed = unhex(rest) == cookie.as_slice();
                if conn.authed {
                    "250 OK\r\n".into()
                } else {
                    "515 Authentication failed: bad cookie\r\n".into()
                }
            }
            (_, "QUIT") => "250 closing connection\r\n".into(),
            _ if conn.authed => Self::command(st, cmd, rest, line),
            _ => "514 Authentication required.\r\n".into(),
        }
    }

    fn command(st: &mut MockTorState, cmd: &str, rest: &str, line: &str) -> String {
        match cmd {
            "GETINFO" if rest == "version" => "250-version=0.4.8.0\r\n250 OK\r\n".into(),
            "GETINFO" if rest == "onions/detached" => {
                if st.services.is_empty() {
                    "250-onions/detached=\r\n250 OK\r\n".into()
                } else {
                    let ids: Vec<&str> = st.services.keys().map(String::as_str).collect();
                    format!(
                        "250+onions/detached=\r\n{}\r\n.\r\n250 OK\r\n",
                        ids.join("\r\n")
                    )
                }
            }
            "ADD_ONION" => {
                let key = rest.split(' ').next().unwrap_or_default();
                let (id, private) = match key.strip_prefix("ED25519-V3:") {
                    // A real key blob gives its derived name; a plain name names itself.
                    Some(name) => (
                        crate::networks::onion_key::service_id_of_secret(key)
                            .unwrap_or_else(|_| name.to_string()),
                        None,
                    ),
                    None => {
                        st.created += 1;
                        let id = format!("mocksvc{}", st.created);
                        (id.clone(), Some(format!("ED25519-V3:{id}")))
                    }
                };
                st.services.insert(id.clone(), line.to_string());
                match private {
                    Some(k) => format!("250-ServiceID={id}\r\n250-PrivateKey={k}\r\n250 OK\r\n"),
                    None => format!("250-ServiceID={id}\r\n250 OK\r\n"),
                }
            }
            "DEL_ONION" => {
                if st.services.remove(rest).is_some() {
                    "250 OK\r\n".into()
                } else {
                    "552 Unknown Onion Service id\r\n".into()
                }
            }
            _ => "510 Unrecognized command\r\n".into(),
        }
    }
}
