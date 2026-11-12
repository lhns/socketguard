use super::{with_prefix64, AllocatedAddress, Ipv6Backend, Prefix};
use crate::iface::InterfaceManager;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use socketguard_core::BackendType;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

/// How long node info is reused before asking Yggdrasil again.
const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// The reasons a status shows when Yggdrasil cannot be used.
pub const NOT_FOUND: &str = "yggdrasilctl not found";
pub const NOT_RUNNING: &str = "the Yggdrasil node is not running";
pub const NO_ADAPTER_ADDRESS: &str = "the Yggdrasil adapter has no address";

/// Why `yggdrasilctl getSelf` gave no answer; the Display text is the status reason.
#[derive(Debug, thiserror::Error)]
pub enum NodeProblem {
    #[error("{NOT_FOUND}")]
    NotFound,
    #[error("{NOT_RUNNING}")]
    NotRunning(String),
}

/// What `yggdrasilctl getSelf` tells us about the local node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// Hex-encoded public key.
    pub key: String,
    /// The node's own `200::/7` address.
    pub address: Ipv6Addr,
    /// The routed `300::/64` subnet this node owns.
    pub subnet: Prefix,
}

/// Source of the local node's identity; mockable.
pub trait YggdrasilNode: Send + Sync {
    fn get_self(&self) -> Result<NodeInfo>;
}

/// Where `yggdrasilctl` is: on PATH, else in the installer's directory (a service started
/// before the install has a PATH without it).
pub fn find_yggdrasilctl() -> Option<PathBuf> {
    if let Some(p) = crate::setup::find_in_path("yggdrasilctl") {
        return Some(p);
    }
    #[cfg(windows)]
    {
        let dirs = ["ProgramFiles", "ProgramW6432"]
            .into_iter()
            .filter_map(std::env::var_os)
            .map(|d| PathBuf::from(d).join("Yggdrasil"));
        for dir in dirs {
            let p = dir.join("yggdrasilctl.exe");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// Reads node info by running `yggdrasilctl -json getSelf`.
pub struct YggdrasilctlNode {
    endpoint: Option<String>,
}

impl YggdrasilctlNode {
    pub fn new(endpoint: Option<String>) -> Self {
        Self { endpoint }
    }
}

impl YggdrasilNode for YggdrasilctlNode {
    fn get_self(&self) -> Result<NodeInfo> {
        // Looked up on every call, so a Yggdrasil installed while we run is found.
        let ctl = find_yggdrasilctl().ok_or(NodeProblem::NotFound)?;
        let mut cmd = Command::new(ctl);
        cmd.arg("-json");
        if let Some(ep) = &self.endpoint {
            cmd.args(["-endpoint", ep]);
        }
        cmd.arg("getSelf");
        let output = cmd.output().context("failed to run yggdrasilctl")?;
        if !output.status.success() {
            return Err(NodeProblem::NotRunning(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            )
            .into());
        }
        parse_get_self(&String::from_utf8_lossy(&output.stdout))
    }
}

#[derive(Deserialize)]
struct GetSelf {
    key: String,
    address: String,
    subnet: String,
}

/// Parse the JSON printed by `yggdrasilctl -json getSelf`.
pub fn parse_get_self(json: &str) -> Result<NodeInfo> {
    let raw: GetSelf = serde_json::from_str(json).context("invalid getSelf JSON")?;
    let address: Ipv6Addr = raw.address.parse().context("invalid node address")?;
    let (net, len) = raw
        .subnet
        .split_once('/')
        .with_context(|| format!("invalid subnet {:?}", raw.subnet))?;
    let net: Ipv6Addr = net.parse().context("invalid subnet address")?;
    let len: u8 = len.parse().context("invalid subnet length")?;
    if len != 64 {
        bail!("unexpected Yggdrasil subnet length /{len}");
    }
    Ok(NodeInfo {
        key: raw.key,
        address,
        subnet: Prefix::new(net, len),
    })
}

/// The host's interfaces, to find the one that holds the node's address.
struct Host {
    ifaces: Arc<dyn InterfaceManager>,
    /// The interface named in the config; wins over detection.
    configured: Option<String>,
}

#[derive(Default)]
struct Cache {
    /// When Yggdrasil was last asked, successfully or not.
    at: Option<Instant>,
    /// The last successful answer (kept while Yggdrasil restarts).
    info: Option<NodeInfo>,
    /// Why the last ask failed; None after a success.
    error: Option<String>,
    /// The interface in use: configured, else the one holding the node's address.
    interface: Option<String>,
}

/// Yggdrasil backend: allocates /128s inside the node's own `300::/64` subnet. Yggdrasil
/// routes the whole /64 to this node, so the addresses need no key material.
pub struct YggdrasilBackend {
    node: Box<dyn YggdrasilNode>,
    refresh: Duration,
    host: Option<Host>,
    cache: Mutex<Cache>,
}

impl YggdrasilBackend {
    pub fn new(node: Box<dyn YggdrasilNode>) -> Self {
        Self::with_refresh(node, REFRESH_INTERVAL)
    }

    pub fn with_refresh(node: Box<dyn YggdrasilNode>, refresh: Duration) -> Self {
        Self {
            node,
            refresh,
            host: None,
            cache: Mutex::new(Cache::default()),
        }
    }

    /// Find the interface through `ifaces` (the one that holds the node's address), unless
    /// `configured` names it.
    pub fn with_host(
        mut self,
        ifaces: Arc<dyn InterfaceManager>,
        configured: Option<String>,
    ) -> Self {
        self.host = Some(Host { ifaces, configured });
        self
    }

    /// The interface that holds `address`.
    fn find_interface(&self, address: Ipv6Addr) -> Option<String> {
        let host = self.host.as_ref()?;
        if let Some(name) = &host.configured {
            return Some(name.clone());
        }
        host.ifaces
            .list_interfaces()
            .ok()?
            .into_iter()
            .find(|i| {
                host.ifaces
                    .list_addresses(&i.name)
                    .is_ok_and(|a| a.contains(&address))
            })
            .map(|i| i.name)
    }

    /// Ask Yggdrasil again if the last answer is older than `refresh`.
    fn refresh_cache(&self, cache: &mut Cache) {
        if cache.at.is_some_and(|at| at.elapsed() < self.refresh) {
            return;
        }
        cache.at = Some(Instant::now());
        match self.node.get_self() {
            Ok(info) => {
                cache.interface = self.find_interface(info.address);
                cache.info = Some(info);
                cache.error = None;
            }
            Err(e) => {
                let reason = match e.downcast_ref::<NodeProblem>() {
                    Some(p) => p.to_string(),
                    None => format!("{e:#}"),
                };
                if cache.info.is_some() {
                    warn!("Yggdrasil node info refresh failed, using last known: {e:#}");
                }
                cache.error = Some(reason);
            }
        }
    }

    /// Node info, refreshed at most every `refresh`. If a refresh fails (e.g. Yggdrasil is
    /// restarting) the last known info is used for allocation; [`Ipv6Backend::problem`]
    /// still reports it.
    fn info(&self) -> Result<NodeInfo> {
        let mut cache = self.cache.lock().unwrap();
        self.refresh_cache(&mut cache);
        match (&cache.info, &cache.error) {
            (Some(info), _) => Ok(info.clone()),
            (None, Some(reason)) => bail!("{reason}"),
            (None, None) => bail!("{NOT_RUNNING}"),
        }
    }
}

impl Ipv6Backend for YggdrasilBackend {
    fn current_prefix(&self) -> Result<Option<Prefix>> {
        Ok(Some(self.info()?.subnet))
    }

    fn allocate(&self, iid: Option<u64>) -> Result<AllocatedAddress> {
        let subnet = self.info()?.subnet;
        let address = with_prefix64(subnet.addr, iid.unwrap_or_else(rand::random));
        Ok(AllocatedAddress {
            address,
            prefix_len: 128,
            backend: BackendType::Yggdrasil,
        })
    }

    fn interface(&self) -> Option<String> {
        let mut cache = self.cache.lock().unwrap();
        self.refresh_cache(&mut cache);
        let configured = self.host.as_ref().and_then(|h| h.configured.clone());
        configured.or_else(|| cache.interface.clone())
    }

    fn node(&self) -> Option<crate::ruleset::OverlayNode> {
        let mut cache = self.cache.lock().unwrap();
        self.refresh_cache(&mut cache);
        let info = cache.info.as_ref()?;
        let subnet = ipnet::Ipv6Net::new(info.subnet.addr, info.subnet.len).ok()?;
        Some(crate::ruleset::OverlayNode {
            address: info.address,
            subnet: subnet.trunc(),
        })
    }

    fn problem(&self) -> Option<String> {
        let mut cache = self.cache.lock().unwrap();
        self.refresh_cache(&mut cache);
        if let Some(reason) = &cache.error {
            return Some(reason.clone());
        }
        (self.host.is_some() && cache.interface.is_none()).then(|| NO_ADAPTER_ADDRESS.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networks::ip::{iid_of, same_prefix64};
    use crate::test_support::MockYggdrasilNode;

    const SAMPLE: &str = r#"{"build_name":"yggdrasil","build_version":"0.5.15","key":"ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b","address":"200:8af8:ba35:56ae:bef0:6284:981f:5972","routing_entries":3,"subnet":"300:8af8:ba35:56ae::/64"}"#;

    #[test]
    fn parses_get_self() {
        let info = parse_get_self(SAMPLE).unwrap();
        assert!(info.key.starts_with("ba83a2e5"));
        assert_eq!(
            info.address,
            "200:8af8:ba35:56ae:bef0:6284:981f:5972"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(
            info.subnet,
            Prefix::new("300:8af8:ba35:56ae::".parse().unwrap(), 64)
        );
    }

    #[test]
    fn rejects_malformed_get_self() {
        assert!(parse_get_self("not json").is_err());
        assert!(parse_get_self(r#"{"key":"aa","address":"200::1","subnet":"300::"}"#).is_err());
        assert!(parse_get_self(r#"{"key":"aa","address":"200::1","subnet":"300::/48"}"#).is_err());
    }

    #[test]
    fn allocates_inside_subnet_and_keeps_iid() {
        let node = MockYggdrasilNode::new("300:1:2:3::/64");
        let backend = YggdrasilBackend::with_refresh(Box::new(node.clone()), Duration::ZERO);

        let a = backend.allocate(None).unwrap();
        assert_eq!(a.prefix_len, 128);
        assert!(same_prefix64(a.address, "300:1:2:3::".parse().unwrap()));

        node.set_subnet("300:9:9:9::/64");
        let b = backend.allocate(Some(iid_of(a.address))).unwrap();
        assert!(same_prefix64(b.address, "300:9:9:9::".parse().unwrap()));
        assert_eq!(iid_of(b.address), iid_of(a.address));
    }

    fn host(
        ifaces: &crate::test_support::MockInterfaceManager,
        configured: Option<&str>,
    ) -> YggdrasilBackend {
        let node = MockYggdrasilNode::new("300:1:2:3::/64");
        node.set_address("200::1");
        YggdrasilBackend::with_refresh(Box::new(node), Duration::ZERO)
            .with_host(Arc::new(ifaces.clone()), configured.map(str::to_string))
    }

    fn ifaces() -> crate::test_support::MockInterfaceManager {
        crate::test_support::MockInterfaceManager::new(Default::default())
    }

    #[test]
    fn the_interface_is_the_one_holding_the_node_address() {
        let net = ifaces();
        net.add_interface("Yggdrasil");
        net.add_interface("Ethernet");
        let backend = host(&net, None);
        assert_eq!(backend.interface(), None);
        assert_eq!(backend.problem().as_deref(), Some(NO_ADAPTER_ADDRESS));

        net.plant_address("Yggdrasil", "200::1".parse().unwrap());
        assert_eq!(backend.interface().as_deref(), Some("Yggdrasil"));
        assert_eq!(backend.problem(), None);

        // The adapter is recreated under another name: the backend follows it.
        net.drop_address("Yggdrasil", "200::1".parse().unwrap());
        net.plant_address("Ethernet", "200::1".parse().unwrap());
        assert_eq!(backend.interface().as_deref(), Some("Ethernet"));
    }

    #[test]
    fn a_configured_interface_wins_over_detection() {
        let net = ifaces();
        net.add_interface("Yggdrasil");
        net.add_interface("tun0");
        net.plant_address("Yggdrasil", "200::1".parse().unwrap());
        let backend = host(&net, Some("tun0"));
        assert_eq!(backend.interface().as_deref(), Some("tun0"));
        assert_eq!(backend.problem(), None);
    }

    #[test]
    fn a_stopped_node_is_reported_even_though_allocation_keeps_working() {
        let net = ifaces();
        let node = MockYggdrasilNode::new("300:1:2:3::/64");
        let backend = YggdrasilBackend::with_refresh(Box::new(node.clone()), Duration::ZERO)
            .with_host(Arc::new(net), None);
        backend.current_prefix().unwrap();
        node.set_failing(true);
        assert!(backend.current_prefix().unwrap().is_some());
        assert!(backend.problem().is_some());

        let down = MockYggdrasilNode::new("300:1:2:3::/64");
        down.set_failing(true);
        let fresh = YggdrasilBackend::with_refresh(Box::new(down), Duration::ZERO);
        assert!(fresh.current_prefix().is_err());
    }

    #[test]
    fn problems_are_named_in_plain_words() {
        struct Missing;
        impl YggdrasilNode for Missing {
            fn get_self(&self) -> Result<NodeInfo> {
                Err(NodeProblem::NotFound.into())
            }
        }
        struct Stopped;
        impl YggdrasilNode for Stopped {
            fn get_self(&self) -> Result<NodeInfo> {
                Err(NodeProblem::NotRunning("connection refused".into()).into())
            }
        }
        let b = YggdrasilBackend::with_refresh(Box::new(Missing), Duration::ZERO);
        assert_eq!(b.current_prefix().unwrap_err().to_string(), NOT_FOUND);
        assert_eq!(b.problem().as_deref(), Some(NOT_FOUND));
        let b = YggdrasilBackend::with_refresh(Box::new(Stopped), Duration::ZERO);
        assert_eq!(b.current_prefix().unwrap_err().to_string(), NOT_RUNNING);
    }

    #[test]
    fn caches_node_info_and_survives_failures() {
        let node = MockYggdrasilNode::new("300:1:2:3::/64");
        let backend = YggdrasilBackend::with_refresh(Box::new(node.clone()), Duration::ZERO);
        backend.current_prefix().unwrap();
        node.set_failing(true);
        // Stale info is used while Yggdrasil is unreachable.
        assert!(backend.current_prefix().unwrap().is_some());

        let node = MockYggdrasilNode::new("300:1:2:3::/64");
        let backend = YggdrasilBackend::new(Box::new(node.clone()));
        backend.current_prefix().unwrap();
        backend.current_prefix().unwrap();
        assert_eq!(node.calls(), 1);

        let down = MockYggdrasilNode::new("300:1:2:3::/64");
        down.set_failing(true);
        assert!(YggdrasilBackend::new(Box::new(down))
            .current_prefix()
            .is_err());
    }
}
