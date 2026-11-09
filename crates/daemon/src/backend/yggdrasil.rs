use super::{with_prefix64, Ipv6Backend, Prefix};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use socketguard_core::{AllocatedAddress, BackendType};
use std::net::Ipv6Addr;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::warn;

/// How long node info is reused before asking Yggdrasil again.
const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

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
        let mut cmd = Command::new("yggdrasilctl");
        cmd.arg("-json");
        if let Some(ep) = &self.endpoint {
            cmd.args(["-endpoint", ep]);
        }
        cmd.arg("getSelf");
        let output = cmd.output().context("failed to run yggdrasilctl")?;
        if !output.status.success() {
            bail!(
                "yggdrasilctl getSelf failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
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

/// Yggdrasil backend: allocates /128s inside the node's own `300::/64` subnet. Yggdrasil
/// routes the whole /64 to this node, so the addresses need no key material.
pub struct YggdrasilBackend {
    node: Box<dyn YggdrasilNode>,
    refresh: Duration,
    cache: Mutex<Option<(Instant, NodeInfo)>>,
}

impl YggdrasilBackend {
    pub fn new(node: Box<dyn YggdrasilNode>) -> Self {
        Self::with_refresh(node, REFRESH_INTERVAL)
    }

    pub fn with_refresh(node: Box<dyn YggdrasilNode>, refresh: Duration) -> Self {
        Self {
            node,
            refresh,
            cache: Mutex::new(None),
        }
    }

    /// Node info, refreshed at most every `refresh`. If a refresh fails (e.g. Yggdrasil is
    /// restarting) the last known info is used.
    fn info(&self) -> Result<NodeInfo> {
        let mut cache = self.cache.lock().unwrap();
        if let Some((at, info)) = cache.as_ref() {
            if at.elapsed() < self.refresh {
                return Ok(info.clone());
            }
        }
        match self.node.get_self() {
            Ok(info) => {
                *cache = Some((Instant::now(), info.clone()));
                Ok(info)
            }
            Err(e) => match cache.as_ref() {
                Some((_, stale)) => {
                    warn!("Yggdrasil node info refresh failed, using last known: {e}");
                    Ok(stale.clone())
                }
                None => Err(e),
            },
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

    fn release_address(&self, _addr: &Ipv6Addr) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{iid_of, same_prefix64};
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
