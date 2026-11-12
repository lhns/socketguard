//! The allocator of the Yggdrasil network (ADR 0052). It never asks the node: the addresses
//! follow from the key SocketGuard generated, so they are known before the node runs and
//! while it is down. What the node is doing is the
//! child's state.

use super::{with_prefix64, AllocatedAddress, Ipv6Backend, Prefix};
use crate::networks::ygg_child::YggChild;
use crate::ruleset::OverlayNode;
use anyhow::{anyhow, Result};
use socketguard_core::{BackendType, ChildInfo, ChildState};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long the number of connected peers is reused: counting asks the node.
const PEERS_REFRESH: Duration = Duration::from_secs(5);

pub struct YggChildBackend {
    ygg: YggChild,
    peers: Mutex<Option<(Instant, Option<u32>)>>,
}

impl YggChildBackend {
    pub fn new(ygg: YggChild) -> Self {
        Self {
            ygg,
            peers: Mutex::new(None),
        }
    }

    fn node_or_err(&self) -> Result<OverlayNode> {
        self.ygg
            .node()
            .ok_or_else(|| anyhow!("the Yggdrasil node's key is not available"))
    }

    /// Connected peers, asked of the node at most every [`PEERS_REFRESH`].
    fn peers_connected(&self) -> Option<u32> {
        let mut cache = self.peers.lock().unwrap();
        if let Some((at, n)) = *cache {
            if at.elapsed() < PEERS_REFRESH {
                return n;
            }
        }
        let n = self
            .ygg
            .peers()
            .map(|p| crate::networks::ygg_child::connected_count(&p));
        *cache = Some((Instant::now(), n));
        n
    }
}

impl Ipv6Backend for YggChildBackend {
    fn current_prefix(&self) -> Result<Option<Prefix>> {
        let subnet = self.node_or_err()?.subnet;
        Ok(Some(Prefix::new(subnet.network(), subnet.prefix_len())))
    }

    fn allocate(&self, iid: Option<u64>) -> Result<AllocatedAddress> {
        let subnet = self.node_or_err()?.subnet;
        Ok(AllocatedAddress {
            address: with_prefix64(subnet.network(), iid.unwrap_or_else(rand::random)),
            prefix_len: 128,
            backend: BackendType::Yggdrasil,
        })
    }

    fn interface(&self) -> Option<String> {
        self.ygg.interface()
    }

    fn node(&self) -> Option<OverlayNode> {
        self.ygg.node()
    }

    fn problem(&self) -> Option<String> {
        (self.ygg.child().state != ChildState::Up).then(|| self.ygg.reason())
    }

    fn child_info(&self) -> Option<ChildInfo> {
        let up = self.ygg.child().state == ChildState::Up;
        Some(
            self.ygg
                .info(if up { self.peers_connected() } else { None }),
        )
    }
}
