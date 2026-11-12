//! IP networks (Local, LAN, Yggdrasil, DHCPv6): an [`IpNetwork`] allocates addresses through
//! an [`Ipv6Backend`], one per kind of address source.

pub mod dhcpv6;
mod network;
pub mod slaac;
pub mod ula;
pub mod ygg_admin;
pub mod yggdrasil_managed;

pub use network::IpNetwork;

use anyhow::Result;
use socketguard_core::BackendType;
use std::net::Ipv6Addr;

/// Result of allocating a new IPv6 address
#[derive(Debug, Clone)]
pub struct AllocatedAddress {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
    pub backend: BackendType,
}

/// An IPv6 prefix (network address plus length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: Ipv6Addr,
    pub len: u8,
}

impl Prefix {
    pub fn new(addr: Ipv6Addr, len: u8) -> Self {
        Self { addr, len }
    }
}

/// Interface ID: the low 64 bits of an address.
pub fn iid_of(addr: Ipv6Addr) -> u64 {
    u128::from(addr) as u64
}

/// Combine the upper 64 bits of `prefix` with `iid`.
pub fn with_prefix64(prefix: Ipv6Addr, iid: u64) -> Ipv6Addr {
    Ipv6Addr::from((u128::from(prefix) & !(u64::MAX as u128)) | iid as u128)
}

/// Whether two addresses share the same /64.
pub fn same_prefix64(a: Ipv6Addr, b: Ipv6Addr) -> bool {
    (u128::from(a) >> 64) == (u128::from(b) >> 64)
}

/// Trait for IPv6 address generation backends
pub trait Ipv6Backend: Send + Sync {
    /// The /64 this backend currently allocates from, or None for backends without one
    /// (ULA, DHCPv6). The engine re-homes stored addresses when it changes.
    fn current_prefix(&self) -> Result<Option<Prefix>>;
    /// Allocate an address: the current prefix plus `iid` (or a random one).
    /// Backends without a prefix ignore `iid`.
    fn allocate(&self, iid: Option<u64>) -> Result<AllocatedAddress>;
    /// The interface this backend works out at runtime (Yggdrasil: the one holding the
    /// node's address); None when the config names it or it cannot be found.
    fn interface(&self) -> Option<String> {
        None
    }
    /// The node's addresses, the last known ones while the node is down.
    fn node(&self) -> Option<crate::ruleset::OverlayNode> {
        None
    }
    /// Why the network cannot be used right now, beyond `current_prefix` failing.
    fn problem(&self) -> Option<String> {
        None
    }
    /// How the child process behind a managed network stands (ADR 0052).
    fn managed(&self) -> Option<socketguard_core::ManagedInfo> {
        None
    }
    /// Release an address (cleanup). Most backends hold no state per address.
    fn release_address(&self, _addr: &Ipv6Addr) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_helpers() {
        let p: Ipv6Addr = "300:1:2:3::".parse().unwrap();
        let a = with_prefix64(p, 0xdead_beef);
        assert_eq!(a, "300:1:2:3::dead:beef".parse::<Ipv6Addr>().unwrap());
        assert_eq!(iid_of(a), 0xdead_beef);
        assert!(same_prefix64(a, p));
        assert!(!same_prefix64(a, "300:1:2:4::1".parse().unwrap()));
    }
}
