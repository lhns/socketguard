pub mod dhcpv6;
pub mod slaac;
pub mod ula;
pub mod yggdrasil;

use anyhow::Result;
use socketguard_core::config::BackendConfig;
use socketguard_core::AllocatedAddress;
use std::net::Ipv6Addr;

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
    /// Release an address (cleanup)
    fn release_address(&self, addr: &Ipv6Addr) -> Result<()>;
}

/// Create the appropriate backend from config.
/// `ula_global_id` is the installation's persisted ULA global ID.
pub fn create_backend(
    config: &BackendConfig,
    ula_global_id: [u8; 5],
) -> Result<Box<dyn Ipv6Backend>> {
    match config {
        BackendConfig::Ula { .. } => Ok(Box::new(ula::UlaBackend::new(ula_global_id))),
        BackendConfig::Yggdrasil { admin_endpoint, .. } => {
            Ok(Box::new(yggdrasil::YggdrasilBackend::new(Box::new(
                yggdrasil::YggdrasilctlNode::new(admin_endpoint.clone()),
            ))))
        }
        BackendConfig::Slaac { interface, prefix } => Ok(Box::new(slaac::SlaacBackend::new(
            interface,
            prefix.as_deref(),
        )?)),
        BackendConfig::Dhcpv6 { interface } => Ok(Box::new(dhcpv6::Dhcpv6Backend::new(interface)?)),
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
