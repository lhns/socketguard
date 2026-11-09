pub mod dhcpv6;
pub mod slaac;
pub mod ula;
pub mod yggdrasil;

use anyhow::Result;
use socketguard_core::config::BackendConfig;
use socketguard_core::AllocatedAddress;
use std::net::Ipv6Addr;

/// Trait for IPv6 address generation backends
pub trait Ipv6Backend: Send + Sync {
    /// Generate a new unique IPv6 address
    fn allocate_address(&self) -> Result<AllocatedAddress>;
    /// Release an address (cleanup)
    fn release_address(&self, addr: &Ipv6Addr) -> Result<()>;
}

/// Create the appropriate backend from config
pub fn create_backend(config: &BackendConfig) -> Result<Box<dyn Ipv6Backend>> {
    match config {
        BackendConfig::Ula { .. } => Ok(Box::new(ula::UlaBackend::new())),
        BackendConfig::Yggdrasil { .. } => Ok(Box::new(yggdrasil::YggdrasilBackend::new())),
        BackendConfig::Slaac { interface, prefix } => Ok(Box::new(slaac::SlaacBackend::new(
            interface,
            prefix.as_deref(),
        )?)),
        BackendConfig::Dhcpv6 { interface } => Ok(Box::new(dhcpv6::Dhcpv6Backend::new(interface)?)),
    }
}
