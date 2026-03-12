pub mod ula;
pub mod yggdrasil;

use anyhow::Result;
use socketguard_core::{AllocatedAddress, BackendType};
use std::net::Ipv6Addr;

/// Trait for IPv6 address generation backends
pub trait Ipv6Backend: Send + Sync {
    /// Generate a new unique IPv6 address
    fn allocate_address(&self) -> Result<AllocatedAddress>;
    /// Release an address (cleanup)
    fn release_address(&self, addr: &Ipv6Addr) -> Result<()>;
}

/// Create the appropriate backend
pub fn create_backend(backend_type: BackendType) -> Box<dyn Ipv6Backend> {
    match backend_type {
        BackendType::Ula => Box::new(ula::UlaBackend::new()),
        BackendType::Yggdrasil => Box::new(yggdrasil::YggdrasilBackend::new()),
    }
}
