use super::{Ipv6Backend, Prefix};
use anyhow::Result;
use rand::Rng;
use socketguard_core::{AllocatedAddress, BackendType};
use std::net::Ipv6Addr;

/// ULA (Unique Local Address) backend
/// Generates random addresses in the fd00::/8 range
pub struct UlaBackend {
    /// Fixed 40-bit Global ID for this installation
    global_id: [u8; 5],
}

impl UlaBackend {
    pub fn new(global_id: [u8; 5]) -> Self {
        Self { global_id }
    }

    /// Generate a fresh random global ID (persisted by the caller).
    pub fn random_global_id() -> [u8; 5] {
        let mut global_id = [0u8; 5];
        rand::thread_rng().fill(&mut global_id);
        global_id
    }
}

impl Ipv6Backend for UlaBackend {
    fn current_prefix(&self) -> Result<Option<Prefix>> {
        // Addresses are scattered over random /64s of the /48; there is no single prefix.
        Ok(None)
    }

    fn allocate(&self, iid: Option<u64>) -> Result<AllocatedAddress> {
        let mut rng = rand::thread_rng();

        // Build a ULA address: fd + 40-bit Global ID + 16-bit Subnet ID + 64-bit Interface ID
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfd;
        bytes[1..6].copy_from_slice(&self.global_id);

        // Random subnet ID (2 bytes)
        let subnet: u16 = rng.gen();
        bytes[6] = (subnet >> 8) as u8;
        bytes[7] = subnet as u8;

        let iface_id: u64 = iid.unwrap_or_else(|| rng.gen());
        bytes[8..16].copy_from_slice(&iface_id.to_be_bytes());

        let address = Ipv6Addr::from(bytes);

        Ok(AllocatedAddress {
            address,
            prefix_len: 128,
            backend: BackendType::Ula,
        })
    }

    fn release_address(&self, _addr: &Ipv6Addr) -> Result<()> {
        // ULA addresses are stateless, nothing to clean up
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_use_the_configured_global_id() {
        let b = UlaBackend::new([1, 2, 3, 4, 5]);
        let a = b.allocate(Some(7)).unwrap().address.octets();
        assert_eq!(&a[..6], &[0xfd, 1, 2, 3, 4, 5]);
        assert_eq!(u64::from_be_bytes(a[8..].try_into().unwrap()), 7);
        assert!(b.current_prefix().unwrap().is_none());
    }
}
