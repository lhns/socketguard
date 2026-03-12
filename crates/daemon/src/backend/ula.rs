use super::Ipv6Backend;
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
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut global_id = [0u8; 5];
        rng.fill(&mut global_id);
        Self { global_id }
    }
}

impl Ipv6Backend for UlaBackend {
    fn allocate_address(&self) -> Result<AllocatedAddress> {
        let mut rng = rand::thread_rng();

        // Build a ULA address: fd + 40-bit Global ID + 16-bit Subnet ID + 64-bit Interface ID
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfd;
        bytes[1..6].copy_from_slice(&self.global_id);

        // Random subnet ID (2 bytes)
        let subnet: u16 = rng.gen();
        bytes[6] = (subnet >> 8) as u8;
        bytes[7] = subnet as u8;

        // Random interface ID (8 bytes)
        let iface_id: u64 = rng.gen();
        bytes[8..16].copy_from_slice(&iface_id.to_be_bytes());

        let address = Ipv6Addr::from(bytes);

        Ok(AllocatedAddress {
            address,
            prefix_len: 128,
            keypair: None,
            backend: BackendType::Ula,
        })
    }

    fn release_address(&self, _addr: &Ipv6Addr) -> Result<()> {
        // ULA addresses are stateless, nothing to clean up
        Ok(())
    }
}
