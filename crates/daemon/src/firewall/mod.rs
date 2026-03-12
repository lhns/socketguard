#[cfg(target_os = "linux")]
pub mod nftables;
#[cfg(target_os = "macos")]
pub mod pf;
#[cfg(target_os = "windows")]
pub mod wfp;

use anyhow::Result;
use socketguard_core::Protocol;
use std::net::Ipv6Addr;

/// Trait for platform-specific firewall management
pub trait Firewall: Send + Sync {
    /// Ensure only `allowed` source IPs can reach `dest_ip:dest_port`.
    /// An empty `allowed` list means deny all.
    fn apply_acl(
        &self,
        dest_ip: Ipv6Addr,
        dest_port: u16,
        protocol: Protocol,
        allowed: &[Ipv6Addr],
    ) -> Result<()>;

    /// Remove all rules for a dest_ip:port:protocol
    fn remove_acl(&self, dest_ip: Ipv6Addr, dest_port: u16, protocol: Protocol) -> Result<()>;

    /// Block all traffic to a specific dest_ip:port
    fn block_all(&self, dest_ip: Ipv6Addr, dest_port: u16, protocol: Protocol) -> Result<()> {
        self.apply_acl(dest_ip, dest_port, protocol, &[])
    }

    /// Allow all traffic to a specific dest_ip:port (remove restrictions)
    fn allow_all(&self, dest_ip: Ipv6Addr, dest_port: u16, protocol: Protocol) -> Result<()> {
        self.remove_acl(dest_ip, dest_port, protocol)
    }

    /// Remove all SocketGuard-managed firewall rules (for startup cleanup / shutdown)
    fn cleanup_all_rules(&self) -> Result<()>;
}

/// Create the platform-appropriate firewall
pub fn create_firewall() -> Box<dyn Firewall> {
    #[cfg(target_os = "linux")]
    {
        Box::new(nftables::NftablesFirewall::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(wfp::WfpFirewall::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(pf::PfFirewall::new())
    }
}
