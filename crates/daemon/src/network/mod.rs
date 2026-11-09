#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use anyhow::Result;
use std::net::Ipv6Addr;

/// Trait for managing IPv6 addresses on network interfaces
pub trait NetworkInterface: Send + Sync {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()>;
    fn remove_address(&self, iface: &str, addr: Ipv6Addr) -> Result<()>;
    /// List all available network interface names on this system.
    fn list_interfaces(&self) -> Result<Vec<String>>;
    /// IPv6 addresses currently configured on `iface`. Errors if the interface doesn't exist.
    fn list_addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>>;
}

/// Create the platform-appropriate network interface manager
pub fn create_network_interface() -> Box<dyn NetworkInterface> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxNetworkInterface)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsNetworkInterface)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosNetworkInterface)
    }
}
