//! The host's network interfaces and the IPv6 addresses on them, one implementation per OS.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub(crate) use self::windows::alias_to_luid;

use anyhow::Result;
use std::net::Ipv6Addr;

/// Trait for managing IPv6 addresses on network interfaces
pub trait InterfaceManager: Send + Sync {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()>;
    /// Remove `addr/prefix`, the prefix it was added with (Linux matches on it).
    fn remove_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()>;
    /// List all available network interface names on this system.
    fn list_interfaces(&self) -> Result<Vec<String>>;
    /// IPv6 addresses currently configured on `iface`. Errors if the interface doesn't exist.
    fn list_addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>>;
}

/// Create the platform-appropriate network interface manager
pub fn create() -> Box<dyn InterfaceManager> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxInterfaces)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsInterfaces)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosInterfaces)
    }
}
