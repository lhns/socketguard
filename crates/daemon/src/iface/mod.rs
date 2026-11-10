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
use ipnet::Ipv4Net;
use std::net::Ipv6Addr;

/// A network interface of the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    /// The VLAN id of a VLAN subinterface (`eth0.20`). Known on Linux only; other systems
    /// show the adapter as a plain interface.
    pub vlan_id: Option<u16>,
}

/// Trait for managing IPv6 addresses on network interfaces
pub trait InterfaceManager: Send + Sync {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()>;
    /// Remove `addr/prefix`, the prefix it was added with (Linux matches on it).
    fn remove_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()>;
    /// All network interfaces on this system, VLAN subinterfaces included, sorted by name.
    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>>;
    /// The IPv4 subnets `iface` is on (its addresses with their prefix lengths, as the
    /// network address). Errors if the interface doesn't exist.
    fn list_ipv4_subnets(&self, iface: &str) -> Result<Vec<Ipv4Net>>;
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
