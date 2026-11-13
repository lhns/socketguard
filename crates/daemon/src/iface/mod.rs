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
use std::net::{Ipv4Addr, Ipv6Addr};

/// A network interface of the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    /// The VLAN id of a VLAN subinterface (`eth0.20`). Known on Linux only; other systems
    /// show the adapter as a plain interface.
    pub vlan_id: Option<u16>,
}

/// A host interface with what the setup screen needs to offer it as a LAN (ADR 0048).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostInterface {
    pub name: String,
    /// The adapter's description (Windows).
    pub description: Option<String>,
    pub vlan_id: Option<u16>,
    pub loopback: bool,
    /// A tunnel or virtual adapter (VPN, Yggdrasil, container bridge), not a LAN.
    pub tunnel: bool,
    /// The interface the default route leaves by.
    pub default_route: bool,
    /// It has a non-link-local IPv6 address that is not a Yggdrasil one.
    pub has_ipv6_prefix: bool,
}

/// Whether `addr` shows that a router announced an IPv6 prefix on the link: anything but
/// loopback, link-local, multicast, unspecified and the Yggdrasil `200::/7`.
pub fn is_lan_prefix_address(addr: Ipv6Addr) -> bool {
    let first = addr.segments()[0];
    !(addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || first & 0xffc0 == 0xfe80
        || first & 0xfe00 == 0x0200)
}

/// The subnets of interface addresses (with their prefix lengths) as network addresses,
/// sorted, without duplicates: two addresses in one subnet are one subnet.
pub(crate) fn subnets_of(addrs: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let mut nets: Vec<Ipv4Net> = addrs.iter().map(Ipv4Net::trunc).collect();
    nets.sort();
    nets.dedup();
    nets
}

/// The addresses of interface addresses, sorted, without duplicates.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) fn addresses_of(addrs: &[Ipv4Net]) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = addrs.iter().map(Ipv4Net::addr).collect();
    out.sort();
    out.dedup();
    out
}

/// Whether the name is that of a tunnel or virtual interface commonly seen on Unix hosts.
pub fn tunnel_like_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "tun", "tap", "wg", "ygg", "utun", "awdl", "llw", "gif", "stf", "docker", "veth", "virbr",
        "br-", "vnet", "lo",
    ];
    let n = name.to_ascii_lowercase();
    PREFIXES.iter().any(|p| n.starts_with(p))
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
    /// The IPv4 addresses on `iface`, sorted, without duplicates. Windows reports none: its
    /// backend cuts no connections, which is all this is for.
    fn list_ipv4_addresses(&self, _iface: &str) -> Result<Vec<Ipv4Addr>> {
        Ok(Vec::new())
    }
    /// IPv6 addresses currently configured on `iface`. Errors if the interface doesn't exist.
    fn list_addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>>;
    /// The interface the default route leaves by, if the system can tell.
    fn default_route_interface(&self) -> Option<String> {
        None
    }
    /// All interfaces with what is needed to offer them as a LAN. The default builds it
    /// from the other methods; Windows adds descriptions and adapter types.
    fn describe_interfaces(&self) -> Result<Vec<HostInterface>> {
        let default = self.default_route_interface();
        Ok(self
            .list_interfaces()?
            .into_iter()
            .map(|i| {
                let has_ipv6_prefix = self
                    .list_addresses(&i.name)
                    .is_ok_and(|a| a.into_iter().any(is_lan_prefix_address));
                HostInterface {
                    loopback: socketguard_core::is_loopback_interface(&i.name),
                    tunnel: tunnel_like_name(&i.name),
                    default_route: default.as_deref() == Some(i.name.as_str()),
                    has_ipv6_prefix,
                    vlan_id: i.vlan_id,
                    description: None,
                    name: i.name,
                }
            })
            .collect())
    }
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
