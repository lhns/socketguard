use super::Ipv6Backend;
use anyhow::{bail, Context, Result};
use rand::Rng;
use socketguard_core::{AllocatedAddress, BackendType};
use std::net::Ipv6Addr;
use std::process::Command;
use tracing::{debug, info};

/// Maximum retry attempts for collision avoidance
const MAX_COLLISION_RETRIES: usize = 10;

/// SLAAC backend: generates addresses within an existing /64 prefix
/// discovered from (or configured for) a physical network interface.
pub struct SlaacBackend {
    interface: String,
    /// The /64 prefix (first 8 bytes of the IPv6 address)
    prefix: [u8; 8],
}

impl SlaacBackend {
    /// Create a new SLAAC backend.
    /// If `prefix` is None or "auto", discovers the prefix from the interface.
    pub fn new(interface: &str, prefix: Option<&str>) -> Result<Self> {
        let prefix_bytes = match prefix {
            Some(p) if !p.is_empty() && p != "auto" => parse_prefix(p)?,
            _ => discover_prefix(interface)?,
        };

        info!(
            "SLAAC backend initialized: interface={}, prefix={:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/64",
            interface,
            prefix_bytes[0], prefix_bytes[1], prefix_bytes[2], prefix_bytes[3],
            prefix_bytes[4], prefix_bytes[5], prefix_bytes[6], prefix_bytes[7],
        );

        Ok(Self {
            interface: interface.to_string(),
            prefix: prefix_bytes,
        })
    }
}

impl Ipv6Backend for SlaacBackend {
    fn allocate_address(&self) -> Result<AllocatedAddress> {
        let mut rng = rand::thread_rng();

        for attempt in 0..MAX_COLLISION_RETRIES {
            // Generate random 64-bit interface ID within the prefix
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&self.prefix);
            let iface_id: u64 = rng.gen();
            bytes[8..16].copy_from_slice(&iface_id.to_be_bytes());

            let address = Ipv6Addr::from(bytes);

            // Check for collision with existing addresses on the interface
            if !is_address_in_use(&self.interface, address)? {
                debug!("SLAAC allocated {} (attempt {})", address, attempt + 1);
                return Ok(AllocatedAddress {
                    address,
                    prefix_len: 128,
                    keypair: None,
                    backend: BackendType::Slaac,
                });
            }

            debug!(
                "SLAAC address {} already in use, retrying (attempt {})",
                address,
                attempt + 1
            );
        }

        bail!(
            "failed to allocate unique SLAAC address after {} attempts",
            MAX_COLLISION_RETRIES
        )
    }

    fn release_address(&self, _addr: &Ipv6Addr) -> Result<()> {
        // Address removal is handled by the engine's network layer
        Ok(())
    }
}

/// Parse a prefix string like "2001:db8:1:2::/64" into the first 8 bytes
fn parse_prefix(prefix_str: &str) -> Result<[u8; 8]> {
    // Strip optional /64 suffix
    let addr_part = prefix_str
        .split('/')
        .next()
        .unwrap_or(prefix_str)
        .trim_end_matches(':');

    // Pad with :: if needed to make a full address for parsing
    let full_addr = if addr_part.contains("::") {
        format!("{}1", prefix_str.split('/').next().unwrap_or(prefix_str))
    } else {
        format!("{addr_part}::1")
    };

    let addr: Ipv6Addr = full_addr
        .parse()
        .with_context(|| format!("invalid prefix: {prefix_str}"))?;

    let octets = addr.octets();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&octets[..8]);
    Ok(prefix)
}

/// Discover the /64 prefix from an interface by listing its existing IPv6 addresses.
/// Looks for a global unicast address (2000::/3) assigned via SLAAC.
#[cfg(target_os = "windows")]
fn discover_prefix(interface: &str) -> Result<[u8; 8]> {
    let output = Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "show",
            "address",
            &format!("interface={interface}"),
        ])
        .output()
        .context("failed to run netsh to discover prefix")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse netsh output for global IPv6 addresses
    // Lines containing IPv6 addresses typically look like:
    // "Address 2001:db8:1:2:abc:def:1234:5678"
    for line in stdout.lines() {
        let line = line.trim();
        // Look for lines containing an IPv6 address
        if let Some(addr_str) = extract_ipv6_from_line(line) {
            if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
                let octets = addr.octets();
                // Check if it's a global unicast address (2000::/3)
                if (octets[0] & 0xe0) == 0x20 {
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&octets[..8]);
                    info!(
                        "Discovered SLAAC prefix from {}: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/64",
                        interface,
                        prefix[0], prefix[1], prefix[2], prefix[3],
                        prefix[4], prefix[5], prefix[6], prefix[7],
                    );
                    return Ok(prefix);
                }
            }
        }
    }

    bail!(
        "no global IPv6 address found on interface '{}'. \
         Make sure the interface has a SLAAC-assigned address or specify the prefix manually.",
        interface
    )
}

#[cfg(target_os = "linux")]
fn discover_prefix(interface: &str) -> Result<[u8; 8]> {
    let output = Command::new("ip")
        .args(["-6", "addr", "show", "dev", interface, "scope", "global"])
        .output()
        .context("failed to run ip addr show")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("inet6") {
            // Format: "inet6 2001:db8::1/64 scope global ..."
            if let Some(addr_cidr) = line.split_whitespace().nth(1) {
                let addr_str = addr_cidr.split('/').next().unwrap_or(addr_cidr);
                if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
                    let octets = addr.octets();
                    if (octets[0] & 0xe0) == 0x20 {
                        let mut prefix = [0u8; 8];
                        prefix.copy_from_slice(&octets[..8]);
                        return Ok(prefix);
                    }
                }
            }
        }
    }

    bail!(
        "no global IPv6 address found on interface '{}'. \
         Make sure the interface has a SLAAC-assigned address or specify the prefix manually.",
        interface
    )
}

#[cfg(target_os = "macos")]
fn discover_prefix(interface: &str) -> Result<[u8; 8]> {
    let output = Command::new("ifconfig")
        .arg(interface)
        .output()
        .context("failed to run ifconfig")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("inet6") && !line.contains("scopeid") {
            // Format: "inet6 2001:db8::1 prefixlen 64 ..."
            if let Some(addr_str) = line.split_whitespace().nth(1) {
                // Strip %interface suffix if present
                let addr_str = addr_str.split('%').next().unwrap_or(addr_str);
                if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
                    let octets = addr.octets();
                    if (octets[0] & 0xe0) == 0x20 {
                        let mut prefix = [0u8; 8];
                        prefix.copy_from_slice(&octets[..8]);
                        return Ok(prefix);
                    }
                }
            }
        }
    }

    bail!(
        "no global IPv6 address found on interface '{}'. \
         Make sure the interface has a SLAAC-assigned address or specify the prefix manually.",
        interface
    )
}

/// Extract an IPv6 address string from a netsh output line
#[cfg(target_os = "windows")]
fn extract_ipv6_from_line(line: &str) -> Option<&str> {
    // netsh output lines may contain "Address <ipv6>" or just the address
    for word in line.split_whitespace() {
        // Quick heuristic: contains ':' and at least one hex char
        if word.contains(':') && word.chars().any(|c| c.is_ascii_hexdigit()) {
            // Strip trailing % scope ID
            let addr = word.split('%').next().unwrap_or(word);
            return Some(addr);
        }
    }
    None
}

/// Check if an address is already in use on the specified interface
#[cfg(target_os = "windows")]
fn is_address_in_use(interface: &str, addr: Ipv6Addr) -> Result<bool> {
    let output = Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "show",
            "address",
            &format!("interface={interface}"),
        ])
        .output()
        .context("failed to check existing addresses")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check each line for the address
    for line in stdout.lines() {
        if let Some(existing) = extract_ipv6_from_line(line.trim()) {
            if let Ok(existing_addr) = existing.parse::<Ipv6Addr>() {
                if existing_addr == addr {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

#[cfg(target_os = "linux")]
fn is_address_in_use(interface: &str, addr: Ipv6Addr) -> Result<bool> {
    let output = Command::new("ip")
        .args(["-6", "addr", "show", "dev", interface])
        .output()
        .context("failed to check existing addresses")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let target = addr.to_string();

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("inet6") {
            if let Some(addr_cidr) = line.split_whitespace().nth(1) {
                let existing = addr_cidr.split('/').next().unwrap_or(addr_cidr);
                if existing == target {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

#[cfg(target_os = "macos")]
fn is_address_in_use(interface: &str, addr: Ipv6Addr) -> Result<bool> {
    let output = Command::new("ifconfig")
        .arg(interface)
        .output()
        .context("failed to check existing addresses")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let addr_str = addr.to_string();

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("inet6") {
            if let Some(existing) = line.split_whitespace().nth(1) {
                let existing = existing.split('%').next().unwrap_or(existing);
                if existing == addr_str {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefix_with_slash() {
        let prefix = parse_prefix("2001:db8:1:2::/64").unwrap();
        assert_eq!(prefix, [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn parse_prefix_without_slash() {
        let prefix = parse_prefix("2001:db8:abcd:ef01::").unwrap();
        assert_eq!(prefix, [0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0xef, 0x01]);
    }

    #[test]
    fn parse_prefix_invalid() {
        assert!(parse_prefix("not-an-address").is_err());
    }
}
