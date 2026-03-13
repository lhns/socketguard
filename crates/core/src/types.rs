use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            _ => Err(format!("invalid protocol: {s}")),
        }
    }
}

/// A listening socket detected on the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningSocket {
    pub pid: u32,
    pub process_name: String,
    pub port: u16,
    pub protocol: Protocol,
    pub bind_address: IpAddr,
    /// Full path to the executable (if available)
    pub exe_path: Option<String>,
    /// Command line arguments (if available)
    pub cmdline: Option<String>,
}

/// Access control policy for a socket
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// ACL-based access control (default).
    /// With no ACL entries: blocks all incoming connections.
    /// With ACL entries: allows only whitelisted IPs.
    Closed,
    /// Allow all incoming connections (no restrictions)
    Open,
}

impl Default for Policy {
    fn default() -> Self {
        Self::Closed
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Policy::Closed => write!(f, "closed"),
            Policy::Open => write!(f, "open"),
        }
    }
}

impl std::str::FromStr for Policy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "closed" => Ok(Policy::Closed),
            "open" => Ok(Policy::Open),
            // Accept "managed" as alias for backwards compatibility with existing DBs
            "managed" => Ok(Policy::Closed),
            _ => Err(format!("invalid policy: {s}")),
        }
    }
}

/// IPv6 backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    /// Random ULA addresses (fd00::/8)
    Ula,
    /// Yggdrasil-derived addresses (200::/7)
    Yggdrasil,
    /// SLAAC addresses from an existing /64 prefix on a physical interface
    Slaac,
    /// DHCPv6 addresses requested from a DHCPv6 server
    Dhcpv6,
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendType::Ula => write!(f, "ula"),
            BackendType::Yggdrasil => write!(f, "yggdrasil"),
            BackendType::Slaac => write!(f, "slaac"),
            BackendType::Dhcpv6 => write!(f, "dhcpv6"),
        }
    }
}

impl std::str::FromStr for BackendType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ula" => Ok(BackendType::Ula),
            "yggdrasil" => Ok(BackendType::Yggdrasil),
            "slaac" => Ok(BackendType::Slaac),
            "dhcpv6" => Ok(BackendType::Dhcpv6),
            _ => Err(format!("invalid backend: {s}")),
        }
    }
}

/// A managed socket with its assigned IPv6 and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedSocket {
    pub id: String,
    pub pid: u32,
    pub process_name: String,
    pub port: u16,
    pub protocol: Protocol,
    pub assigned_ipv6: Ipv6Addr,
    pub backend: BackendType,
    pub policy: Policy,
    pub keypair_id: Option<String>,
    pub exe_path: Option<String>,
    pub cmdline: Option<String>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// An ACL entry allowing a specific source IP to connect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub id: i64,
    pub socket_id: String,
    pub allowed_ip: String,
    pub label: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Result of allocating a new IPv6 address
#[derive(Debug, Clone)]
pub struct AllocatedAddress {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
    pub keypair: Option<KeyPair>,
    pub backend: BackendType,
}

/// A keypair (for Yggdrasil backend)
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub id: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub derived_ipv6: Ipv6Addr,
}

/// Generate a deterministic socket ID from process name, port, and protocol.
///
/// This ensures the same service keeps its IPv6 address and ACLs across
/// process restarts (new PIDs). The PID is stored as metadata but does not
/// affect identity.
pub fn socket_id(process_name: &str, port: u16, protocol: Protocol) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    process_name.hash(&mut hasher);
    port.hash(&mut hasher);
    protocol.to_string().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_id_is_deterministic() {
        let id1 = socket_id("nginx", 80, Protocol::Tcp);
        let id2 = socket_id("nginx", 80, Protocol::Tcp);
        assert_eq!(id1, id2);
    }

    #[test]
    fn socket_id_differs_by_process_name() {
        let id1 = socket_id("nginx", 80, Protocol::Tcp);
        let id2 = socket_id("apache", 80, Protocol::Tcp);
        assert_ne!(id1, id2);
    }

    #[test]
    fn socket_id_differs_by_port() {
        let id1 = socket_id("nginx", 80, Protocol::Tcp);
        let id2 = socket_id("nginx", 443, Protocol::Tcp);
        assert_ne!(id1, id2);
    }

    #[test]
    fn socket_id_differs_by_protocol() {
        let id1 = socket_id("dns", 53, Protocol::Tcp);
        let id2 = socket_id("dns", 53, Protocol::Udp);
        assert_ne!(id1, id2);
    }

    #[test]
    fn socket_id_is_16_hex_chars() {
        let id = socket_id("test", 1234, Protocol::Tcp);
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn protocol_display_roundtrip() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("udp".parse::<Protocol>().unwrap(), Protocol::Udp);
        assert!("invalid".parse::<Protocol>().is_err());
    }

    #[test]
    fn policy_display_roundtrip() {
        assert_eq!(Policy::Closed.to_string(), "closed");
        assert_eq!(Policy::Open.to_string(), "open");
        assert_eq!("closed".parse::<Policy>().unwrap(), Policy::Closed);
        assert_eq!("open".parse::<Policy>().unwrap(), Policy::Open);
        // "managed" accepted as backwards-compat alias for closed
        assert_eq!("managed".parse::<Policy>().unwrap(), Policy::Closed);
        assert!("invalid".parse::<Policy>().is_err());
    }

    #[test]
    fn backend_type_display_roundtrip() {
        assert_eq!(BackendType::Ula.to_string(), "ula");
        assert_eq!(BackendType::Yggdrasil.to_string(), "yggdrasil");
        assert_eq!(BackendType::Slaac.to_string(), "slaac");
        assert_eq!(BackendType::Dhcpv6.to_string(), "dhcpv6");
        assert_eq!("ula".parse::<BackendType>().unwrap(), BackendType::Ula);
        assert_eq!(
            "yggdrasil".parse::<BackendType>().unwrap(),
            BackendType::Yggdrasil
        );
        assert_eq!("slaac".parse::<BackendType>().unwrap(), BackendType::Slaac);
        assert_eq!("dhcpv6".parse::<BackendType>().unwrap(), BackendType::Dhcpv6);
        assert!("invalid".parse::<BackendType>().is_err());
    }

    #[test]
    fn policy_default_is_closed() {
        assert_eq!(Policy::default(), Policy::Closed);
    }

    #[test]
    fn protocol_serde_roundtrip() {
        let tcp = Protocol::Tcp;
        let json = serde_json::to_string(&tcp).unwrap();
        assert_eq!(json, "\"tcp\"");
        let parsed: Protocol = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tcp);
    }

    #[test]
    fn policy_serde_roundtrip() {
        for policy in [Policy::Closed, Policy::Open] {
            let json = serde_json::to_string(&policy).unwrap();
            let parsed: Policy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, policy);
        }
    }

    #[test]
    fn backend_type_serde_roundtrip() {
        for backend in [BackendType::Ula, BackendType::Yggdrasil, BackendType::Slaac, BackendType::Dhcpv6] {
            let json = serde_json::to_string(&backend).unwrap();
            let parsed: BackendType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, backend);
        }
    }
}
