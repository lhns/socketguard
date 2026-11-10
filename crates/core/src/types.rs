use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};

/// Network protocol
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

/// TCP ports of remote administration (ssh, RDP): closing them can lock the user out.
pub const REMOTE_ADMIN_PORTS: &[u16] = &[22, 3389];

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
    /// Command line arguments, argv[0] first (if available)
    pub cmdline: Option<Vec<String>>,
    /// Owning user: the uid on Unix, the owner SID string on Windows (if available).
    #[serde(default)]
    pub uid: Option<String>,
    /// The process lives in another mount namespace than the daemon (Linux), so its
    /// `exe_path` may not name the file the host sees there.
    #[serde(default)]
    pub foreign_mntns: bool,
    /// The process's working directory (if available); relative script paths are resolved
    /// against it for the app identity.
    #[serde(default)]
    pub cwd: Option<String>,
}

/// Network backend type
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
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
    /// Onion services published through a Tor control port (not an IPv6 backend)
    Tor,
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendType::Ula => write!(f, "ula"),
            BackendType::Yggdrasil => write!(f, "yggdrasil"),
            BackendType::Slaac => write!(f, "slaac"),
            BackendType::Dhcpv6 => write!(f, "dhcpv6"),
            BackendType::Tor => write!(f, "tor"),
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
            "tor" => Ok(BackendType::Tor),
            _ => Err(format!("invalid backend: {s}")),
        }
    }
}

/// Result of allocating a new IPv6 address
#[derive(Debug, Clone)]
pub struct AllocatedAddress {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
    pub backend: BackendType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_display_roundtrip() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("udp".parse::<Protocol>().unwrap(), Protocol::Udp);
        assert!("invalid".parse::<Protocol>().is_err());
    }

    #[test]
    fn backend_type_display_roundtrip() {
        for (t, s) in [
            (BackendType::Ula, "ula"),
            (BackendType::Yggdrasil, "yggdrasil"),
            (BackendType::Slaac, "slaac"),
            (BackendType::Dhcpv6, "dhcpv6"),
            (BackendType::Tor, "tor"),
        ] {
            assert_eq!(t.to_string(), s);
            assert_eq!(s.parse::<BackendType>().unwrap(), t);
            let json = serde_json::to_string(&t).unwrap();
            assert_eq!(serde_json::from_str::<BackendType>(&json).unwrap(), t);
        }
        assert!("invalid".parse::<BackendType>().is_err());
    }

    #[test]
    fn protocol_serde_roundtrip() {
        let json = serde_json::to_string(&Protocol::Tcp).unwrap();
        assert_eq!(json, "\"tcp\"");
        assert_eq!(
            serde_json::from_str::<Protocol>(&json).unwrap(),
            Protocol::Tcp
        );
    }
}
