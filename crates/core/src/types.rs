use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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

/// Which IP versions a listening port accepts connections over.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum AddrFamily {
    V4,
    V6,
    /// Both: a dual-stack socket, or separate IPv4 and IPv6 sockets on the port. Also what
    /// a port stored before the family was recorded counts as, the cautious reading.
    #[default]
    Dual,
}

impl AddrFamily {
    pub fn has_v4(self) -> bool {
        self != AddrFamily::V6
    }

    pub fn has_v6(self) -> bool {
        self != AddrFamily::V4
    }

    /// The family of a port served by sockets of `self` and `other`.
    pub fn union(self, other: AddrFamily) -> AddrFamily {
        if self == other {
            self
        } else {
            AddrFamily::Dual
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AddrFamily::V4 => "v4",
            AddrFamily::V6 => "v6",
            AddrFamily::Dual => "dual",
        }
    }
}

impl std::str::FromStr for AddrFamily {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "v4" => Ok(AddrFamily::V4),
            "v6" => Ok(AddrFamily::V6),
            "dual" => Ok(AddrFamily::Dual),
            _ => Err(format!("invalid address family: {s}")),
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
    /// The process owning the socket could not be identified (ADR 0046): the socket becomes
    /// an app of its own, `unknown:<proto>/<port>`.
    #[serde(default)]
    pub unidentified: bool,
    /// Linux: the process runs in a systemd service unit.
    #[serde(default)]
    pub in_service_unit: bool,
}

impl ListeningSocket {
    /// A socket with no process details yet; fill them in with the `with_*` setters.
    pub fn new(pid: u32, port: u16, protocol: Protocol, bind_address: IpAddr) -> Self {
        Self {
            pid,
            process_name: String::new(),
            port,
            protocol,
            bind_address,
            exe_path: None,
            cmdline: None,
            uid: None,
            foreign_mntns: false,
            cwd: None,
            unidentified: false,
            in_service_unit: false,
        }
    }

    /// The IP versions this socket accepts. An IPv4 bind is v4 and a specific IPv6 bind v6.
    /// The IPv6 wildcard `::` is dual-stack on Unix (IPV6_V6ONLY is off by default and not
    /// visible in /proc) and v6-only on Windows, where a dual-stack listener shows up
    /// as a separate IPv4 socket; ports merge their sockets' families.
    pub fn family(&self) -> AddrFamily {
        self.family_on(cfg!(windows))
    }

    pub fn family_on(&self, windows: bool) -> AddrFamily {
        match self.bind_address {
            IpAddr::V4(_) => AddrFamily::V4,
            IpAddr::V6(a) if a.is_unspecified() && !windows => AddrFamily::Dual,
            IpAddr::V6(_) => AddrFamily::V6,
        }
    }

    pub fn with_process_name(mut self, name: impl Into<String>) -> Self {
        self.process_name = name.into();
        self
    }

    pub fn with_exe_path(mut self, exe_path: Option<String>) -> Self {
        self.exe_path = exe_path;
        self
    }

    pub fn with_cmdline(mut self, cmdline: Option<Vec<String>>) -> Self {
        self.cmdline = cmdline;
        self
    }

    pub fn with_uid(mut self, uid: Option<String>) -> Self {
        self.uid = uid;
        self
    }

    pub fn with_cwd(mut self, cwd: Option<String>) -> Self {
        self.cwd = cwd;
        self
    }

    pub fn with_in_service_unit(mut self, in_unit: bool) -> Self {
        self.in_service_unit = in_unit;
        self
    }

    pub fn with_foreign_mntns(mut self, foreign: bool) -> Self {
        self.foreign_mntns = foreign;
        self
    }
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

    fn sock(bind: &str) -> ListeningSocket {
        ListeningSocket::new(1, 80, Protocol::Tcp, bind.parse().unwrap())
    }

    #[test]
    fn socket_family_by_bind_address_and_platform() {
        assert_eq!(sock("0.0.0.0").family_on(false), AddrFamily::V4);
        assert_eq!(sock("127.0.0.1").family_on(true), AddrFamily::V4);
        assert_eq!(sock("fd00::1").family_on(false), AddrFamily::V6);
        assert_eq!(sock("::").family_on(false), AddrFamily::Dual);
        assert_eq!(sock("::").family_on(true), AddrFamily::V6);
    }

    #[test]
    fn families_merge_per_port() {
        use AddrFamily::*;
        assert_eq!(V4.union(V6), Dual);
        assert_eq!(V6.union(V6), V6);
        assert!(Dual.has_v4() && Dual.has_v6() && !V6.has_v4() && !V4.has_v6());
        for f in [V4, V6, Dual] {
            assert_eq!(f.as_str().parse::<AddrFamily>().unwrap(), f);
        }
    }
}
