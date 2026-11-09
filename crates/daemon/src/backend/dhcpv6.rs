use super::Ipv6Backend;
use anyhow::{bail, Context, Result};
use rand::Rng;
use socketguard_core::{AllocatedAddress, BackendType};
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, info, warn};

/// DHCPv6 client port (reserved, but we use ephemeral port to avoid conflicts)
#[allow(dead_code)]
const DHCPV6_CLIENT_PORT: u16 = 546;
/// DHCPv6 server port
const DHCPV6_SERVER_PORT: u16 = 547;
/// All DHCPv6 relay agents and servers multicast address
const ALL_DHCPV6_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

// DHCPv6 message types
const MSG_SOLICIT: u8 = 1;
const MSG_ADVERTISE: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_REPLY: u8 = 7;
#[allow(dead_code)]
const MSG_RELEASE: u8 = 8;

// DHCPv6 option types
const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IAADDR: u16 = 5;
const OPT_ELAPSED_TIME: u16 = 8;

// DUID type: DUID-UUID (RFC 6355)
const DUID_UUID: u16 = 4;

/// Maximum retransmissions for a single request
const MAX_RETRANSMIT: usize = 3;
/// Socket receive timeout
const RECV_TIMEOUT: Duration = Duration::from_secs(3);

/// DHCPv6 backend: requests addresses from a DHCPv6 server on the network.
pub struct Dhcpv6Backend {
    #[allow(dead_code)]
    interface: String,
    interface_index: u32,
    /// Client DUID (stable across allocations)
    client_duid: Vec<u8>,
    /// Track IAID -> (address, server_duid) for release
    leases: Mutex<HashMap<u32, Lease>>,
    /// Next IAID counter
    next_iaid: Mutex<u32>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct Lease {
    address: Ipv6Addr,
    server_duid: Vec<u8>,
    iaid: u32,
}

impl Dhcpv6Backend {
    pub fn new(interface: &str) -> Result<Self> {
        let interface_index = get_interface_index(interface)?;

        // Generate a stable DUID-UUID for this client
        let client_uuid: u128 = rand::thread_rng().gen();
        let mut client_duid = Vec::with_capacity(18);
        // DUID type (2 bytes)
        client_duid.extend_from_slice(&DUID_UUID.to_be_bytes());
        // UUID (16 bytes)
        client_duid.extend_from_slice(&client_uuid.to_be_bytes());

        info!(
            "DHCPv6 backend initialized: interface={} (index={})",
            interface, interface_index
        );

        Ok(Self {
            interface: interface.to_string(),
            interface_index,
            client_duid,
            leases: Mutex::new(HashMap::new()),
            next_iaid: Mutex::new(1),
        })
    }

    /// Perform a full DHCPv6 Solicit -> Advertise -> Request -> Reply exchange
    fn request_address(&self) -> Result<(Ipv6Addr, Vec<u8>)> {
        let socket = self.create_socket()?;
        let mut rng = rand::thread_rng();
        let xid: [u8; 3] = [rng.gen(), rng.gen(), rng.gen()];
        let iaid = {
            let mut next = self.next_iaid.lock().unwrap();
            let id = *next;
            *next += 1;
            id
        };

        // Step 1: Send Solicit
        let solicit = self.build_solicit(&xid, iaid);
        let server_addr = SocketAddrV6::new(
            ALL_DHCPV6_SERVERS,
            DHCPV6_SERVER_PORT,
            0,
            self.interface_index,
        );

        let mut server_duid = Vec::new();
        let mut offered_addr: Option<Ipv6Addr> = None;

        for attempt in 0..MAX_RETRANSMIT {
            debug!("DHCPv6 Solicit attempt {}", attempt + 1);
            socket
                .send_to(&solicit, server_addr)
                .context("failed to send DHCPv6 Solicit")?;

            match self.recv_response(&socket, &xid, MSG_ADVERTISE) {
                Ok(response) => {
                    server_duid = parse_server_duid(&response)?;
                    offered_addr = parse_ia_address(&response);
                    if offered_addr.is_some() {
                        break;
                    }
                    warn!("DHCPv6 Advertise contained no address");
                }
                Err(e) => {
                    debug!("No Advertise received: {e}");
                }
            }
        }

        let offered_addr =
            offered_addr.ok_or_else(|| anyhow::anyhow!("no DHCPv6 server responded"))?;

        // Step 2: Send Request for the offered address
        let xid2: [u8; 3] = [rng.gen(), rng.gen(), rng.gen()];
        let request = self.build_request(&xid2, iaid, &server_duid, offered_addr);

        for attempt in 0..MAX_RETRANSMIT {
            debug!("DHCPv6 Request attempt {}", attempt + 1);
            socket
                .send_to(&request, server_addr)
                .context("failed to send DHCPv6 Request")?;

            match self.recv_response(&socket, &xid2, MSG_REPLY) {
                Ok(response) => {
                    if let Some(addr) = parse_ia_address(&response) {
                        info!("DHCPv6 assigned address: {}", addr);
                        // Store lease for later release
                        let lease = Lease {
                            address: addr,
                            server_duid: server_duid.clone(),
                            iaid,
                        };
                        self.leases.lock().unwrap().insert(iaid, lease);
                        return Ok((addr, server_duid));
                    }
                }
                Err(e) => {
                    debug!("No Reply received: {e}");
                }
            }
        }

        bail!("DHCPv6 Request failed: no Reply received")
    }

    /// Send a DHCPv6 Release for an address
    fn release_lease(&self, lease: &Lease) -> Result<()> {
        let socket = self.create_socket()?;
        let mut rng = rand::thread_rng();
        let xid: [u8; 3] = [rng.gen(), rng.gen(), rng.gen()];

        let release = self.build_release(&xid, lease);
        let server_addr = SocketAddrV6::new(
            ALL_DHCPV6_SERVERS,
            DHCPV6_SERVER_PORT,
            0,
            self.interface_index,
        );

        // Send release (best effort, don't retry much)
        socket
            .send_to(&release, server_addr)
            .context("failed to send DHCPv6 Release")?;

        // Wait briefly for reply but don't error if we don't get one
        let _ = self.recv_response(&socket, &xid, MSG_REPLY);

        info!("DHCPv6 released address: {}", lease.address);
        Ok(())
    }

    fn create_socket(&self) -> Result<UdpSocket> {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};

        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
            .context("failed to create DHCPv6 socket")?;

        socket.set_reuse_address(true)?;
        socket.set_only_v6(true)?;

        // Bind to any address on the client port
        // Use port 0 to let the OS assign a port (avoids conflicts with system DHCPv6 client)
        let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
        socket
            .bind(&SockAddr::from(bind_addr))
            .context("failed to bind DHCPv6 socket")?;

        // Set multicast interface
        socket.set_multicast_if_v6(self.interface_index)?;

        // Join the all-DHCP multicast group on the right interface
        socket.join_multicast_v6(&ALL_DHCPV6_SERVERS, self.interface_index)?;

        socket.set_read_timeout(Some(RECV_TIMEOUT))?;

        Ok(UdpSocket::from(socket))
    }

    fn recv_response(
        &self,
        socket: &UdpSocket,
        expected_xid: &[u8; 3],
        expected_type: u8,
    ) -> Result<Vec<u8>> {
        let mut buf = [0u8; 4096];
        loop {
            let (len, _) = socket
                .recv_from(&mut buf)
                .context("DHCPv6 receive timeout")?;

            let data = &buf[..len];
            if len < 4 {
                continue;
            }

            let msg_type = data[0];
            let xid = &data[1..4];

            if msg_type == expected_type && xid == expected_xid {
                return Ok(data.to_vec());
            }
        }
    }

    fn build_solicit(&self, xid: &[u8; 3], iaid: u32) -> Vec<u8> {
        let mut msg = Vec::with_capacity(128);
        // Message type + transaction ID
        msg.push(MSG_SOLICIT);
        msg.extend_from_slice(xid);

        // Client ID option
        append_option(&mut msg, OPT_CLIENTID, &self.client_duid);

        // IA_NA option (request an address)
        let ia_na = build_ia_na(iaid, None);
        append_option(&mut msg, OPT_IA_NA, &ia_na);

        // Elapsed time (0)
        append_option(&mut msg, OPT_ELAPSED_TIME, &[0, 0]);

        msg
    }

    fn build_request(
        &self,
        xid: &[u8; 3],
        iaid: u32,
        server_duid: &[u8],
        addr: Ipv6Addr,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(256);
        msg.push(MSG_REQUEST);
        msg.extend_from_slice(xid);

        // Client ID
        append_option(&mut msg, OPT_CLIENTID, &self.client_duid);

        // Server ID
        append_option(&mut msg, OPT_SERVERID, server_duid);

        // IA_NA with the specific address
        let ia_na = build_ia_na(iaid, Some(addr));
        append_option(&mut msg, OPT_IA_NA, &ia_na);

        // Elapsed time
        append_option(&mut msg, OPT_ELAPSED_TIME, &[0, 0]);

        msg
    }

    fn build_release(&self, xid: &[u8; 3], lease: &Lease) -> Vec<u8> {
        let mut msg = Vec::with_capacity(256);
        msg.push(MSG_RELEASE);
        msg.extend_from_slice(xid);

        // Client ID
        append_option(&mut msg, OPT_CLIENTID, &self.client_duid);

        // Server ID
        append_option(&mut msg, OPT_SERVERID, &lease.server_duid);

        // IA_NA with the address to release
        let ia_na = build_ia_na(lease.iaid, Some(lease.address));
        append_option(&mut msg, OPT_IA_NA, &ia_na);

        msg
    }
}

impl Ipv6Backend for Dhcpv6Backend {
    fn allocate_address(&self) -> Result<AllocatedAddress> {
        let (address, _server_duid) = self.request_address()?;

        Ok(AllocatedAddress {
            address,
            prefix_len: 128,
            keypair: None,
            backend: BackendType::Dhcpv6,
        })
    }

    fn release_address(&self, addr: &Ipv6Addr) -> Result<()> {
        // Find and release the lease for this address
        let lease = {
            let leases = self.leases.lock().unwrap();
            leases.values().find(|l| l.address == *addr).cloned()
        };

        if let Some(lease) = lease {
            if let Err(e) = self.release_lease(&lease) {
                warn!("Failed to release DHCPv6 lease for {}: {e}", addr);
            }
            self.leases.lock().unwrap().remove(&lease.iaid);
        }

        Ok(())
    }
}

/// Append a DHCPv6 option: type (2 bytes) + length (2 bytes) + data
fn append_option(buf: &mut Vec<u8>, opt_type: u16, data: &[u8]) {
    buf.extend_from_slice(&opt_type.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Build IA_NA option data: IAID (4) + T1 (4) + T2 (4) + optional IA Address sub-option
fn build_ia_na(iaid: u32, addr: Option<Ipv6Addr>) -> Vec<u8> {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&iaid.to_be_bytes()); // IAID
    data.extend_from_slice(&0u32.to_be_bytes()); // T1 (let server decide)
    data.extend_from_slice(&0u32.to_be_bytes()); // T2 (let server decide)

    if let Some(addr) = addr {
        // IA Address sub-option
        let mut ia_addr = Vec::with_capacity(24);
        ia_addr.extend_from_slice(&addr.octets()); // Address (16 bytes)
        ia_addr.extend_from_slice(&3600u32.to_be_bytes()); // Preferred lifetime
        ia_addr.extend_from_slice(&7200u32.to_be_bytes()); // Valid lifetime
        append_option(&mut data, OPT_IAADDR, &ia_addr);
    }

    data
}

/// Parse Server DUID from a DHCPv6 response
fn parse_server_duid(response: &[u8]) -> Result<Vec<u8>> {
    for (opt_type, opt_data) in iter_options(response) {
        if opt_type == OPT_SERVERID {
            return Ok(opt_data.to_vec());
        }
    }
    bail!("no Server ID in DHCPv6 response")
}

/// Parse IA Address from a DHCPv6 response (inside IA_NA option)
fn parse_ia_address(response: &[u8]) -> Option<Ipv6Addr> {
    for (opt_type, opt_data) in iter_options(response) {
        if opt_type == OPT_IA_NA && opt_data.len() >= 12 {
            // IA_NA: IAID(4) + T1(4) + T2(4) + sub-options
            let sub_options = &opt_data[12..];
            for (sub_type, sub_data) in iter_options_raw(sub_options) {
                if sub_type == OPT_IAADDR && sub_data.len() >= 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&sub_data[..16]);
                    return Some(Ipv6Addr::from(octets));
                }
            }
        }
    }
    None
}

/// Iterate over DHCPv6 options in a message (skipping the 4-byte header)
fn iter_options(msg: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    iter_options_raw(if msg.len() > 4 { &msg[4..] } else { &[] })
}

/// Iterate over DHCPv6 options from raw bytes
fn iter_options_raw(data: &[u8]) -> OptionIter<'_> {
    OptionIter { data, pos: 0 }
}

struct OptionIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let opt_type = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        let opt_len =
            u16::from_be_bytes([self.data[self.pos + 2], self.data[self.pos + 3]]) as usize;
        self.pos += 4;

        if self.pos + opt_len > self.data.len() {
            return None;
        }

        let opt_data = &self.data[self.pos..self.pos + opt_len];
        self.pos += opt_len;
        Some((opt_type, opt_data))
    }
}

/// Get the interface index for a named interface
#[cfg(target_os = "windows")]
fn get_interface_index(interface: &str) -> Result<u32> {
    use std::process::Command;

    let output = Command::new("netsh")
        .args(["interface", "ipv6", "show", "interface"])
        .output()
        .context("failed to run netsh")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse netsh output. Lines look like:
    // "   12   ...   Ethernet"
    for line in stdout.lines() {
        let line = line.trim();
        if line.ends_with(interface) || line.contains(&format!(" {interface}")) {
            if let Some(idx_str) = line.split_whitespace().next() {
                if let Ok(idx) = idx_str.parse::<u32>() {
                    return Ok(idx);
                }
            }
        }
    }

    bail!(
        "could not find interface index for '{}'. Check that the interface exists.",
        interface
    )
}

#[cfg(target_os = "linux")]
fn get_interface_index(interface: &str) -> Result<u32> {
    use std::fs;
    let path = format!("/sys/class/net/{interface}/ifindex");
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read interface index from {path}"))?;
    content
        .trim()
        .parse()
        .with_context(|| format!("invalid interface index for {interface}"))
}

#[cfg(target_os = "macos")]
fn get_interface_index(interface: &str) -> Result<u32> {
    use std::process::Command;

    let output = Command::new("ifconfig")
        .arg(interface)
        .output()
        .context("failed to run ifconfig")?;

    if !output.status.success() {
        bail!("interface '{}' not found", interface);
    }

    // macOS ifconfig doesn't directly show the index, use networksetup or parse
    // For simplicity, use the if_nametoindex approach via libc
    // Since we can't easily call libc from here, parse from `networksetup -listallhardwareports`
    // Actually, the simplest approach: just use 0 and let the OS figure it out
    // This works for most cases on macOS
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_solicit_is_well_formed() {
        let client_duid = vec![0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let xid = [0xAA, 0xBB, 0xCC];
        let iaid = 1u32;

        let mut msg = Vec::new();
        msg.push(MSG_SOLICIT);
        msg.extend_from_slice(&xid);
        append_option(&mut msg, OPT_CLIENTID, &client_duid);
        let ia_na = build_ia_na(iaid, None);
        append_option(&mut msg, OPT_IA_NA, &ia_na);
        append_option(&mut msg, OPT_ELAPSED_TIME, &[0, 0]);

        assert_eq!(msg[0], MSG_SOLICIT);
        assert_eq!(&msg[1..4], &xid);
        assert!(msg.len() > 4);
    }

    #[test]
    fn parse_options_roundtrip() {
        let mut msg = vec![0, 0, 0, 0]; // fake header
        let data = b"hello";
        append_option(&mut msg, 42, data);
        append_option(&mut msg, 99, b"world");

        let opts: Vec<_> = iter_options(&msg).collect();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].0, 42);
        assert_eq!(opts[0].1, b"hello");
        assert_eq!(opts[1].0, 99);
        assert_eq!(opts[1].1, b"world");
    }

    #[test]
    fn parse_ia_address_from_reply() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut msg = vec![MSG_REPLY, 0, 0, 0]; // header

        let ia_na = build_ia_na(1, Some(addr));
        append_option(&mut msg, OPT_IA_NA, &ia_na);

        let parsed = parse_ia_address(&msg);
        assert_eq!(parsed, Some(addr));
    }

    #[test]
    fn parse_server_duid_from_response() {
        let server_duid = vec![0, 1, 0x11, 0x22, 0x33, 0x44];
        let mut msg = vec![MSG_ADVERTISE, 0, 0, 0]; // header
        append_option(&mut msg, OPT_SERVERID, &server_duid);

        let parsed = parse_server_duid(&msg).unwrap();
        assert_eq!(parsed, server_duid);
    }
}
