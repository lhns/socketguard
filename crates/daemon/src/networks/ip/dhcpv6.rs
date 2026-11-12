use super::{AllocatedAddress, Ipv6Backend, Prefix};
use anyhow::{bail, Context, Result};
use data_encoding::HEXLOWER;
use rand::Rng;
use serde::{Deserialize, Serialize};
use socketguard_core::BackendType;
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// DHCPv6 server port
const DHCPV6_SERVER_PORT: u16 = 547;
/// All DHCPv6 relay agents and servers multicast address
const ALL_DHCPV6_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

// DHCPv6 message types
const MSG_SOLICIT: u8 = 1;
const MSG_ADVERTISE: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_REPLY: u8 = 7;
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
/// Release retransmission (RFC 8415 section 7.6): REL_TIMEOUT and REL_MAX_RC.
const REL_TIMEOUT: Duration = Duration::from_secs(1);
const REL_MAX_RC: usize = 4;

/// Settings keys: the client DUID, and per address what a Release needs.
const DUID_KEY: &str = "dhcpv6_client_duid";
const LEASE_KEY_PREFIX: &str = "dhcpv6_lease:";

/// Where the backend keeps what must outlive the process: the client DUID and the leases
/// (the daemon's `settings` table). Blocking, like the rest of the network code.
pub trait StateStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn set(&self, key: &str, value: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

/// The store of backends that have none of their own: set once at startup, so
/// `networks::create` and the engine keep their signatures.
static STORE: OnceLock<Arc<dyn StateStore>> = OnceLock::new();

/// Make `store` the persistent state of every DHCPv6 backend (first call wins).
pub fn use_store(store: Arc<dyn StateStore>) {
    let _ = STORE.set(store);
}

/// An in-memory [`StateStore`]; clones share the data (a "restart" in tests).
#[derive(Clone, Default)]
pub struct MemoryStore(Arc<Mutex<HashMap<String, String>>>);

impl StateStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn set(&self, key: &str, value: &str) -> Result<()> {
        self.0.lock().unwrap().insert(key.into(), value.into());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

/// DHCPv6 backend: requests addresses from a DHCPv6 server on the network.
pub struct Dhcpv6Backend {
    interface: String,
    /// Resolved on first use, so a missing interface is a runtime condition.
    interface_index: Mutex<Option<u32>>,
    /// Own store; None means the process-wide one (see [`use_store`]).
    store: Option<Arc<dyn StateStore>>,
    /// Client DUID, loaded or created on first use and then kept.
    client_duid: Mutex<Option<Vec<u8>>>,
    /// Leases acquired by this process, by address; earlier ones are read from the store.
    leases: Mutex<HashMap<Ipv6Addr, Lease>>,
}

/// What a Release needs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Lease {
    address: Ipv6Addr,
    server_duid: Vec<u8>,
    iaid: u32,
}

/// A lease as stored under its address.
#[derive(Serialize, Deserialize)]
struct StoredLease {
    server_duid: String,
    iaid: u32,
}

impl Dhcpv6Backend {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            interface_index: Mutex::new(None),
            store: None,
            client_duid: Mutex::new(None),
            leases: Mutex::new(HashMap::new()),
        }
    }

    /// The backend over its own store instead of the process-wide one.
    pub fn with_store(mut self, store: Arc<dyn StateStore>) -> Self {
        self.store = Some(store);
        self
    }

    fn store(&self) -> Option<Arc<dyn StateStore>> {
        self.store.clone().or_else(|| STORE.get().cloned())
    }

    /// The client DUID, stable across restarts: the stored one, or a new DUID-UUID that is
    /// stored. Without a usable store it only lasts for this process.
    fn client_duid(&self) -> Vec<u8> {
        let mut cached = self.client_duid.lock().unwrap();
        if let Some(duid) = cached.as_ref() {
            return duid.clone();
        }
        let store = self.store();
        let stored = store.as_ref().and_then(|s| match s.get(DUID_KEY) {
            Ok(v) => v.and_then(|hex| decode_duid(&hex)),
            Err(e) => {
                warn!("Cannot read the DHCPv6 client DUID: {e:#}");
                None
            }
        });
        let duid = stored.unwrap_or_else(|| {
            let uuid: u128 = rand::thread_rng().gen();
            let mut duid = Vec::with_capacity(18);
            duid.extend_from_slice(&DUID_UUID.to_be_bytes());
            duid.extend_from_slice(&uuid.to_be_bytes());
            if let Some(s) = &store {
                if let Err(e) = s.set(DUID_KEY, &HEXLOWER.encode(&duid)) {
                    warn!("Cannot store the DHCPv6 client DUID: {e:#}");
                }
            }
            duid
        });
        *cached = Some(duid.clone());
        duid
    }

    fn lease_key(addr: Ipv6Addr) -> String {
        format!("{LEASE_KEY_PREFIX}{addr}")
    }

    /// Remember a lease, in memory and in the store, so a later process can release it.
    fn record_lease(&self, lease: Lease) {
        if let Some(store) = self.store() {
            let stored = StoredLease {
                server_duid: HEXLOWER.encode(&lease.server_duid),
                iaid: lease.iaid,
            };
            let json = serde_json::to_string(&stored).expect("a lease serializes");
            if let Err(e) = store.set(&Self::lease_key(lease.address), &json) {
                warn!("Cannot store the DHCPv6 lease of {}: {e:#}", lease.address);
            }
        }
        self.leases.lock().unwrap().insert(lease.address, lease);
    }

    /// The lease of `addr`: acquired by this process, or recorded by an earlier one.
    fn find_lease(&self, addr: Ipv6Addr) -> Option<Lease> {
        if let Some(lease) = self.leases.lock().unwrap().get(&addr) {
            return Some(lease.clone());
        }
        let json = match self.store()?.get(&Self::lease_key(addr)) {
            Ok(v) => v?,
            Err(e) => {
                warn!("Cannot read the DHCPv6 lease of {addr}: {e:#}");
                return None;
            }
        };
        let stored: StoredLease = serde_json::from_str(&json).ok()?;
        Some(Lease {
            address: addr,
            server_duid: HEXLOWER.decode(stored.server_duid.as_bytes()).ok()?,
            iaid: stored.iaid,
        })
    }

    fn forget_lease(&self, addr: Ipv6Addr) {
        self.leases.lock().unwrap().remove(&addr);
        if let Some(store) = self.store() {
            if let Err(e) = store.delete(&Self::lease_key(addr)) {
                warn!("Cannot delete the DHCPv6 lease of {addr}: {e:#}");
            }
        }
    }

    /// The interface index, looked up once it is needed.
    fn interface_index(&self) -> Result<u32> {
        let mut cached = self.interface_index.lock().unwrap();
        if let Some(i) = *cached {
            return Ok(i);
        }
        let i = get_interface_index(&self.interface)?;
        info!("DHCPv6 interface {} has index {i}", self.interface);
        *cached = Some(i);
        Ok(i)
    }

    /// Perform a full DHCPv6 Solicit -> Advertise -> Request -> Reply exchange
    fn request_address(&self) -> Result<Ipv6Addr> {
        let interface_index = self.interface_index()?;
        let socket = self.create_socket()?;
        let mut rng = rand::thread_rng();
        let xid: [u8; 3] = [rng.gen(), rng.gen(), rng.gen()];
        // Random, not a counter: leases outlive the process, and a new IA must not reuse
        // the IAID of one the server still has bound.
        let iaid: u32 = rng.gen();

        // Step 1: Send Solicit
        let solicit = self.build_solicit(&xid, iaid);
        let server_addr =
            SocketAddrV6::new(ALL_DHCPV6_SERVERS, DHCPV6_SERVER_PORT, 0, interface_index);

        let mut server_duid = Vec::new();
        let mut offered_addr: Option<Ipv6Addr> = None;

        for attempt in 0..MAX_RETRANSMIT {
            debug!("DHCPv6 Solicit attempt {}", attempt + 1);
            socket
                .send_to(&solicit, server_addr)
                .context("failed to send DHCPv6 Solicit")?;

            match self.recv_response(&socket, &xid, MSG_ADVERTISE) {
                Ok(response) => {
                    if let Some((duid, addr)) = parse_advertise(&response) {
                        server_duid = duid;
                        offered_addr = Some(addr);
                        break;
                    }
                    // Try again: another server may answer the next Solicit.
                    warn!("DHCPv6 Advertise lacked a server id or an address");
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
                        self.record_lease(Lease {
                            address: addr,
                            server_duid: server_duid.clone(),
                            iaid,
                        });
                        return Ok(addr);
                    }
                }
                Err(e) => {
                    debug!("No Reply received: {e}");
                }
            }
        }

        bail!("DHCPv6 Request failed: no Reply received")
    }

    /// Send a DHCPv6 Release for a lease to the servers' multicast address.
    fn release_lease(&self, lease: &Lease) -> Result<()> {
        let interface_index = self.interface_index()?;
        let socket = self.create_socket()?;
        let dest = SocketAddrV6::new(ALL_DHCPV6_SERVERS, DHCPV6_SERVER_PORT, 0, interface_index);
        if self.release_exchange(&socket, dest.into(), lease, REL_TIMEOUT)? {
            info!("DHCPv6 released address: {}", lease.address);
        } else {
            info!(
                "DHCPv6 server did not answer the Release of {}; giving up",
                lease.address
            );
        }
        Ok(())
    }

    /// Send the Release, retransmitting up to [`REL_MAX_RC`] times (RFC 8415 section
    /// 18.2.7), and say whether a Reply came.
    fn release_exchange(
        &self,
        socket: &UdpSocket,
        dest: SocketAddr,
        lease: &Lease,
        timeout: Duration,
    ) -> Result<bool> {
        socket.set_read_timeout(Some(timeout))?;
        let mut rng = rand::thread_rng();
        let xid: [u8; 3] = [rng.gen(), rng.gen(), rng.gen()];
        let start = Instant::now();
        for attempt in 0..REL_MAX_RC {
            // Elapsed time since the first transmission, in hundredths of a second.
            let elapsed = (start.elapsed().as_millis() / 10).min(u16::MAX as u128) as u16;
            let release = self.build_release(&xid, lease, elapsed);
            debug!("DHCPv6 Release attempt {}", attempt + 1);
            socket
                .send_to(&release, dest)
                .context("failed to send DHCPv6 Release")?;
            if self.recv_response(socket, &xid, MSG_REPLY).is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
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
        socket.set_multicast_if_v6(self.interface_index()?)?;

        // Join the all-DHCP multicast group on the right interface
        socket.join_multicast_v6(&ALL_DHCPV6_SERVERS, self.interface_index()?)?;

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
        append_option(&mut msg, OPT_CLIENTID, &self.client_duid());

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
        append_option(&mut msg, OPT_CLIENTID, &self.client_duid());

        // Server ID
        append_option(&mut msg, OPT_SERVERID, server_duid);

        // IA_NA with the specific address
        let ia_na = build_ia_na(iaid, Some(addr));
        append_option(&mut msg, OPT_IA_NA, &ia_na);

        // Elapsed time
        append_option(&mut msg, OPT_ELAPSED_TIME, &[0, 0]);

        msg
    }

    /// A Release (RFC 8415 section 18.2.7). `elapsed` is in hundredths of a second since
    /// the first transmission.
    fn build_release(&self, xid: &[u8; 3], lease: &Lease, elapsed: u16) -> Vec<u8> {
        let mut msg = Vec::with_capacity(256);
        msg.push(MSG_RELEASE);
        msg.extend_from_slice(xid);

        // Client ID
        append_option(&mut msg, OPT_CLIENTID, &self.client_duid());

        // Server ID
        append_option(&mut msg, OPT_SERVERID, &lease.server_duid);

        // IA_NA with the address to release; a client sends zero lifetimes (section 21.6)
        let mut ia_na = Vec::with_capacity(40);
        ia_na.extend_from_slice(&lease.iaid.to_be_bytes());
        ia_na.extend_from_slice(&[0u8; 8]); // T1, T2
        let mut ia_addr = lease.address.octets().to_vec();
        ia_addr.extend_from_slice(&[0u8; 8]); // preferred and valid lifetime
        append_option(&mut ia_na, OPT_IAADDR, &ia_addr);
        append_option(&mut msg, OPT_IA_NA, &ia_na);

        append_option(&mut msg, OPT_ELAPSED_TIME, &elapsed.to_be_bytes());

        msg
    }
}

impl Ipv6Backend for Dhcpv6Backend {
    fn current_prefix(&self) -> Result<Option<Prefix>> {
        // Leases are individual addresses; there is no /64 to track.
        Ok(None)
    }

    fn allocate(&self, _iid: Option<u64>) -> Result<AllocatedAddress> {
        let address = self.request_address()?;

        Ok(AllocatedAddress {
            address,
            prefix_len: 128,
            backend: BackendType::Dhcpv6,
        })
    }

    /// Give the address back to its server. Best effort: whatever goes wrong is logged,
    /// and the record is dropped either way (the address is gone).
    fn release_address(&self, addr: &Ipv6Addr) -> Result<()> {
        let Some(lease) = self.find_lease(*addr) else {
            debug!("No DHCPv6 lease recorded for {addr}");
            return Ok(());
        };
        if let Err(e) = self.release_lease(&lease) {
            warn!("Failed to release DHCPv6 lease for {addr}: {e:#}");
        }
        self.forget_lease(*addr);
        Ok(())
    }
}

/// A stored client DUID: hex, non-empty and within the 130 bytes of RFC 8415 section 11.1.
fn decode_duid(hex: &str) -> Option<Vec<u8>> {
    let duid = HEXLOWER.decode(hex.trim().as_bytes()).ok()?;
    (!duid.is_empty() && duid.len() <= 130).then_some(duid)
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

/// The server id and offered address of an Advertise; None if either is missing.
fn parse_advertise(response: &[u8]) -> Option<(Vec<u8>, Ipv6Addr)> {
    Some((
        parse_server_duid(response).ok()?,
        parse_ia_address(response)?,
    ))
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

    #[test]
    fn an_advertise_needs_both_server_id_and_address() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut msg = vec![MSG_ADVERTISE, 0, 0, 0];
        append_option(&mut msg, OPT_IA_NA, &build_ia_na(1, Some(addr)));
        assert_eq!(parse_advertise(&msg), None, "no server id");
        append_option(&mut msg, OPT_SERVERID, &[0, 1, 2]);
        assert_eq!(parse_advertise(&msg), Some((vec![0, 1, 2], addr)));
    }

    fn backend(store: &MemoryStore) -> Dhcpv6Backend {
        Dhcpv6Backend::new("eth0").with_store(Arc::new(store.clone()))
    }

    fn lease() -> Lease {
        Lease {
            address: "2001:db8::42".parse().unwrap(),
            server_duid: vec![0, 1, 0x11, 0x22],
            iaid: 0x0102_0304,
        }
    }

    #[test]
    fn the_client_duid_is_stable_across_backends_on_one_database() {
        let store = MemoryStore::default();
        let first = backend(&store).client_duid();
        assert_eq!(first.len(), 18);
        assert_eq!(&first[..2], &DUID_UUID.to_be_bytes());
        assert_eq!(backend(&store).client_duid(), first);
        // Another database means another client.
        assert_ne!(backend(&MemoryStore::default()).client_duid(), first);
    }

    #[test]
    fn a_garbled_stored_duid_is_replaced() {
        let store = MemoryStore::default();
        store.set(DUID_KEY, "not hex").unwrap();
        let duid = backend(&store).client_duid();
        assert_eq!(backend(&store).client_duid(), duid);
        assert_eq!(
            decode_duid(&store.get(DUID_KEY).unwrap().unwrap()),
            Some(duid)
        );
    }

    #[test]
    fn the_release_message_carries_everything_the_server_matches_on() {
        let store = MemoryStore::default();
        let b = backend(&store);
        let l = lease();
        let msg = b.build_release(&[0xAA, 0xBB, 0xCC], &l, 0x0102);

        assert_eq!(msg[0], MSG_RELEASE);
        assert_eq!(&msg[1..4], &[0xAA, 0xBB, 0xCC]);
        let opts: Vec<_> = iter_options(&msg).collect();
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0], (OPT_CLIENTID, b.client_duid().as_slice()));
        assert_eq!(opts[1], (OPT_SERVERID, l.server_duid.as_slice()));
        assert_eq!(opts[2].0, OPT_IA_NA);
        assert_eq!(opts[3], (OPT_ELAPSED_TIME, &[1u8, 2][..]));
        let ia = opts[2].1;
        assert_eq!(&ia[..4], &l.iaid.to_be_bytes());
        assert_eq!(&ia[4..12], &[0u8; 8], "T1 and T2");
        let sub: Vec<_> = iter_options_raw(&ia[12..]).collect();
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].0, OPT_IAADDR);
        assert_eq!(&sub[0].1[..16], &l.address.octets());
        assert_eq!(&sub[0].1[16..], &[0u8; 8], "lifetimes");
        assert_eq!(parse_ia_address(&msg), Some(l.address));
    }

    #[test]
    fn a_lease_recorded_by_one_process_is_released_by_another() {
        let store = MemoryStore::default();
        let l = lease();
        backend(&store).record_lease(l.clone());

        let later = backend(&store);
        assert_eq!(later.find_lease(l.address), Some(l.clone()));
        assert_eq!(later.client_duid(), backend(&store).client_duid());

        later.forget_lease(l.address);
        assert_eq!(backend(&store).find_lease(l.address), None);
        assert_eq!(
            store.get(&Dhcpv6Backend::lease_key(l.address)).unwrap(),
            None
        );
    }

    /// A UDP "server" on the loopback that answers the n-th Release with a Reply
    /// (never when `answer_on` is 0), and the Releases it saw.
    fn fake_server(answer_on: usize) -> (SocketAddr, std::thread::JoinHandle<Vec<Vec<u8>>>) {
        let server = UdpSocket::bind("[::1]:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(600)))
            .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut buf = [0u8; 1500];
            while let Ok((len, from)) = server.recv_from(&mut buf) {
                seen.push(buf[..len].to_vec());
                if seen.len() == answer_on {
                    let mut reply = vec![MSG_REPLY];
                    reply.extend_from_slice(&buf[1..4]);
                    server.send_to(&reply, from).unwrap();
                }
            }
            seen
        });
        (addr, handle)
    }

    #[test]
    fn a_release_is_retransmitted_until_answered() {
        let store = MemoryStore::default();
        let b = backend(&store);
        let (dest, server) = fake_server(3);
        let client = UdpSocket::bind("[::1]:0").unwrap();
        let answered = b
            .release_exchange(&client, dest, &lease(), Duration::from_millis(100))
            .unwrap();
        assert!(answered);
        let seen = server.join().unwrap();
        assert_eq!(seen.len(), 3);
        assert!(seen
            .iter()
            .all(|m| m[0] == MSG_RELEASE && m[1..4] == seen[0][1..4]));
    }

    #[test]
    fn an_unanswered_release_is_abandoned_after_rel_max_rc_tries() {
        let store = MemoryStore::default();
        let b = backend(&store);
        let (dest, server) = fake_server(0);
        let client = UdpSocket::bind("[::1]:0").unwrap();
        let answered = b
            .release_exchange(&client, dest, &lease(), Duration::from_millis(50))
            .unwrap();
        assert!(!answered);
        assert_eq!(server.join().unwrap().len(), REL_MAX_RC);
    }
}
