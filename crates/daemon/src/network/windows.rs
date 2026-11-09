use super::NetworkInterface;
use anyhow::Result;
use std::net::Ipv6Addr;
use windows::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, FreeMibTable,
    GetUnicastIpAddressTable, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    IpDadStatePreferred, AF_INET6, SOCKADDR_IN6, SOCKADDR_INET,
};

pub struct WindowsNetworkInterface;

/// Look up the NET_LUID for a network interface by its display name.
fn get_interface_luid(iface: &str) -> Result<NET_LUID_LH> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, IP_ADAPTER_ADDRESSES_LH,
    };

    let family = AF_INET6.0 as u32;
    let flags = GAA_FLAG_SKIP_ANYCAST;

    // First call to get required buffer size
    let mut size = 0u32;
    unsafe {
        let _ = GetAdaptersAddresses(family, flags, None, None, &mut size);
    }

    let mut buf = vec![0u8; size as usize];
    let adapter_ptr = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let ret = unsafe { GetAdaptersAddresses(family, flags, None, Some(adapter_ptr), &mut size) };
    if ret != 0 {
        anyhow::bail!("GetAdaptersAddresses failed with error {ret}");
    }

    let mut current = adapter_ptr;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let friendly_name = unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default();
        if friendly_name == iface {
            return Ok(adapter.Luid);
        }
        current = adapter.Next;
    }

    anyhow::bail!("network interface {iface:?} not found")
}

/// Build a SOCKADDR_INET from an Ipv6Addr.
fn sockaddr_from_ipv6(addr: Ipv6Addr) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.u.Byte = addr.octets();
    SOCKADDR_INET { Ipv6: sa }
}

/// Check a WIN32_ERROR return value, treating NO_ERROR as success.
fn check_win32(err: WIN32_ERROR, ignore: &[WIN32_ERROR]) -> Result<()> {
    if err.is_ok() || ignore.contains(&err) {
        Ok(())
    } else {
        anyhow::bail!("Windows API error: {}", err.0)
    }
}

/// List all network interface friendly names.
fn enumerate_interface_names() -> Result<Vec<String>> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, IP_ADAPTER_ADDRESSES_LH,
    };
    let family = AF_INET6.0 as u32;
    let flags = GAA_FLAG_SKIP_ANYCAST;

    let mut size = 0u32;
    unsafe {
        let _ = GetAdaptersAddresses(family, flags, None, None, &mut size);
    }

    let mut buf = vec![0u8; size as usize];
    let adapter_ptr = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let ret = unsafe { GetAdaptersAddresses(family, flags, None, Some(adapter_ptr), &mut size) };
    if ret != 0 {
        anyhow::bail!("GetAdaptersAddresses failed with error {ret}");
    }

    let mut names = Vec::new();
    let mut current = adapter_ptr;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let friendly_name = unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default();
        if !friendly_name.is_empty() {
            names.push(friendly_name);
        }
        current = adapter.Next;
    }

    names.sort();
    Ok(names)
}

impl NetworkInterface for WindowsNetworkInterface {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        let luid = get_interface_luid(iface)?;

        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid = luid;
        row.Address = sockaddr_from_ipv6(addr);
        row.OnLinkPrefixLength = prefix;
        // Skip duplicate address detection; our /128s are unique by construction.
        row.DadState = IpDadStatePreferred;

        let err = unsafe { CreateUnicastIpAddressEntry(&row) };
        check_win32(err, &[ERROR_OBJECT_ALREADY_EXISTS])
    }

    fn remove_address(&self, iface: &str, addr: Ipv6Addr) -> Result<()> {
        let target_octets = addr.octets();

        // Enumerate all unicast addresses and find matching entry
        let mut table_ptr = std::ptr::null_mut();
        let ret = unsafe { GetUnicastIpAddressTable(AF_INET6, &mut table_ptr) };
        if !ret.is_ok() {
            anyhow::bail!("GetUnicastIpAddressTable failed: {}", ret.0);
        }

        let table = unsafe { &*table_ptr };
        let entries =
            unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };

        let luid = get_interface_luid(iface)?;

        for entry in entries {
            if unsafe { entry.InterfaceLuid.Value } != unsafe { luid.Value } {
                continue;
            }
            let entry_octets = unsafe { entry.Address.Ipv6.sin6_addr.u.Byte };
            if entry_octets == target_octets {
                let del_result = unsafe { DeleteUnicastIpAddressEntry(entry) };
                unsafe { FreeMibTable(table_ptr as *const _) };
                return check_win32(del_result, &[ERROR_NOT_FOUND]);
            }
        }

        unsafe { FreeMibTable(table_ptr as *const _) };

        // Address not found — not an error (may have been removed already)
        Ok(())
    }

    fn list_addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>> {
        let luid = get_interface_luid(iface)?;

        let mut table_ptr = std::ptr::null_mut();
        let ret = unsafe { GetUnicastIpAddressTable(AF_INET6, &mut table_ptr) };
        if !ret.is_ok() {
            anyhow::bail!("GetUnicastIpAddressTable failed: {}", ret.0);
        }

        let table = unsafe { &*table_ptr };
        let entries =
            unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };
        let addrs = entries
            .iter()
            .filter(|e| unsafe { e.InterfaceLuid.Value } == unsafe { luid.Value })
            .map(|e| Ipv6Addr::from(unsafe { e.Address.Ipv6.sin6_addr.u.Byte }))
            .collect();
        unsafe { FreeMibTable(table_ptr as *const _) };
        Ok(addrs)
    }

    fn list_interfaces(&self) -> Result<Vec<String>> {
        enumerate_interface_names()
    }
}
