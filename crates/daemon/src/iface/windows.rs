use super::{InterfaceInfo, InterfaceManager};
use anyhow::Result;
use ipnet::Ipv4Net;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry,
    FreeMibTable, GetAdaptersAddresses, GetUnicastIpAddressTable, InitializeUnicastIpAddressEntry,
    GAA_FLAG_SKIP_ANYCAST, IP_ADAPTER_ADDRESSES_LH, MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    IpDadStatePreferred, AF_INET, AF_INET6, SOCKADDR_IN6, SOCKADDR_INET,
};

pub struct WindowsInterfaces;

/// The LUID of the interface with this display name (alias), if there is one.
pub(crate) fn alias_to_luid(alias: &str) -> Option<NET_LUID_LH> {
    let wide: Vec<u16> = alias.encode_utf16().chain(Some(0)).collect();
    let mut luid = NET_LUID_LH::default();
    let rc = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &mut luid) };
    (rc.0 == 0).then_some(luid)
}

fn get_interface_luid(iface: &str) -> Result<NET_LUID_LH> {
    alias_to_luid(iface).ok_or_else(|| anyhow::anyhow!("network interface {iface:?} not found"))
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

/// Call `visit` on every IPv6-capable adapter. The adapter list can grow between the size
/// query and the fetch (ERROR_BUFFER_OVERFLOW), so retry a few times.
fn for_each_adapter(mut visit: impl FnMut(&IP_ADAPTER_ADDRESSES_LH)) -> Result<()> {
    let family = AF_INET6.0 as u32;
    let mut size = 0u32;
    for _ in 0..4 {
        // u64 elements keep the buffer aligned for the adapter structs.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let first = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let ptr = (size > 0).then_some(first);
        let ret =
            unsafe { GetAdaptersAddresses(family, GAA_FLAG_SKIP_ANYCAST, None, ptr, &mut size) };
        if ret == ERROR_BUFFER_OVERFLOW.0 {
            continue; // `size` now holds the required length
        }
        if ret != 0 {
            anyhow::bail!("GetAdaptersAddresses failed with error {ret}");
        }
        let mut current = first;
        while !current.is_null() {
            let adapter = unsafe { &*current };
            visit(adapter);
            current = adapter.Next;
        }
        return Ok(());
    }
    anyhow::bail!("GetAdaptersAddresses: the adapter list kept growing")
}

/// All network interface friendly names, sorted.
fn enumerate_interface_names() -> Result<Vec<String>> {
    let mut names = Vec::new();
    for_each_adapter(|adapter| {
        let name = unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default();
        if !name.is_empty() {
            names.push(name);
        }
    })?;
    names.sort();
    Ok(names)
}

impl InterfaceManager for WindowsInterfaces {
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

    fn remove_address(&self, iface: &str, addr: Ipv6Addr, _prefix: u8) -> Result<()> {
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

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        // Windows has no generic API for VLAN ids; adapters show as plain interfaces.
        Ok(enumerate_interface_names()?
            .into_iter()
            .map(|name| InterfaceInfo {
                name,
                vlan_id: None,
            })
            .collect())
    }

    fn list_ipv4_subnets(&self, iface: &str) -> Result<Vec<Ipv4Net>> {
        let luid = get_interface_luid(iface)?;

        let mut table_ptr = std::ptr::null_mut();
        let ret = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table_ptr) };
        if !ret.is_ok() {
            anyhow::bail!("GetUnicastIpAddressTable failed: {}", ret.0);
        }

        let table = unsafe { &*table_ptr };
        let entries =
            unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };
        let nets = entries
            .iter()
            .filter(|e| unsafe { e.InterfaceLuid.Value } == unsafe { luid.Value })
            .filter_map(|e| {
                // The address bytes are in network order in memory.
                let octets = unsafe { e.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes();
                Ipv4Net::new(Ipv4Addr::from(octets), e.OnLinkPrefixLength)
                    .ok()
                    .map(|n| n.trunc())
            })
            .collect();
        unsafe { FreeMibTable(table_ptr as *const _) };
        Ok(nets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_interfaces_resolve_to_a_luid() {
        let names = enumerate_interface_names().unwrap();
        assert!(!names.is_empty());
        // Every adapter can be asked for its IPv4 subnets.
        for n in &names {
            WindowsInterfaces.list_ipv4_subnets(n).unwrap();
        }
        for n in names {
            assert!(alias_to_luid(&n).is_some(), "{n}");
        }
        assert!(alias_to_luid("no such interface").is_none());
    }
}
