use super::SocketMonitor;
use anyhow::Result;
use socketguard_core::{normalize_exe_path, ListeningSocket, Platform, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

pub struct WindowsSocketMonitor;

/// Set once the first unattributable socket was logged.
static LOGGED_UNATTRIBUTABLE: AtomicBool = AtomicBool::new(false);

impl SocketMonitor for WindowsSocketMonitor {
    fn list_listening_sockets(&self) -> Result<Vec<ListeningSocket>> {
        let mut sockets = Vec::new();
        sockets.extend(list_tcp4_listeners()?);
        sockets.extend(list_tcp6_listeners()?);
        sockets.extend(list_udp4_listeners()?);
        sockets.extend(list_udp6_listeners()?);

        tracing::debug!("native API detected {} raw sockets", sockets.len());

        // Collect unique PIDs and resolve process info in batch
        let unique_pids: Vec<u32> = sockets
            .iter()
            .map(|s| s.pid)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let process_map = resolve_processes(&unique_pids);
        let details = super::procinfo::lookup(&unique_pids);

        // Fill in process info
        for socket in &mut sockets {
            if let Some(info) = process_map.get(&socket.pid) {
                socket.process_name = info.name.clone();
                // Paths are case-insensitive: one spelling per app identity.
                socket.exe_path = info
                    .exe_path
                    .as_deref()
                    .map(|p| normalize_exe_path(p, Platform::Windows));
            }
            if let Some(d) = details.get(&socket.pid) {
                socket.cmdline = d.cmdline.clone();
                socket.uid = d.uid.clone();
                if socket.exe_path.is_none() {
                    socket.exe_path = d
                        .exe_path
                        .as_deref()
                        .map(|p| normalize_exe_path(p, Platform::Windows));
                }
            }
            if socket.process_name == "unknown" {
                if let Some(name) = socket
                    .exe_path
                    .as_deref()
                    .map(|p| p.rsplit('\\').next().unwrap_or(p))
                {
                    socket.process_name = name.to_string();
                }
            }
        }

        // A socket whose owner cannot be told gets no app and no addresses: merging all of
        // them into one "unknown" app would let any of them inherit the others' grants.
        let before = sockets.len();
        sockets.retain(|s| s.pid != 0 && s.process_name != "unknown");
        if sockets.len() != before && !LOGGED_UNATTRIBUTABLE.swap(true, Ordering::Relaxed) {
            tracing::debug!(
                "Skipping {} sockets with no attributable process (further ones are not logged)",
                before - sockets.len()
            );
        }

        Ok(sockets)
    }
}

fn list_tcp4_listeners() -> Result<Vec<ListeningSocket>> {
    unsafe {
        let mut size: u32 = 0;
        // First call to get required buffer size
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );

        if ret != 0 {
            anyhow::bail!("GetExtendedTcpTable (TCP4) failed with error {ret}");
        }

        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);

        let mut sockets = Vec::with_capacity(count);
        for row in rows {
            let port = u16::from_be(row.dwLocalPort as u16);
            let ip_bytes = row.dwLocalAddr.to_ne_bytes();
            let addr = IpAddr::V4(std::net::Ipv4Addr::new(
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            ));
            sockets.push(ListeningSocket {
                pid: row.dwOwningPid,
                process_name: "unknown".to_string(),
                port,
                protocol: Protocol::Tcp,
                bind_address: addr,
                exe_path: None,
                cmdline: None,
                uid: None,
                foreign_mntns: false,
            });
        }

        Ok(sockets)
    }
}

fn list_tcp6_listeners() -> Result<Vec<ListeningSocket>> {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );

        if ret != 0 {
            anyhow::bail!("GetExtendedTcpTable (TCP6) failed with error {ret}");
        }

        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);

        let mut sockets = Vec::with_capacity(count);
        for row in rows {
            let port = u16::from_be(row.dwLocalPort as u16);
            let addr = IpAddr::V6(std::net::Ipv6Addr::from(row.ucLocalAddr));
            sockets.push(ListeningSocket {
                pid: row.dwOwningPid,
                process_name: "unknown".to_string(),
                port,
                protocol: Protocol::Tcp,
                bind_address: addr,
                exe_path: None,
                cmdline: None,
                uid: None,
                foreign_mntns: false,
            });
        }

        Ok(sockets)
    }
}

fn list_udp4_listeners() -> Result<Vec<ListeningSocket>> {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != 0 {
            anyhow::bail!("GetExtendedUdpTable (UDP4) failed with error {ret}");
        }

        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);

        let mut sockets = Vec::with_capacity(count);
        for row in rows {
            let port = u16::from_be(row.dwLocalPort as u16);
            let ip_bytes = row.dwLocalAddr.to_ne_bytes();
            let addr = IpAddr::V4(std::net::Ipv4Addr::new(
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            ));
            sockets.push(ListeningSocket {
                pid: row.dwOwningPid,
                process_name: "unknown".to_string(),
                port,
                protocol: Protocol::Udp,
                bind_address: addr,
                exe_path: None,
                cmdline: None,
                uid: None,
                foreign_mntns: false,
            });
        }

        Ok(sockets)
    }
}

fn list_udp6_listeners() -> Result<Vec<ListeningSocket>> {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != 0 {
            anyhow::bail!("GetExtendedUdpTable (UDP6) failed with error {ret}");
        }

        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);

        let mut sockets = Vec::with_capacity(count);
        for row in rows {
            let port = u16::from_be(row.dwLocalPort as u16);
            let addr = IpAddr::V6(std::net::Ipv6Addr::from(row.ucLocalAddr));
            sockets.push(ListeningSocket {
                pid: row.dwOwningPid,
                process_name: "unknown".to_string(),
                port,
                protocol: Protocol::Udp,
                bind_address: addr,
                exe_path: None,
                cmdline: None,
                uid: None,
                foreign_mntns: false,
            });
        }

        Ok(sockets)
    }
}

struct ProcessInfo {
    name: String,
    exe_path: Option<String>,
}

/// Resolve process names and exe paths for a set of PIDs using native Windows APIs.
/// Falls back to tasklist if the native API fails.
fn resolve_processes(pids: &[u32]) -> HashMap<u32, ProcessInfo> {
    let mut map = HashMap::new();

    for &pid in pids {
        if pid == 0 {
            map.insert(
                pid,
                ProcessInfo {
                    name: "System Idle".to_string(),
                    exe_path: None,
                },
            );
            continue;
        }
        if pid == 4 {
            map.insert(
                pid,
                ProcessInfo {
                    name: "System".to_string(),
                    exe_path: None,
                },
            );
            continue;
        }

        if let Some(exe_path) = query_process_image_name(pid) {
            let name = std::path::Path::new(&exe_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            map.insert(
                pid,
                ProcessInfo {
                    name,
                    exe_path: Some(exe_path),
                },
            );
        } else {
            // Fallback: process may be protected/system, try to get at least a name
            map.insert(
                pid,
                ProcessInfo {
                    name: "unknown".to_string(),
                    exe_path: None,
                },
            );
        }
    }

    // For any PIDs we couldn't resolve, try tasklist as batch fallback
    let unresolved: Vec<u32> = pids
        .iter()
        .filter(|pid| map.get(pid).is_none_or(|info| info.name == "unknown"))
        .copied()
        .collect();

    if !unresolved.is_empty() {
        if let Ok(output) = std::process::Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let fields: Vec<&str> = line.split(',').collect();
                if fields.len() >= 2 {
                    let name = fields[0].trim_matches('"').to_string();
                    if let Ok(pid) = fields[1].trim_matches('"').parse::<u32>() {
                        if unresolved.contains(&pid) {
                            if let Some(info) = map.get_mut(&pid) {
                                info.name = name;
                            }
                        }
                    }
                }
            }
        }
    }

    map
}

/// Use Windows API QueryFullProcessImageNameW to get the exe path for a PID.
/// Returns None if the process can't be opened (access denied, exited, etc).
fn query_process_image_name(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;

        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut size,
        );

        let _ = CloseHandle(handle);

        result.ok()?;

        Some(String::from_utf16_lossy(&buf[..size as usize]))
    }
}
