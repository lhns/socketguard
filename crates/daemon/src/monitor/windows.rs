use super::SocketMonitor;
use anyhow::Result;
use socketguard_core::{normalize_exe_path, ListeningSocket, Platform, Protocol};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
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
        sockets.extend(tcp4_listeners()?);
        sockets.extend(tcp6_listeners()?);
        sockets.extend(udp4_listeners()?);
        sockets.extend(udp6_listeners()?);

        tracing::debug!("native API detected {} raw sockets", sockets.len());

        // Resolve the processes in batch: names and paths from the native API first,
        // then command lines and owners (and paths the native API could not read).
        let unique_pids: Vec<u32> = sockets
            .iter()
            .map(|s| s.pid)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let process_map = resolve_processes(&unique_pids);
        for socket in &mut sockets {
            if let Some(info) = process_map.get(&socket.pid) {
                socket.process_name = info.name.clone();
                socket.exe_path = info.exe_path.clone();
            }
        }
        super::procinfo::apply(&mut sockets, false);

        for socket in &mut sockets {
            // Paths are case-insensitive: one spelling per app identity.
            socket.exe_path = socket
                .exe_path
                .as_deref()
                .map(|p| normalize_exe_path(p, Platform::Windows));
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

/// The table that `get` fills. A table can grow between the size query and the fetch
/// (ERROR_INSUFFICIENT_BUFFER), so ask again a few times. The buffer is u64-aligned for
/// the table structs.
fn fetch_table(what: &str, get: impl Fn(Option<*mut c_void>, &mut u32) -> u32) -> Result<Vec<u64>> {
    let mut size = 0u32;
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let ptr = (size > 0).then(|| buf.as_mut_ptr() as *mut c_void);
        match get(ptr, &mut size) {
            0 => return Ok(buf),
            code if code == ERROR_INSUFFICIENT_BUFFER.0 => continue,
            code => anyhow::bail!("{what} failed with error {code}"),
        }
    }
    anyhow::bail!("{what}: the table kept growing")
}

/// The rows of a fetched `MIB_*TABLE_OWNER_PID` buffer.
///
/// # Safety
/// `buf` must come from `fetch_table` for the table type `T`.
unsafe fn table_rows<T, R>(buf: &[u64], rows: impl Fn(&T) -> (*const R, u32)) -> &[R] {
    if buf.is_empty() {
        return &[];
    }
    let (first, count) = rows(&*(buf.as_ptr() as *const T));
    std::slice::from_raw_parts(first, count as usize)
}

fn port_of(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

fn tcp4_listeners() -> Result<Vec<ListeningSocket>> {
    let buf = fetch_table("GetExtendedTcpTable (TCP4)", |p, size| unsafe {
        GetExtendedTcpTable(
            p,
            size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    })?;
    let rows = unsafe {
        table_rows(&buf, |t: &MIB_TCPTABLE_OWNER_PID| {
            (t.table.as_ptr(), t.dwNumEntries)
        })
    };
    Ok(rows
        .iter()
        .map(|r| {
            let addr = Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes());
            unknown(
                r.dwOwningPid,
                port_of(r.dwLocalPort),
                Protocol::Tcp,
                addr.into(),
            )
        })
        .collect())
}

fn tcp6_listeners() -> Result<Vec<ListeningSocket>> {
    let buf = fetch_table("GetExtendedTcpTable (TCP6)", |p, size| unsafe {
        GetExtendedTcpTable(
            p,
            size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    })?;
    let rows = unsafe {
        table_rows(&buf, |t: &MIB_TCP6TABLE_OWNER_PID| {
            (t.table.as_ptr(), t.dwNumEntries)
        })
    };
    Ok(rows
        .iter()
        .map(|r| {
            let addr = Ipv6Addr::from(r.ucLocalAddr);
            unknown(
                r.dwOwningPid,
                port_of(r.dwLocalPort),
                Protocol::Tcp,
                addr.into(),
            )
        })
        .collect())
}

fn udp4_listeners() -> Result<Vec<ListeningSocket>> {
    let buf = fetch_table("GetExtendedUdpTable (UDP4)", |p, size| unsafe {
        GetExtendedUdpTable(p, size, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    let rows = unsafe {
        table_rows(&buf, |t: &MIB_UDPTABLE_OWNER_PID| {
            (t.table.as_ptr(), t.dwNumEntries)
        })
    };
    Ok(rows
        .iter()
        .map(|r| {
            let addr = Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes());
            unknown(
                r.dwOwningPid,
                port_of(r.dwLocalPort),
                Protocol::Udp,
                addr.into(),
            )
        })
        .collect())
}

fn udp6_listeners() -> Result<Vec<ListeningSocket>> {
    let buf = fetch_table("GetExtendedUdpTable (UDP6)", |p, size| unsafe {
        GetExtendedUdpTable(p, size, false, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    let rows = unsafe {
        table_rows(&buf, |t: &MIB_UDP6TABLE_OWNER_PID| {
            (t.table.as_ptr(), t.dwNumEntries)
        })
    };
    Ok(rows
        .iter()
        .map(|r| {
            let addr = Ipv6Addr::from(r.ucLocalAddr);
            unknown(
                r.dwOwningPid,
                port_of(r.dwLocalPort),
                Protocol::Udp,
                addr.into(),
            )
        })
        .collect())
}

/// A socket whose process is not resolved yet.
fn unknown(pid: u32, port: u16, protocol: Protocol, bind: IpAddr) -> ListeningSocket {
    ListeningSocket::new(pid, port, protocol, bind).with_process_name("unknown")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_our_own_listeners_with_their_process() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = std::net::UdpSocket::bind("[::1]:0").unwrap();
        let (tcp_port, udp_port) = (
            tcp.local_addr().unwrap().port(),
            udp.local_addr().unwrap().port(),
        );
        let socks = WindowsSocketMonitor.list_listening_sockets().unwrap();
        let find = |port, proto| {
            socks
                .iter()
                .find(|s| s.port == port && s.protocol == proto)
                .unwrap_or_else(|| panic!("no socket on {port}"))
        };
        let (t, u) = (find(tcp_port, Protocol::Tcp), find(udp_port, Protocol::Udp));
        assert_eq!(t.pid, std::process::id());
        assert_eq!(u.pid, std::process::id());
        assert!(t.bind_address.is_ipv4() && u.bind_address.is_ipv6());
        assert!(t.exe_path.is_some() && t.cmdline.is_some());
    }
}
