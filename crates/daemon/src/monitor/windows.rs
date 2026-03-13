use super::SocketMonitor;
use anyhow::Result;
use socketguard_core::{ListeningSocket, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;

pub struct WindowsSocketMonitor;

impl SocketMonitor for WindowsSocketMonitor {
    fn list_listening_sockets(&self) -> Result<Vec<ListeningSocket>> {
        let mut sockets = Vec::new();

        // Single netstat call for all protocols — much faster than 4 separate calls
        let output = std::process::Command::new("netstat")
            .args(["-ano"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.contains("LISTENING") {
                // TCP/TCPv6
                if let Some(socket) = parse_netstat_line(line, Protocol::Tcp) {
                    sockets.push(socket);
                }
            } else if line.starts_with("UDP") && line.contains("*:*") {
                // UDP/UDPv6 (no "LISTENING" state for UDP in netstat)
                if let Some(socket) = parse_netstat_line(line, Protocol::Udp) {
                    sockets.push(socket);
                }
            }
        }

        tracing::debug!("netstat detected {} raw sockets", sockets.len());

        // Collect unique PIDs and resolve process info in batch
        let unique_pids: Vec<u32> = sockets
            .iter()
            .map(|s| s.pid)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let process_map = resolve_processes(&unique_pids);

        // Fill in process info
        for socket in &mut sockets {
            if let Some(info) = process_map.get(&socket.pid) {
                socket.process_name = info.name.clone();
                socket.exe_path = info.exe_path.clone();
            }
        }

        Ok(sockets)
    }
}

fn parse_netstat_line(line: &str, protocol: Protocol) -> Option<ListeningSocket> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }

    let local_addr = fields[1];
    let pid_str = fields.last()?;
    let pid: u32 = pid_str.parse().ok()?;

    let (addr_str, port_str) = if local_addr.contains("]:") {
        let idx = local_addr.rfind("]:")?;
        (&local_addr[1..idx], &local_addr[idx + 2..])
    } else {
        let idx = local_addr.rfind(':')?;
        (&local_addr[..idx], &local_addr[idx + 1..])
    };

    let port: u16 = port_str.parse().ok()?;
    let bind_address: IpAddr = addr_str.parse().ok()?;

    Some(ListeningSocket {
        pid,
        process_name: "unknown".to_string(), // filled in later from process_map
        port,
        protocol,
        bind_address,
        exe_path: None,
        cmdline: None,
    })
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
            map.insert(pid, ProcessInfo { name: "System Idle".to_string(), exe_path: None });
            continue;
        }
        if pid == 4 {
            map.insert(pid, ProcessInfo { name: "System".to_string(), exe_path: None });
            continue;
        }

        if let Some(exe_path) = query_process_image_name(pid) {
            let name = std::path::Path::new(&exe_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            map.insert(pid, ProcessInfo { name, exe_path: Some(exe_path) });
        } else {
            // Fallback: process may be protected/system, try to get at least a name
            map.insert(pid, ProcessInfo { name: "unknown".to_string(), exe_path: None });
        }
    }

    // For any PIDs we couldn't resolve, try tasklist as batch fallback
    let unresolved: Vec<u32> = pids.iter()
        .filter(|pid| map.get(pid).map_or(true, |info| info.name == "unknown"))
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
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_NAME_WIN32,
    };
    use windows::Win32::Foundation::CloseHandle;

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
