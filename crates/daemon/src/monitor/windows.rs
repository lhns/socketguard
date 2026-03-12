use super::SocketMonitor;
use anyhow::Result;
use socketguard_core::{ListeningSocket, Protocol};
use std::net::IpAddr;

pub struct WindowsSocketMonitor;

impl SocketMonitor for WindowsSocketMonitor {
    fn list_listening_sockets(&self) -> Result<Vec<ListeningSocket>> {
        let mut sockets = Vec::new();

        // TCP + TCPv6 listeners
        for proto_flag in ["TCPv6", "TCP"] {
            let output = std::process::Command::new("netstat")
                .args(["-ano", "-p", proto_flag])
                .output()?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if !line.contains("LISTENING") {
                    continue;
                }
                if let Some(socket) = parse_netstat_line(line, Protocol::Tcp) {
                    sockets.push(socket);
                }
            }
        }

        // UDP + UDPv6 listeners
        for proto_flag in ["UDPv6", "UDP"] {
            let output = std::process::Command::new("netstat")
                .args(["-ano", "-p", proto_flag])
                .output()?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                // UDP has no LISTENING state; look for *:* as foreign address
                if line.contains("*:*") {
                    if let Some(socket) = parse_netstat_line(line, Protocol::Udp) {
                        sockets.push(socket);
                    }
                }
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

    // TCP: Proto  Local Address  Foreign Address  State  PID
    // UDP: Proto  Local Address  Foreign Address  PID
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

    let info = get_process_info(pid);

    Some(ListeningSocket {
        pid,
        process_name: info.name,
        port,
        protocol,
        bind_address,
        exe_path: info.exe_path,
        cmdline: None, // not easily available on Windows without WMI
    })
}

struct ProcessInfo {
    name: String,
    exe_path: Option<String>,
}

/// Batch-friendly process info lookup. Uses tasklist /FI to avoid
/// spawning a process per socket in the common case.
fn get_process_info(pid: u32) -> ProcessInfo {
    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let name = stdout
                .lines()
                .next()
                .and_then(|line| line.split(',').next())
                .map(|name| name.trim_matches('"').to_string())
                .unwrap_or_else(|| "unknown".to_string());

            ProcessInfo {
                exe_path: None, // TODO: use WMI or QueryFullProcessImageName for exe path
                name,
            }
        }
        Err(_) => ProcessInfo {
            name: "unknown".to_string(),
            exe_path: None,
        },
    }
}
