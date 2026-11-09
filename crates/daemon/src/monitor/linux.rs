use super::SocketMonitor;
use anyhow::Result;
use socketguard_core::{ListeningSocket, Protocol};
use std::net::{IpAddr, Ipv6Addr};

pub struct LinuxSocketMonitor;

impl SocketMonitor for LinuxSocketMonitor {
    fn list_listening_sockets(&self) -> Result<Vec<ListeningSocket>> {
        let mut sockets = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp6") {
            for line in content.lines().skip(1) {
                if let Some(socket) = parse_proc_net_line(line, Protocol::Tcp) {
                    sockets.push(socket);
                }
            }
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            for line in content.lines().skip(1) {
                if let Some(socket) = parse_proc_net_line(line, Protocol::Tcp) {
                    sockets.push(socket);
                }
            }
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/udp6") {
            for line in content.lines().skip(1) {
                if let Some(socket) = parse_proc_net_line(line, Protocol::Udp) {
                    sockets.push(socket);
                }
            }
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/udp") {
            for line in content.lines().skip(1) {
                if let Some(socket) = parse_proc_net_line(line, Protocol::Udp) {
                    sockets.push(socket);
                }
            }
        }

        Ok(sockets)
    }
}

fn parse_proc_net_line(line: &str, protocol: Protocol) -> Option<ListeningSocket> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }

    // State: 0A = LISTEN for TCP; UDP sockets don't have a LISTEN state
    let state = fields[3];
    if protocol == Protocol::Tcp && state != "0A" {
        return None;
    }

    let local = fields[1];
    let (addr_hex, port_hex) = local.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    let bind_address = parse_hex_addr(addr_hex)?;

    let inode: u64 = fields[9].parse().ok()?;
    let proc_info = find_pid_by_inode(inode);

    Some(ListeningSocket {
        pid: proc_info.pid,
        process_name: proc_info.name,
        port,
        protocol,
        bind_address,
        exe_path: proc_info.exe_path,
        cmdline: proc_info.cmdline,
    })
}

fn parse_hex_addr(hex: &str) -> Option<IpAddr> {
    if hex.len() == 32 {
        let bytes: Vec<u8> = (0..32)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
            .collect();
        // /proc/net/tcp6 stores in host byte order per 32-bit word
        let mut addr_bytes = [0u8; 16];
        for group in 0..4 {
            let offset = group * 4;
            addr_bytes[offset] = bytes[offset + 3];
            addr_bytes[offset + 1] = bytes[offset + 2];
            addr_bytes[offset + 2] = bytes[offset + 1];
            addr_bytes[offset + 3] = bytes[offset];
        }
        Some(IpAddr::V6(Ipv6Addr::from(addr_bytes)))
    } else if hex.len() == 8 {
        let n = u32::from_str_radix(hex, 16).ok()?;
        let bytes = n.to_le_bytes();
        Some(IpAddr::from(bytes))
    } else {
        None
    }
}

struct ProcInfo {
    pid: u32,
    name: String,
    exe_path: Option<String>,
    cmdline: Option<String>,
}

fn find_pid_by_inode(inode: u64) -> ProcInfo {
    let target = format!("socket:[{inode}]");
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let pid_str = name.to_string_lossy();
            if let Ok(pid) = pid_str.parse::<u32>() {
                let fd_dir = format!("/proc/{pid}/fd");
                if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                    for fd in fds.flatten() {
                        if let Ok(link) = std::fs::read_link(fd.path()) {
                            if link.to_string_lossy() == target {
                                let process_name =
                                    std::fs::read_to_string(format!("/proc/{pid}/comm"))
                                        .unwrap_or_default()
                                        .trim()
                                        .to_string();

                                let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
                                    .ok()
                                    .map(|p| p.to_string_lossy().to_string());

                                let cmdline =
                                    std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                                        .ok()
                                        .map(|s| s.replace('\0', " ").trim().to_string())
                                        .filter(|s| !s.is_empty());

                                return ProcInfo {
                                    pid,
                                    name: process_name,
                                    exe_path,
                                    cmdline,
                                };
                            }
                        }
                    }
                }
            }
        }
    }
    ProcInfo {
        pid: 0,
        name: "unknown".to_string(),
        exe_path: None,
        cmdline: None,
    }
}
