use super::SocketMonitor;
use anyhow::Result;
use socketguard_core::{ListeningSocket, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;

pub struct MacosSocketMonitor;

impl SocketMonitor for MacosSocketMonitor {
    fn list_listening_sockets(&self) -> Result<Vec<ListeningSocket>> {
        // Build PID→exe_path map once per poll cycle
        let exe_map = build_exe_map();

        let mut sockets = Vec::new();

        // TCP listeners
        let output = std::process::Command::new("lsof")
            .args(["-iTCP", "-sTCP:LISTEN", "-nP", "-F", "pcnT"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_lsof_output(&stdout, Protocol::Tcp, &exe_map, &mut sockets);

        // UDP listeners
        let output = std::process::Command::new("lsof")
            .args(["-iUDP", "-nP", "-F", "pcnT"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_lsof_output(&stdout, Protocol::Udp, &exe_map, &mut sockets);

        // Command lines (and a better executable path) from sysinfo.
        super::procinfo::apply(&mut sockets, true);

        Ok(sockets)
    }
}

fn parse_lsof_output(
    stdout: &str,
    protocol: Protocol,
    exe_map: &HashMap<u32, String>,
    sockets: &mut Vec<ListeningSocket>,
) {
    let mut current_pid: u32 = 0;
    let mut current_name = String::new();

    for line in stdout.lines() {
        if let Some(pid_str) = line.strip_prefix('p') {
            current_pid = pid_str.parse().unwrap_or(0);
        } else if let Some(name) = line.strip_prefix('c') {
            current_name = name.to_string();
        } else if let Some(name_field) = line.strip_prefix('n') {
            if let Some(mut socket) =
                parse_lsof_name(name_field, current_pid, &current_name, protocol)
            {
                socket.exe_path = exe_map.get(&current_pid).cloned();
                sockets.push(socket);
            }
        }
    }
}

fn parse_lsof_name(
    name: &str,
    pid: u32,
    process_name: &str,
    protocol: Protocol,
) -> Option<ListeningSocket> {
    let (addr_str, port_str) = if name.contains("]:") {
        let idx = name.rfind("]:")?;
        (&name[1..idx], &name[idx + 2..])
    } else {
        let idx = name.rfind(':')?;
        (&name[..idx], &name[idx + 1..])
    };

    let port: u16 = port_str.parse().ok()?;

    let bind_address: IpAddr = if addr_str == "*" {
        "0.0.0.0".parse().unwrap()
    } else {
        addr_str.parse().ok()?
    };

    // exe_path comes from the caller's exe_map, the rest from sysinfo.
    Some(ListeningSocket::new(pid, port, protocol, bind_address).with_process_name(process_name))
}

/// Build a PID→exe_path map using `ps` (single call for all processes).
fn build_exe_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();

    if let Ok(output) = std::process::Command::new("ps")
        .args(["-axo", "pid=,comm="])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if let Some((pid_str, path)) = line.split_once(char::is_whitespace) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    let path = path.trim();
                    if !path.is_empty() {
                        map.insert(pid, path.to_string());
                    }
                }
            }
        }
    }

    map
}
