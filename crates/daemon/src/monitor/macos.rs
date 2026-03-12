use super::SocketMonitor;
use anyhow::Result;
use socketguard_core::{ListeningSocket, Protocol};
use std::net::IpAddr;

pub struct MacosSocketMonitor;

impl SocketMonitor for MacosSocketMonitor {
    fn list_listening_sockets(&self) -> Result<Vec<ListeningSocket>> {
        let mut sockets = Vec::new();

        // TCP listeners
        let output = std::process::Command::new("lsof")
            .args(["-iTCP", "-sTCP:LISTEN", "-nP", "-F", "pcnT"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_lsof_output(&stdout, Protocol::Tcp, &mut sockets);

        // UDP listeners
        let output = std::process::Command::new("lsof")
            .args(["-iUDP", "-nP", "-F", "pcnT"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_lsof_output(&stdout, Protocol::Udp, &mut sockets);

        Ok(sockets)
    }
}

fn parse_lsof_output(stdout: &str, protocol: Protocol, sockets: &mut Vec<ListeningSocket>) {
    let mut current_pid: u32 = 0;
    let mut current_name = String::new();

    for line in stdout.lines() {
        if let Some(pid_str) = line.strip_prefix('p') {
            current_pid = pid_str.parse().unwrap_or(0);
        } else if let Some(name) = line.strip_prefix('c') {
            current_name = name.to_string();
        } else if let Some(name_field) = line.strip_prefix('n') {
            if let Some(socket) = parse_lsof_name(name_field, current_pid, &current_name, protocol)
            {
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

    Some(ListeningSocket {
        pid,
        process_name: process_name.to_string(),
        port,
        protocol,
        bind_address,
        exe_path: None, // TODO: resolve via proc_pidpath
        cmdline: None,
    })
}
