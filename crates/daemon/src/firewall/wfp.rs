use super::Firewall;
use anyhow::{Context, Result};
use socketguard_core::Protocol;
use std::net::Ipv6Addr;
use std::process::Command;

pub struct WfpFirewall;

impl WfpFirewall {
    pub fn new() -> Self {
        Self
    }

    fn rule_name(dest_ip: &Ipv6Addr, dest_port: u16, protocol: &Protocol) -> String {
        format!("SocketGuard_{protocol}_{dest_ip}_{dest_port}")
    }

    fn allow_rule_name(
        dest_ip: &Ipv6Addr,
        dest_port: u16,
        protocol: &Protocol,
        src_ip: &Ipv6Addr,
    ) -> String {
        let src_str = src_ip.to_string().replace(':', "-");
        format!("SocketGuard_Allow_{protocol}_{dest_ip}_{dest_port}_{src_str}")
    }
}

impl Firewall for WfpFirewall {
    fn apply_acl(
        &self,
        dest_ip: Ipv6Addr,
        dest_port: u16,
        protocol: Protocol,
        allowed: &[Ipv6Addr],
    ) -> Result<()> {
        self.remove_acl(dest_ip, dest_port, protocol)?;

        let block_name = Self::rule_name(&dest_ip, dest_port, &protocol);
        let proto = protocol.to_string();

        if allowed.is_empty() {
            Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={block_name}"),
                    "dir=in",
                    "action=block",
                    &format!("protocol={proto}"),
                    &format!("localip={dest_ip}"),
                    &format!("localport={dest_port}"),
                ])
                .output()
                .context("failed to add block rule")?;
        } else {
            for src_ip in allowed {
                let allow_name = Self::allow_rule_name(&dest_ip, dest_port, &protocol, src_ip);
                Command::new("netsh")
                    .args([
                        "advfirewall", "firewall", "add", "rule",
                        &format!("name={allow_name}"),
                        "dir=in",
                        "action=allow",
                        &format!("protocol={proto}"),
                        &format!("remoteip={src_ip}"),
                        &format!("localip={dest_ip}"),
                        &format!("localport={dest_port}"),
                    ])
                    .output()
                    .context("failed to add allow rule")?;
            }

            Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={block_name}"),
                    "dir=in",
                    "action=block",
                    &format!("protocol={proto}"),
                    &format!("localip={dest_ip}"),
                    &format!("localport={dest_port}"),
                ])
                .output()
                .context("failed to add block rule")?;
        }

        Ok(())
    }

    fn remove_acl(&self, dest_ip: Ipv6Addr, dest_port: u16, protocol: Protocol) -> Result<()> {
        let block_name = Self::rule_name(&dest_ip, dest_port, &protocol);

        let _ = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "delete", "rule",
                &format!("name={block_name}"),
            ])
            .output();

        let output = Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", "name=all", "dir=in"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let prefix = format!("SocketGuard_Allow_{protocol}_{dest_ip}_{dest_port}_");

        for line in stdout.lines() {
            if let Some(name) = line.strip_prefix("Rule Name:") {
                let name = name.trim();
                if name.starts_with(&prefix) {
                    let _ = Command::new("netsh")
                        .args([
                            "advfirewall", "firewall", "delete", "rule",
                            &format!("name={name}"),
                        ])
                        .output();
                }
            }
        }

        Ok(())
    }
}
