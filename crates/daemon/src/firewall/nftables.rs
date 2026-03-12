use super::Firewall;
use anyhow::{Context, Result};
use socketguard_core::Protocol;
use std::net::Ipv6Addr;
use std::process::Command;

const TABLE_NAME: &str = "socketguard";
const CHAIN_NAME: &str = "input";

pub struct NftablesFirewall;

impl NftablesFirewall {
    pub fn new() -> Self {
        Self
    }

    fn ensure_table(&self) -> Result<()> {
        let commands = format!(
            "add table ip6 {TABLE_NAME}\nadd chain ip6 {TABLE_NAME} {CHAIN_NAME} {{ type filter hook input priority 0; policy accept; }}\n"
        );

        use std::io::Write;
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("failed to run nft")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(commands.as_bytes())?;
        }
        child.wait()?;

        Ok(())
    }

    fn rule_comment(dest_ip: &Ipv6Addr, dest_port: u16, protocol: &Protocol) -> String {
        format!("sg_{dest_ip}_{dest_port}_{protocol}")
    }
}

impl Firewall for NftablesFirewall {
    fn apply_acl(
        &self,
        dest_ip: Ipv6Addr,
        dest_port: u16,
        protocol: Protocol,
        allowed: &[Ipv6Addr],
    ) -> Result<()> {
        self.ensure_table()?;
        self.remove_acl(dest_ip, dest_port, protocol)?;

        let comment = Self::rule_comment(&dest_ip, dest_port, &protocol);
        let proto = protocol.to_string();

        if allowed.is_empty() {
            let rule = format!(
                "add rule ip6 {TABLE_NAME} {CHAIN_NAME} ip6 daddr {dest_ip} {proto} dport {dest_port} drop comment \"{comment}\""
            );
            Command::new("nft").arg(&rule).output()?;
        } else {
            for src_ip in allowed {
                let rule = format!(
                    "add rule ip6 {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src_ip} ip6 daddr {dest_ip} {proto} dport {dest_port} accept comment \"{comment}\""
                );
                Command::new("nft").arg(&rule).output()?;
            }
            let rule = format!(
                "add rule ip6 {TABLE_NAME} {CHAIN_NAME} ip6 daddr {dest_ip} {proto} dport {dest_port} drop comment \"{comment}\""
            );
            Command::new("nft").arg(&rule).output()?;
        }

        Ok(())
    }

    fn remove_acl(&self, dest_ip: Ipv6Addr, dest_port: u16, protocol: Protocol) -> Result<()> {
        let comment = Self::rule_comment(&dest_ip, dest_port, &protocol);

        let output = Command::new("nft")
            .args(["--handle", "list", "chain", "ip6", TABLE_NAME, CHAIN_NAME])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains(&comment) {
                if let Some(handle) = line.split("# handle ").nth(1) {
                    let handle = handle.trim();
                    Command::new("nft")
                        .args([
                            "delete", "rule", "ip6", TABLE_NAME, CHAIN_NAME, "handle", handle,
                        ])
                        .output()?;
                }
            }
        }

        Ok(())
    }

    fn cleanup_all_rules(&self) -> Result<()> {
        // Flush the entire socketguard table — removes all rules in one shot
        let _ = Command::new("nft")
            .args(["flush", "table", "ip6", TABLE_NAME])
            .output();
        let _ = Command::new("nft")
            .args(["delete", "table", "ip6", TABLE_NAME])
            .output();
        Ok(())
    }
}
