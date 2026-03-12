use super::Firewall;
use anyhow::{Context, Result};
use socketguard_core::Protocol;
use std::net::Ipv6Addr;
use std::process::Command;

const ANCHOR_NAME: &str = "socketguard";

pub struct PfFirewall;

impl PfFirewall {
    pub fn new() -> Self {
        Self
    }

    fn anchor_path(dest_ip: &Ipv6Addr, dest_port: u16, protocol: &Protocol) -> String {
        let ip_str = dest_ip.to_string().replace(':', "_");
        format!("{ANCHOR_NAME}/sg_{ip_str}_{dest_port}_{protocol}")
    }
}

impl Firewall for PfFirewall {
    fn apply_acl(
        &self,
        dest_ip: Ipv6Addr,
        dest_port: u16,
        protocol: Protocol,
        allowed: &[Ipv6Addr],
    ) -> Result<()> {
        let anchor = Self::anchor_path(&dest_ip, dest_port, &protocol);
        let proto = protocol.to_string();

        let mut rules = String::new();

        if allowed.is_empty() {
            rules.push_str(&format!(
                "block in quick inet6 proto {proto} to {dest_ip} port {dest_port}\n"
            ));
        } else {
            for src_ip in allowed {
                rules.push_str(&format!(
                    "pass in quick inet6 proto {proto} from {src_ip} to {dest_ip} port {dest_port}\n"
                ));
            }
            rules.push_str(&format!(
                "block in quick inet6 proto {proto} to {dest_ip} port {dest_port}\n"
            ));
        }

        let mut child = Command::new("pfctl")
            .args(["-a", &anchor, "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("failed to run pfctl")?;

        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(rules.as_bytes())?;
        }
        child.wait()?;

        Ok(())
    }

    fn remove_acl(&self, dest_ip: Ipv6Addr, dest_port: u16, protocol: Protocol) -> Result<()> {
        let anchor = Self::anchor_path(&dest_ip, dest_port, &protocol);

        Command::new("pfctl")
            .args(["-a", &anchor, "-F", "rules"])
            .output()?;

        Ok(())
    }
}
