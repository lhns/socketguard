use super::NetworkInterface;
use anyhow::{Context, Result};
use std::net::Ipv6Addr;
use std::process::Command;

pub struct LinuxNetworkInterface;

impl NetworkInterface for LinuxNetworkInterface {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        let output = Command::new("ip")
            .args(["addr", "add", &format!("{addr}/{prefix}"), "dev", iface])
            .output()
            .context("failed to run ip addr add")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "already exists" errors
            if !stderr.contains("RTNETLINK answers: File exists") {
                anyhow::bail!("ip addr add failed: {stderr}");
            }
        }

        Ok(())
    }

    fn remove_address(&self, iface: &str, addr: Ipv6Addr) -> Result<()> {
        let output = Command::new("ip")
            .args(["addr", "del", &format!("{addr}/128"), "dev", iface])
            .output()
            .context("failed to run ip addr del")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("Cannot assign requested address") {
                anyhow::bail!("ip addr del failed: {stderr}");
            }
        }

        Ok(())
    }
}
