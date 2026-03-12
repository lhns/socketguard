use super::NetworkInterface;
use anyhow::{Context, Result};
use std::net::Ipv6Addr;
use std::process::Command;

pub struct MacosNetworkInterface;

impl NetworkInterface for MacosNetworkInterface {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        let output = Command::new("ifconfig")
            .args([iface, "inet6", &format!("{addr}"), "prefixlen", &prefix.to_string(), "alias"])
            .output()
            .context("failed to run ifconfig add")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("already exists") {
                anyhow::bail!("ifconfig add failed: {stderr}");
            }
        }

        Ok(())
    }

    fn remove_address(&self, iface: &str, addr: Ipv6Addr) -> Result<()> {
        let output = Command::new("ifconfig")
            .args([iface, "inet6", &format!("{addr}"), "-alias"])
            .output()
            .context("failed to run ifconfig remove")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("Can't assign requested address") {
                anyhow::bail!("ifconfig remove failed: {stderr}");
            }
        }

        Ok(())
    }
}
