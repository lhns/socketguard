use super::NetworkInterface;
use anyhow::{Context, Result};
use std::net::Ipv6Addr;
use std::process::Command;

pub struct WindowsNetworkInterface;

impl NetworkInterface for WindowsNetworkInterface {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        let output = Command::new("netsh")
            .args([
                "interface", "ipv6", "add", "address",
                &format!("interface={iface}"),
                &format!("address={addr}/{prefix}"),
            ])
            .output()
            .context("failed to run netsh add address")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let msg = if stderr.trim().is_empty() { &stdout } else { &stderr };
            // Ignore if address already exists
            if !msg.contains("already") && !msg.contains("Object already exists") {
                anyhow::bail!("netsh add address failed: {}", msg.trim());
            }
        }

        Ok(())
    }

    fn remove_address(&self, iface: &str, addr: Ipv6Addr) -> Result<()> {
        let output = Command::new("netsh")
            .args([
                "interface", "ipv6", "delete", "address",
                &format!("interface={iface}"),
                &format!("address={addr}"),
            ])
            .output()
            .context("failed to run netsh delete address")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let msg = if stderr.trim().is_empty() { &stdout } else { &stderr };
            if !msg.contains("not found") && !msg.contains("Element not found") {
                anyhow::bail!("netsh delete address failed: {}", msg.trim());
            }
        }

        Ok(())
    }
}
