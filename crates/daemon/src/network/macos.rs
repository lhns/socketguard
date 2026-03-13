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

    fn list_interfaces(&self) -> Result<Vec<String>> {
        let output = Command::new("ifconfig")
            .args(["-l"])
            .output()
            .context("failed to run ifconfig -l")?;

        if !output.status.success() {
            anyhow::bail!(
                "ifconfig -l failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut names: Vec<String> = stdout.split_whitespace().map(|s| s.to_string()).collect();
        names.sort();
        Ok(names)
    }
}
