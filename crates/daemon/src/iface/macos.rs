use super::{InterfaceInfo, InterfaceManager};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use std::net::Ipv6Addr;
use std::process::Command;

pub struct MacosInterfaces;

impl InterfaceManager for MacosInterfaces {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        let output = Command::new("ifconfig")
            .args([
                iface,
                "inet6",
                &format!("{addr}"),
                "prefixlen",
                &prefix.to_string(),
                "alias",
            ])
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

    fn remove_address(&self, iface: &str, addr: Ipv6Addr, _prefix: u8) -> Result<()> {
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

    fn list_addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>> {
        let output = Command::new("ifconfig")
            .args([iface, "inet6"])
            .output()
            .context("failed to run ifconfig")?;

        if !output.status.success() {
            anyhow::bail!(
                "ifconfig {iface} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        // Lines look like "	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1".
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .filter_map(|l| {
                let mut words = l.split_whitespace();
                (words.next()? == "inet6").then_some(())?;
                words.next()?.split('%').next()?.parse().ok()
            })
            .collect())
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
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
        // macOS VLANs (vlan0) carry their id in `ifconfig`; not read yet.
        Ok(names
            .into_iter()
            .map(|name| InterfaceInfo {
                name,
                vlan_id: None,
            })
            .collect())
    }

    fn list_ipv4_subnets(&self, iface: &str) -> Result<Vec<Ipv4Net>> {
        let output = Command::new("ifconfig")
            .args([iface, "inet"])
            .output()
            .context("failed to run ifconfig")?;

        if !output.status.success() {
            anyhow::bail!(
                "ifconfig {iface} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(parse_ifconfig_inet(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }
}

/// Subnets from "<tab>inet 192.168.1.5 netmask 0xffffff00 broadcast ..." lines.
fn parse_ifconfig_inet(out: &str) -> Vec<Ipv4Net> {
    out.lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            (words.next()? == "inet").then_some(())?;
            let addr: std::net::Ipv4Addr = words.next()?.parse().ok()?;
            (words.next()? == "netmask").then_some(())?;
            let mask = u32::from_str_radix(words.next()?.strip_prefix("0x")?, 16).ok()?;
            Ipv4Net::with_netmask(addr, mask.into())
                .ok()
                .map(|n| n.trunc())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ifconfig_inet_lines() {
        let out =
            "en0: flags=8863<UP>\n\tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255\n";
        assert_eq!(
            parse_ifconfig_inet(out),
            vec!["192.168.1.0/24".parse::<Ipv4Net>().unwrap()]
        );
    }
}
