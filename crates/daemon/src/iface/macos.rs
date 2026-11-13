use super::{InterfaceInfo, InterfaceManager};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use std::net::{Ipv4Addr, Ipv6Addr};
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

    fn default_route_interface(&self) -> Option<String> {
        let out = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        parse_route_interface(&String::from_utf8_lossy(&out.stdout))
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
        Ok(super::subnets_of(&parse_ifconfig_inet(
            &String::from_utf8_lossy(&output.stdout),
        )))
    }

    fn list_ipv4_addresses(&self, iface: &str) -> Result<Vec<Ipv4Addr>> {
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
        Ok(super::addresses_of(&parse_ifconfig_inet(
            &String::from_utf8_lossy(&output.stdout),
        )))
    }
}

/// Addresses with prefix lengths from "<tab>inet 192.168.1.5 netmask 0xffffff00 broadcast ..." lines.
/// The `interface:` line of `route -n get default`.
fn parse_route_interface(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("interface:"))
        .map(|i| i.trim().to_string())
        .filter(|i| !i.is_empty())
}

fn parse_ifconfig_inet(out: &str) -> Vec<Ipv4Net> {
    out.lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            (words.next()? == "inet").then_some(())?;
            let addr: std::net::Ipv4Addr = words.next()?.parse().ok()?;
            (words.next()? == "netmask").then_some(())?;
            let mask = u32::from_str_radix(words.next()?.strip_prefix("0x")?, 16).ok()?;
            Ipv4Net::with_netmask(addr, mask.into()).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_default_route_interface() {
        let out = "   route to: default\ndestination: default\n  interface: en0\n";
        assert_eq!(parse_route_interface(out).as_deref(), Some("en0"));
        assert_eq!(
            parse_route_interface("route: writing to routing socket"),
            None
        );
    }

    #[test]
    fn parses_ifconfig_inet_lines() {
        let out =
            "en0: flags=8863<UP>\n\tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255\n";
        assert_eq!(
            parse_ifconfig_inet(out),
            vec!["192.168.1.5/24".parse::<Ipv4Net>().unwrap()]
        );
        assert_eq!(
            crate::iface::subnets_of(&parse_ifconfig_inet(out)),
            vec!["192.168.1.0/24".parse::<Ipv4Net>().unwrap()]
        );
    }
}
