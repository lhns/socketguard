use super::InterfaceManager;
use anyhow::{Context, Result};
use std::net::Ipv6Addr;
use std::process::Command;

pub struct LinuxInterfaces;

impl InterfaceManager for LinuxInterfaces {
    fn add_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        let mut cmd = Command::new("ip");
        cmd.args(["addr", "add", &format!("{addr}/{prefix}"), "dev", iface]);
        if prefix == 128 {
            // Skip duplicate address detection: our /128s are unique by construction and
            // a tentative address cannot be bound or reached for a second or so.
            cmd.arg("nodad");
        }
        let output = cmd.output().context("failed to run ip addr add")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "already exists" errors
            if !stderr.contains("RTNETLINK answers: File exists") {
                anyhow::bail!("ip addr add failed: {stderr}");
            }
        }

        Ok(())
    }

    fn remove_address(&self, iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        let output = Command::new("ip")
            .args(["addr", "del", &format!("{addr}/{prefix}"), "dev", iface])
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

    fn list_addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>> {
        let output = Command::new("ip")
            .args(["-6", "-j", "addr", "show", "dev", iface])
            .output()
            .context("failed to run ip addr show")?;

        if !output.status.success() {
            anyhow::bail!(
                "ip addr show dev {iface} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        parse_ip_addr_json(&String::from_utf8_lossy(&output.stdout))
    }

    fn list_interfaces(&self) -> Result<Vec<String>> {
        let output = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .context("failed to run ip link show")?;

        if !output.status.success() {
            anyhow::bail!(
                "ip link show failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut names: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                // Format: "2: eth0: <FLAGS> ..."
                let after_num = line.split_once(": ")?.1;
                let name = after_num.split_once(": ")?.0;
                // Strip @... suffix (e.g. "veth0@if3")
                let name = name.split('@').next().unwrap_or(name);
                Some(name.to_string())
            })
            .collect();
        names.sort();
        Ok(names)
    }
}

/// Parse `ip -6 -j addr show` output into the addresses it lists.
fn parse_ip_addr_json(json: &str) -> Result<Vec<Ipv6Addr>> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("invalid `ip -j addr` output")?;
    let mut addrs = Vec::new();
    for iface in value.as_array().into_iter().flatten() {
        for info in iface["addr_info"].as_array().into_iter().flatten() {
            if let Some(a) = info["local"].as_str().and_then(|a| a.parse().ok()) {
                addrs.push(a);
            }
        }
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_addr_json() {
        let json = r#"[{"ifindex":3,"ifname":"ygg0","addr_info":[
            {"family":"inet6","local":"200:1::1","prefixlen":7,"scope":"global"},
            {"family":"inet6","local":"300:1:2:3::5","prefixlen":128,"scope":"global"},
            {"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}]"#;
        let addrs = parse_ip_addr_json(json).unwrap();
        assert_eq!(addrs.len(), 3);
        assert!(addrs.contains(&"300:1:2:3::5".parse().unwrap()));
        assert!(parse_ip_addr_json("[]").unwrap().is_empty());
    }
}
