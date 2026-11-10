use super::{InterfaceInfo, InterfaceManager};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
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

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        // `-d` adds the link info that names a VLAN and its id.
        let output = Command::new("ip")
            .args(["-d", "-j", "link", "show"])
            .output()
            .context("failed to run ip link show")?;

        if !output.status.success() {
            anyhow::bail!(
                "ip link show failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        parse_ip_link_json(&String::from_utf8_lossy(&output.stdout))
    }

    fn list_ipv4_subnets(&self, iface: &str) -> Result<Vec<Ipv4Net>> {
        let output = Command::new("ip")
            .args(["-4", "-j", "addr", "show", "dev", iface])
            .output()
            .context("failed to run ip addr show")?;

        if !output.status.success() {
            anyhow::bail!(
                "ip addr show dev {iface} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        parse_ipv4_subnets(&String::from_utf8_lossy(&output.stdout))
    }
}

/// Parse `ip -d -j link show` into interfaces with their VLAN ids.
fn parse_ip_link_json(json: &str) -> Result<Vec<InterfaceInfo>> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("invalid `ip -j link` output")?;
    let mut out: Vec<InterfaceInfo> = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|l| {
            let vlan = &l["linkinfo"];
            let vlan_id = (vlan["info_kind"] == "vlan")
                .then(|| vlan["info_data"]["id"].as_u64())
                .flatten()
                .and_then(|id| u16::try_from(id).ok());
            Some(InterfaceInfo {
                name: l["ifname"].as_str()?.to_string(),
                vlan_id,
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Parse `ip -4 -j addr show` into the subnets of the addresses it lists.
fn parse_ipv4_subnets(json: &str) -> Result<Vec<Ipv4Net>> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("invalid `ip -j addr` output")?;
    let mut nets = Vec::new();
    for iface in value.as_array().into_iter().flatten() {
        for info in iface["addr_info"].as_array().into_iter().flatten() {
            let addr = info["local"].as_str().and_then(|a| a.parse().ok());
            let len = info["prefixlen"]
                .as_u64()
                .and_then(|l| u8::try_from(l).ok());
            if let Some(net) = addr
                .zip(len)
                .and_then(|(a, l)| Ipv4Net::new(a, l).ok())
                .map(|n| n.trunc())
            {
                nets.push(net);
            }
        }
    }
    Ok(nets)
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
    fn parses_vlan_ids_from_link_json() {
        let json = r#"[
            {"ifindex":2,"ifname":"eth0","linkinfo":{}},
            {"ifindex":5,"ifname":"eth0.20","link":"eth0",
             "linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":20}}},
            {"ifindex":6,"ifname":"br0","linkinfo":{"info_kind":"bridge"}}]"#;
        let got = parse_ip_link_json(json).unwrap();
        let got: Vec<_> = got.iter().map(|i| (i.name.as_str(), i.vlan_id)).collect();
        assert_eq!(got, [("br0", None), ("eth0", None), ("eth0.20", Some(20))]);
    }

    #[test]
    fn parses_ipv4_subnets() {
        let json = r#"[{"ifname":"eth0","addr_info":[
            {"family":"inet","local":"192.168.1.5","prefixlen":24},
            {"family":"inet","local":"10.0.0.9","prefixlen":32}]}]"#;
        let got = parse_ipv4_subnets(json).unwrap();
        let want: Vec<Ipv4Net> = vec![
            "192.168.1.0/24".parse().unwrap(),
            "10.0.0.9/32".parse().unwrap(),
        ];
        assert_eq!(got, want);
    }

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
