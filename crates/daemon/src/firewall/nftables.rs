//! nftables backend (ADR 0029): one `inet` table rendered whole and swapped in a single
//! `nft -f -` transaction. `render` is pure and golden-tested on every platform.

use super::{
    Counter, DesiredRuleset, DropSink, Families, Firewall, Rule, Scope, ScopeMatch, Sources,
};
use anyhow::{bail, Context, Result};
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::process::{Command, Stdio};

const TABLE: &str = "socketguard";
/// NFLOG group for scope drops.
pub const LOG_GROUP: u16 = 7;

/// nft counter names are bare identifiers; escape everything else as `.hh` (hex byte) so
/// the id can be recovered from `nft -j list counters`.
fn counter_name(id: &str) -> String {
    let mut out = String::new();
    for b in id.bytes() {
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
            out.push(b as char);
        } else {
            let _ = write!(out, ".{b:02x}");
        }
    }
    out
}

fn id_from_counter_name(name: &str) -> String {
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let esc = (b[i] == b'.')
            .then(|| b.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
        match esc {
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn set<T: std::fmt::Display>(items: impl IntoIterator<Item = T>) -> String {
    let v: Vec<String> = items.into_iter().map(|i| i.to_string()).collect();
    format!("{{ {} }}", v.join(", "))
}

fn l3(ip: &IpAddr) -> &'static str {
    if ip.is_ipv6() {
        "ip6"
    } else {
        "ip"
    }
}

fn rule_line(r: &Rule) -> String {
    let mut s = String::new();
    if let Some(iif) = &r.iif {
        let _ = write!(s, "iifname \"{iif}\" ");
    }
    if let Sources::Nets(nets) = &r.sources {
        let _ = write!(s, "{} saddr {} ", l3(&r.dst), set(nets));
    }
    let _ = write!(
        s,
        "{} daddr {} {} dport {} counter name \"{}\" accept",
        l3(&r.dst),
        r.dst,
        r.proto,
        r.port,
        counter_name(&r.id)
    );
    s
}

/// The match expressions of a scope (one per address family for destination lists).
fn scope_matches(sc: &Scope) -> Vec<String> {
    match &sc.matcher {
        ScopeMatch::Destinations(dsts) => {
            let (v6, v4): (Vec<&IpAddr>, Vec<&IpAddr>) = dsts.iter().partition(|d| d.is_ipv6());
            let mut m = Vec::new();
            if !v6.is_empty() {
                m.push(format!("ip6 daddr {}", set(v6)));
            }
            if !v4.is_empty() {
                m.push(format!("ip daddr {}", set(v4)));
            }
            m
        }
        ScopeMatch::Interface { name, families } => {
            let fam = match families {
                Families::Both => "",
                Families::V6 => " meta nfproto ipv6",
                Families::V4 => " meta nfproto ipv4",
            };
            vec![format!("iifname \"{name}\"{fam}")]
        }
    }
}

/// Render the whole `table inet socketguard`.
pub fn render(rs: &DesiredRuleset) -> String {
    let mut ids: Vec<&str> = rs
        .scopes
        .iter()
        .map(|s| s.id.as_str())
        .chain(rs.rules.iter().map(|r| r.id.as_str()))
        .collect();
    ids.sort_unstable();
    ids.dedup();

    let mut o = String::new();
    let _ = writeln!(o, "table inet {TABLE} {{");
    for id in &ids {
        let _ = writeln!(o, "\tcounter {} {{ }}", counter_name(id));
    }
    o.push_str("\tchain input {\n");
    o.push_str("\t\ttype filter hook input priority 0; policy accept;\n");
    o.push_str("\t\t# always allowed\n");
    for l in [
        "ct state established,related accept",
        "iif lo accept",
        "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-redirect, packet-too-big, destination-unreachable, time-exceeded, parameter-problem, mld-listener-query, mld-listener-report, mld2-listener-report } accept",
        "icmpv6 type echo-request limit rate 5/second accept",
        "icmp type { destination-unreachable, time-exceeded, parameter-problem } accept",
        "icmp type echo-request limit rate 5/second accept",
        "meta nfproto ipv6 udp sport 547 udp dport 546 accept",
        "meta nfproto ipv4 udp sport 67 udp dport 68 accept",
    ] {
        let _ = writeln!(o, "\t\t{l}");
    }
    o.push_str("\t\t# rules\n");
    for r in &rs.rules {
        let _ = writeln!(o, "\t\t{}", rule_line(r));
    }
    o.push_str("\t\t# scopes\n");
    for sc in &rs.scopes {
        for m in scope_matches(sc) {
            let _ = writeln!(
                o,
                "\t\t{m} limit rate 10/second burst 20 packets log group {LOG_GROUP} prefix \"sg:{}\"",
                sc.id
            );
            let _ = writeln!(o, "\t\t{m} counter name \"{}\" drop", counter_name(&sc.id));
        }
    }
    o.push_str("\t}\n}\n");
    o
}

/// The full transaction piped to `nft -f -`: create-if-missing, delete, recreate. One
/// transaction, so the previous table stays in force if anything fails. Also removes the
/// pre-ADR-0029 `ip6 socketguard` table, whose per-socket rules would otherwise linger.
fn transaction(rs: &DesiredRuleset) -> String {
    format!(
        "table inet {TABLE} {{}}\ndelete table inet {TABLE}\n{}\n{LEGACY_CLEANUP}",
        render(rs)
    )
}

const LEGACY_CLEANUP: &str = "table ip6 socketguard {}\ndelete table ip6 socketguard\n";

fn run_nft(args: &[&str], stdin: Option<&str>) -> Result<std::process::Output> {
    let mut child = Command::new("nft")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run nft")?;
    if let (Some(text), Some(mut si)) = (stdin, child.stdin.take()) {
        si.write_all(text.as_bytes())?;
    }
    Ok(child.wait_with_output()?)
}

pub struct NftablesFirewall;

impl NftablesFirewall {
    pub fn new() -> Self {
        Self
    }
}

impl Firewall for NftablesFirewall {
    fn apply(&self, desired: &DesiredRuleset) -> Result<()> {
        let out = run_nft(&["-f", "-"], Some(&transaction(desired)))?;
        if !out.status.success() {
            bail!(
                "nft apply failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        let out = run_nft(&["delete", "table", "inet", TABLE], None)?;
        let err = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && !err.contains("No such file or directory") {
            bail!("nft delete table failed: {}", err.trim());
        }
        Ok(())
    }

    fn counters(&self) -> Result<Vec<Counter>> {
        let out = run_nft(&["-j", "list", "counters", "table", "inet", TABLE], None)?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            if err.contains("No such file or directory") {
                return Ok(Vec::new());
            }
            bail!("nft list counters failed: {}", err.trim());
        }
        parse_counters(&String::from_utf8_lossy(&out.stdout))
    }

    fn subscribe_drops(&self, sink: DropSink) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            super::nflog::subscribe(LOG_GROUP, sink)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = sink;
            Ok(())
        }
    }
}

/// Parse the output of `nft -j list counters`.
fn parse_counters(json: &str) -> Result<Vec<Counter>> {
    let v: serde_json::Value = serde_json::from_str(json).context("invalid nft JSON")?;
    let items = v["nftables"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    Ok(items
        .iter()
        .filter_map(|i| i.get("counter"))
        .filter_map(|c| {
            Some(Counter {
                id: id_from_counter_name(c["name"].as_str()?),
                packets: c["packets"].as_u64()?,
                bytes: c["bytes"].as_u64()?,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::golden_ruleset;
    use socketguard_core::Protocol;

    #[test]
    fn golden_render() {
        insta::assert_snapshot!(render(&golden_ruleset()));
    }

    #[test]
    fn empty_ruleset_still_has_always_allowed() {
        let out = render(&DesiredRuleset::default());
        assert!(out.contains("ct state established,related accept"));
        assert!(!out.contains("drop"));
    }

    #[test]
    fn transaction_swaps_atomically() {
        let t = transaction(&DesiredRuleset::default());
        assert!(t.starts_with(
            "table inet socketguard {}\ndelete table inet socketguard\ntable inet socketguard {"
        ));
    }

    #[test]
    fn counter_names_round_trip() {
        for id in [
            "managed",
            "s:0af:ygg:80:tcp:ygg:ygg0",
            "host:eth0.100",
            "a-b_c é",
        ] {
            let n = counter_name(id);
            assert!(n
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)));
            assert_eq!(id_from_counter_name(&n), id);
        }
    }

    #[test]
    fn parses_counter_json() {
        let json = r#"{"nftables": [{"metainfo": {}}, {"counter": {"family": "inet",
            "name": "s.3aa.3a80", "table": "socketguard", "handle": 2, "packets": 3, "bytes": 180}}]}"#;
        assert_eq!(
            parse_counters(json).unwrap(),
            vec![Counter {
                id: "s:a:80".into(),
                packets: 3,
                bytes: 180
            }]
        );
    }

    #[test]
    fn rule_protocol_and_family() {
        let r = Rule {
            id: "x".into(),
            iif: None,
            dst: "10.0.0.1".parse().unwrap(),
            port: 53,
            proto: Protocol::Udp,
            sources: Sources::Any,
        };
        assert_eq!(
            rule_line(&r),
            "ip daddr 10.0.0.1 udp dport 53 counter name \"x\" accept"
        );
    }
}
