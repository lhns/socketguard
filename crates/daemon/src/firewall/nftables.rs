//! nftables backend (ADR 0029): one `inet` table rendered whole and swapped in a single
//! `nft -f -` transaction. `render` is pure and golden-tested on every platform.

use super::{
    Counter, DesiredRuleset, DropSink, Families, Firewall, Rule, Scope, ScopeMatch, Sources,
};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::Mutex;

const TABLE: &str = "socketguard";
/// NFLOG group for scope drops.
pub const LOG_GROUP: u16 = 7;

/// nft counter names are bare identifiers of at most 31 characters, and ids contain
/// colons and interface names. A counter is named `c` + 16 hex of SHA-256(id); the firewall
/// remembers the mapping from the ruleset it applied.
fn counter_name(id: &str) -> String {
    let digest = Sha256::digest(id.as_bytes());
    let mut out = String::from("c");
    for b in &digest[..8] {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Counter name to id, for every rule and scope of `rs`.
fn counter_names(rs: &DesiredRuleset) -> HashMap<String, String> {
    rs.scopes
        .iter()
        .map(|s| s.id.as_str())
        .chain(rs.rules.iter().map(|r| r.id.as_str()))
        .map(|id| (counter_name(id), id.to_string()))
        .collect()
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
        // The comment keeps the hashed names readable in `nft list ruleset`.
        let _ = writeln!(o, "\t# {id}");
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

#[derive(Default)]
pub struct NftablesFirewall {
    /// Counter name to rule or scope id, from the last applied ruleset.
    names: Mutex<HashMap<String, String>>,
}

impl NftablesFirewall {
    pub fn new() -> Self {
        Self::default()
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
        *self.names.lock().unwrap() = counter_names(desired);
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
        parse_counters(
            &String::from_utf8_lossy(&out.stdout),
            &self.names.lock().unwrap(),
        )
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

/// Parse the output of `nft -j list counters`; counters whose name is unknown are skipped.
fn parse_counters(json: &str, names: &HashMap<String, String>) -> Result<Vec<Counter>> {
    let v: serde_json::Value = serde_json::from_str(json).context("invalid nft JSON")?;
    let items = v["nftables"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    Ok(items
        .iter()
        .filter_map(|i| i.get("counter"))
        .filter_map(|c| {
            Some(Counter {
                id: names.get(c["name"].as_str()?)?.clone(),
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
    fn counter_names_are_short_and_deterministic() {
        for id in [
            "managed",
            "a:6f1c0a9e-1111-2222-3333-444455556666:443:tcp:6f1c0a9e-1111-2222-3333-444455556667:Yggdrasil 0",
            "host:eth0.100",
        ] {
            let n = counter_name(id);
            assert_eq!(n.len(), 17);
            assert!(n.starts_with('c') && n.bytes().all(|b| b.is_ascii_alphanumeric()));
            assert_eq!(n, counter_name(id));
        }
        assert_ne!(counter_name("a"), counter_name("b"));
    }

    #[test]
    fn parses_counter_json() {
        let id = "a:addr:80:tcp:grant";
        let names = HashMap::from([(counter_name(id), id.to_string())]);
        let json = format!(
            r#"{{"nftables": [{{"metainfo": {{}}}},
            {{"counter": {{"family": "inet", "name": "{}", "table": "socketguard", "handle": 2, "packets": 3, "bytes": 180}}}},
            {{"counter": {{"family": "inet", "name": "cunknown", "table": "socketguard", "handle": 3, "packets": 1, "bytes": 1}}}}]}}"#,
            counter_name(id)
        );
        assert_eq!(
            parse_counters(&json, &names).unwrap(),
            vec![Counter {
                id: id.into(),
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
            format!(
                "ip daddr 10.0.0.1 udp dport 53 counter name \"{}\" accept",
                counter_name("x")
            )
        );
    }
}
