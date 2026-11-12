//! nftables backend (ADR 0029): one `inet` table rendered whole and swapped in a single
//! `nft -f -` transaction. `render` is pure and golden-tested on every platform.

use super::{
    brace_list, run_with_stdin, safe_text, Counter, DesiredRuleset, DropSink, Dst, Families,
    Firewall, Revocation, Rule, Scope, ScopeMatch, Sources,
};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use socketguard_core::PortRange;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tracing::warn;

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
    rs.ids()
        .map(|id| (counter_name(id), id.to_string()))
        .collect()
}

fn l3(dst: &Dst) -> &'static str {
    if dst.is_ipv6() {
        "ip6"
    } else {
        "ip"
    }
}

fn rule_line(r: &Rule) -> String {
    let mut s = String::new();
    if let Some(iif) = &r.iif {
        let _ = write!(s, "iifname \"{}\" ", safe_text(iif));
    }
    match &r.sources {
        Sources::Nets(nets) => {
            let _ = write!(s, "{} saddr {} ", l3(&r.dst), brace_list(nets));
        }
        // A rule for any IPv4 destination must not match IPv6 packets.
        Sources::Any if r.dst == Dst::HostV4 => s.push_str("meta nfproto ipv4 "),
        Sources::Any => {}
    }
    if let Dst::Addr(addr) = r.dst {
        let _ = write!(s, "{} daddr {addr} ", l3(&r.dst));
    }
    let _ = write!(
        s,
        "{} dport {} counter name \"{}\" accept",
        r.ports.proto,
        r.ports.port_text(),
        counter_name(&r.id)
    );
    s
}

/// The match expressions of a scope (one per address family for destination lists).
fn scope_matches(sc: &Scope) -> Vec<String> {
    match &sc.matcher {
        ScopeMatch::Destinations(_) => {
            let (v6, v4) = sc.destinations_by_family();
            let mut m = Vec::new();
            if !v6.is_empty() {
                m.push(format!("ip6 daddr {}", brace_list(v6)));
            }
            if !v4.is_empty() {
                m.push(format!("ip daddr {}", brace_list(v4)));
            }
            m
        }
        ScopeMatch::DestinationNet(net) => vec![format!(
            "{} daddr {net}",
            if net.addr().is_ipv6() { "ip6" } else { "ip" }
        )],
        ScopeMatch::Interface { name, families } => {
            let fam = match families {
                Families::Both => "",
                Families::V6 => " meta nfproto ipv6",
                Families::V4 => " meta nfproto ipv4",
            };
            vec![format!("iifname \"{}\"{fam}", safe_text(name))]
        }
    }
}

/// Render the whole `table inet socketguard`.
pub fn render(rs: &DesiredRuleset) -> String {
    let mut ids: Vec<&str> = rs.ids().collect();
    ids.sort_unstable();
    ids.dedup();

    let mut o = String::new();
    let _ = writeln!(o, "table inet {TABLE} {{");
    for id in &ids {
        // The comment keeps the hashed names readable in `nft list ruleset`.
        let _ = writeln!(o, "\t# {}", safe_text(id));
        let _ = writeln!(o, "\tcounter {} {{ }}", counter_name(id));
    }
    o.push_str("\tchain input {\n");
    o.push_str("\t\ttype filter hook input priority 0; policy accept;\n");
    o.push_str("\t\t# always allowed\n");
    // DHCP replies and echo are for ordinary links; an overlay interface gets neither.
    let overlays = rs.overlay_interfaces();
    let not_overlay = if overlays.is_empty() {
        String::new()
    } else {
        format!(
            "iifname != {} ",
            brace_list(overlays.iter().map(|i| format!("\"{}\"", safe_text(i))))
        )
    };
    let always = [
        // Only the reply direction of established flows is accepted blindly. Original-
        // direction packets of an inbound flow go through the rules below on every packet,
        // so a revoked grant or a spoofed interface cuts the flow at once, without conntrack.
        "ct state established ct direction reply accept".to_string(),
        "ct state related accept".to_string(),
        "iif lo accept".to_string(),
        // Neighbour discovery is only valid with hop limit 255 (never forwarded). Redirects
        // and MLD reports are not accepted: a host needs neither.
        "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } ip6 hoplimit 255 accept".to_string(),
        "icmpv6 type { packet-too-big, destination-unreachable, time-exceeded, parameter-problem } accept".to_string(),
        "icmpv6 type mld-listener-query ip6 saddr fe80::/10 accept".to_string(),
        "icmpv6 type echo-request limit rate 5/second accept".to_string(),
        "icmp type { destination-unreachable, time-exceeded, parameter-problem } accept".to_string(),
        "icmp type echo-request limit rate 5/second accept".to_string(),
        format!("{not_overlay}ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp sport 547 udp dport 546 accept"),
        format!("{not_overlay}meta nfproto ipv4 udp sport 67 udp dport 68 accept"),
    ];
    for l in always {
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
                safe_text(&sc.id)
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

/// Drops the pre-ADR-0029 table; installations from before it may still have one.
const LEGACY_CLEANUP: &str = "table ip6 socketguard {}\ndelete table ip6 socketguard\n";

fn run_nft(args: &[&str], stdin: Option<&str>) -> Result<std::process::Output> {
    run_with_stdin("nft", args, stdin)
}

/// `conntrack` arguments selecting the flows to a revoked destination: the original
/// direction's destination, protocol and, for a single port, the port. `conntrack` takes no
/// port range, so for a range [`flush_conntrack`] lists the flows and deletes them by port.
fn conntrack_selector(r: &Revocation) -> Vec<String> {
    let mut a = vec![
        "-f".to_string(),
        if r.dst.is_ipv6() { "ipv6" } else { "ipv4" }.into(),
    ];
    if let Some(dst) = r.dst.addr() {
        a.extend(["-d".to_string(), dst.to_string()]);
    }
    a.extend(["-p".to_string(), r.ports.proto.to_string()]);
    if r.ports.is_single() {
        a.extend(["--dport".to_string(), r.ports.start.to_string()]);
    }
    a
}

fn conntrack_args(verb: &str, r: &Revocation, src: Option<IpAddr>) -> Vec<String> {
    let mut a = vec![verb.to_string()];
    a.extend(conntrack_selector(r));
    if let Some(src) = src {
        a.extend(["-s".to_string(), src.to_string()]);
    }
    a
}

/// The original source addresses in `conntrack -L` output (the first `src=` of a line).
fn parse_conntrack_sources(out: &str) -> Vec<IpAddr> {
    parse_conntrack_flows(out)
        .into_iter()
        .map(|(s, _)| s)
        .collect()
}

/// The original source address and destination port of each flow in `conntrack -L` output
/// (the first `src=` and `dport=` of a line).
fn parse_conntrack_flows(out: &str) -> Vec<(IpAddr, Option<u16>)> {
    out.lines()
        .filter_map(|l| {
            let find = |key: &str| l.split_whitespace().find_map(|t| t.strip_prefix(key));
            let src = find("src=")?.parse().ok()?;
            Some((src, find("dport=").and_then(|p| p.parse().ok())))
        })
        .collect()
}

fn run_conntrack(args: &[String]) -> std::io::Result<std::process::Output> {
    Command::new("conntrack")
        .args(args)
        .stdin(Stdio::null())
        .output()
}

/// Delete the flows a revocation names. `conntrack -D` takes no network for the source,
/// so a net is resolved through a listing first. Returns false when the tool is missing.
fn flush_conntrack(r: &Revocation) -> bool {
    if !r.ports.is_single() {
        return flush_conntrack_range(r);
    }
    let mut sources: Vec<Option<IpAddr>> = Vec::new();
    match r.src {
        None => sources.push(None),
        Some(net) if net.prefix_len() == net.max_prefix_len() => sources.push(Some(net.addr())),
        Some(net) => match run_conntrack(&conntrack_args("-L", r, None)) {
            Ok(out) => {
                let mut found = parse_conntrack_sources(&String::from_utf8_lossy(&out.stdout));
                found.retain(|a| net.contains(a));
                found.sort();
                found.dedup();
                sources.extend(found.into_iter().map(Some));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(e) => warn!("conntrack listing failed: {e}"),
        },
    }
    for src in sources {
        match run_conntrack(&conntrack_args("-D", r, src)) {
            Ok(_) => {} // a non-zero exit only means no flow matched
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(e) => warn!("conntrack delete failed: {e}"),
        }
    }
    true
}

/// [`flush_conntrack`] for a port range: list the flows to the destination and delete the
/// ones inside the range from the revoked source, one by one.
fn flush_conntrack_range(r: &Revocation) -> bool {
    let out = match run_conntrack(&conntrack_args("-L", r, None)) {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(e) => {
            warn!("conntrack listing failed: {e}");
            return true;
        }
    };
    let mut flows = parse_conntrack_flows(&String::from_utf8_lossy(&out.stdout));
    flows.retain(|(src, port)| {
        port.is_some_and(|p| (r.ports.start..=r.ports.end).contains(&p))
            && r.src.is_none_or(|net| net.contains(src))
    });
    flows.sort();
    flows.dedup();
    for (src, port) in flows {
        let single = Revocation {
            ports: PortRange {
                start: port.unwrap_or_default(),
                end: port.unwrap_or_default(),
                proto: r.ports.proto,
            },
            ..r.clone()
        };
        match run_conntrack(&conntrack_args("-D", &single, Some(src))) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(e) => warn!("conntrack delete failed: {e}"),
        }
    }
    true
}

#[derive(Default)]
pub struct NftablesFirewall {
    /// The missing-conntrack warning is logged once.
    conntrack_warned: AtomicBool,
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
        desired.validate()?;
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

    fn verify(&self) -> Result<bool> {
        // The table of earlier versions (`ip6`) counts too: it is ours and disable removes it.
        for family in ["inet", "ip6"] {
            let out = run_nft(&["list", "table", family, TABLE], None)?;
            if out.status.success() {
                return Ok(true);
            }
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.contains("No such file or directory") {
                bail!("nft list table failed: {}", err.trim());
            }
        }
        Ok(false)
    }

    fn revoke(&self, revoked: &[Revocation]) -> Result<()> {
        for r in revoked {
            if !flush_conntrack(r) {
                if !self.conntrack_warned.swap(true, Ordering::Relaxed) {
                    warn!(
                        "conntrack is not installed: connections of revoked grants stay open until they close"
                    );
                }
                break;
            }
        }
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        let out = run_nft(&["delete", "table", "inet", TABLE], None)?;
        let err = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && !err.contains("No such file or directory") {
            bail!("nft delete table failed: {}", err.trim());
        }
        // The table of earlier versions (`table ip6 socketguard`), if one is still around.
        let out = run_nft(&["delete", "table", "ip6", TABLE], None)?;
        let err = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && !err.contains("No such file or directory") {
            bail!("nft delete table (legacy ip6) failed: {}", err.trim());
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
    use socketguard_core::{PortRef, Protocol};

    #[test]
    fn a_destination_net_scope_is_a_daddr_match_after_the_permit_rules() {
        let out = render(&golden_ruleset());
        let permit = out
            .find("ip6 saddr { fd00::10/128, fd00:5::/32 } ip6 daddr 301::1 tcp dport 8080")
            .expect("the permit rule");
        let addr = out
            .find("ip6 daddr 200:1:2:3::5/128 counter name")
            .expect("the address drop");
        let subnet = out
            .find("ip6 daddr 300:1:2:3::/64 counter name")
            .expect("the subnet drop");
        assert!(permit < addr && permit < subnet, "rules come before scopes");
        assert!(out.contains("ip6 daddr 300:1:2:3::/64 limit rate 10/second burst 20 packets log group 7 prefix \"sg:overlay:ygg:subnet\""));
        assert!(out.contains("sg:overlay:ygg:subnet"));
    }

    #[test]
    fn the_range_scope_drops_200_7_after_the_granted_rule() {
        let out = render(&crate::firewall::range_ruleset());
        let permit = out
            .find("ip6 daddr 300:1:2:3::100 tcp dport 8080 counter name")
            .expect("the granted rule");
        let drop = out
            .find("ip6 daddr 200::/7 counter name")
            .expect("the range drop");
        assert!(permit < drop, "rules come before scopes");
        assert!(out.contains("ip6 daddr 200::/7 limit rate 10/second burst 20 packets log group 7 prefix \"sg:overlay:ygg:range\""));
    }

    #[test]
    fn golden_render() {
        insta::assert_snapshot!(render(&golden_ruleset()));
    }

    #[test]
    fn empty_ruleset_still_has_always_allowed() {
        let out = render(&DesiredRuleset::default());
        assert!(out.contains("ct state established ct direction reply accept"));
        assert!(out.contains("ct state related accept"));
        assert!(!out.contains("established,related"));
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

    fn revocation(src: Option<&str>) -> Revocation {
        Revocation {
            dst: Dst::Addr("fd00::9".parse().unwrap()),
            ports: PortRange::single(PortRef {
                port: 80,
                proto: Protocol::Tcp,
            }),
            src: src.map(|s| s.parse().unwrap()),
        }
    }

    #[test]
    fn conntrack_selects_host_ipv4_flows_without_a_destination() {
        let r = Revocation {
            dst: Dst::HostV4,
            ports: PortRange::single(PortRef {
                port: 22,
                proto: Protocol::Tcp,
            }),
            src: None,
        };
        assert_eq!(
            conntrack_args("-D", &r, Some("192.168.1.5".parse().unwrap())).join(" "),
            "-D -f ipv4 -p tcp --dport 22 -s 192.168.1.5"
        );
    }

    #[test]
    fn conntrack_commands() {
        let r = revocation(Some("fd00::1/128"));
        assert_eq!(
            conntrack_args("-D", &r, Some("fd00::1".parse().unwrap())).join(" "),
            "-D -f ipv6 -d fd00::9 -p tcp --dport 80 -s fd00::1"
        );
        assert_eq!(
            conntrack_args("-D", &revocation(None), None).join(" "),
            "-D -f ipv6 -d fd00::9 -p tcp --dport 80"
        );
    }

    #[test]
    fn port_ranges_render_as_nft_ranges() {
        let rule = |ports: &str| Rule {
            id: "r".into(),
            iif: Some("eth0".into()),
            dst: Dst::Addr("fd00::9".parse().unwrap()),
            ports: ports.parse().unwrap(),
            sources: Sources::Any,
        };
        let line = rule_line(&rule("50000-51000/tcp"));
        assert!(
            line.starts_with("iifname \"eth0\" ip6 daddr fd00::9 tcp dport 50000-51000 counter"),
            "{line}"
        );
        assert!(rule_line(&rule("80/udp")).contains(" udp dport 80 counter"));
        let rs = DesiredRuleset {
            scopes: vec![],
            rules: vec![rule("1000-2000/udp")],
        };
        assert!(render(&rs).contains("udp dport 1000-2000 counter name"));
    }

    #[test]
    fn conntrack_lists_a_range_instead_of_naming_a_port() {
        let r = Revocation {
            ports: "50000-51000/tcp".parse().unwrap(),
            ..revocation(None)
        };
        assert_eq!(
            conntrack_args("-L", &r, None).join(" "),
            "-L -f ipv6 -d fd00::9 -p tcp"
        );
        let out = "tcp 6 431999 ESTABLISHED src=fd00::1 dst=fd00::9 sport=5000 dport=50500 src=fd00::9 dst=fd00::1 sport=50500 dport=5000 [ASSURED]\n";
        assert_eq!(
            parse_conntrack_flows(out),
            vec![("fd00::1".parse::<IpAddr>().unwrap(), Some(50500))]
        );
    }

    #[test]
    fn parses_conntrack_listing() {
        let out = "tcp      6 431999 ESTABLISHED src=fd00::1 dst=fd00::9 sport=5000 dport=80 src=fd00::9 dst=fd00::1 sport=80 dport=5000 [ASSURED] mark=0 use=1\n\
                   udp      17 5 src=fd00::2 dst=fd00::9 sport=1 dport=80 [UNREPLIED] src=fd00::9 dst=fd00::2 sport=80 dport=1 mark=0 use=1\n";
        assert_eq!(
            parse_conntrack_sources(out),
            vec![
                "fd00::1".parse::<IpAddr>().unwrap(),
                "fd00::2".parse().unwrap()
            ]
        );
    }

    #[test]
    fn ids_cannot_break_out() {
        let mut rs = golden_ruleset();
        let hostile = format!("x{}flush ruleset{}y", char::from(10u8), '"');
        rs.rules[0].id = hostile.clone();
        rs.scopes[0].id = hostile;
        let out = render(&rs);
        assert!(!out.contains("flush ruleset\n"));
        assert!(!out.lines().any(|l| l.trim_start().starts_with("flush")));
        for l in out
            .lines()
            .filter(|l| l.contains("prefix") && l.contains("flush"))
        {
            assert_eq!(l.matches('"').count(), 2, "{l}");
        }
    }

    #[test]
    fn dhcp_and_echo_are_narrow_and_skip_overlays() {
        let out = render(&golden_ruleset());
        assert!(out.contains(
            "iifname != { \"ygg0\" } ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp sport 547 udp dport 546 accept"
        ));
        assert!(out.contains(
            "iifname != { \"ygg0\" } meta nfproto ipv4 udp sport 67 udp dport 68 accept"
        ));
        assert!(out.contains("ip6 hoplimit 255 accept"));
        assert!(!out.contains("nd-redirect"));
        assert!(!out.contains("mld-listener-report"));
        assert!(!out.contains("mld2-listener-report"));
        assert!(out.contains("mld-listener-query ip6 saddr fe80::/10 accept"));
        // Without an overlay there is no exclusion.
        let plain = render(&DesiredRuleset::default());
        assert!(plain.contains(
            "\t\tip6 saddr fe80::/10 ip6 daddr fe80::/10 udp sport 547 udp dport 546 accept"
        ));
    }

    #[test]
    fn rule_protocol_and_family() {
        let r = Rule {
            id: "x".into(),
            iif: None,
            dst: Dst::Addr("10.0.0.1".parse().unwrap()),
            ports: PortRange::single(PortRef {
                port: 53,
                proto: Protocol::Udp,
            }),
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
