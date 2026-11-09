//! pf backend for macOS (ADR 0029): the whole `socketguard` anchor is reloaded on every
//! apply. `render` is pure and golden-tested on every platform; the pfctl calls only run
//! on macOS.

use super::{DesiredRuleset, Families, Firewall, Rule, Scope, ScopeMatch, Sources};
use anyhow::{bail, Context, Result};
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use tracing::error;

const ANCHOR: &str = "socketguard";

fn list<T: std::fmt::Display>(items: impl IntoIterator<Item = T>) -> String {
    let v: Vec<String> = items.into_iter().map(|i| i.to_string()).collect();
    format!("{{ {} }}", v.join(", "))
}

fn inet(ip: &IpAddr) -> &'static str {
    if ip.is_ipv6() {
        "inet6"
    } else {
        "inet"
    }
}

fn rule_line(r: &Rule) -> String {
    let on = r
        .iif
        .as_ref()
        .map(|i| format!(" on {i}"))
        .unwrap_or_default();
    let from = match &r.sources {
        Sources::Any => "any".to_string(),
        Sources::Nets(n) => list(n),
    };
    format!(
        "pass in quick{on} {} proto {} from {from} to {} port {} keep state",
        inet(&r.dst),
        r.proto,
        r.dst,
        r.port
    )
}

fn scope_lines(sc: &Scope) -> Vec<String> {
    match &sc.matcher {
        ScopeMatch::Destinations(dsts) => {
            let (v6, v4): (Vec<&IpAddr>, Vec<&IpAddr>) = dsts.iter().partition(|d| d.is_ipv6());
            [("inet6", v6), ("inet", v4)]
                .into_iter()
                .filter(|(_, d)| !d.is_empty())
                .map(|(fam, d)| format!("block drop in log quick {fam} from any to {}", list(d)))
                .collect()
        }
        ScopeMatch::Interface { name, families } => {
            let fam = match families {
                Families::Both => "",
                Families::V6 => " inet6",
                Families::V4 => " inet",
            };
            vec![format!("block drop in log quick on {name}{fam} all")]
        }
    }
}

/// Render the anchor's ruleset.
pub fn render(rs: &DesiredRuleset) -> String {
    let mut o = String::new();
    o.push_str("# always allowed (replies to outbound traffic match existing state)\n");
    o.push_str("pass quick on lo0 all\n");
    o.push_str("pass in quick inet6 proto icmp6 icmp6-type { 1, 2, 3, 4, 130, 131, 134, 135, 136, 137, 143 }\n");
    o.push_str("pass in quick inet6 proto icmp6 icmp6-type 128\n");
    o.push_str("pass in quick inet proto icmp icmp-type { 3, 11, 12, 8 }\n");
    o.push_str("pass in quick inet6 proto udp from any port 547 to any port 546\n");
    o.push_str("pass in quick inet proto udp from any port 67 to any port 68\n");
    o.push_str("# rules\n");
    for r in &rs.rules {
        let _ = writeln!(o, "{}", rule_line(r));
    }
    o.push_str("# scopes\n");
    for sc in &rs.scopes {
        for l in scope_lines(sc) {
            let _ = writeln!(o, "{l}");
        }
    }
    o
}

fn pfctl(args: &[&str], stdin: Option<&str>) -> Result<std::process::Output> {
    let mut child = Command::new("pfctl")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run pfctl")?;
    if let (Some(text), Some(mut si)) = (stdin, child.stdin.take()) {
        si.write_all(text.as_bytes())?;
    }
    Ok(child.wait_with_output()?)
}

/// pf must be enabled and the main ruleset must evaluate our anchor; otherwise the
/// anchor's rules are loaded but never consulted.
fn check_active() -> Result<()> {
    let info = pfctl(&["-s", "info"], None)?;
    if !String::from_utf8_lossy(&info.stdout).contains("Status: Enabled") {
        bail!("pf is not enabled (run `pfctl -e`)");
    }
    let rules = pfctl(&["-s", "rules"], None)?;
    if !String::from_utf8_lossy(&rules.stdout).contains(&format!("anchor \"{ANCHOR}\"")) {
        bail!("the main pf ruleset does not reference anchor \"{ANCHOR}\"; add `anchor \"{ANCHOR}\"` to /etc/pf.conf");
    }
    Ok(())
}

#[derive(Default)]
pub struct PfFirewall;

impl PfFirewall {
    pub fn new() -> Self {
        Self
    }
}

impl Firewall for PfFirewall {
    fn apply(&self, desired: &DesiredRuleset) -> Result<()> {
        let out = pfctl(&["-a", ANCHOR, "-f", "-"], Some(&render(desired)))?;
        if !out.status.success() {
            bail!(
                "pfctl load failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        if let Err(e) = check_active() {
            error!("pf rules are loaded but not enforced: {e}");
            return Err(e);
        }
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        let out = pfctl(&["-a", ANCHOR, "-F", "all"], None)?;
        if !out.status.success() {
            bail!(
                "pfctl flush failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::golden_ruleset;

    #[test]
    fn golden_render() {
        insta::assert_snapshot!(render(&golden_ruleset()));
    }

    #[test]
    fn empty_ruleset_keeps_essentials() {
        let out = render(&DesiredRuleset::default());
        assert!(out.contains("pass quick on lo0"));
        assert!(!out.contains("block"));
    }
}
