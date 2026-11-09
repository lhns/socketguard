//! pf backend for macOS (ADR 0029): the whole `socketguard` anchor is reloaded on every
//! apply. `render` is pure and golden-tested on every platform; the pfctl calls only run
//! on macOS.

use super::{
    safe_text, DesiredRuleset, Families, Firewall, Revocation, Rule, Scope, ScopeMatch, Sources,
};
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
        .map(|i| format!(" on {}", safe_text(i)))
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
            vec![format!(
                "block drop in log quick on {}{fam} all",
                safe_text(name)
            )]
        }
    }
}

/// Render the anchor's ruleset.
pub fn render(rs: &DesiredRuleset) -> String {
    let mut o = String::new();
    o.push_str("# always allowed (replies to outbound traffic match existing state)\n");
    o.push_str("pass quick on lo0 all\n");
    // Overlay interfaces get neither echo nor DHCP. pf cannot rate-limit ICMP, so echo is
    // only allowed off the overlays; quick blocks come first.
    for iface in rs.overlay_interfaces() {
        let i = safe_text(iface);
        let _ = writeln!(
            o,
            "block drop in quick on {i} inet6 proto icmp6 icmp6-type 128"
        );
        let _ = writeln!(o, "block drop in quick on {i} inet proto icmp icmp-type 8");
        let _ = writeln!(o, "block drop in quick on {i} proto udp from any port {{ 547, 67 }} to any port {{ 546, 68 }}");
    }
    // pf cannot match the hop limit; the kernels drop ND with a hop limit other than 255
    // themselves. Redirects (137) and MLD reports (131, 132, 143) are not accepted, MLD
    // queries (130) only from link-local sources.
    o.push_str("pass in quick inet6 proto icmp6 icmp6-type { 1, 2, 3, 4, 134, 135, 136 }\n");
    o.push_str("pass in quick inet6 proto icmp6 from fe80::/10 icmp6-type 130\n");
    o.push_str("pass in quick inet6 proto icmp6 icmp6-type 128\n");
    o.push_str("pass in quick inet proto icmp icmp-type { 3, 11, 12, 8 }\n");
    o.push_str("pass in quick inet6 proto udp from fe80::/10 port 547 to any port 546\n");
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

/// `pfctl -k` commands killing the states from revoked sources to revoked destinations.
/// pf cannot kill by port, so every state between the pair goes, whatever its port; a
/// peer that is still allowed on another port reconnects.
fn kill_commands(revoked: &[Revocation]) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = revoked
        .iter()
        .map(|r| {
            let any = if r.dst.is_ipv6() { "::/0" } else { "0.0.0.0/0" };
            let src = r.src.map(|n| n.to_string()).unwrap_or_else(|| any.into());
            ["-k", &src, "-k", &r.dst.to_string()]
                .map(String::from)
                .to_vec()
        })
        .collect();
    out.sort();
    out.dedup();
    out
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
        desired.validate()?;
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

    fn revoke(&self, revoked: &[Revocation]) -> Result<()> {
        for cmd in kill_commands(revoked) {
            let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
            // Killing states finds nothing to do when no state exists: not an error.
            if let Err(e) = pfctl(&args, None) {
                tracing::warn!("pfctl state kill failed: {e}");
            }
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
    fn state_kill_commands() {
        use socketguard_core::Protocol;
        let r = |src: Option<&str>, dst: &str| Revocation {
            dst: dst.parse().unwrap(),
            port: 80,
            proto: Protocol::Tcp,
            src: src.map(|s| s.parse().unwrap()),
        };
        let cmds = kill_commands(&[
            r(Some("fd00::1/128"), "fd00::9"),
            r(Some("fd00::1/128"), "fd00::9"),
            r(None, "fd00::9"),
            r(None, "192.0.2.9"),
        ]);
        let cmds: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        assert_eq!(
            cmds,
            vec![
                "-k 0.0.0.0/0 -k 192.0.2.9",
                "-k ::/0 -k fd00::9",
                "-k fd00::1/128 -k fd00::9",
            ]
        );
    }

    #[test]
    fn overlays_get_no_echo_or_dhcp() {
        let out = render(&golden_ruleset());
        assert!(out.contains("block drop in quick on ygg0 inet6 proto icmp6 icmp6-type 128"));
        assert!(!out.contains("137"));
        assert!(out.contains("from fe80::/10 port 547"));
    }

    #[test]
    fn empty_ruleset_keeps_essentials() {
        let out = render(&DesiredRuleset::default());
        assert!(out.contains("pass quick on lo0"));
        assert!(!out.contains("block"));
    }
}
