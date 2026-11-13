// The renderers and the WFP plan are pure, so nftables, pf and `wfp::plan` compile (and
// are tested) everywhere; only the command invocations and the WFP FFI are platform specific.
pub mod nflog;
pub mod nftables;
pub mod pf;
pub mod wfp;

pub mod desired;

use anyhow::{Context, Result};
pub use desired::{
    resolve_host_v4, revocations, safe_text, Counter, DesiredRuleset, DropEvent, DropSink, Dst,
    Families, Revocation, Rule, Scope, ScopeKind, ScopeMatch, Sources,
};
use std::io::Write as _;
use std::process::{Command, Stdio};

/// Run `cmd args` with `stdin` piped in (or closed), capturing its output. The caller
/// checks the exit status.
fn run_with_stdin(cmd: &str, args: &[&str], stdin: Option<&str>) -> Result<std::process::Output> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {cmd}"))?;
    if let (Some(text), Some(mut si)) = (stdin, child.stdin.take()) {
        si.write_all(text.as_bytes())?;
    }
    Ok(child.wait_with_output()?)
}

/// `{ a, b, c }`, the list syntax of nft and pf.
fn brace_list<T: std::fmt::Display>(items: impl IntoIterator<Item = T>) -> String {
    let v: Vec<String> = items.into_iter().map(|i| i.to_string()).collect();
    format!("{{ {} }}", v.join(", "))
}

/// Platform firewall backend (ADR 0029). Implementations hold no per-socket state: every
/// call to [`Firewall::apply`] replaces SocketGuard's whole ruleset atomically, so a failed
/// apply leaves the previous ruleset in force. Rules survive daemon exit (the state is
/// frozen, ADR 0026); only [`Firewall::disable`] removes them. The exception is portable
/// mode on Windows (ADR 0054): its WFP objects live in a dynamic session and go with the
/// process.
pub trait Firewall: Send + Sync {
    /// Atomically replace all SocketGuard rules with `desired`.
    fn apply(&self, desired: &DesiredRuleset) -> Result<()>;

    /// Whether the installed state is still in force (e.g. nobody deleted the table).
    /// Cheap enough to call every reconcile pass; `false` makes the engine re-apply.
    fn verify(&self) -> Result<bool> {
        Ok(true)
    }

    /// Whether a rule on an interface that does not exist yet holds once the adapter
    /// appears. False for WFP, which binds filters to adapter LUIDs: it cannot make one for
    /// an adapter that is not there (ADR 0051).
    fn blocks_absent_interfaces(&self) -> bool {
        true
    }

    /// Whether interfaces resolve differently from the last apply (WFP binds filters to
    /// interface LUIDs, which change when an adapter is recreated). Cheap; `true` makes
    /// the engine re-apply.
    fn interfaces_changed(&self) -> bool {
        false
    }

    /// Cut established connections that a ruleset change stopped allowing. Called after a
    /// successful apply. Best effort: backends that cannot do it say so in their docs. A
    /// revocation names a concrete destination ([`resolve_host_v4`]); one that is still
    /// "any IPv4 destination of the host" is ignored, since cutting it would also cut the
    /// host's own flows.
    fn revoke(&self, _revoked: &[Revocation]) -> Result<()> {
        Ok(())
    }

    /// Called once at daemon start, after the first successful apply. Backends whose
    /// states outlive a ruleset swap and are not bound to an interface (pf) drop the states
    /// of every scoped destination, so grants revoked while the daemon was down, or flows
    /// spoofed onto another interface, cannot ride on old states. nftables needs nothing:
    /// it checks original-direction packets against the rules on every packet.
    fn purge_states(&self, _applied: &DesiredRuleset) -> Result<()> {
        Ok(())
    }

    /// Remove everything SocketGuard installed. Only for explicit `disable` / uninstall.
    fn disable(&self) -> Result<()>;

    /// Current counters for rules and scopes, keyed by their ids. Empty if unsupported.
    fn counters(&self) -> Result<Vec<Counter>> {
        Ok(Vec::new())
    }

    /// Start delivering drop events to `sink` (rate-limited by the platform). No-op if
    /// unsupported. Called at most once.
    fn subscribe_drops(&self, _sink: DropSink) -> Result<()> {
        Ok(())
    }
}

/// Create the platform-appropriate firewall
pub fn create_firewall() -> Box<dyn Firewall> {
    #[cfg(target_os = "linux")]
    {
        Box::new(nftables::NftablesFirewall::new())
    }
    #[cfg(target_os = "windows")]
    {
        if socketguard_core::portable::is_portable() {
            Box::new(wfp::WfpFirewall::new_dynamic())
        } else {
            Box::new(wfp::WfpFirewall::new())
        }
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(pf::PfFirewall::new())
    }
}

/// A representative ruleset shared by the renderers' golden tests.
#[cfg(test)]
pub(crate) fn golden_ruleset() -> DesiredRuleset {
    use socketguard_core::{PortRange, PortRef, Protocol};
    let rule = |id: &str, iif: Option<&str>, dst: &str, port, proto, sources| Rule {
        id: id.to_string(),
        iif: iif.map(str::to_string),
        dst: Dst::Addr(dst.parse().unwrap()),
        ports: PortRange::single(PortRef { port, proto }),
        sources,
    };
    DesiredRuleset {
        scopes: vec![
            Scope {
                id: "managed".into(),
                kind: ScopeKind::ManagedAddresses,
                matcher: ScopeMatch::Destinations(vec![
                    "fd00::1".parse().unwrap(),
                    "301::1".parse().unwrap(),
                    "192.0.2.9".parse().unwrap(),
                ]),
            },
            Scope {
                id: "overlay:ygg0".into(),
                kind: ScopeKind::Overlay,
                matcher: ScopeMatch::Interface {
                    name: "ygg0".into(),
                    families: Families::Both,
                },
            },
            Scope {
                id: "overlay:ygg:addr".into(),
                kind: ScopeKind::Overlay,
                matcher: ScopeMatch::DestinationNet("200:1:2:3::5/128".parse().unwrap()),
            },
            Scope {
                id: "overlay:ygg:subnet".into(),
                kind: ScopeKind::Overlay,
                matcher: ScopeMatch::DestinationNet("300:1:2:3::/64".parse().unwrap()),
            },
            Scope {
                id: "host:eth0".into(),
                kind: ScopeKind::WholeHost,
                matcher: ScopeMatch::Interface {
                    name: "eth0".into(),
                    families: Families::Both,
                },
            },
            Scope {
                id: "host:wlan0".into(),
                kind: ScopeKind::WholeHost,
                matcher: ScopeMatch::Interface {
                    name: "wlan0".into(),
                    families: Families::V6,
                },
            },
        ],
        rules: vec![
            rule(
                "a:al1:53:udp:g1:eth0",
                Some("eth0"),
                "fd00::9",
                53,
                Protocol::Udp,
                Sources::Any,
            ),
            rule(
                "a:ay1:8080:tcp:g1",
                None,
                "301::1",
                8080,
                Protocol::Tcp,
                Sources::Nets(vec![
                    "fd00::10/128".parse().unwrap(),
                    "fd00:5::/32".parse().unwrap(),
                ]),
            ),
            rule(
                "a:ay1:8080:tcp:g2:ygg0",
                Some("ygg0"),
                "301::1",
                8080,
                Protocol::Tcp,
                Sources::Nets(vec!["200:1::5/128".parse().unwrap()]),
            ),
            rule(
                "a:av4:22:tcp:g3:eth0",
                Some("eth0"),
                "192.0.2.9",
                22,
                Protocol::Tcp,
                Sources::Nets(vec!["198.51.100.0/24".parse().unwrap()]),
            ),
            // IPv4 grants to the host's own addresses (ADR 0044): peers, and everyone.
            Rule {
                id: "v4:app1:22:tcp:g4:eth0".into(),
                iif: Some("eth0".into()),
                dst: Dst::HostV4,
                ports: PortRange::single(PortRef {
                    port: 22,
                    proto: Protocol::Tcp,
                }),
                sources: Sources::Nets(vec![
                    "192.168.1.5/32".parse().unwrap(),
                    "10.0.20.0/24".parse().unwrap(),
                ]),
            },
            Rule {
                id: "v4:app2:53:udp:g5:eth0".into(),
                iif: Some("eth0".into()),
                dst: Dst::HostV4,
                ports: PortRange::single(PortRef {
                    port: 53,
                    proto: Protocol::Udp,
                }),
                sources: Sources::Any,
            },
            // A segment grant: everyone on the interface's prefix and link-local range.
            rule(
                "a:al1:443:tcp:g6:eth0",
                Some("eth0"),
                "fd00::9",
                443,
                Protocol::Tcp,
                Sources::Nets(vec![
                    "fd00:1:2:3::/64".parse().unwrap(),
                    "fe80::/10".parse().unwrap(),
                ]),
            ),
        ],
    }
}
