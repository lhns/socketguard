// The renderers are pure, so nftables and pf compile (and are golden-tested) everywhere;
// only their command invocations are platform specific.
pub mod nflog;
pub mod nftables;
pub mod pf;
#[cfg(target_os = "windows")]
pub mod wfp;

pub mod desired;

use anyhow::Result;
pub use desired::{
    revocations, safe_text, Counter, DesiredRuleset, DropEvent, DropSink, Families, Revocation,
    Rule, Scope, ScopeKind, ScopeMatch, Sources,
};

/// Platform firewall backend (ADR 0029). Implementations hold no per-socket state: every
/// call to [`Firewall::apply`] replaces SocketGuard's whole ruleset atomically, so a failed
/// apply leaves the previous ruleset in force. Rules survive daemon exit (the state is
/// frozen, ADR 0026); only [`Firewall::disable`] removes them.
pub trait Firewall: Send + Sync {
    /// Atomically replace all SocketGuard rules with `desired`.
    fn apply(&self, desired: &DesiredRuleset) -> Result<()>;

    /// Whether the installed state is still in force (e.g. nobody deleted the table).
    /// Cheap enough to call every reconcile pass; `false` makes the engine re-apply.
    fn verify(&self) -> Result<bool> {
        Ok(true)
    }

    /// Whether interfaces resolve differently from the last apply (WFP binds filters to
    /// interface LUIDs, which change when an adapter is recreated). Cheap; `true` makes
    /// the engine re-apply.
    fn interfaces_changed(&self) -> bool {
        false
    }

    /// Cut established connections that a ruleset change stopped allowing. Called after a
    /// successful apply. Best effort: backends that cannot do it say so in their docs.
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
        Box::new(wfp::WfpFirewall::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(pf::PfFirewall::new())
    }
}

/// A representative ruleset shared by the renderers' golden tests.
#[cfg(test)]
pub(crate) fn golden_ruleset() -> DesiredRuleset {
    use socketguard_core::Protocol;
    let rule = |id: &str, iif: Option<&str>, dst: &str, port, proto, sources| Rule {
        id: id.to_string(),
        iif: iif.map(str::to_string),
        dst: dst.parse().unwrap(),
        port,
        proto,
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
        ],
    }
}
