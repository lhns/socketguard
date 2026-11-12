//! Parsing of the small mini-languages of the command line: `app:port/proto`, subjects,
//! credentials. Pure functions, unit tested.

use anyhow::{anyhow, bail, Result};
use socketguard_core::{parse_input, CredentialKind, NewCredential, PortRef, Protocol};

/// `80`, `80/tcp`, `53/udp`; the protocol defaults to tcp.
pub fn parse_port(s: &str) -> Result<PortRef> {
    let (port, proto) = match s.split_once('/') {
        Some((p, proto)) => (p, proto.parse::<Protocol>().map_err(|e| anyhow!(e))?),
        None => (s, Protocol::Tcp),
    };
    let port: u16 = port.parse().map_err(|_| {
        anyhow!("invalid port {port:?} (expected 1-65535, optionally /tcp or /udp)")
    })?;
    if port == 0 {
        bail!("port 0 is not valid");
    }
    Ok(PortRef { port, proto })
}

/// Which ports of a target, by name as typed (a port group by label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSpec {
    All,
    Port(PortRef),
    Group(String),
}

/// The marker of a port group in `<app>:port-group=<label>`.
pub const PORT_GROUP_MARKER: &str = ":port-group=";

/// `nginx`, `nginx:80`, `nginx:53/udp`, `nginx:port-group=passive`. The text after the
/// last `:` is a port only if it parses as one, so app names with a colon still work; the
/// port group marker is recognised anywhere, so group labels may contain colons too.
pub fn parse_target(s: &str) -> (String, ScopeSpec) {
    if let Some(at) = s.rfind(PORT_GROUP_MARKER) {
        let label = &s[at + PORT_GROUP_MARKER.len()..];
        if at > 0 && !label.is_empty() {
            return (s[..at].to_string(), ScopeSpec::Group(label.to_string()));
        }
    }
    if let Some((app, port)) = s.rsplit_once(':') {
        if !app.is_empty() {
            if let Ok(p) = parse_port(port) {
                return (app.to_string(), ScopeSpec::Port(p));
            }
        }
    }
    (s.to_string(), ScopeSpec::All)
}

/// `80/tcp`, `50000-51000/udp`, repeated: the ports of a port group, normalized.
pub fn parse_ranges(items: &[String]) -> Result<Vec<socketguard_core::PortRange>> {
    socketguard_core::parse_ranges(items).map_err(|e| anyhow!(e))
}

/// What a grant covers, by name as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSpec {
    App(String),
    Tag(String),
    Reservation(String),
}

/// [`parse_target`] that also takes `tag:<label>[:port[/proto]]` and `reservation:<label>`.
/// A reservation is always granted whole: a scope typed after its label is returned for the
/// caller to refuse, with the label cut off before it.
pub fn parse_target_spec(s: &str) -> (TargetSpec, ScopeSpec) {
    if let Some(rest) = s.strip_prefix("tag:") {
        let (label, port) = parse_target(rest);
        (TargetSpec::Tag(label), port)
    } else if let Some(rest) = s.strip_prefix("reservation:") {
        let (label, port) = parse_target(rest);
        (TargetSpec::Reservation(label), port)
    } else {
        let (app, port) = parse_target(s);
        (TargetSpec::App(app), port)
    }
}

/// Who a grant is for, by name as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectSpec {
    Peer(String),
    Group(String),
    Anyone,
}

/// `anyone`, `group:<label>`, or a peer label.
pub fn parse_subject(s: &str) -> SubjectSpec {
    if s == "anyone" {
        SubjectSpec::Anyone
    } else if let Some(g) = s.strip_prefix("group:") {
        SubjectSpec::Group(g.to_string())
    } else {
        SubjectSpec::Peer(s.to_string())
    }
}

fn kinds() -> String {
    CredentialKind::ALL.map(|k| k.as_str()).join(", ")
}

/// Bare credential values (any mix of spaces, commas and newlines), classified by the one
/// parser in core: see `socketguard_core::parse_input`.
pub fn guess_credentials(text: &str) -> Result<Vec<NewCredential>> {
    let parsed = parse_input(text);
    if parsed.is_empty() {
        bail!("no credential given");
    }
    parsed
        .into_iter()
        .map(|p| match (p.kind, p.normalized, p.error) {
            (Some(kind), Some(value), None) => Ok(cred(kind, &value)),
            (_, _, error) => bail!(
                "{}: {} (or use --key, --addr, --subnet, --suffix, --cred kind=value;                  kinds: {})",
                p.input,
                error.unwrap_or_default(),
                kinds()
            ),
        })
        .collect()
}

/// `kind=value`.
pub fn parse_cred(s: &str) -> Result<NewCredential> {
    let (kind, value) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("expected kind=value, got {s:?}"))?;
    let kind: CredentialKind = kind
        .trim()
        .parse()
        .map_err(|e: String| anyhow!("{e} (kinds: {})", kinds()))?;
    Ok(cred(kind, value.trim()))
}

pub fn cred(kind: CredentialKind, value: &str) -> NewCredential {
    NewCredential {
        kind,
        value: value.to_string(),
        label: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports() {
        assert_eq!(
            parse_port("80").unwrap(),
            PortRef {
                port: 80,
                proto: Protocol::Tcp
            }
        );
        assert_eq!(parse_port("53/udp").unwrap().proto, Protocol::Udp);
        assert!(parse_port("0").is_err());
        assert!(parse_port("70000").is_err());
        assert!(parse_port("80/sctp").is_err());
    }

    #[test]
    fn targets() {
        assert_eq!(parse_target("nginx"), ("nginx".into(), ScopeSpec::All));
        assert_eq!(
            parse_target("nginx:8080").1,
            ScopeSpec::Port(PortRef {
                port: 8080,
                proto: Protocol::Tcp
            })
        );
        assert!(matches!(
            parse_target("dns:53/udp").1,
            ScopeSpec::Port(p) if p.proto == Protocol::Udp
        ));
        // Not a port: the whole text is the app.
        assert_eq!(
            parse_target("node:server.js"),
            ("node:server.js".into(), ScopeSpec::All)
        );
        assert_eq!(parse_target(":80"), (":80".into(), ScopeSpec::All));
    }

    #[test]
    fn port_group_targets() {
        assert_eq!(
            parse_target("ftpd:port-group=passive"),
            ("ftpd".into(), ScopeSpec::Group("passive".into()))
        );
        // An app name with a colon, and a label with one.
        assert_eq!(
            parse_target("node:server.js:port-group=a:b"),
            ("node:server.js".into(), ScopeSpec::Group("a:b".into()))
        );
        // No label or no app: not a group.
        assert_eq!(
            parse_target("ftpd:port-group="),
            ("ftpd:port-group=".into(), ScopeSpec::All)
        );
        assert_eq!(
            parse_target(":port-group=x"),
            (":port-group=x".into(), ScopeSpec::All)
        );
        assert_eq!(
            parse_target_spec("tag:dev:port-group=passive"),
            (
                TargetSpec::Tag("dev".into()),
                ScopeSpec::Group("passive".into())
            )
        );
    }

    #[test]
    fn port_ranges_of_a_port_group() {
        let r =
            parse_ranges(&["443/tcp".into(), "50000-51000/tcp".into(), "80/tcp".into()]).unwrap();
        assert_eq!(
            r.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
            ["80/tcp", "443/tcp", "50000-51000/tcp"]
        );
        assert!(parse_ranges(&["80".into()]).is_err());
        assert!(parse_ranges(&["9-5/tcp".into()]).is_err());
    }

    #[test]
    fn tag_targets() {
        assert_eq!(
            parse_target_spec("tag:dev"),
            (TargetSpec::Tag("dev".into()), ScopeSpec::All)
        );
        let (t, p) = parse_target_spec("tag:dev:53/udp");
        assert_eq!(t, TargetSpec::Tag("dev".into()));
        assert!(matches!(p, ScopeSpec::Port(p) if p.proto == Protocol::Udp));
        assert_eq!(
            parse_target_spec("nginx:80").0,
            TargetSpec::App("nginx".into())
        );
    }

    #[test]
    fn reservation_targets() {
        assert_eq!(
            parse_target_spec("reservation:web"),
            (TargetSpec::Reservation("web".into()), ScopeSpec::All)
        );
        // A scope is parsed so that the caller can refuse it.
        assert!(matches!(
            parse_target_spec("reservation:web:80").1,
            ScopeSpec::Port(_)
        ));
    }

    #[test]
    fn subjects() {
        assert_eq!(parse_subject("anyone"), SubjectSpec::Anyone);
        assert_eq!(
            parse_subject("group:team"),
            SubjectSpec::Group("team".into())
        );
        assert_eq!(parse_subject("alice"), SubjectSpec::Peer("alice".into()));
    }

    #[test]
    fn bare_credentials_are_classified_by_the_core_parser() {
        let key = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";
        let got = guess_credentials(key).unwrap();
        assert_eq!(got[0].kind, CredentialKind::YggKey);
        let got = guess_credentials(
            "2001:db8::1, 10.0.0.1
200:1::5",
        )
        .unwrap();
        let kinds: Vec<_> = got.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            [
                CredentialKind::Ip,
                CredentialKind::Ip,
                CredentialKind::YggAddr
            ]
        );
        assert_eq!(got[1].value, "10.0.0.1/32");
        let tor = "ZGBMJ4VIRNVUOQ5SJ2JXPSSWHB2R4YGTKPDGSMZ4HWCD5WLT2YKQ";
        let got = guess_credentials(&format!("descriptor:x25519:{tor}")).unwrap();
        assert_eq!(got[0].kind, CredentialKind::TorClientKey);
        let err = guess_credentials("hello").unwrap_err().to_string();
        assert!(err.contains("--cred kind=value"), "{err}");
        assert!(guess_credentials("200::").is_err());
        assert!(guess_credentials("  ").is_err());
    }

    #[test]
    fn kind_value_pairs() {
        let c = parse_cred("wg_key=abc=").unwrap();
        assert_eq!((c.kind, c.value.as_str()), (CredentialKind::WgKey, "abc="));
        assert!(parse_cred("nokind").is_err());
        assert!(parse_cred("bogus=1")
            .unwrap_err()
            .to_string()
            .contains("kinds:"));
    }
}
