//! Parsing of the small mini-languages of the command line: `app:port/proto`, subjects,
//! credentials. Pure functions, unit tested.

use anyhow::{anyhow, bail, Result};
use socketguard_core::{CredentialKind, NewCredential, PortRef, Protocol};

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

/// `nginx`, `nginx:80`, `nginx:53/udp`. The text after the last `:` is a port only if it
/// parses as one, so app names with a colon still work.
pub fn parse_target(s: &str) -> (String, Option<PortRef>) {
    if let Some((app, port)) = s.rsplit_once(':') {
        if !app.is_empty() {
            if let Ok(p) = parse_port(port) {
                return (app.to_string(), Some(p));
            }
        }
    }
    (s.to_string(), None)
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

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn kinds() -> String {
    CredentialKind::ALL.map(|k| k.as_str()).join(", ")
}

/// A bare credential value: 64 hex characters are a Yggdrasil key, an IP address or CIDR
/// is `ip` (the daemon turns values in 200::/7 into `ygg_addr` or `ygg_subnet`).
pub fn guess_credential(value: &str) -> Result<NewCredential> {
    let kind = if is_hex64(value) {
        CredentialKind::YggKey
    } else if looks_like_ip(value) {
        CredentialKind::Ip
    } else {
        bail!(
            "cannot tell what {value:?} is; use --key, --addr, --subnet, --suffix or \
             --cred kind=value (kinds: {})",
            kinds()
        );
    };
    Ok(cred(kind, value))
}

fn looks_like_ip(s: &str) -> bool {
    let addr = s.split_once('/').map_or(s, |(a, _)| a);
    addr.parse::<std::net::IpAddr>().is_ok()
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
        assert_eq!(parse_target("nginx"), ("nginx".into(), None));
        assert_eq!(parse_target("nginx:8080").1.unwrap().port, 8080);
        assert_eq!(parse_target("dns:53/udp").1.unwrap().proto, Protocol::Udp);
        // Not a port: the whole text is the app.
        assert_eq!(
            parse_target("node:server.js"),
            ("node:server.js".into(), None)
        );
        assert_eq!(parse_target(":80"), (":80".into(), None));
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
    fn bare_credentials_are_guessed() {
        let key = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";
        assert_eq!(guess_credential(key).unwrap().kind, CredentialKind::YggKey);
        for ip in ["2001:db8::1", "2001:db8::/64", "10.0.0.1"] {
            assert_eq!(guess_credential(ip).unwrap().kind, CredentialKind::Ip);
        }
        let err = guess_credential("hello").unwrap_err().to_string();
        assert!(err.contains("--cred kind=value"), "{err}");
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
