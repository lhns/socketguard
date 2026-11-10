//! Reach (ADR 0028): how well a credential identifies a source on a network, and the
//! source networks credentials contribute to the firewall.

use crate::credential::{is_tor_key, parse_hex32, ygg_range, ygg_subnet_range};
use crate::model::{Credential, CredentialKind, Network, NetworkId, NetworkKind, Subject};
use crate::yggdrasil::derive_yggdrasil_ipv6;
use ipnet::{IpNet, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

/// How strongly a source is identified on a network.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    /// The source address is verified by a key (Yggdrasil: the interface only delivers
    /// packets from the address its peer's key derives).
    Verified,
    /// A whole subnet is trusted (Yggdrasil verifies the node, not the host behind it).
    WholeSubnet,
    /// Matched by source IP only; spoofable on a shared link.
    IpOnly,
    /// Anyone.
    Open,
    NotReachable,
}

impl Reach {
    /// Strength among credential reaches: Verified > WholeSubnet > IpOnly > the rest.
    fn rank(self) -> u8 {
        match self {
            Reach::Verified => 4,
            Reach::WholeSubnet => 3,
            Reach::IpOnly => 2,
            Reach::Open => 1,
            Reach::NotReachable => 0,
        }
    }

    pub fn best(self, other: Reach) -> Reach {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantReach {
    pub network_id: NetworkId,
    pub reach: Reach,
}

fn is_ygg_subnet_host(addr: Ipv6Addr) -> bool {
    ygg_subnet_range().contains(&addr)
}

/// Whether `name` is a loopback interface (`lo`, `lo0`, "Loopback Pseudo-Interface 1").
/// Local networks on one are this machine only; grants have no effect there.
pub fn is_loopback_interface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "lo" || n == "lo0" || n.contains("loopback")
}

/// How well `credential` identifies a source on `network` (ADR 0028). A network on which
/// grants do not apply (Local on loopback) reaches nothing.
pub fn reach(credential: &Credential, network: &Network) -> Reach {
    if !network.grants_apply {
        return Reach::NotReachable;
    }
    match (credential.kind, network.kind) {
        (CredentialKind::YggKey, NetworkKind::Yggdrasil) => {
            if parse_hex32(&credential.value).is_some() {
                Reach::Verified
            } else {
                Reach::NotReachable
            }
        }
        (CredentialKind::YggAddr, NetworkKind::Yggdrasil) => match credential.value.parse() {
            Ok(a) if is_ygg_subnet_host(a) => Reach::WholeSubnet,
            Ok(a) if ygg_range().contains(&a) => Reach::Verified,
            _ => Reach::NotReachable,
        },
        (CredentialKind::YggSubnet, NetworkKind::Yggdrasil) => Reach::WholeSubnet,
        // Local takes grants only when its interface is not loopback (ADR 0027); it then
        // behaves like any IP network.
        (CredentialKind::Ip, NetworkKind::Lan | NetworkKind::Local) => Reach::IpOnly,
        (CredentialKind::IpSuffix, NetworkKind::Lan | NetworkKind::Local)
            if network.prefix.is_some() =>
        {
            Reach::IpOnly
        }
        // Tor authorizes each client by its key (ClientAuthV3).
        (CredentialKind::TorClientKey, NetworkKind::Tor) if is_tor_key(&credential.value) => {
            Reach::Verified
        }
        _ => Reach::NotReachable,
    }
}

/// The best reach among `credentials` on `network`.
pub fn best_reach(credentials: &[Credential], network: &Network) -> Reach {
    credentials
        .iter()
        .fold(Reach::NotReachable, |acc, c| acc.best(reach(c, network)))
}

/// The source network a credential contributes on `network`, or None when it is
/// `NotReachable` there. Yggdrasil sources must additionally be bound to the network's
/// interface by the caller.
pub fn credential_source(credential: &Credential, network: &Network) -> Option<IpNet> {
    if reach(credential, network) == Reach::NotReachable {
        return None;
    }
    match credential.kind {
        CredentialKind::YggKey => {
            let key = parse_hex32(&credential.value)?;
            Some(IpNet::V6(
                Ipv6Net::new(derive_yggdrasil_ipv6(&key), 128).ok()?,
            ))
        }
        CredentialKind::YggAddr => {
            let a: Ipv6Addr = credential.value.parse().ok()?;
            Some(IpNet::V6(Ipv6Net::new(a, 128).ok()?))
        }
        CredentialKind::YggSubnet | CredentialKind::Ip => {
            credential.value.parse::<Ipv6Net>().ok().map(IpNet::V6)
        }
        CredentialKind::IpSuffix => {
            let suffix: Ipv6Addr = credential.value.parse().ok()?;
            let prefix = network.prefix?;
            let bits = (u128::from(prefix) & !(u64::MAX as u128))
                | (u128::from(suffix) & u64::MAX as u128);
            Some(IpNet::V6(Ipv6Net::new(Ipv6Addr::from(bits), 128).ok()?))
        }
        CredentialKind::WgKey | CredentialKind::TorClientKey | CredentialKind::TlsSpki => None,
    }
}

/// The reach of a grant on each network it applies to: `network_id`, or every network on
/// which grants apply. `credentials` are those of the subject's peers (all peers of a
/// group); `Subject::Anyone` is open everywhere.
pub fn grant_reach(
    subject: &Subject,
    credentials: &[Credential],
    network_id: Option<&str>,
    networks: &[Network],
) -> Vec<GrantReach> {
    networks
        .iter()
        .filter(|n| match network_id {
            Some(id) => n.id == id,
            None => n.grants_apply,
        })
        .map(|n| GrantReach {
            network_id: n.id.clone(),
            reach: match subject {
                Subject::Anyone if n.grants_apply => Reach::Open,
                Subject::Anyone => Reach::NotReachable,
                _ => best_reach(credentials, n),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixtures::{cred, net, KEY, TOR_KEY};

    #[test]
    fn reach_table_every_cell() {
        use CredentialKind as C;
        use NetworkKind as N;
        use Reach::*;
        let creds: [(Credential, [Reach; 5]); 10] = [
            // Local, Lan, Yggdrasil, WireGuard, Tor
            (
                cred(C::YggKey, KEY),
                [
                    NotReachable,
                    NotReachable,
                    Verified,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::YggAddr, "200:1::5"),
                [
                    NotReachable,
                    NotReachable,
                    Verified,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::YggAddr, "300:1:2:3::5"),
                [
                    NotReachable,
                    NotReachable,
                    WholeSubnet,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::YggSubnet, "300:1:2:3::/64"),
                [
                    NotReachable,
                    NotReachable,
                    WholeSubnet,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::Ip, "fd00::5/128"),
                [
                    NotReachable,
                    IpOnly,
                    NotReachable,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (
                cred(C::IpSuffix, "::a:b:c:d"),
                [
                    NotReachable,
                    IpOnly,
                    NotReachable,
                    NotReachable,
                    NotReachable,
                ],
            ),
            (cred(C::WgKey, "AAAA"), [NotReachable; 5]),
            (
                cred(C::TorClientKey, TOR_KEY),
                [
                    NotReachable,
                    NotReachable,
                    NotReachable,
                    NotReachable,
                    Verified,
                ],
            ),
            (cred(C::TorClientKey, "AAAA"), [NotReachable; 5]),
            (cred(C::TlsSpki, "AAAA"), [NotReachable; 5]),
        ];
        let kinds = [N::Local, N::Lan, N::Yggdrasil, N::WireGuard, N::Tor];
        for (c, expected) in &creds {
            for (k, want) in kinds.iter().zip(expected) {
                let n = net("n", *k, Some("fd00:1:2:3::"));
                assert_eq!(reach(c, &n), *want, "{:?} on {:?}", c.kind, k);
            }
        }
    }

    #[test]
    fn local_on_a_real_interface_takes_grants() {
        let mut local = net("local", NetworkKind::Local, Some("fd00:1:2:3::"));
        local.grants_apply = true;
        let ip = cred(CredentialKind::Ip, "fd00::5/128");
        let suffix = cred(CredentialKind::IpSuffix, "::a:b:c:d");
        let key = cred(CredentialKind::YggKey, KEY);
        assert_eq!(reach(&ip, &local), Reach::IpOnly);
        assert_eq!(reach(&suffix, &local), Reach::IpOnly);
        assert_eq!(reach(&key, &local), Reach::NotReachable);
        assert!(credential_source(&ip, &local).is_some());
        local.prefix = None;
        assert_eq!(reach(&suffix, &local), Reach::NotReachable);
        // Loopback keeps it machine-only.
        local.grants_apply = false;
        assert_eq!(reach(&ip, &local), Reach::NotReachable);
    }

    #[test]
    fn loopback_interface_names() {
        for n in ["lo", "lo0", "Loopback Pseudo-Interface 1"] {
            assert!(is_loopback_interface(n), "{n}");
        }
        for n in ["eth0", "dummy0", "Ethernet", "lo1"] {
            assert!(!is_loopback_interface(n), "{n}");
        }
    }

    #[test]
    fn ip_suffix_needs_a_prefix() {
        let c = cred(CredentialKind::IpSuffix, "::a:b:c:d");
        let lan = net("lan", NetworkKind::Lan, None);
        assert_eq!(reach(&c, &lan), Reach::NotReachable);
        assert_eq!(credential_source(&c, &lan), None);
        let lan = net("lan", NetworkKind::Lan, Some("2001:db8:1:2::"));
        assert_eq!(reach(&c, &lan), Reach::IpOnly);
        assert_eq!(
            credential_source(&c, &lan),
            Some("2001:db8:1:2:a:b:c:d/128".parse().unwrap())
        );
        let moved = net("lan", NetworkKind::Lan, Some("2001:db8:9:9::"));
        assert_eq!(
            credential_source(&c, &moved),
            Some("2001:db8:9:9:a:b:c:d/128".parse().unwrap())
        );
    }

    #[test]
    fn grants_do_not_apply_on_a_network_that_says_so() {
        let mut lan = net("lan", NetworkKind::Lan, None);
        lan.grants_apply = false;
        assert_eq!(
            reach(&cred(CredentialKind::Ip, "fd00::5/128"), &lan),
            Reach::NotReachable
        );
    }

    #[test]
    fn credential_sources() {
        let ygg = net("ygg", NetworkKind::Yggdrasil, None);
        let lan = net("lan", NetworkKind::Lan, None);
        assert_eq!(
            credential_source(&cred(CredentialKind::YggKey, KEY), &ygg),
            Some(
                "200:8af8:ba35:56ae:bef0:6284:981f:5972/128"
                    .parse()
                    .unwrap()
            )
        );
        assert_eq!(
            credential_source(&cred(CredentialKind::YggKey, KEY), &lan),
            None
        );
        assert_eq!(
            credential_source(&cred(CredentialKind::YggSubnet, "300:1:2:3::/64"), &ygg),
            Some("300:1:2:3::/64".parse().unwrap())
        );
        assert_eq!(
            credential_source(&cred(CredentialKind::Ip, "fd00::/48"), &lan),
            Some("fd00::/48".parse().unwrap())
        );
    }

    #[test]
    fn best_reach_prefers_the_strongest_credential() {
        let ygg = net("ygg", NetworkKind::Yggdrasil, None);
        let creds = [
            cred(CredentialKind::YggSubnet, "300:1:2:3::/64"),
            cred(CredentialKind::Ip, "fd00::1/128"),
            cred(CredentialKind::YggKey, KEY),
        ];
        assert_eq!(best_reach(&creds, &ygg), Reach::Verified);
        assert_eq!(best_reach(&creds[..2], &ygg), Reach::WholeSubnet);
        assert_eq!(best_reach(&[], &ygg), Reach::NotReachable);
    }

    #[test]
    fn grant_reach_covers_applicable_networks() {
        let nets = [
            net("local", NetworkKind::Local, None),
            net("lan", NetworkKind::Lan, None),
            net("ygg", NetworkKind::Yggdrasil, None),
        ];
        let creds = [cred(CredentialKind::YggKey, KEY)];
        let r = grant_reach(&Subject::Peer("p".into()), &creds, None, &nets);
        assert_eq!(
            r,
            vec![
                GrantReach {
                    network_id: "lan".into(),
                    reach: Reach::NotReachable
                },
                GrantReach {
                    network_id: "ygg".into(),
                    reach: Reach::Verified
                },
            ]
        );
        let r = grant_reach(&Subject::Anyone, &[], None, &nets);
        assert!(r.iter().all(|g| g.reach == Reach::Open) && r.len() == 2);
        let r = grant_reach(&Subject::Anyone, &[], Some("ygg"), &nets);
        assert_eq!(r.len(), 1);
    }
}
