//! Credential normalization (ADR 0028): validate what a user typed and store one canonical
//! form per credential.

use crate::model::{Credential, CredentialKind, Network, NetworkKind, NetworkStatus};
use crate::reach::{reach, Reach};
use data_encoding::{
    BASE32_NOPAD, BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD, HEXLOWER_PERMISSIVE,
};
use ipnet::{IpNet, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, CredentialError> {
    Err(CredentialError::Invalid(msg.into()))
}

pub(crate) fn ygg_range() -> Ipv6Net {
    "200::/7".parse().unwrap()
}

pub(crate) fn ygg_subnet_range() -> Ipv6Net {
    "300::/8".parse().unwrap()
}

/// Parse an IP address or CIDR.
fn parse_ip_or_net(value: &str) -> Result<IpNet, CredentialError> {
    let value = value.trim();
    match value.parse::<IpNet>() {
        Ok(n) => Ok(n),
        Err(_) => match value.parse::<IpAddr>() {
            Ok(a) => Ok(IpNet::from(a)),
            Err(_) => invalid(format!("{value:?} is not an IP address or network")),
        },
    }
}

/// Decode `value` as 64 hex characters (either case).
pub fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    HEXLOWER_PERMISSIVE
        .decode(value.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

/// Base64 in the standard or URL-safe alphabet, with or without padding.
fn is_base64(value: &str) -> bool {
    let v = value.as_bytes();
    !v.is_empty()
        && [BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD]
            .iter()
            .any(|e| e.decode(v).is_ok())
}

/// Validate and normalize a credential value, returning the kind to store and the
/// canonical value. Rejects invalid input with a message for the user.
///
/// - `YggKey`: 64 hex characters, stored lowercase.
/// - `YggAddr`: one address in `200::/7`, stored as an address.
/// - `YggSubnet`: a /64 in `300::/8`, stored as `net/64`.
/// - `Ip`: an IPv4 or IPv6 address or CIDR, stored as `net/len` (`/32` or `/128` for a
///   single address). A value inside `200::/7` becomes `YggAddr` or `YggSubnet`; other
///   networks in that range are rejected.
/// - `IpSuffix`: an interface ID written as an address with zero upper 64 bits
///   (`::a:b:c:d`, optionally followed by `/64`), stored as the address.
/// - `TorClientKey`: an x25519 public key in base32 (52 characters), or a full
///   `descriptor:x25519:<base32>` authorized_clients line; stored as the bare key,
///   uppercase.
/// - `WgKey`, `TlsSpki`: base64, stored as given.
pub fn normalize_credential(
    kind: CredentialKind,
    value: &str,
) -> Result<(CredentialKind, String), CredentialError> {
    let value = value.trim();
    match kind {
        CredentialKind::YggKey => match parse_hex32(value) {
            Some(_) => Ok((kind, value.to_ascii_lowercase())),
            None => invalid("a Yggdrasil key is 64 hex characters"),
        },
        CredentialKind::TorClientKey => normalize_tor_key(value).map(|k| (kind, k)),
        CredentialKind::WgKey | CredentialKind::TlsSpki => {
            if is_base64(value) {
                Ok((kind, value.to_string()))
            } else {
                invalid(format!("{kind} must be base64"))
            }
        }
        CredentialKind::IpSuffix => {
            let addr_part = value.strip_suffix("/64").unwrap_or(value);
            let addr: Ipv6Addr = match addr_part.parse() {
                Ok(a) => a,
                Err(_) => return invalid("an interface ID looks like ::a:b:c:d"),
            };
            if (u128::from(addr) >> 64) != 0 {
                return invalid("an interface ID has zero upper 64 bits (::a:b:c:d)");
            }
            if addr == Ipv6Addr::UNSPECIFIED {
                return invalid("an interface ID must not be zero");
            }
            Ok((kind, addr.to_string()))
        }
        CredentialKind::YggAddr | CredentialKind::YggSubnet | CredentialKind::Ip => {
            let net = match parse_ip_or_net(value)? {
                IpNet::V6(n) => n,
                IpNet::V4(n) if kind == CredentialKind::Ip => {
                    if n.prefix_len() == 0 {
                        return invalid(
                            "0.0.0.0/0 would match every source; grant to Anyone instead",
                        );
                    }
                    return Ok((kind, n.trunc().to_string()));
                }
                IpNet::V4(_) => return invalid("a Yggdrasil value is an IPv6 address in 200::/7"),
            };
            let in_ygg = ygg_range().contains(&net);
            // A plain IP network must not contain the Yggdrasil range (`::/6`, `::/0`): it
            // would trust overlay sources without the interface binding. Networks inside
            // the range are normalized as Yggdrasil values below.
            if kind == CredentialKind::Ip && net.prefix_len() == 0 {
                return invalid("::/0 would match every source; grant to Anyone instead");
            }
            if kind == CredentialKind::Ip && !in_ygg && net.contains(&ygg_range()) {
                return invalid("this network crosses the Yggdrasil range 200::/7");
            }
            if in_ygg || kind != CredentialKind::Ip {
                // Yggdrasil value: a single address, or a /64 in 300::/8.
                return normalize_ygg(kind, net);
            }
            Ok((CredentialKind::Ip, net.trunc().to_string()))
        }
    }
}

// --- Parsing pasted input ----------------------------------------------------

/// Where a credential identifies its holder: one network kind and how strongly.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkReach {
    pub network_kind: NetworkKind,
    pub reach: Reach,
}

/// One value of pasted input, classified (ADR 0045). Exactly one of `normalized` and
/// `error` is set.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedCredential {
    /// The value as typed.
    pub input: String,
    /// The kind it would be stored as; on an error, the kind it looked like (if any).
    pub kind: Option<CredentialKind>,
    /// The canonical value to store.
    pub normalized: Option<String>,
    /// The network kinds it works on; empty on error.
    pub reach: Vec<NetworkReach>,
    pub error: Option<String>,
}

/// Network kinds worth showing a reach for.
const REACH_KINDS: [NetworkKind; 3] = [NetworkKind::Lan, NetworkKind::Yggdrasil, NetworkKind::Tor];

fn reach_of(kind: CredentialKind, value: &str) -> Vec<NetworkReach> {
    let credential = Credential {
        id: String::new(),
        kind,
        value: value.to_string(),
        label: None,
    };
    REACH_KINDS
        .into_iter()
        .filter_map(|network_kind| {
            // A /64, so that an `IpSuffix` resolves.
            let network = Network {
                id: String::new(),
                kind: network_kind,
                name: String::new(),
                interface: None,
                grants_apply: true,
                status: NetworkStatus::Up,
                prefix: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)),
                vlan_id: None,
                child: None,
            };
            match reach(&credential, &network) {
                Reach::NotReachable => None,
                r => Some(NetworkReach {
                    network_kind,
                    reach: r,
                }),
            }
        })
        .collect()
}

fn looks_like_ip(value: &str) -> bool {
    value.parse::<IpNet>().is_ok() || value.parse::<IpAddr>().is_ok()
}

/// Split pasted text into values (newlines, commas, whitespace) and classify each one, in
/// this order: 64 hex characters are a `ygg_key`; an IP address or CIDR is an `ip`
/// (`normalize_credential` files 200::/7 values under `ygg_addr` / `ygg_subnet`); a Tor
/// client key or `descriptor:x25519:` line is a `tor_client_key`. `wg_key` and `tls_spki`
/// are never guessed (base64 overlaps the other formats): they need an explicit kind.
pub fn parse_input(text: &str) -> Vec<ParsedCredential> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|v| !v.is_empty())
        .map(parse_value)
        .collect()
}

fn parse_value(value: &str) -> ParsedCredential {
    let detected = if parse_hex32(value).is_some() {
        Some(CredentialKind::YggKey)
    } else if looks_like_ip(value) {
        Some(CredentialKind::Ip)
    } else if normalize_credential(CredentialKind::TorClientKey, value).is_ok() {
        Some(CredentialKind::TorClientKey)
    } else {
        None
    };
    let result = match detected {
        Some(kind) => normalize_credential(kind, value).map_err(|e| e.to_string()),
        None => Err(format!(
            "cannot tell what {value:?} is: expected a 64-character Yggdrasil key, an IP              address or network, or a Tor client key (a WireGuard or TLS key needs its kind              stated)"
        )),
    };
    match result {
        Ok((kind, normalized)) => ParsedCredential {
            input: value.to_string(),
            kind: Some(kind),
            reach: reach_of(kind, &normalized),
            normalized: Some(normalized),
            error: None,
        },
        Err(error) => ParsedCredential {
            input: value.to_string(),
            kind: detected,
            normalized: None,
            reach: Vec::new(),
            error: Some(error),
        },
    }
}

/// One realistic value per kind of credential, for placeholders and help text. The UI gets
/// them as generated TypeScript (`credentialExamples.ts`), so no frontend invents its own.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialExample {
    /// What `parse_input` files the value under.
    pub kind: CredentialKind,
    pub value: &'static str,
    /// What the value is, in a few words.
    pub what: &'static str,
}

pub const CREDENTIAL_EXAMPLES: &[CredentialExample] = &[
    CredentialExample {
        kind: CredentialKind::YggKey,
        value: "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b",
        what: "Yggdrasil public key",
    },
    CredentialExample {
        kind: CredentialKind::YggAddr,
        value: "200:8af8:ba35:56ae:bef0:6284:981f:5972",
        what: "Yggdrasil address",
    },
    CredentialExample {
        kind: CredentialKind::YggSubnet,
        value: "301:5c1a:8e4b:2f90::/64",
        what: "Yggdrasil subnet",
    },
    CredentialExample {
        kind: CredentialKind::Ip,
        value: "192.168.1.20",
        what: "IPv4 address",
    },
    CredentialExample {
        kind: CredentialKind::Ip,
        value: "10.0.20.0/24",
        what: "IPv4 network",
    },
    CredentialExample {
        kind: CredentialKind::Ip,
        value: "fd00:1234:5678::5",
        what: "IPv6 address",
    },
    CredentialExample {
        kind: CredentialKind::TorClientKey,
        value: "ZGBMJ4VIRNVUOQ5SJ2JXPSSWHB2R4YGTKPDGSMZ4HWCD5WLT2YKQ",
        what: "Tor client key",
    },
];

/// The x25519 points of small order (RFC 7748 / libsodium blocklist) in canonical and
/// non-canonical form, with the unused top bit cleared. A client key like these gives a
/// shared secret an observer can guess, so an authorization with it protects nothing.
const SMALL_ORDER: [[u8; 32]; 7] = [
    [0; 32],
    {
        let mut k = [0; 32];
        k[0] = 1;
        k
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    p_plus(0xec),
    p_plus(0xed),
    p_plus(0xee),
];

/// A value just below 2^255 (p-1, p, p+1 with p = 2^255 - 19), as little-endian bytes, by
/// its lowest byte.
const fn p_plus(low: u8) -> [u8; 32] {
    let mut k = [0xff; 32];
    k[0] = low;
    k[31] = 0x7f;
    k
}

/// 52 base32 characters (RFC 4648, no padding, no stray trailing bits) as the 32 bytes
/// they encode.
fn decode_tor_key(key: &str) -> Option<[u8; 32]> {
    BASE32_NOPAD.decode(key.as_bytes()).ok()?.try_into().ok()
}

/// Whether `key` is a Tor v3 client-auth public key: 52 base32 characters (no padding)
/// encoding 32 bytes, so the last character carries no extra bits, and not a small-order
/// point.
pub(crate) fn is_tor_key(key: &str) -> bool {
    let Some(mut point) = decode_tor_key(key) else {
        return false;
    };
    point[31] &= 0x7f;
    !SMALL_ORDER.contains(&point)
}

fn normalize_tor_key(value: &str) -> Result<String, CredentialError> {
    let bare = match value.rsplit_once(':') {
        Some((prefix, key)) => {
            if !prefix.eq_ignore_ascii_case("descriptor:x25519") {
                return invalid(
                    "a Tor client key is 52 base32 characters, or a line like \
                     descriptor:x25519:<key> from authorized_clients",
                );
            }
            key
        }
        None => value,
    };
    let key = bare.to_ascii_uppercase();
    if is_tor_key(&key) {
        Ok(key)
    } else {
        invalid("a Tor client key is a public key in base32 (52 characters)")
    }
}

fn normalize_ygg(
    kind: CredentialKind,
    net: Ipv6Net,
) -> Result<(CredentialKind, String), CredentialError> {
    if !ygg_range().contains(&net) {
        return invalid("a Yggdrasil address is in 200::/7");
    }
    // The network bases are what a placeholder or a half-typed address looks like.
    let base = net.network();
    if base == Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 0)
        || base == Ipv6Addr::new(0x300, 0, 0, 0, 0, 0, 0, 0)
    {
        return invalid(format!(
            "{} is the start of the Yggdrasil range, not a node's address",
            net.addr()
        ));
    }
    match net.prefix_len() {
        128 if kind != CredentialKind::YggSubnet => {
            Ok((CredentialKind::YggAddr, net.addr().to_string()))
        }
        64 if kind != CredentialKind::YggAddr => {
            if !ygg_subnet_range().contains(&net) {
                return invalid("a Yggdrasil subnet is a /64 in 300::/8");
            }
            Ok((CredentialKind::YggSubnet, net.trunc().to_string()))
        }
        _ => match kind {
            CredentialKind::YggAddr => invalid("a Yggdrasil address is a single address"),
            CredentialKind::YggSubnet => invalid("a Yggdrasil subnet is a /64 in 300::/8"),
            _ => invalid("only a single Yggdrasil address or a /64 in 300::/8 is supported"),
        },
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixtures::{cred, net, KEY, TOR_KEY};
    use crate::model::NetworkKind;
    use crate::reach::{reach, Reach};

    fn norm(kind: CredentialKind, v: &str) -> Result<(CredentialKind, String), String> {
        normalize_credential(kind, v).map_err(|e| e.to_string())
    }

    #[test]
    fn ipv4_is_an_ip_credential_only() {
        use CredentialKind::*;
        assert_eq!(
            norm(Ip, "192.168.1.5").unwrap(),
            (Ip, "192.168.1.5/32".into())
        );
        assert_eq!(norm(Ip, "10.1.2.3/8").unwrap(), (Ip, "10.0.0.0/8".into()));
        assert!(norm(Ip, "0.0.0.0/0")
            .unwrap_err()
            .contains("grant to Anyone"));
        for k in [YggAddr, YggSubnet, IpSuffix] {
            assert!(norm(k, "192.168.1.5").is_err(), "{k}");
        }
    }

    #[test]
    fn ip_normalization() {
        use CredentialKind::*;
        assert_eq!(norm(Ip, "FD00::5").unwrap(), (Ip, "fd00::5/128".into()));
        assert_eq!(norm(Ip, "fd00::5/128").unwrap(), (Ip, "fd00::5/128".into()));
        assert_eq!(
            norm(Ip, "fd00:1:2::7/48").unwrap(),
            (Ip, "fd00:1:2::/48".into())
        );
        assert!(norm(Ip, "::/0").unwrap_err().contains("grant to Anyone"));
        assert!(norm(Ip, "not an ip").is_err());
    }

    #[test]
    fn ygg_range_values_are_renormalized() {
        use CredentialKind::*;
        // 200::/7 values given as plain Ip become Yggdrasil credentials.
        assert_eq!(norm(Ip, "200:1::5").unwrap(), (YggAddr, "200:1::5".into()));
        assert_eq!(
            norm(Ip, "200:1::5/128").unwrap(),
            (YggAddr, "200:1::5".into())
        );
        assert_eq!(
            norm(Ip, "300:1:2:3::/64").unwrap(),
            (YggSubnet, "300:1:2:3::/64".into())
        );
        assert_eq!(
            norm(Ip, "300:1:2:3::9/64").unwrap(),
            (YggSubnet, "300:1:2:3::/64".into())
        );
        // A host behind a Yggdrasil node is a YggAddr in 300::/8, reached as WholeSubnet.
        let (k, v) = norm(Ip, "300:1:2:3::5").unwrap();
        assert_eq!((k, v.as_str()), (YggAddr, "300:1:2:3::5"));
        let ygg = net("ygg", NetworkKind::Yggdrasil, None);
        assert_eq!(reach(&cred(k, &v), &ygg), Reach::WholeSubnet);
        // Other networks in the range are rejected.
        assert!(norm(Ip, "200::/16").is_err());
        assert!(norm(Ip, "300:1:2::/48").is_err());
        assert!(norm(Ip, "200::/6").is_err());
        // Networks that contain the range (`::/6`, `::/1`, `::/0`) must not pass as plain IP.
        for wide in ["::/6", "::/1", "::/3", "200::/6"] {
            let err = norm(Ip, wide).unwrap_err();
            assert!(err.contains("crosses the Yggdrasil range"), "{wide}: {err}");
        }
        let err = norm(Ip, "::/0").unwrap_err();
        assert!(err.contains("grant to Anyone"), "{err}");
        assert!(norm(Ip, "2001:db8::/32").is_ok());
        assert!(norm(Ip, "fc00::/7").is_ok());
        // Explicit kinds validate their shape.
        assert!(norm(YggAddr, "fd00::1").is_err());
        assert!(norm(YggAddr, "300:1:2:3::/64").is_err());
        assert!(norm(YggSubnet, "300:1:2:3::5").is_err());
        assert!(norm(YggSubnet, "200:1:2:3::/64").is_err());
        assert_eq!(
            norm(YggSubnet, "300:1:2:3::/64").unwrap(),
            (YggSubnet, "300:1:2:3::/64".into())
        );
    }

    #[test]
    fn ygg_key_normalization() {
        use CredentialKind::*;
        assert_eq!(
            norm(YggKey, &KEY.to_uppercase()).unwrap(),
            (YggKey, KEY.into())
        );
        assert!(norm(YggKey, "abcd").is_err());
        assert!(norm(YggKey, &"zz".repeat(32)).is_err());
        // Not hex, though `from_str_radix` takes a sign.
        assert!(norm(YggKey, &format!("+a{}", "00".repeat(31))).is_err());
    }

    #[test]
    fn ip_suffix_with_and_without_slash_64() {
        use CredentialKind::*;
        assert_eq!(
            norm(IpSuffix, "::a:b:c:d").unwrap(),
            (IpSuffix, "::a:b:c:d".into())
        );
        assert_eq!(
            norm(IpSuffix, "::a:b:c:d/64").unwrap(),
            (IpSuffix, "::a:b:c:d".into())
        );
        assert!(norm(IpSuffix, "::a:b:c:d/48").is_err());
        assert!(norm(IpSuffix, "fd00::1").is_err(), "non-zero upper bits");
        assert!(norm(IpSuffix, "::").is_err());
        assert!(norm(IpSuffix, "10.0.0.1").is_err());
    }

    #[test]
    fn base64_kinds_are_stored() {
        use CredentialKind::*;
        let k = "mFZTRZ0v3m0/yN7Zf3zH1yG2m1pE2n3YhQ5b7kqVQXY=";
        assert_eq!(norm(WgKey, k).unwrap(), (WgKey, k.into()));
        assert!(norm(TlsSpki, "not base64!").is_err());
        assert!(norm(TorClientKey, "").is_err());
    }

    #[test]
    fn small_order_tor_keys_are_refused() {
        use CredentialKind::TorClientKey;
        for key in [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "4DVXU7B3IG4K4FSW4P5PDH6ENLNATDPLTQZLD7MGMICRMX2JXAAA",
            "L6OJLPFDKCGCJMOQWFKZZA7PLMCEIXGELAOI5BWYEJHN3UE7CFLQ",
            "5T7777777777777777777777777777777777777777777777757Q",
            "5X7777777777777777777777777777777777777777777777757Q",
            "537777777777777777777777777777777777777777777777757Q",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAA",
        ] {
            assert!(norm(TorClientKey, key).is_err(), "{key}");
        }
    }

    #[test]
    fn tor_client_keys_normalize() {
        use CredentialKind::TorClientKey;
        let want = (TorClientKey, TOR_KEY.to_string());
        assert_eq!(norm(TorClientKey, TOR_KEY).unwrap(), want);
        assert_eq!(norm(TorClientKey, &TOR_KEY.to_lowercase()).unwrap(), want);
        let line = format!("descriptor:x25519:{TOR_KEY}");
        assert_eq!(norm(TorClientKey, &line).unwrap(), want);
        assert_eq!(
            norm(TorClientKey, &format!(" {} ", line.to_lowercase())).unwrap(),
            want
        );
        // Wrong length, characters or trailing bits.
        assert!(norm(TorClientKey, &TOR_KEY[1..]).is_err());
        assert!(norm(TorClientKey, &format!("{TOR_KEY}A")).is_err());
        assert!(norm(TorClientKey, &format!("{}1", &TOR_KEY[..51])).is_err());
        assert!(norm(TorClientKey, &format!("{}B", &TOR_KEY[..51])).is_err());
        // A client's private-key line carries the onion name first.
        assert!(norm(TorClientKey, &format!("abc:descriptor:x25519:{TOR_KEY}")).is_err());
        assert!(norm(TorClientKey, &format!("other:{TOR_KEY}")).is_err());
    }

    fn one(text: &str) -> ParsedCredential {
        let mut v = parse_input(text);
        assert_eq!(v.len(), 1, "{text:?}: {v:?}");
        v.remove(0)
    }

    #[test]
    fn parse_input_splits_on_newlines_commas_and_whitespace() {
        let v = parse_input(&format!("{KEY},\n 10.0.0.1  fd00::1\r\n\n{TOR_KEY}"));
        let kinds: Vec<_> = v.iter().map(|p| p.kind).collect();
        assert_eq!(
            kinds,
            [
                Some(CredentialKind::YggKey),
                Some(CredentialKind::Ip),
                Some(CredentialKind::Ip),
                Some(CredentialKind::TorClientKey)
            ]
        );
        assert!(parse_input(" , \n").is_empty());
    }

    #[test]
    fn parse_input_detects_and_normalizes() {
        use CredentialKind::*;
        let p = one(&KEY.to_uppercase());
        assert_eq!((p.kind, p.normalized.as_deref()), (Some(YggKey), Some(KEY)));
        let p = one("200:1::5");
        assert_eq!(
            (p.kind, p.normalized.as_deref()),
            (Some(YggAddr), Some("200:1::5"))
        );
        let p = one("300:1:2:3::9/64");
        assert_eq!(
            (p.kind, p.normalized.as_deref()),
            (Some(YggSubnet), Some("300:1:2:3::/64"))
        );
        let p = one("2001:DB8::7/48");
        assert_eq!(
            (p.kind, p.normalized.as_deref()),
            (Some(Ip), Some("2001:db8::/48"))
        );
        let p = one(&format!("descriptor:x25519:{}", TOR_KEY.to_lowercase()));
        assert_eq!(
            (p.kind, p.normalized.as_deref()),
            (Some(TorClientKey), Some(TOR_KEY))
        );
    }

    #[test]
    fn parse_input_reports_reach_per_network_kind() {
        let reach_of = |text: &str| -> Vec<(NetworkKind, Reach)> {
            one(text)
                .reach
                .into_iter()
                .map(|r| (r.network_kind, r.reach))
                .collect()
        };
        assert_eq!(reach_of(KEY), [(NetworkKind::Yggdrasil, Reach::Verified)]);
        assert_eq!(reach_of("fd00::5"), [(NetworkKind::Lan, Reach::IpOnly)]);
        assert_eq!(reach_of(TOR_KEY), [(NetworkKind::Tor, Reach::Verified)]);
        assert_eq!(
            reach_of("300:1:2:3::/64"),
            [(NetworkKind::Yggdrasil, Reach::WholeSubnet)]
        );
    }

    #[test]
    fn parse_input_rejects_the_bare_network_bases() {
        // A live peer was stored as `200::`, copied from a placeholder.
        for bad in ["200::", "300::", "300::/64", "200::/128"] {
            let p = one(bad);
            assert!(p.error.is_some() && p.normalized.is_none(), "{bad}: {p:?}");
        }
        // The same through the daemon's explicit kinds.
        for (k, v) in [
            (CredentialKind::YggAddr, "200::"),
            (CredentialKind::YggAddr, "300::"),
            (CredentialKind::YggSubnet, "300::/64"),
        ] {
            assert!(norm(k, v).is_err(), "{v}");
        }
    }

    #[test]
    fn parse_input_never_guesses_base64_kinds() {
        let wg = "mFZTRZ0v3m0/yN7Zf3zH1yG2m1pE2n3YhQ5b7kqVQXY=";
        let p = one(wg);
        assert_eq!((p.kind, p.normalized), (None, None));
        assert!(p.error.unwrap().contains("cannot tell"));
        assert!(one("hello").error.is_some());
        // Looks like an IP but is refused: the kind stays visible.
        let p = one("::/0");
        assert_eq!(p.kind, Some(CredentialKind::Ip));
        assert!(p.error.unwrap().contains("grant to Anyone"));
    }

    #[test]
    fn every_example_parses_to_its_kind() {
        for e in CREDENTIAL_EXAMPLES {
            let p = one(e.value);
            assert_eq!(p.error, None, "{}", e.value);
            assert_eq!(p.kind, Some(e.kind), "{}", e.value);
            assert!(!p.reach.is_empty(), "{} works nowhere", e.value);
        }
        let kinds: Vec<_> = CREDENTIAL_EXAMPLES.iter().map(|e| e.kind).collect();
        for k in [
            CredentialKind::YggKey,
            CredentialKind::YggAddr,
            CredentialKind::YggSubnet,
            CredentialKind::Ip,
            CredentialKind::TorClientKey,
        ] {
            assert!(kinds.contains(&k), "no example for {k}");
        }
    }

    /// Emits the examples as TypeScript next to the ts-rs types (`export_bindings`).
    #[cfg(feature = "ts")]
    #[test]
    fn export_bindings_credential_examples() {
        let dir = std::env::var("TS_RS_EXPORT_DIR").unwrap_or_else(|_| "ui/src/generated".into());
        let mut out = String::from(
            "// Generated by `cargo test -p socketguard-core --features ts export_bindings` from\n\
             // CREDENTIAL_EXAMPLES in crates/core/src/credential.rs. Do not edit this file manually.\n\
             import type { CredentialExample } from \"./CredentialExample\";\n\n\
             export const CREDENTIAL_EXAMPLES: CredentialExample[] = ",
        );
        out.push_str(&serde_json::to_string_pretty(CREDENTIAL_EXAMPLES).unwrap());
        out.push_str(";\n");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            std::path::Path::new(&dir).join("credentialExamples.ts"),
            out,
        )
        .unwrap();
    }
}
