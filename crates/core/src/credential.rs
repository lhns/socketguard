//! Credential normalization (ADR 0028): validate what a user typed and store one canonical
//! form per credential.

use crate::model::CredentialKind;
use ipnet::{IpNet, Ipv6Net};
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

/// Parse an IPv6 address or CIDR, with a clear error for IPv4.
fn parse_ip_or_net(value: &str) -> Result<Ipv6Net, CredentialError> {
    let value = value.trim();
    let net: IpNet = match value.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => match value.parse::<IpAddr>() {
            Ok(a) => IpNet::from(a),
            Err(_) => return invalid(format!("{value:?} is not an IP address or network")),
        },
    };
    match net {
        IpNet::V4(_) => invalid("IPv4 isn't supported yet"),
        IpNet::V6(n) => Ok(n),
    }
}

/// Decode `value` as 64 hex characters (either case).
pub fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    // `from_str_radix` would also take a leading `+`.
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn is_base64(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
}

/// Validate and normalize a credential value, returning the kind to store and the
/// canonical value. Rejects invalid input with a message for the user.
///
/// - `YggKey`: 64 hex characters, stored lowercase.
/// - `YggAddr`: one address in `200::/7`, stored as an address.
/// - `YggSubnet`: a /64 in `300::/8`, stored as `net/64`.
/// - `Ip`: an IPv6 address or CIDR, stored as `net/len` (`/128` for a single address).
///   IPv4 is rejected. A value inside `200::/7` becomes `YggAddr` or `YggSubnet`; other
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
            let net = parse_ip_or_net(value)?;
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

/// 52 base32 characters (RFC 4648, no padding) as the 32 bytes they encode.
fn decode_tor_key(key: &str) -> Option<[u8; 32]> {
    let (mut out, mut n) = ([0u8; 32], 0usize);
    let (mut buf, mut bits) = (0u32, 0u32);
    for b in key.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if n == 32 {
                return None;
            }
            out[n] = (buf >> bits) as u8;
            n += 1;
        }
    }
    (n == 32).then_some(out)
}

/// Whether `key` is a Tor v3 client-auth public key: 52 base32 characters (no padding)
/// encoding 32 bytes, so the last character carries no extra bits, and not a small-order
/// point.
pub(crate) fn is_tor_key(key: &str) -> bool {
    let well_formed = key.len() == 52
        && key.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
        && matches!(key.as_bytes()[51], b'A' | b'Q');
    let Some(mut point) = well_formed.then(|| decode_tor_key(key)).flatten() else {
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
    fn ipv4_is_rejected() {
        for k in [
            CredentialKind::Ip,
            CredentialKind::YggAddr,
            CredentialKind::YggSubnet,
        ] {
            let err = norm(k, "192.168.1.5").unwrap_err();
            assert!(err.contains("IPv4"), "{err}");
        }
        assert!(norm(CredentialKind::Ip, "10.0.0.0/8")
            .unwrap_err()
            .contains("IPv4"));
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
}
