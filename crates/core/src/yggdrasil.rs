//! Yggdrasil address derivation, matching upstream `AddrForKey` / `SubnetForKey`.

use std::net::Ipv6Addr;

/// Derive the node address (`200::/8`) for an ed25519 public key.
///
/// Upstream algorithm: invert all key bits, count the leading ones, skip them and the
/// following zero bit; the address is `[0x02, ones, remaining bits...]`.
pub fn derive_yggdrasil_ipv6(public_key: &[u8; 32]) -> Ipv6Addr {
    let mut bits = public_key.iter().flat_map(|b| {
        let b = !*b;
        (0..8).map(move |i| (b >> (7 - i)) & 1)
    });

    let mut ones = 0u8;
    // Consume the leading ones and the first zero.
    for bit in bits.by_ref() {
        if bit == 0 {
            break;
        }
        ones += 1;
    }

    let mut out = [0u8; 16];
    out[0] = 0x02;
    out[1] = ones;
    for byte in out[2..].iter_mut() {
        for _ in 0..8 {
            *byte = (*byte << 1) | bits.next().unwrap_or(0);
        }
    }
    Ipv6Addr::from(out)
}

/// The routed `/64` (`300::/64`) a node owns: the first 8 bytes of its address with
/// the lowest bit of byte 0 set. Returned as the network address (host bits zero).
pub fn subnet_for_key(public_key: &[u8; 32]) -> Ipv6Addr {
    let mut o = derive_yggdrasil_ipv6(public_key).octets();
    o[0] |= 0x01;
    o[8..].fill(0);
    Ipv6Addr::from(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verified against Yggdrasil 0.5.15 `yggdrasilctl getSelf`.
    const KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::from_str_radix(&KEY[i * 2..i * 2 + 2], 16).unwrap();
        }
        k
    }

    #[test]
    fn address_matches_upstream_vector() {
        assert_eq!(
            derive_yggdrasil_ipv6(&key()),
            "200:8af8:ba35:56ae:bef0:6284:981f:5972"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
    }

    #[test]
    fn subnet_matches_upstream_vector() {
        assert_eq!(
            subnet_for_key(&key()),
            "300:8af8:ba35:56ae::".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn leading_ones_are_counted() {
        // key 00 80 ff.. inverts to ff 7f 00..: 8 ones, a zero, then 1111111 0000...
        let mut k = [0xffu8; 32];
        k[0] = 0x00;
        k[1] = 0x80;
        let a = derive_yggdrasil_ipv6(&k).octets();
        assert_eq!(a[0], 0x02);
        assert_eq!(a[1], 8);
        assert_eq!(a[2], 0xfe); // 7 ones then 0 from the inverted 0x7f / 0x00
    }
}
