//! Onion service keys, generated here instead of by Tor (ADR 0039): a new address gets its
//! name without any control-port call, so nothing is published before the first grant.
//!
//! The key is Tor's `ED25519-V3` blob: the expanded secret key (clamped scalar then hash
//! prefix, 64 bytes, as Tor stores it), base64. The name is derived per rend-spec-v3.

use super::tor_control::base32;
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use sha3::Sha3_256;

const PREFIX: &str = "ED25519-V3:";

pub struct OnionKey {
    /// `ED25519-V3:<base64 of the 64-byte expanded secret key>`, for ADD_ONION.
    pub secret: String,
    /// The service id (the name without `.onion`).
    pub service_id: String,
}

/// A fresh random key.
pub fn generate() -> OnionKey {
    from_seed(&rand::random::<[u8; 32]>())
}

/// The key of an Ed25519 seed (expanded as RFC 8032 does).
pub fn from_seed(seed: &[u8; 32]) -> OnionKey {
    let mut expanded: [u8; 64] = Sha512::digest(seed).into();
    expanded[0] &= 248;
    expanded[31] &= 63;
    expanded[31] |= 64;
    OnionKey {
        secret: format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(expanded)
        ),
        service_id: service_id_of(&public_key(&expanded)),
    }
}

/// The service id of a stored `ED25519-V3:` secret, whoever generated it (Tor's own are
/// the same 64-byte expanded form).
pub fn service_id_of_secret(secret: &str) -> Result<String> {
    let b64 = secret
        .strip_prefix(PREFIX)
        .context("not an ED25519-V3 key")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("the key is not base64")?;
    let Ok(expanded) = <[u8; 64]>::try_from(bytes.as_slice()) else {
        bail!("the key is {} bytes, not 64", bytes.len());
    };
    Ok(service_id_of(&public_key(&expanded)))
}

/// Scalar times the base point. The scalar is already clamped; reducing it mod the group
/// order does not change the point.
fn public_key(expanded: &[u8; 64]) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&expanded[..32]);
    (Scalar::from_bytes_mod_order(scalar) * ED25519_BASEPOINT_POINT)
        .compress()
        .to_bytes()
}

/// `base32(pubkey ‖ checksum[0..2] ‖ 0x03)`, lowercase, with
/// `checksum = SHA3-256(".onion checksum" ‖ pubkey ‖ 0x03)`.
fn service_id_of(pubkey: &[u8; 32]) -> String {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pubkey);
    h.update([3u8]);
    let checksum = h.finalize();
    let mut raw = Vec::with_capacity(35);
    raw.extend_from_slice(pubkey);
    raw.extend_from_slice(&checksum[..2]);
    raw.push(3);
    base32(&raw).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 test 1: seed and public key (d75a98...511a) are the RFC's; the blob and the
    // name were derived independently (hashlib: SHA-512 + clamp, SHA3-256 checksum, base32).
    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const BLOB: &str = "ED25519-V3:MHyDhk8oM8tCei7xwAoBPP3/J2jZgMCjpSDwBpBN6U+bTwr+KAt0aneGhOdUQlAgV7dHOgPwj5b1o46Sh+Afjw==";
    const ID: &str = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid";

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::from_str_radix(&SEED[2 * i..2 * i + 2], 16).unwrap();
        }
        s
    }

    #[test]
    fn known_vector() {
        let k = from_seed(&seed());
        assert_eq!(k.secret, BLOB);
        assert_eq!(k.service_id, ID);
        assert_eq!(service_id_of_secret(BLOB).unwrap(), ID);
    }

    #[test]
    fn blob_is_a_64_byte_clamped_expanded_key() {
        let k = generate();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(k.secret.strip_prefix("ED25519-V3:").unwrap())
            .unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes[0] & 7, 0);
        assert_eq!(bytes[31] & 0xc0, 0x40);
        assert_eq!(k.service_id.len(), 56);
        assert_eq!(service_id_of_secret(&k.secret).unwrap(), k.service_id);
        assert_ne!(k.secret, generate().secret);
    }

    #[test]
    fn bad_secrets_are_rejected() {
        assert!(service_id_of_secret("RSA1024:abcd").is_err());
        assert!(service_id_of_secret("ED25519-V3:AAAA").is_err());
        assert!(service_id_of_secret("ED25519-V3:!!!").is_err());
    }
}
