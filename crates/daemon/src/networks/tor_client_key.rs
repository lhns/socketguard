//! Tor client authorization keys generated here (ADR 0045): an x25519 pair, the public
//! half in base32 for the service's `authorized_clients` (and the peer's credential), the
//! private half in base32 for the client's `ClientOnionAuthDir`.
//!
//! The format is Tor's: rend-spec-v3 and the tor manual describe the client file as
//! `<56-char onion address without .onion>:descriptor:x25519:<base32 private key>`, in a
//! file ending in `.auth_private`; keys are RFC 4648 base32 without padding, 52 characters
//! for 32 bytes.

use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::clamp_integer;
use data_encoding::BASE32_NOPAD;

pub struct ClientKey {
    /// The public key, 52 base32 characters (what `ADD_ONION ClientAuthV3=` takes).
    pub public: String,
    /// The private key, 52 base32 characters.
    pub private: String,
}

/// A fresh random key pair. The private scalar is stored clamped, which is what the public
/// key is derived from (Tor clamps again when it reads the file, which changes nothing).
pub fn generate() -> ClientKey {
    from_secret(rand::random::<[u8; 32]>())
}

pub fn from_secret(secret: [u8; 32]) -> ClientKey {
    let secret = clamp_integer(secret);
    let public = MontgomeryPoint::mul_base_clamped(secret);
    ClientKey {
        public: BASE32_NOPAD.encode(public.as_bytes()),
        private: BASE32_NOPAD.encode(&secret),
    }
}

/// The `.auth_private` line for a service: `service_id` is the onion name, with or without
/// the `.onion` suffix.
pub fn auth_private_line(service_id: &str, private: &str) -> String {
    let id = service_id.strip_suffix(".onion").unwrap_or(service_id);
    format!("{id}:descriptor:x25519:{private}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use socketguard_core::{normalize_credential, CredentialKind};

    #[test]
    fn rfc7748_vector_gives_the_known_public_key() {
        // RFC 7748 section 6.1, Alice: the private key is already clamped by the RFC's rules.
        let secret: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let public: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let k = from_secret(secret);
        assert_eq!(k.public, BASE32_NOPAD.encode(&public));
        assert_eq!(k.private.len(), 52);
        assert_eq!(k.public.len(), 52);
    }

    #[test]
    fn a_generated_public_key_is_a_valid_credential() {
        let k = generate();
        let (kind, value) = normalize_credential(CredentialKind::TorClientKey, &k.public).unwrap();
        assert_eq!(kind, CredentialKind::TorClientKey);
        assert_eq!(value, k.public);
        assert_ne!(generate().private, k.private);
    }

    #[test]
    fn the_client_file_line_has_tors_format() {
        let line = auth_private_line(
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
            "KEY",
        );
        assert_eq!(
            line,
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx:descriptor:x25519:KEY"
        );
        assert_eq!(auth_private_line("abc", "K"), "abc:descriptor:x25519:K");
    }
}
