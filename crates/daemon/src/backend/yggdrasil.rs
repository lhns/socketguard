use super::Ipv6Backend;
use anyhow::Result;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use socketguard_core::{AllocatedAddress, BackendType, KeyPair};
use std::net::Ipv6Addr;

/// Yggdrasil backend
/// Generates Ed25519 keypairs and derives 200::/7 IPv6 addresses
pub struct YggdrasilBackend;

impl YggdrasilBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Ipv6Backend for YggdrasilBackend {
    fn allocate_address(&self) -> Result<AllocatedAddress> {
        // Generate keypairs until we find one that produces a 200::/7 address
        loop {
            let signing_key = SigningKey::generate(&mut OsRng);
            let public_key = signing_key.verifying_key();

            let address = derive_yggdrasil_ipv6(public_key.as_bytes());

            // Check that address falls in 200::/7 (first byte 0x02 or 0x03)
            let octets = address.octets();
            if octets[0] == 0x02 || octets[0] == 0x03 {
                let id = uuid::Uuid::new_v4().to_string();
                return Ok(AllocatedAddress {
                    address,
                    prefix_len: 128,
                    keypair: Some(KeyPair {
                        id,
                        public_key: public_key.as_bytes().to_vec(),
                        private_key: signing_key.to_bytes().to_vec(),
                        derived_ipv6: address,
                    }),
                    backend: BackendType::Yggdrasil,
                });
            }
        }
    }

    fn release_address(&self, _addr: &Ipv6Addr) -> Result<()> {
        // Keypair can be deleted from storage separately
        Ok(())
    }
}

/// Derive a Yggdrasil-style IPv6 address from a public key.
/// This follows Yggdrasil's address derivation:
/// 1. SHA-512 hash the public key
/// 2. Count leading ones in the hash
/// 3. Build address: 0x02 prefix + leading-ones-count + truncated hash bits
fn derive_yggdrasil_ipv6(public_key: &[u8; 32]) -> Ipv6Addr {
    let hash = Sha512::digest(public_key);

    // Count leading 1-bits
    let mut ones = 0usize;
    for &byte in hash.iter() {
        if byte == 0xff {
            ones += 8;
        } else {
            // Count leading ones in this byte
            let mut b = byte;
            while b & 0x80 != 0 {
                ones += 1;
                b <<= 1;
            }
            break;
        }
    }

    // Skip the leading ones + one zero bit
    let skip_bits = ones + 1;

    // Build the address bytes
    let mut addr_bytes = [0u8; 16];
    addr_bytes[0] = 0x02;
    addr_bytes[1] = ones as u8;

    // Fill remaining 14 bytes from hash after skip_bits
    for i in 2..16 {
        let total_bit = (i - 2) * 8;
        let src_bit = skip_bits + total_bit;
        let src_byte = src_bit / 8;
        let src_offset = src_bit % 8;

        if src_byte < hash.len() {
            let mut val = hash[src_byte] << src_offset;
            if src_offset > 0 && src_byte + 1 < hash.len() {
                val |= hash[src_byte + 1] >> (8 - src_offset);
            }
            addr_bytes[i] = val;
        }
    }

    Ipv6Addr::from(addr_bytes)
}
