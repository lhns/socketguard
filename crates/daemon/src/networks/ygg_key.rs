//! The key of a managed Yggdrasil node (ADR 0052), generated here instead of by Yggdrasil:
//! the node's address and its /64 follow from the key alone, so the ruleset that blocks them
//! can be applied before any Yggdrasil software runs (ADR 0051).
//!
//! Yggdrasil's `PrivateKey` is Go's `ed25519.PrivateKey`: the 32-byte seed followed by the
//! public key, as 128 hex digits. The key is kept in the database (setting `ygg_key:<id>`)
//! and in memory for the networks, which are built without database access ([`KeyRing`]).

use super::onion_key::public_key_of_seed;
use crate::ruleset::OverlayNode;
use anyhow::{bail, Context, Result};
use socketguard_core::yggdrasil::{derive_yggdrasil_ipv6, subnet_for_key};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The settings key prefix of a managed node's private key; the network id follows.
pub const KEY_PREFIX: &str = "ygg_key:";

#[derive(Clone, PartialEq, Eq)]
pub struct YggKey {
    seed: [u8; 32],
    public: [u8; 32],
}

// The seed is secret: never printed.
impl std::fmt::Debug for YggKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "YggKey({})", self.public_hex())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2 || !text.is_ascii() {
        bail!("expected {} hex digits, found {}", N * 2, text.len());
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).context("not hex")?;
    }
    Ok(out)
}

impl YggKey {
    pub fn generate() -> Self {
        Self::from_seed(rand::random())
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            public: public_key_of_seed(&seed),
            seed,
        }
    }

    /// Parse the stored form: `seed ‖ public key` as hex. A public half that does not
    /// belong to the seed is an error (the file would make Yggdrasil use another key).
    pub fn from_private_hex(text: &str) -> Result<Self> {
        let both: [u8; 64] = unhex(text.trim()).context("the Yggdrasil private key")?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&both[..32]);
        let key = Self::from_seed(seed);
        if key.public[..] != both[32..] {
            bail!("the public half of the Yggdrasil private key does not match its seed");
        }
        Ok(key)
    }

    /// What Yggdrasil's `PrivateKey` holds.
    pub fn private_hex(&self) -> String {
        format!("{}{}", hex(&self.seed), hex(&self.public))
    }

    pub fn public_hex(&self) -> String {
        hex(&self.public)
    }

    /// The node's addresses, from the key alone.
    pub fn node(&self) -> OverlayNode {
        let subnet = ipnet::Ipv6Net::new(subnet_for_key(&self.public), 64)
            .expect("a /64 is a valid prefix length");
        OverlayNode {
            address: derive_yggdrasil_ipv6(&self.public),
            subnet,
        }
    }
}

/// The keys of the managed Yggdrasil networks by network id, shared between the engine
/// (which loads and creates them) and the networks (which read them).
#[derive(Clone, Default)]
pub struct KeyRing(Arc<Mutex<HashMap<String, YggKey>>>);

impl KeyRing {
    pub fn get(&self, id: &str) -> Option<YggKey> {
        self.0.lock().unwrap().get(id).cloned()
    }

    pub fn insert(&self, id: &str, key: YggKey) {
        self.0.lock().unwrap().insert(id.to_string(), key);
    }

    pub fn remove(&self, id: &str) {
        self.0.lock().unwrap().remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Produced with the real Yggdrasil 0.5.15 built by `deploy/bundle/fetch.sh
    // --build-yggdrasil linux-x86_64` (in a golang:1.26 container): `yggdrasil -genconf
    // -json` gave the `PrivateKey` (seed ‖ public key), then `yggdrasil -useconffile
    // <conf> -address`, `-subnet` and `-publickey` gave the rest.
    const SEED: &str = "d20dbc4f35cf53079f03a6c61ab57ac17b2b7dd838bed20dea94fe30ed804566";
    const PUBLIC: &str = "58926089882365c29f6aaf27fc64955554ff9568c78a5e17d9d87dba8ed1c44d";
    const ADDRESS: &str = "201:9db6:7dd9:df72:68f5:8255:4360:e6d";
    const SUBNET: &str = "301:9db6:7dd9:df72::/64";

    #[test]
    fn the_seed_gives_the_public_key_yggdrasil_derives() {
        let key = YggKey::from_seed(unhex(SEED).unwrap());
        assert_eq!(key.public_hex(), PUBLIC);
        assert_eq!(key.private_hex(), format!("{SEED}{PUBLIC}"));
    }

    #[test]
    fn the_key_gives_the_address_and_subnet_yggdrasil_prints() {
        let key = YggKey::from_private_hex(&format!("{SEED}{PUBLIC}")).unwrap();
        let node = key.node();
        assert_eq!(node.address, ADDRESS.parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(node.subnet, SUBNET.parse::<ipnet::Ipv6Net>().unwrap());
    }

    #[test]
    fn a_stored_key_round_trips_and_a_mismatched_one_is_refused() {
        let key = YggKey::generate();
        assert_eq!(YggKey::from_private_hex(&key.private_hex()).unwrap(), key);
        assert_ne!(key, YggKey::generate());
        assert!(YggKey::from_private_hex("abcd").is_err());
        assert!(YggKey::from_private_hex(&format!("{SEED}{}", "00".repeat(32))).is_err());
        assert!(YggKey::from_private_hex(&"zz".repeat(64)).is_err());
        assert!(!format!("{key:?}").contains(&hex(&key.seed)));
    }
}
