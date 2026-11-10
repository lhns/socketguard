use super::{with_prefix64, AllocatedAddress, Ipv6Backend, Prefix};
use crate::iface::InterfaceManager;
use anyhow::{bail, Context, Result};
use ipnet::Ipv6Net;
use rand::Rng;
use socketguard_core::BackendType;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Maximum retry attempts for collision avoidance
const MAX_COLLISION_RETRIES: usize = 10;

/// How long a discovered prefix is reused before the interface is read again.
pub const DISCOVERY_CACHE: Duration = Duration::from_secs(10);

/// SLAAC backend: generates addresses within an existing /64 prefix, either configured
/// or discovered from the addresses of a network interface. A discovered prefix is
/// re-read regularly, so a changed ISP prefix is followed.
pub struct SlaacBackend {
    interface: String,
    net: Arc<dyn InterfaceManager>,
    /// A configured prefix; never rediscovered.
    fixed: Option<Ipv6Addr>,
    cache_for: Duration,
    /// The last discovery: when, and the prefix it found.
    cache: Mutex<Option<(Instant, Ipv6Addr)>>,
}

impl SlaacBackend {
    /// `prefix` None or "auto" discovers the prefix from the interface. Only an invalid
    /// prefix is an error; an interface without a usable prefix is a runtime condition.
    pub fn new(
        interface: &str,
        prefix: Option<&str>,
        net: Arc<dyn InterfaceManager>,
    ) -> Result<Self> {
        Self::with_cache(interface, prefix, net, DISCOVERY_CACHE)
    }

    pub fn with_cache(
        interface: &str,
        prefix: Option<&str>,
        net: Arc<dyn InterfaceManager>,
        cache_for: Duration,
    ) -> Result<Self> {
        let fixed = match prefix {
            Some(p) if !p.is_empty() && p != "auto" => Some(parse_prefix(p)?),
            _ => None,
        };
        Ok(Self {
            interface: interface.to_string(),
            net,
            fixed,
            cache_for,
            cache: Mutex::new(None),
        })
    }

    /// The /64 to allocate from: the configured one, or the one discovered on the
    /// interface (cached for `cache_for`).
    fn prefix(&self) -> Result<Ipv6Addr> {
        if let Some(p) = self.fixed {
            return Ok(p);
        }
        let mut cache = self.cache.lock().unwrap();
        if let Some((at, p)) = *cache {
            if at.elapsed() < self.cache_for {
                return Ok(p);
            }
        }
        let addrs = self.net.list_addresses(&self.interface).with_context(|| {
            format!("cannot read the addresses of interface {}", self.interface)
        })?;
        let Some(found) = pick_prefix(&addrs) else {
            *cache = None;
            bail!(
                "no global or unique-local IPv6 prefix on interface {}",
                self.interface
            );
        };
        if cache.is_none_or(|(_, old)| old != found) {
            info!("SLAAC prefix of {}: {found}", self.interface);
        }
        *cache = Some((Instant::now(), found));
        Ok(found)
    }
}

/// Choose the /64 to allocate from among the addresses of an interface. Global unicast
/// (2000::/3) beats unique-local (fc00::/7); link-local, loopback, multicast and
/// Yggdrasil (200::/7) never count. Within a class the prefix shared by the most
/// addresses wins, then the lowest.
fn pick_prefix(addrs: &[Ipv6Addr]) -> Option<Ipv6Addr> {
    let rank = |a: &Ipv6Addr| -> Option<u8> {
        let first = a.octets()[0];
        if first & 0xe0 == 0x20 {
            Some(1) // global unicast
        } else if first & 0xfe == 0xfc {
            Some(0) // unique-local
        } else {
            None
        }
    };
    let mut counts: std::collections::BTreeMap<(u8, Ipv6Addr), usize> = Default::default();
    for a in addrs {
        if let Some(r) = rank(a) {
            *counts.entry((r, with_prefix64(*a, 0))).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|(ka, ca), (kb, cb)| {
            // Higher class, then more addresses, then the lower prefix.
            ka.0.cmp(&kb.0).then(ca.cmp(cb)).then(kb.1.cmp(&ka.1))
        })
        .map(|((_, p), _)| p)
}

impl Ipv6Backend for SlaacBackend {
    fn current_prefix(&self) -> Result<Option<Prefix>> {
        Ok(Some(Prefix::new(self.prefix()?, 64)))
    }

    fn allocate(&self, iid: Option<u64>) -> Result<AllocatedAddress> {
        let prefix = self.prefix()?;
        if let Some(iid) = iid {
            // A stable interface ID is ours already; no collision check.
            return Ok(AllocatedAddress {
                address: with_prefix64(prefix, iid),
                prefix_len: 128,
                backend: BackendType::Slaac,
            });
        }
        let mut rng = rand::thread_rng();
        for attempt in 0..MAX_COLLISION_RETRIES {
            let address = with_prefix64(prefix, rng.gen());
            // Check for collision with existing addresses on the interface
            if !self.net.list_addresses(&self.interface)?.contains(&address) {
                debug!("SLAAC allocated {} (attempt {})", address, attempt + 1);
                return Ok(AllocatedAddress {
                    address,
                    prefix_len: 128,
                    backend: BackendType::Slaac,
                });
            }
            debug!(
                "SLAAC address {} already in use, retrying (attempt {})",
                address,
                attempt + 1
            );
        }
        bail!(
            "failed to allocate unique SLAAC address after {} attempts",
            MAX_COLLISION_RETRIES
        )
    }
}

/// Parse a configured prefix to its /64: "2001:db8:1:2::/64", "2001:db8:1:2::" or the
/// bare "2001:db8:1:2".
fn parse_prefix(prefix: &str) -> Result<Ipv6Addr> {
    let addr = match prefix.parse::<Ipv6Net>() {
        Ok(net) => net.network(),
        Err(_) => prefix
            .parse::<Ipv6Addr>()
            .or_else(|_| format!("{}::", prefix.trim_end_matches(':')).parse())
            .with_context(|| format!("invalid prefix: {prefix}"))?,
    };
    Ok(with_prefix64(addr, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MockInterfaceManager;

    #[test]
    fn parse_prefix_with_slash() {
        let prefix = parse_prefix("2001:db8:1:2::/64").unwrap();
        assert_eq!(prefix, "2001:db8:1:2::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn parse_prefix_without_slash() {
        let prefix = parse_prefix("2001:db8:abcd:ef01::").unwrap();
        assert_eq!(prefix, "2001:db8:abcd:ef01::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn parse_prefix_bare_groups() {
        let want = "2001:db8:1:2::".parse::<Ipv6Addr>().unwrap();
        assert_eq!(parse_prefix("2001:db8:1:2").unwrap(), want);
        assert_eq!(parse_prefix("2001:db8:1:2:").unwrap(), want);
    }

    #[test]
    fn parse_prefix_invalid() {
        assert!(parse_prefix("not-an-address").is_err());
    }

    fn ips(list: &[&str]) -> Vec<Ipv6Addr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    fn pick(list: &[&str]) -> Option<String> {
        pick_prefix(&ips(list)).map(|p| p.to_string())
    }

    #[test]
    fn pick_prefix_table() {
        assert_eq!(pick(&[]), None);
        assert_eq!(
            pick(&["2001:db8:1:2::5"]).as_deref(),
            Some("2001:db8:1:2::")
        );
        assert_eq!(
            pick(&["fd3e:1eec:520:582e::5", "fd3e:1eec:520:582e::6"]).as_deref(),
            Some("fd3e:1eec:520:582e::")
        );
        // Global beats unique-local, even when the ULA has more addresses.
        assert_eq!(
            pick(&["fd00:1:2:3::1", "fd00:1:2:3::2", "2001:db8::1"]).as_deref(),
            Some("2001:db8::")
        );
        // Link-local, loopback, multicast, Yggdrasil never count.
        assert_eq!(
            pick(&["fe80::1", "::1", "ff02::1", "200:1:2:3::1", "300:1:2:3::1"]),
            None
        );
        assert_eq!(
            pick(&["fe80::1", "::1", "300:1:2:3::1", "fd00:1:2:3::1"]).as_deref(),
            Some("fd00:1:2:3::")
        );
        // The prefix shared by most addresses wins, then the lowest.
        assert_eq!(
            pick(&["2001:db8:2::1", "2001:db8:1::1", "2001:db8:2::2"]).as_deref(),
            Some("2001:db8:2::")
        );
        assert_eq!(
            pick(&["2001:db8:2::1", "2001:db8:1::1"]).as_deref(),
            Some("2001:db8:1::")
        );
    }

    fn mock() -> MockInterfaceManager {
        MockInterfaceManager::new(Arc::default())
    }

    fn add(m: &MockInterfaceManager, addr: &str) {
        m.add_address("eth0", addr.parse().unwrap(), 64).unwrap();
    }

    #[test]
    fn discovers_and_follows_the_prefix() {
        let m = mock();
        let b =
            SlaacBackend::with_cache("eth0", None, Arc::new(m.clone()), Duration::ZERO).unwrap();
        // No addresses: down, with a clear message.
        let err = b.current_prefix().unwrap_err().to_string();
        assert!(err.contains("no global or unique-local IPv6 prefix on interface eth0"));
        assert!(b.allocate(None).is_err());

        // A ULA address makes the interface usable.
        add(&m, "fd3e:1eec:520:582e::10");
        let p = b.current_prefix().unwrap().unwrap();
        assert_eq!(p.addr, "fd3e:1eec:520:582e::".parse::<Ipv6Addr>().unwrap());
        let a = b.allocate(None).unwrap();
        assert!(crate::networks::ip::same_prefix64(a.address, p.addr));

        // A global prefix appears and wins; allocation follows.
        add(&m, "2001:db8:9:9::1");
        let p = b.current_prefix().unwrap().unwrap();
        assert_eq!(p.addr, "2001:db8:9:9::".parse::<Ipv6Addr>().unwrap());
        let a = b.allocate(Some(7)).unwrap();
        assert_eq!(a.address, "2001:db8:9:9::7".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn discovery_is_cached() {
        let m = mock();
        add(&m, "2001:db8:1::1");
        let b =
            SlaacBackend::with_cache("eth0", None, Arc::new(m.clone()), Duration::from_secs(3600))
                .unwrap();
        let first = b.current_prefix().unwrap().unwrap();
        m.remove_address("eth0", "2001:db8:1::1".parse().unwrap(), 128)
            .unwrap();
        add(&m, "2001:db8:2::1");
        assert_eq!(b.current_prefix().unwrap().unwrap(), first);
    }

    #[test]
    fn configured_prefix_is_static() {
        let m = mock();
        add(&m, "2001:db8:1::1");
        let b =
            SlaacBackend::with_cache("eth0", Some("2001:db8:5::/64"), Arc::new(m), Duration::ZERO)
                .unwrap();
        assert_eq!(
            b.current_prefix().unwrap().unwrap().addr,
            "2001:db8:5::".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn invalid_configured_prefix_is_an_error() {
        assert!(SlaacBackend::new("eth0", Some("nonsense"), Arc::new(mock())).is_err());
    }
}
