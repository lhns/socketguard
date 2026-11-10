use super::super::{Capabilities, LocatorRequest, Network, NetworkEnforcement, NewLocator};
use super::{Ipv6Backend, Prefix};
use anyhow::Result;
use socketguard_core::config::BackendConfig;
use socketguard_core::{
    is_loopback_interface, Address, CredentialKind, Locator, NetworkKind, NetworkStatus,
};
use std::net::Ipv6Addr;
use std::sync::Mutex;
use tracing::{info, warn};

/// An IP network: allocation through an [`Ipv6Backend`].
pub struct IpNetwork {
    kind: NetworkKind,
    grants_apply: bool,
    backend: Box<dyn Ipv6Backend>,
    /// Why the network is down, once it has been seen to be (to log changes only).
    down: Mutex<Option<String>>,
    /// The last allocation failed with this (a DHCPv6 server that does not answer).
    alloc_error: Mutex<Option<String>>,
}

impl IpNetwork {
    pub fn new(kind: NetworkKind, grants_apply: bool, backend: Box<dyn Ipv6Backend>) -> Self {
        Self {
            kind,
            grants_apply,
            backend,
            down: Mutex::new(None),
            alloc_error: Mutex::new(None),
        }
    }

    /// Log a change between up and down, not every poll.
    fn observe(&self, down: Option<&str>) {
        let mut seen = self.down.lock().unwrap();
        match (seen.is_some(), down) {
            (false, Some(reason)) => warn!("{:?} network is down: {reason}", self.kind),
            (true, None) => info!("{:?} network is up again", self.kind),
            _ => {}
        }
        *seen = down.map(str::to_string);
    }

    /// The network for `config` around an already built allocator. Local on loopback is
    /// this machine only; on another interface it takes grants like any IP network.
    pub fn for_config(config: &BackendConfig, backend: Box<dyn Ipv6Backend>) -> Self {
        let kind = NetworkKind::from(config.backend_type());
        let grants_apply =
            kind != NetworkKind::Local || !config.interface().is_some_and(is_loopback_interface);
        Self::new(kind, grants_apply, backend)
    }
}

impl Network for IpNetwork {
    fn kind(&self) -> NetworkKind {
        self.kind
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            ip_locators: true,
            verifies: match self.kind {
                NetworkKind::Yggdrasil => &[CredentialKind::YggKey, CredentialKind::YggAddr],
                _ => &[],
            },
            grants_apply: self.grants_apply,
            udp: true,
        }
    }

    fn status(&self) -> (NetworkStatus, Option<Ipv6Addr>) {
        let prefix = self.current_prefix();
        let (status, addr) = match prefix {
            Ok(Some(p)) if p.len == 64 => (NetworkStatus::Up, Some(p.addr)),
            Ok(_) => (NetworkStatus::Up, None),
            Err(e) => (
                NetworkStatus::Down {
                    reason: format!("{e:#}"),
                },
                None,
            ),
        };
        let status = match (status, self.alloc_error.lock().unwrap().clone()) {
            (NetworkStatus::Up, Some(reason)) => NetworkStatus::Down { reason },
            (s, _) => s,
        };
        match &status {
            NetworkStatus::Down { reason } => self.observe(Some(reason)),
            NetworkStatus::Up => self.observe(None),
        }
        (status, addr)
    }

    fn current_prefix(&self) -> Result<Option<Prefix>> {
        self.backend.current_prefix()
    }

    fn ensure_locator(&self, _req: &LocatorRequest) -> Result<NewLocator> {
        let alloc = match self.backend.allocate(None) {
            Ok(a) => {
                *self.alloc_error.lock().unwrap() = None;
                self.observe(None);
                a
            }
            Err(e) => {
                let reason = format!("{e:#}");
                *self.alloc_error.lock().unwrap() = Some(reason.clone());
                self.observe(Some(&reason));
                return Err(e);
            }
        };
        Ok(NewLocator {
            locator: Locator::Ipv6 {
                addr: alloc.address,
            },
            secret: None,
        })
    }

    fn remove_locator(&self, address: &Address) -> Result<()> {
        match address.locator.ipv6() {
            Some(addr) => self.backend.release_address(&addr),
            None => Ok(()),
        }
    }

    fn enforce(&self, _enforcement: &NetworkEnforcement) -> Result<()> {
        Ok(())
    }

    fn disable(&self, _addresses: &[Address]) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MockIpv6Backend;

    #[test]
    fn local_on_loopback_declares_no_grants() {
        let ula = |iface: &str| BackendConfig::Ula {
            interface: iface.into(),
        };
        let mock = || Box::new(MockIpv6Backend::new("fd00::", 128, "lo"));
        assert!(
            !IpNetwork::for_config(&ula("lo"), mock())
                .capabilities()
                .grants_apply
        );
        assert!(
            IpNetwork::for_config(&ula("eth0"), mock())
                .capabilities()
                .grants_apply
        );
    }
}
