use super::super::{Capabilities, LocatorRequest, Network, NetworkEnforcement, NewLocator};
use super::{Ipv6Backend, Prefix};
use crate::iface::InterfaceManager;
use anyhow::Result;
use socketguard_core::config::BackendConfig;
use socketguard_core::{
    is_loopback_interface, Address, CredentialKind, Locator, NetworkKind, NetworkStatus,
};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// How long "the interface exists" is reused: listing interfaces may run a command.
const HOST_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// The host to check the network's interface against.
struct Host {
    ifaces: Arc<dyn InterfaceManager>,
    /// The interface of the config; None when the backend finds it at runtime.
    configured: Option<String>,
    checked: Mutex<Option<(Instant, Option<String>)>>,
}

/// An IP network: allocation through an [`Ipv6Backend`].
pub struct IpNetwork {
    kind: NetworkKind,
    grants_apply: bool,
    backend: Box<dyn Ipv6Backend>,
    host: Option<Host>,
    /// Why the network is down, once it has been seen to be (to log changes only).
    down: Mutex<Option<String>>,
    /// The last allocation failed with this (a DHCPv6 server that does not answer).
    alloc_error: Mutex<Option<String>>,
    /// The interface of the config, handed to [`Host`] by `with_host`.
    configured_interface: Option<String>,
}

impl IpNetwork {
    pub fn new(kind: NetworkKind, grants_apply: bool, backend: Box<dyn Ipv6Backend>) -> Self {
        Self {
            kind,
            grants_apply,
            backend,
            host: None,
            down: Mutex::new(None),
            alloc_error: Mutex::new(None),
            configured_interface: None,
        }
    }

    /// Check the network's interface against the host's (ADR 0048): a network on an
    /// interface that does not exist is down, whatever its allocator says.
    pub fn with_host(mut self, ifaces: Arc<dyn InterfaceManager>) -> Self {
        let configured = self.configured_interface.take();
        self.host = Some(Host {
            ifaces,
            configured,
            checked: Mutex::new(None),
        });
        self
    }

    /// The reason the interface is unusable: it is not on the host.
    fn interface_problem(&self) -> Option<String> {
        let host = self.host.as_ref()?;
        let name = host
            .configured
            .clone()
            .or_else(|| self.backend.interface())?;
        if is_loopback_interface(&name) {
            return None;
        }
        let mut checked = host.checked.lock().unwrap();
        if let Some((at, result)) = checked.as_ref() {
            if at.elapsed() < HOST_CHECK_INTERVAL && result.as_deref() == Some(name.as_str()) {
                return None;
            }
        }
        let exists = match host.ifaces.list_interfaces() {
            Ok(list) => list.iter().any(|i| i.name == name),
            Err(_) => true, // unknown: do not claim it is missing
        };
        if exists {
            *checked = Some((Instant::now(), Some(name)));
            None
        } else {
            *checked = None;
            Some(format!("interface {name} does not exist"))
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
        let mut network = Self::new(kind, grants_apply, backend);
        network.configured_interface = config.interface().map(str::to_string);
        network
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
        let status = match (
            status,
            self.backend.problem().or_else(|| self.interface_problem()),
        ) {
            (NetworkStatus::Up, Some(reason)) => NetworkStatus::Down { reason },
            (s, _) => s,
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

    fn interface(&self) -> Option<String> {
        self.backend.interface()
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

    fn release_lease(&self, addr: Ipv6Addr) -> Result<()> {
        self.backend.release_address(&addr)
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
    fn a_missing_interface_is_down_with_its_name() {
        let ifaces = crate::test_support::MockInterfaceManager::new(Default::default());
        ifaces.add_interface("eth0");
        let slaac = |name: &str| BackendConfig::Slaac {
            interface: name.into(),
            prefix: None,
        };
        let mock = || Box::new(MockIpv6Backend::new("2001:db8::", 128, "eth0"));
        let up = IpNetwork::for_config(&slaac("eth0"), mock()).with_host(Arc::new(ifaces.clone()));
        assert_eq!(up.status().0, NetworkStatus::Up);
        let down = IpNetwork::for_config(&slaac("eth9"), mock()).with_host(Arc::new(ifaces));
        assert_eq!(
            down.status().0,
            NetworkStatus::Down {
                reason: "interface eth9 does not exist".into()
            }
        );
    }

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
