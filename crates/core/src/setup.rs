//! What a host offers for each kind of network (ADR 0048, ADR 0052): the types of
//! `GET /api/networks/setup` and `GET /api/status`'s `bundled`. Detection only reads;
//! nothing here installs or changes software.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Whether an existing node can be used as it is. Installing or configuring one is not
/// SocketGuard's business (ADR 0052).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    /// Running and usable without changes: can be added as it is.
    Ready,
    /// Already one of the daemon's networks.
    Added,
    /// Nothing usable was found.
    Absent,
}

/// An existing, system-wide node of one kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct SetupState {
    pub state: SetupStatus,
    /// What was detected: `interface`, `address`, `version`, `control`, `cookie_path`, ...
    pub found: BTreeMap<String, String>,
    /// A node runs that SocketGuard does not manage (ADR 0051): the host may be reachable
    /// over it. Only set for Yggdrasil.
    #[serde(default)]
    pub exposed: bool,
    /// A plain sentence to show above the Add button.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub warning: Option<String>,
}

impl SetupState {
    pub fn new(state: SetupStatus) -> Self {
        Self {
            state,
            found: BTreeMap::new(),
            exposed: false,
            warning: None,
        }
    }
}

/// Whether SocketGuard can run its own copy (ADR 0052).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct ManagedOffer {
    pub available: bool,
    /// Why not: the build does not include the files, or the files are unusable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub reason: Option<String>,
    /// The shipped version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub version: Option<String>,
}

/// The reason shown when the build carries no third-party files.
pub const NOT_INCLUDED: &str = "Not included in this build";

/// One kind of network on this host: SocketGuard's own copy, and an existing node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct KindSetup {
    pub managed: ManagedOffer,
    pub existing: SetupState,
}

/// A host interface that a LAN network could use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct LanCandidate {
    pub interface: String,
    /// The adapter's description (Windows), e.g. the driver name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub description: Option<String>,
    /// The interface has a global IPv6 address, i.e. a router announces a prefix.
    pub has_ipv6_prefix: bool,
    pub is_default_route: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub vlan_id: Option<u16>,
    /// A LAN network on this interface exists already.
    pub already_added: bool,
}

/// Whether the Yggdrasil network that is added is closed (ADR 0051).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct YggdrasilBlock {
    /// The ruleset in force denies the node by destination on any interface: the whole
    /// range `200::/7` for an existing node, the node's own addresses for a managed one.
    pub closed: bool,
    /// The same as `closed`.
    pub address_blocked: bool,
    /// The ruleset in force denies everything arriving on the network's interface.
    pub interface_blocked: bool,
    /// Why it is not closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub reason: Option<String>,
}

/// `GET /api/networks/setup`: what can be added on this host and how far each is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct NetworkSetup {
    /// Default-route interface first, then by name.
    pub lan: Vec<LanCandidate>,
    pub yggdrasil: KindSetup,
    pub tor: KindSetup,
    pub local: SetupState,
    /// Present when a Yggdrasil network is added: whether its block is in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub yggdrasil_block: Option<YggdrasilBlock>,
    /// The config file the daemon saves its networks in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub config_path: Option<String>,
}

/// One shipped third-party program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct BundledVersion {
    /// `tor`, `yggdrasil`, `wintun`.
    pub name: String,
    pub version: String,
}

/// The third-party files this build ships (`third_party/VERSIONS`), in `GET /api/status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct BundledInfo {
    /// The directory the daemon found, none when this build has no files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub dir: Option<String>,
    pub versions: Vec<BundledVersion>,
}

impl BundledInfo {
    /// Parse `third_party/VERSIONS`: lines of `name version [more]`; `#` starts a comment.
    pub fn parse_versions(text: &str) -> Vec<BundledVersion> {
        text.lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                Some(BundledVersion {
                    name: it.next()?.to_string(),
                    version: it.next()?.to_string(),
                })
            })
            .collect()
    }

    pub fn version_of(&self, name: &str) -> Option<&str> {
        self.versions
            .iter()
            .find(|v| v.name == name)
            .map(|v| v.version.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_file_is_parsed() {
        let info = BundledInfo {
            dir: None,
            versions: BundledInfo::parse_versions(
                "tor 16.0.1\nyggdrasil v0.5.15 abcdef0123 # commit\n\n# nothing\nwintun 0.14.1\n",
            ),
        };
        assert_eq!(info.versions.len(), 3);
        assert_eq!(info.version_of("tor"), Some("16.0.1"));
        assert_eq!(info.version_of("yggdrasil"), Some("v0.5.15"));
        assert_eq!(info.version_of("nothing"), None);
    }
}
