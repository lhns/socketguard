//! What a host offers for each kind of network, and how its software is installed
//! (ADR 0048). Types of `GET /api/networks/setup`, plus the one table of install
//! commands that the daemon (which shows them) and the CLI (which runs them) share.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const YGGDRASIL_DOWNLOAD: &str = "https://yggdrasil-network.github.io/installation.html";
pub const TOR_DOWNLOAD: &str = "https://www.torproject.org/download/tor/";

/// The networks whose software is not part of the host: those `networks setup` handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum SetupKind {
    Yggdrasil,
    Tor,
}

impl std::fmt::Display for SetupKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SetupKind::Yggdrasil => "yggdrasil",
            SetupKind::Tor => "tor",
        })
    }
}

/// How far a network is from being added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    /// Can be added as is.
    Ready,
    /// Installed, but missing a setting.
    NotConfigured,
    /// Installed, but not running.
    NotRunning,
    NotInstalled,
    /// Already one of the daemon's networks.
    Added,
}

/// A command `socketguard networks setup` runs to install the software.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct InstallOffer {
    /// The package manager, e.g. `winget`.
    pub manager: String,
    /// The exact command line.
    pub command: String,
    /// Where to read more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub link: Option<String>,
}

/// One kind of network on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct SetupState {
    pub state: SetupStatus,
    /// What was detected: `interface`, `address`, `version`, `control`, `cookie_path`, ...
    pub found: BTreeMap<String, String>,
    /// One plain sentence naming what is missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub missing: Option<String>,
    /// Present only where this system has a package that is known to exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub install: Option<InstallOffer>,
    /// The official download page, where there is no package to offer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub download_link: Option<String>,
}

impl SetupState {
    pub fn new(state: SetupStatus) -> Self {
        Self {
            state,
            found: BTreeMap::new(),
            missing: None,
            install: None,
            download_link: None,
        }
    }
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

/// `GET /api/networks/setup`: what can be added on this host and how far each is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct NetworkSetup {
    /// Default-route interface first, then by name.
    pub lan: Vec<LanCandidate>,
    pub yggdrasil: SetupState,
    pub tor: SetupState,
    pub local: SetupState,
    /// The config file the daemon saves its networks in (what `networks setup` edits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub config_path: Option<String>,
}

/// A command to run: program and arguments, no shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCommand {
    pub manager: &'static str,
    pub program: &'static str,
    pub args: Vec<&'static str>,
}

impl InstallCommand {
    pub fn command_line(&self) -> String {
        std::iter::once(self.program)
            .chain(self.args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn offer(&self, link: Option<&str>) -> InstallOffer {
        InstallOffer {
            manager: self.manager.to_string(),
            command: self.command_line(),
            link: link.map(str::to_string),
        }
    }
}

/// The official download page of `kind`.
pub fn download_link(kind: SetupKind) -> &'static str {
    match kind {
        SetupKind::Yggdrasil => YGGDRASIL_DOWNLOAD,
        SetupKind::Tor => TOR_DOWNLOAD,
    }
}

/// The command that installs `kind` on `os` (`std::env::consts::OS`), if the package is
/// known to exist and `has` says its manager is on this host. Verified sources:
/// - winget `YggdrasilNetwork.Yggdrasil`: listed by winget on the project owner's machine.
/// - `tor` in Debian (packages.debian.org/tor), Fedora (packages.fedoraproject.org/pkgs/tor)
///   and Arch (archlinux.org/packages/extra/x86_64/tor).
///
/// Not offered, because installing needs more than one package-manager command: Yggdrasil
/// on Linux (its own apt repository or COPR) and macOS (a .pkg); Tor on macOS (Homebrew
/// refuses to run as root, which `networks setup` is); Tor on Windows (no package).
pub fn install_command(
    kind: SetupKind,
    os: &str,
    has: &dyn Fn(&str) -> bool,
) -> Option<InstallCommand> {
    match (kind, os) {
        (SetupKind::Yggdrasil, "windows") if has("winget") => Some(InstallCommand {
            manager: "winget",
            program: "winget",
            args: vec![
                "install",
                "--id",
                "YggdrasilNetwork.Yggdrasil",
                "--source",
                "winget",
                "-e",
            ],
        }),
        (SetupKind::Tor, "linux") => {
            if has("apt-get") {
                Some(InstallCommand {
                    manager: "apt",
                    program: "apt-get",
                    args: vec!["install", "-y", "tor"],
                })
            } else if has("dnf") {
                Some(InstallCommand {
                    manager: "dnf",
                    program: "dnf",
                    args: vec!["install", "-y", "tor"],
                })
            } else if has("pacman") {
                Some(InstallCommand {
                    manager: "pacman",
                    program: "pacman",
                    args: vec!["-S", "--noconfirm", "tor"],
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_commands_exist_only_where_verified() {
        let all = |_: &str| true;
        let none = |_: &str| false;
        let ygg = install_command(SetupKind::Yggdrasil, "windows", &all).unwrap();
        assert_eq!(
            ygg.command_line(),
            "winget install --id YggdrasilNetwork.Yggdrasil --source winget -e"
        );
        assert!(install_command(SetupKind::Yggdrasil, "windows", &none).is_none());
        assert!(install_command(SetupKind::Yggdrasil, "linux", &all).is_none());
        assert!(install_command(SetupKind::Yggdrasil, "macos", &all).is_none());
        assert!(install_command(SetupKind::Tor, "windows", &all).is_none());
        assert!(install_command(SetupKind::Tor, "macos", &all).is_none());
        let apt = install_command(SetupKind::Tor, "linux", &|m| m == "apt-get").unwrap();
        assert_eq!(apt.command_line(), "apt-get install -y tor");
        assert!(install_command(SetupKind::Tor, "linux", &none).is_none());
    }
}
