//! The command line: arguments and subcommands (clap derive).

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
use socketguard_core::ActivityKind;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "socketguard",
    version,
    about = "Per-app access control for network listeners",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Daemon socket path (Unix) or pipe name (Windows) [default: platform default]
    #[arg(long, env = "SOCKETGUARD_SOCKET", global = true, value_name = "PATH")]
    pub socket: Option<String>,

    /// Machine-readable output: print the API types as JSON
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Daemon status, networks, protect-host, counts
    Status,
    /// List, inspect and manage apps
    #[command(subcommand)]
    Apps(AppsCmd),
    /// Manage peers (who may be granted access) and their credentials
    #[command(subcommand)]
    Peers(PeersCmd),
    /// Manage peer groups
    #[command(subcommand)]
    Groups(GroupsCmd),
    /// Let a peer, a group or anyone reach an app: <app>[:port[/proto]] <subject>
    Grant(GrantArgs),
    /// Remove a grant: by id, or by <app>[:port] <subject>
    Revoke(RevokeArgs),
    /// List grants
    Grants(GrantsArgs),
    /// List, add and remove networks
    #[command(subcommand)]
    Networks(NetworksCmd),
    /// Show and change settings
    #[command(subcommand)]
    Settings(SettingsCmd),
    /// Whole-host protection: close every listener of the host on some interfaces
    #[command(subcommand)]
    ProtectHost(ProtectHostCmd),
    /// Show activity (discoveries, changes, blocked attempts)
    Activity(ActivityArgs),
    /// Print every event the daemon pushes, one line each
    Watch,
    /// New apps without a decision; interactive on a terminal
    Pending,
    /// Print an app's addresses as connection strings
    Share(ShareArgs),
    /// First-run setup: networks, remote-admin listeners, protect-host
    Init,
    /// Write the settings, peers, groups and grants as TOML or JSON
    Export(ExportArgs),
    /// Apply an exported file: show the diff, confirm, apply
    Apply(ApplyArgs),
    /// Remove all rules and addresses and keep them off until `enable`
    Disable(DisableArgs),
    /// Undo `disable`: put the rules and addresses back
    Enable,
    /// Print a shell completion script
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand, Debug)]
pub enum AppsCmd {
    /// List apps
    List {
        /// Only apps without a decision yet
        #[arg(long)]
        pending: bool,
    },
    /// Show an app: addresses, ports, grants with reach, counters
    Show { app: String },
    /// Mark an app as reviewed (it stays closed until granted)
    Review {
        app: String,
        /// Mark it pending again
        #[arg(long)]
        unreviewed: bool,
    },
    /// Forget an app, its addresses and grants (it reappears as pending if it listens again)
    Rm { app: String },
    /// Give one port its own address on a network
    Split {
        app: String,
        #[arg(long)]
        network: String,
        /// <port>[/tcp|/udp]
        port: String,
    },
    /// Merge addresses of one network into the first listed
    Merge {
        app: String,
        #[arg(long)]
        network: String,
        /// Address ids (or unique prefixes), from `apps show`
        #[arg(required = true)]
        address_ids: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum PeersCmd {
    /// List peers
    List,
    /// Show a peer with its credentials and grants
    Show { peer: String },
    /// Add a peer. Bare values are guessed: 64 hex characters are a Yggdrasil key, an IP
    /// address or CIDR is an IP credential, 52 base32 characters (or a
    /// `descriptor:x25519:` line) are a Tor client key
    Add(PeerAddArgs),
    /// Rename a peer
    Rename { peer: String, new_label: String },
    /// Remove a peer and the grants naming it
    Rm { peer: String },
    /// Add or remove credentials
    #[command(subcommand)]
    Cred(CredCmd),
}

#[derive(Args, Debug)]
pub struct PeerAddArgs {
    pub label: String,
    /// Credentials with a guessed kind
    pub values: Vec<String>,
    /// Yggdrasil public key (64 hex characters)
    #[arg(long)]
    pub key: Option<String>,
    /// Tor client authorization public key (52 base32 characters, or the
    /// `descriptor:x25519:<key>` line of an authorized_clients file)
    #[arg(long)]
    pub tor_key: Option<String>,
    /// An IP or Yggdrasil address (repeatable)
    #[arg(long)]
    pub addr: Vec<String>,
    /// A Yggdrasil subnet, e.g. 300:1:2:3::/64
    #[arg(long)]
    pub subnet: Option<String>,
    /// An interface ID, e.g. ::a:b:c:d; follows the prefix of each network
    #[arg(long)]
    pub suffix: Option<String>,
    /// kind=value (repeatable); kinds: ygg_key, ygg_addr, ygg_subnet, ip, ip_suffix,
    /// wg_key, tor_client_key, tls_spki
    #[arg(long = "cred", value_name = "KIND=VALUE")]
    pub creds: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum CredCmd {
    /// Add a credential: <peer> <kind>=<value>
    Add { peer: String, cred: String },
    /// Remove a credential by id (see `peers show`)
    Rm { peer: String, cred_id: String },
}

#[derive(Subcommand, Debug)]
pub enum GroupsCmd {
    /// List groups
    List,
    /// Show a group and its members
    Show { group: String },
    /// Create a group, optionally with members
    Add { label: String, peers: Vec<String> },
    /// Rename a group
    Rename { group: String, new_label: String },
    /// Remove a group and the grants naming it
    Rm { group: String },
    /// Set the members of a group (replaces them)
    Members { group: String, peers: Vec<String> },
}

#[derive(Args, Debug)]
pub struct GrantArgs {
    /// <app>[:port[/proto]]: an app id, unique id prefix or name
    pub target: String,
    /// A peer label, group:<label> or anyone
    pub subject: String,
    /// Only on this network (default: all networks)
    #[arg(long)]
    pub network: Option<String>,
    /// Confirm a grant to anyone without asking
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct RevokeArgs {
    /// A grant id, or <app>[:port[/proto]] together with a subject
    pub target: String,
    pub subject: Option<String>,
    #[arg(long)]
    pub network: Option<String>,
}

#[derive(Args, Debug)]
pub struct GrantsArgs {
    #[arg(long)]
    pub app: Option<String>,
    #[arg(long)]
    pub peer: Option<String>,
    #[arg(long)]
    pub group: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum NetworksCmd {
    /// List networks
    List,
    /// Add a network (saved to the daemon's config file)
    Add {
        /// ula, slaac, dhcpv6, yggdrasil or tor
        r#type: String,
        #[arg(long)]
        interface: Option<String>,
        /// Defaults to the type (and interface)
        #[arg(long)]
        id: Option<String>,
        /// Yggdrasil admin endpoint, e.g. unix:///var/run/yggdrasil.sock
        #[arg(long)]
        admin_endpoint: Option<String>,
        /// Tor control port, `host:port` or `unix:/path` [default: 127.0.0.1:9051]
        #[arg(long)]
        control: Option<String>,
        /// Tor control password; without it the cookie file named by Tor is used
        #[arg(long)]
        password: Option<String>,
    },
    /// Remove a network; its addresses leave the interfaces
    Rm {
        id: String,
        /// Remove a Tor network even if Tor cannot confirm its onion services are gone
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SettingsCmd {
    /// Show the settings
    Show,
    /// One address per app, or one per port
    AddressMode {
        #[arg(value_parser = ["per-app", "per-port"])]
        mode: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProtectHostCmd {
    /// Protect the host on these interfaces
    On {
        #[arg(required = true)]
        interfaces: Vec<String>,
        /// Enable even if remote administration would be cut off
        #[arg(long)]
        force: bool,
    },
    /// Turn it off
    Off,
    /// Show the interfaces under protection
    Status,
}

fn parse_kind(s: &str) -> Result<ActivityKind, String> {
    s.parse()
}

#[derive(Args, Debug)]
pub struct ActivityArgs {
    #[arg(long)]
    pub app: Option<String>,
    #[arg(long)]
    pub peer: Option<String>,
    /// app_discovered, grant_added, blocked, ...
    #[arg(long, value_parser = parse_kind)]
    pub kind: Option<ActivityKind>,
    /// Shortcut for --kind blocked
    #[arg(long, conflicts_with = "kind")]
    pub blocked: bool,
    /// Most recent records to show
    #[arg(long, default_value_t = 50)]
    pub limit: u32,
    /// Keep running and print new records as they arrive
    #[arg(long, short = 'f')]
    pub follow: bool,
}

#[derive(Args, Debug)]
pub struct ShareArgs {
    pub app: String,
    #[arg(long)]
    pub network: Option<String>,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Write to a file instead of stdout; `.json` selects JSON
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// toml or json (default: by file extension, else toml)
    #[arg(long, value_parser = ["toml", "json"])]
    pub format: Option<String>,
}

#[derive(Args, Debug)]
pub struct ApplyArgs {
    /// A TOML or JSON file, as written by `export`
    #[arg(short, long)]
    pub file: PathBuf,
    /// Show the diff and stop
    #[arg(long)]
    pub dry_run: bool,
    /// Apply without asking
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct DisableArgs {
    /// Do not ask
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("socketguard").chain(args.iter().copied()))
    }

    #[test]
    fn the_command_tree_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn global_options_work_anywhere() {
        let c = parse(&["--json", "apps", "list", "--pending", "--socket", "/x.sock"]).unwrap();
        assert!(c.json);
        assert_eq!(c.socket.as_deref(), Some("/x.sock"));
        assert!(matches!(
            c.command,
            Command::Apps(AppsCmd::List { pending: true })
        ));
    }

    #[test]
    fn peers_add_takes_values_and_flags() {
        let c = parse(&[
            "peers", "add", "bob", "ba83", "--addr", "a", "--addr", "b", "--cred", "ip=1::1",
            "--key", "k",
        ])
        .unwrap();
        let Command::Peers(PeersCmd::Add(a)) = c.command else {
            panic!()
        };
        assert_eq!(a.label, "bob");
        assert_eq!(a.values, ["ba83"]);
        assert_eq!(a.addr, ["a", "b"]);
        assert_eq!(a.creds, ["ip=1::1"]);
        assert_eq!(a.key.as_deref(), Some("k"));
    }

    #[test]
    fn grant_and_revoke() {
        let c = parse(&[
            "grant",
            "nginx:80/tcp",
            "group:team",
            "--network",
            "ygg",
            "-y",
        ])
        .unwrap();
        let Command::Grant(g) = c.command else {
            panic!()
        };
        assert_eq!(
            (g.target.as_str(), g.subject.as_str(), g.yes),
            ("nginx:80/tcp", "group:team", true)
        );
        assert_eq!(g.network.as_deref(), Some("ygg"));
        let c = parse(&["revoke", "abc123"]).unwrap();
        let Command::Revoke(r) = c.command else {
            panic!()
        };
        assert!(r.subject.is_none());
    }

    #[test]
    fn activity_flags() {
        let c = parse(&["activity", "--blocked", "--limit", "5", "-f"]).unwrap();
        let Command::Activity(a) = c.command else {
            panic!()
        };
        assert!(a.blocked && a.follow);
        assert_eq!(a.limit, 5);
        let c = parse(&["activity", "--kind", "grant_added"]).unwrap();
        let Command::Activity(a) = c.command else {
            panic!()
        };
        assert_eq!(a.kind, Some(ActivityKind::GrantAdded));
        assert!(parse(&["activity", "--kind", "nonsense"]).is_err());
        assert!(parse(&["activity", "--kind", "blocked", "--blocked"]).is_err());
    }

    #[test]
    fn bad_usage_is_rejected() {
        assert!(parse(&[]).is_err(), "a command is required");
        assert!(parse(&["apps", "merge", "x", "--network", "ygg"]).is_err());
        assert!(parse(&["settings", "address-mode", "sometimes"]).is_err());
        assert!(parse(&["protect-host", "on"]).is_err());
        assert!(parse(&["completions", "klingon"]).is_err());
    }
}
