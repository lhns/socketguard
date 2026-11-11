//! The command line: arguments and subcommands (clap derive).

use clap::{Args, Parser, Subcommand, ValueEnum};
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
    /// Manage tags: named sets of apps (or ports) that grants can target
    #[command(subcommand)]
    Tags(TagsCmd),
    /// Manage port groups: named sets of ports and port ranges, attached to apps and then
    /// usable as a scope (`<app>:socket-group=<label>`, `--socket-group <label>`)
    #[command(subcommand)]
    SocketGroups(SocketGroupsCmd),
    /// Manage reservations: a named address that keeps its place while the apps behind it
    /// change; grants can target it (`reservation:<label>`)
    #[command(subcommand)]
    Reservations(ReservationsCmd),
    /// List every address, and turn an automatic one into a reservation
    #[command(subcommand)]
    Addresses(AddressesCmd),
    /// Manage peer groups
    #[command(subcommand)]
    Groups(GroupsCmd),
    /// Let a peer, a group or anyone reach an app, a tag or a reservation: <app>[:port[/proto]]
    /// <subject>, or repeat --app/--tag/--reservation, --port, --to and --network to grant many
    /// at once (one batch)
    Grant(GrantArgs),
    /// Remove a grant: by id, by <app>[:port] <subject>, or with the repeatable flags of `grant`
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
    /// Print an app's addresses as connection strings (it has one once a grant names it)
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
    /// Move everything one app has (grants, tag memberships, addresses, reservation bindings)
    /// to another app, e.g. after an upgrade changed the executable path
    Move {
        /// The app that has it now
        from: String,
        /// The app that takes over
        to: String,
        /// Confirm without asking when this opens an app to anyone
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum PeersCmd {
    /// List peers
    List,
    /// Show a peer with its credentials and grants
    Show { peer: String },
    /// Add a peer. Bare values are classified like `peers parse`: 64 hex characters are a
    /// Yggdrasil key, an IP address or CIDR is an IP credential, 52 base32 characters (or a
    /// `descriptor:x25519:` line) are a Tor client key
    Add(PeerAddArgs),
    /// Show what pasted credentials are and where they work, without adding anything
    Parse {
        /// Values separated by spaces, commas or newlines
        #[arg(required = true)]
        values: Vec<String>,
    },
    /// Generate a Tor client key for a peer (replaces the one generated before). The
    /// private key is shown; `share` prints it as a ClientOnionAuthDir line per app
    TorKey { peer: String },
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
    /// A name for the peer; without one it is named after its first credential
    #[arg(long, short = 'n')]
    pub label: Option<String>,
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

#[derive(Subcommand, Debug)]
pub enum TagsCmd {
    /// List tags
    List,
    /// Show a tag: patterns, members and the grants on it
    Show { tag: String },
    /// Create a tag, optionally with patterns and members. Apps whose process name or
    /// executable path matches a pattern join it, now and when they start later
    Add {
        label: String,
        /// Members: <app>[:port[/proto]]
        members: Vec<String>,
        /// A glob on the process name or the executable path (repeatable), e.g. 'python*'
        #[arg(long = "match", value_name = "PATTERN")]
        patterns: Vec<String>,
    },
    /// Rename a tag
    Rename { tag: String, new_label: String },
    /// Replace the patterns of a tag (none: clear them)
    Patterns {
        tag: String,
        patterns: Vec<String>,
        /// Confirm without asking when apps would join a tag that is open to anyone
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Remove a tag and the grants on it
    Rm { tag: String },
    /// Add or remove members
    #[command(subcommand)]
    Members(TagMembersCmd),
}

#[derive(Subcommand, Debug)]
pub enum SocketGroupsCmd {
    /// List port groups
    List,
    /// Create a port group from ports (`80/tcp`) and ranges (`50000-51000/tcp`)
    Add {
        label: String,
        #[arg(required = true, value_name = "PORTS")]
        ports: Vec<String>,
        /// Attach it to this app right away (repeatable)
        #[arg(long = "app", value_name = "APP")]
        apps: Vec<String>,
        /// Confirm without asking when attaching opens an app to anyone
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Rename a port group and/or replace its ports (they take effect wherever it is used)
    Set {
        group: String,
        /// The new label
        #[arg(long = "label")]
        label: Option<String>,
        /// The new ports, `80/tcp` or `50000-51000/tcp` (repeatable; replaces the old ones)
        #[arg(long = "port", value_name = "PORTS")]
        ports: Vec<String>,
        /// Confirm without asking when the new ports open an app to anyone
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Delete a port group; refused while a grant or tag member uses it
    Rm { group: String },
    /// Attach a port group to an app
    Attach {
        group: String,
        app: String,
        /// Confirm without asking when this opens the app to anyone
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Detach a port group from an app; refused while a grant or tag member uses it there
    Detach { group: String, app: String },
}

#[derive(Subcommand, Debug)]
pub enum ReservationsCmd {
    /// List reservations: bindings, addresses (up or closed), conflicts and grants
    List,
    /// Create a reservation, optionally with bindings. A binding is an app row,
    /// <app>[:port[/proto]] or <app>:socket-group=<label>, or tag:<label>
    Add {
        label: String,
        bindings: Vec<String>,
    },
    /// Rename a reservation
    Rename {
        reservation: String,
        new_label: String,
    },
    /// Bind app rows (or the members of a tag) to a reservation
    Bind {
        reservation: String,
        #[arg(required = true)]
        targets: Vec<String>,
        /// Confirm without asking when the reservation is open to anyone
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Remove bindings, given the way `bind` takes them
    Unbind {
        reservation: String,
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Delete a reservation, its addresses and the grants on it
    Release { reservation: String },
}

#[derive(Subcommand, Debug)]
pub enum AddressesCmd {
    /// List every address with its owner, ports and state
    List,
    /// Turn an automatic address into a reservation that keeps it
    Reserve {
        /// An address id (or unique prefix), from `addresses list`
        address: String,
        /// The reservation's label
        label: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum TagMembersCmd {
    /// Add apps (or one port or port group of an app): <app>[:port[/proto]] or
    /// <app>:socket-group=<label>
    Add {
        tag: String,
        #[arg(required = true)]
        members: Vec<String>,
        /// Confirm without asking when the tag is open to anyone
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Remove members; an app a pattern matches stays out afterwards
    Rm {
        tag: String,
        #[arg(required = true)]
        members: Vec<String>,
    },
}

#[derive(Args, Debug)]
pub struct GrantArgs {
    /// <app>[:port[/proto]], tag:<label>[:port[/proto]] or reservation:<label>: an app id,
    /// unique id prefix or name. Alternatively use the flags below
    pub target: Option<String>,
    /// A peer label, group:<label> or anyone
    pub subject: Option<String>,
    /// An app, `<app>[:port[/proto]]` (repeatable)
    #[arg(long = "app", value_name = "APP")]
    pub apps: Vec<String>,
    /// A tag, `<label>[:port[/proto]]` (repeatable)
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// A reservation, by label (repeatable); it takes no port
    #[arg(long = "reservation", value_name = "RESERVATION")]
    pub reservations: Vec<String>,
    /// Limit the apps and tags to this port, `<port>[/proto]` (repeatable)
    #[arg(long = "port", value_name = "PORT")]
    pub ports: Vec<String>,
    /// Limit the apps and tags to this port group, by label (repeatable)
    #[arg(long = "socket-group", value_name = "LABEL")]
    pub socket_groups: Vec<String>,
    /// A peer label, group:<label> or anyone (repeatable)
    #[arg(long = "to", value_name = "SUBJECT")]
    pub to: Vec<String>,
    /// Only on this network (repeatable; default: all networks)
    #[arg(long = "network")]
    pub networks: Vec<String>,
    /// Confirm a grant to anyone without asking
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// With the flags: show what would change, change nothing
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct RevokeArgs {
    /// A grant id, or <app>[:port[/proto]], tag:<label>[:port[/proto]] or reservation:<label>
    /// with a subject
    pub target: Option<String>,
    pub subject: Option<String>,
    /// An app, `<app>[:port[/proto]]` (repeatable)
    #[arg(long = "app", value_name = "APP")]
    pub apps: Vec<String>,
    /// A tag, `<label>[:port[/proto]]` (repeatable)
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// A reservation, by label (repeatable); it takes no port
    #[arg(long = "reservation", value_name = "RESERVATION")]
    pub reservations: Vec<String>,
    /// Limit the apps and tags to this port, `<port>[/proto]` (repeatable)
    #[arg(long = "port", value_name = "PORT")]
    pub ports: Vec<String>,
    /// Limit the apps and tags to this port group, by label (repeatable)
    #[arg(long = "socket-group", value_name = "LABEL")]
    pub socket_groups: Vec<String>,
    /// A peer label, group:<label> or anyone (repeatable)
    #[arg(long = "to", value_name = "SUBJECT")]
    pub to: Vec<String>,
    /// Only the grants on this network (repeatable; default: any network)
    #[arg(long = "network")]
    pub networks: Vec<String>,
    /// With the flags: show what would change, change nothing
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct GrantsArgs {
    #[arg(long)]
    pub app: Option<String>,
    /// Grants on this tag
    #[arg(long)]
    pub tag: Option<String>,
    /// Grants on this reservation
    #[arg(long)]
    pub reservation: Option<String>,
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
        #[arg(value_enum, ignore_case = true)]
        r#type: NetworkType,
        #[arg(long)]
        interface: Option<String>,
        /// Defaults to the type (and interface)
        #[arg(long)]
        id: Option<String>,
        /// Yggdrasil admin endpoint, e.g. unix:///var/run/yggdrasil.sock
        #[arg(long)]
        admin_endpoint: Option<String>,
        /// Tor control port, `host:port` or `unix:/path` [default: 127.0.0.1:9051]; the daemon refuses
        /// other values unless its config file has the same network (edit the file instead)
        #[arg(long)]
        control: Option<String>,
        /// Tor control password; without it the cookie file named by Tor is used. Like --control,
        /// refused unless the config file has the same network. WARNING: visible to other
        /// users in the process list; prefer --password-env or --password-stdin
        #[arg(long, conflicts_with_all = ["password_env", "password_stdin"])]
        password: Option<String>,
        /// Read the Tor control password from this environment variable
        #[arg(long, value_name = "VAR", conflicts_with = "password_stdin")]
        password_env: Option<String>,
        /// Read the Tor control password from the first line of stdin
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove a network; its addresses leave the interfaces
    Rm {
        id: String,
        /// Remove a Tor network even if Tor cannot confirm its onion services are gone
        #[arg(long)]
        force: bool,
    },
}

/// The kinds of network `networks add` can make.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkType {
    Ula,
    Slaac,
    Dhcpv6,
    Yggdrasil,
    Tor,
}

impl std::fmt::Display for NetworkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_possible_value() {
            Some(v) => f.write_str(v.get_name()),
            None => Ok(()),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum SettingsCmd {
    /// Show the settings
    Show,
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

#[derive(Args, Debug)]
pub struct ActivityArgs {
    #[arg(long)]
    pub app: Option<String>,
    #[arg(long)]
    pub peer: Option<String>,
    /// app_discovered, grant_added, blocked, ...
    #[arg(long)]
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
            "peers", "add", "--label", "bob", "ba83", "--addr", "a", "--addr", "b", "--cred",
            "ip=1::1", "--key", "k",
        ])
        .unwrap();
        let Command::Peers(PeersCmd::Add(a)) = c.command else {
            panic!()
        };
        assert_eq!(a.label.as_deref(), Some("bob"));
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
            (g.target.as_deref(), g.subject.as_deref(), g.yes),
            (Some("nginx:80/tcp"), Some("group:team"), true)
        );
        assert_eq!(g.networks, ["ygg"]);
        let c = parse(&["revoke", "abc123"]).unwrap();
        let Command::Revoke(r) = c.command else {
            panic!()
        };
        assert!(r.subject.is_none());
    }

    #[test]
    fn socket_group_commands_and_flags_parse() {
        let c = parse(&[
            "socket-groups",
            "add",
            "passive",
            "21/tcp",
            "50000-51000/tcp",
            "--app",
            "ftpd",
        ])
        .unwrap();
        let Command::SocketGroups(SocketGroupsCmd::Add {
            label, ports, apps, ..
        }) = c.command
        else {
            panic!()
        };
        assert_eq!(label, "passive");
        assert_eq!(ports, ["21/tcp", "50000-51000/tcp"]);
        assert_eq!(apps, ["ftpd"]);
        assert!(parse(&["socket-groups", "attach", "passive", "ftpd", "-y"]).is_ok());
        let c = parse(&[
            "grant",
            "--app",
            "ftpd",
            "--socket-group",
            "passive",
            "--to",
            "alice",
        ])
        .unwrap();
        let Command::Grant(g) = c.command else {
            panic!()
        };
        assert_eq!(g.socket_groups, ["passive"]);
    }

    #[test]
    fn grant_takes_repeatable_flags() {
        let c = parse(&[
            "grant",
            "--app",
            "a",
            "--app",
            "b:80",
            "--tag",
            "dev",
            "--port",
            "80",
            "--port",
            "443",
            "--to",
            "alice",
            "--to",
            "group:team",
            "--network",
            "lan",
            "--network",
            "ygg",
        ])
        .unwrap();
        let Command::Grant(g) = c.command else {
            panic!()
        };
        assert_eq!(g.apps, ["a", "b:80"]);
        assert_eq!(g.tags, ["dev"]);
        assert_eq!(g.ports, ["80", "443"]);
        assert_eq!(g.to, ["alice", "group:team"]);
        assert_eq!(g.networks, ["lan", "ygg"]);
        assert!(g.target.is_none());
    }

    #[test]
    fn tags_commands() {
        let c = parse(&[
            "tags", "add", "dev", "web:80", "--match", "py*", "--match", "node",
        ])
        .unwrap();
        let Command::Tags(TagsCmd::Add {
            label,
            members,
            patterns,
        }) = c.command
        else {
            panic!()
        };
        assert_eq!((label.as_str(), members.len()), ("dev", 1));
        assert_eq!(patterns, ["py*", "node"]);
        assert!(parse(&["tags", "members", "add", "dev"]).is_err());
        assert!(parse(&["tags", "members", "rm", "dev", "web"]).is_ok());
    }

    #[test]
    fn reservation_and_address_commands() {
        let c = parse(&["reservations", "add", "web", "nginx:80", "tag:dev"]).unwrap();
        let Command::Reservations(ReservationsCmd::Add { label, bindings }) = c.command else {
            panic!()
        };
        assert_eq!((label.as_str(), bindings.len()), ("web", 2));
        let c = parse(&["reservations", "bind", "web", "redis", "-y"]).unwrap();
        let Command::Reservations(ReservationsCmd::Bind { targets, yes, .. }) = c.command else {
            panic!()
        };
        assert_eq!((targets, yes), (vec!["redis".to_string()], true));
        assert!(parse(&["reservations", "unbind", "web", "redis"]).is_ok());
        assert!(parse(&["reservations", "rename", "web", "site"]).is_ok());
        assert!(parse(&["reservations", "release", "web"]).is_ok());
        assert!(parse(&["addresses", "list"]).is_ok());
        assert!(parse(&["addresses", "reserve", "a1b2", "web"]).is_ok());
        assert!(parse(&["addresses", "reserve", "a1b2"]).is_err());
        let c = parse(&["apps", "move", "old", "new", "--yes"]).unwrap();
        let Command::Apps(AppsCmd::Move { from, to, yes }) = c.command else {
            panic!()
        };
        assert_eq!((from.as_str(), to.as_str(), yes), ("old", "new", true));
        let c = parse(&["grant", "--reservation", "web", "--to", "alice"]).unwrap();
        let Command::Grant(g) = c.command else {
            panic!()
        };
        assert_eq!(g.reservations, ["web"]);
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
    fn network_types_are_choices() {
        let c = parse(&["networks", "add", "YGGDRASIL", "--interface", "ygg0"]).unwrap();
        let Command::Networks(NetworksCmd::Add { r#type, .. }) = c.command else {
            panic!()
        };
        assert_eq!(r#type, NetworkType::Yggdrasil);
        assert!(parse(&["networks", "add", "wireguard"]).is_err());
    }

    #[test]
    fn the_tor_password_has_one_source() {
        let add = ["networks", "add", "tor"];
        let with = |extra: &[&str]| parse(&[&add[..], extra].concat());
        assert!(with(&["--password", "x"]).is_ok());
        assert!(with(&["--password-env", "TOR_PW"]).is_ok());
        assert!(with(&["--password-stdin"]).is_ok());
        assert!(with(&["--password", "x", "--password-env", "TOR_PW"]).is_err());
        assert!(with(&["--password", "x", "--password-stdin"]).is_err());
        assert!(with(&["--password-env", "TOR_PW", "--password-stdin"]).is_err());
    }

    #[test]
    fn bad_usage_is_rejected() {
        assert!(parse(&[]).is_err(), "a command is required");
        assert!(parse(&["apps", "split", "x"]).is_err());
        assert!(parse(&["apps", "merge", "x"]).is_err());
        assert!(parse(&["settings", "address-mode", "per-port"]).is_err());
        assert!(parse(&["apps", "move", "only-one"]).is_err());
        assert!(parse(&["reservations", "bind", "web"]).is_err());
        assert!(parse(&["protect-host", "on"]).is_err());
        assert!(parse(&["completions", "klingon"]).is_err());
    }
}
