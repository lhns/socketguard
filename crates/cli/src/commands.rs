//! What each command does: resolve names, call the client, print. The interactive flows
//! are in [`crate::flows`], export documents in [`crate::document`], output formatting in
//! [`crate::render`], parsing in [`crate::parse`].

use crate::cli::*;
use crate::document;
use crate::flows;
use crate::parse::{self, SubjectSpec, TargetSpec};
use crate::prompt::{self, Prompter};
use crate::render::{self, Names};
use crate::resolve::{resolve, short};
use crate::Reported;
use anyhow::{anyhow, bail, Context, Result};
use clap::CommandFactory;
use futures_util::StreamExt;
use serde::Serialize;
use socketguard_client::{ApiEvent, Client, Error as ApiError, GrantQuery, Saved};
use socketguard_core::api_types::{
    error_code, ApplyRequest, ChangeOp, ChangesRequest, Enforcement, LockoutRiskInfo,
    MoveAppRequest, NewBinding, NewGroup, NewNetwork, NewPeer, NewPortGroup, NewReservation,
    NewTag, ProtectHostRequest, ProtectHostResponse, ReserveRequest, UpdatePortGroup, UpdateTag,
};
use socketguard_core::config::TorAuth;
use socketguard_core::{
    ActivityKind, ActivityQuery, ActivityRecord, App, BackendConfig, BindingTarget, CredentialKind,
    GrantView, NewCredential, NewGrant, Peer, PeerGroup, PortGroup, ReservationView, Scope,
    Subject, Tag, TagMember, Target,
};

/// What every command needs: the client and the output mode.
pub struct Ctx {
    pub client: Client,
    pub json: bool,
}

pub async fn run(cli: Cli) -> Result<()> {
    if let Command::Completions { shell } = &cli.command {
        let mut cmd = Cli::command();
        clap_complete::generate(*shell, &mut cmd, "socketguard", &mut std::io::stdout());
        return Ok(());
    }
    // The environment is read by clap (`--socket`); without either, the platform default.
    let endpoint = cli
        .socket
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(socketguard_client::default_endpoint);
    let c = Ctx::new(Client::new(endpoint), cli.json);
    match cli.command {
        Command::Status => status(&c).await,
        Command::Apps(cmd) => apps(&c, cmd).await,
        Command::Peers(cmd) => peers(&c, cmd).await,
        Command::Groups(cmd) => groups(&c, cmd).await,
        Command::Tags(cmd) => tags(&c, cmd).await,
        Command::PortGroups(cmd) => port_groups(&c, cmd).await,
        Command::Reservations(cmd) => reservations(&c, cmd).await,
        Command::Addresses(cmd) => addresses(&c, cmd).await,
        Command::Grant(a) => grant(&c, a).await,
        Command::Revoke(a) => revoke(&c, a).await,
        Command::Grants(a) => grants(&c, a).await,
        Command::Networks(cmd) => networks(&c, cmd).await,
        Command::Settings(cmd) => settings(&c, cmd).await,
        Command::ProtectHost(cmd) => protect_host(&c, cmd).await,
        Command::Activity(a) => activity(&c, a).await,
        Command::Watch => watch(&c).await,
        Command::Share(a) => share(&c, a).await,
        Command::Init => flows::init(&c, &mut prompt::Stdin).await,
        Command::Export(a) => export(&c, a).await,
        Command::Apply(a) => apply(&c, a).await,
        Command::Exposure { without } => {
            let e = c.client.exposure(without.as_deref()).await?;
            c.print(&e, || {
                let text = render::exposure(&e);
                if text.is_empty() {
                    "nothing becomes reachable: no Yggdrasil node keeps running".to_string()
                } else {
                    text
                }
            })
        }
        Command::Disable(a) => disable(&c, a).await,
        Command::Enable => enable(&c).await,
        Command::Access(cmd) => access(cmd),
        Command::Completions { .. } => unreachable!("handled above"),
    }
}

// ─── Access (ADR 0050) ───────────────────────────────────────────────────────

/// The daemon binary installed next to the given `socketguard` executable.
fn daemon_next_to(exe: &std::path::Path) -> Result<std::path::PathBuf> {
    let name = format!("socketguard-daemon{}", std::env::consts::EXE_SUFFIX);
    let daemon = exe.parent().map(|d| d.join(&name));
    match daemon {
        Some(p) if p.is_file() => Ok(p),
        _ => bail!(
            "{name} was not found next to {}; `socketguard access` runs it, so both must be installed together",
            exe.display()
        ),
    }
}

/// `socketguard access allow|deny|list`: hand over to `socketguard-daemon access`, which
/// does the work and needs administrator rights. Its output and exit status are ours.
fn access(cmd: AccessCmd) -> Result<()> {
    let exe = std::env::current_exe().context("cannot tell where socketguard is installed")?;
    let daemon = daemon_next_to(&exe)?;
    let args: Vec<&str> = match &cmd {
        AccessCmd::Allow { account } => vec!["access", "allow", account],
        AccessCmd::Deny { account } => vec!["access", "deny", account],
        AccessCmd::List => vec!["access", "list"],
    };
    let status = std::process::Command::new(&daemon)
        .args(&args)
        .status()
        .with_context(|| format!("cannot run {}", daemon.display()))?;
    if !status.success() {
        bail!("{} {} failed ({status})", daemon.display(), args.join(" "));
    }
    Ok(())
}

// ─── Output and lookups ──────────────────────────────────────────────────────

impl Ctx {
    pub fn new(client: Client, json: bool) -> Self {
        Self { client, json }
    }

    /// Print `value` as JSON, or the human form.
    pub(crate) fn print<T: Serialize>(
        &self,
        value: &T,
        human: impl FnOnce() -> String,
    ) -> Result<()> {
        if self.json {
            println!("{}", serde_json::to_string_pretty(value)?);
        } else {
            let text = human();
            if !text.is_empty() {
                println!("{text}");
            }
        }
        Ok(())
    }

    /// Result of a change that returns nothing: a message, or `{"ok": true}`.
    fn done(&self, message: impl Into<String>) -> Result<()> {
        self.print(&serde_json::json!({"ok": true}), || message.into())
    }

    /// Like [`Ctx::done`] for a change the daemon may not have enforced everywhere yet
    /// (HTTP 202): the warning goes to stderr, and into the JSON.
    fn done_saved(&self, saved: Saved<()>, message: impl Into<String>) -> Result<()> {
        self.warn_pending(&saved.enforcement);
        let mut v = serde_json::json!({"ok": true});
        if let Some(e) = &saved.enforcement {
            v["enforcement"] = serde_json::to_value(e)?;
        }
        self.print(&v, || message.into())
    }

    /// Say that a saved change is not in effect everywhere yet.
    pub(crate) fn warn_pending(&self, enforcement: &Option<Enforcement>) {
        if let Some(e) = enforcement {
            eprintln!("warning: {}", e.message);
        }
    }

    async fn apps(&self) -> Result<Vec<App>> {
        Ok(self.client.list_apps().await?)
    }

    async fn app(&self, query: &str) -> Result<App> {
        Ok(resolve("app", &self.apps().await?, query)?.clone())
    }

    async fn peer(&self, query: &str) -> Result<Peer> {
        Ok(resolve("peer", &self.client.list_peers().await?, query)?.clone())
    }

    async fn group(&self, query: &str) -> Result<PeerGroup> {
        Ok(resolve("group", &self.client.list_groups().await?, query)?.clone())
    }

    /// The id of the app the user named, if they named one.
    async fn opt_app(&self, query: Option<&str>) -> Result<Option<String>> {
        match query {
            Some(q) => Ok(Some(self.app(q).await?.id)),
            None => Ok(None),
        }
    }

    async fn opt_peer(&self, query: Option<&str>) -> Result<Option<String>> {
        match query {
            Some(q) => Ok(Some(self.peer(q).await?.id)),
            None => Ok(None),
        }
    }

    async fn opt_group(&self, query: Option<&str>) -> Result<Option<String>> {
        match query {
            Some(q) => Ok(Some(self.group(q).await?.id)),
            None => Ok(None),
        }
    }

    async fn names(&self) -> Result<Names> {
        Ok(Names::new(
            &self.apps().await?,
            &self.client.list_peers().await?,
            &self.client.list_groups().await?,
        )
        .with_tags(&self.client.list_tags().await?)
        .with_reservations(&self.client.list_reservations().await?)
        .with_port_groups(&self.client.list_port_groups().await?))
    }

    async fn reservation(&self, query: &str) -> Result<ReservationView> {
        Ok(resolve(
            "reservation",
            &self.client.list_reservations().await?,
            query,
        )?
        .clone())
    }

    async fn port_group(&self, query: &str) -> Result<PortGroup> {
        Ok(resolve("port group", &self.client.list_port_groups().await?, query)?.clone())
    }

    /// A scope as typed, with a port group resolved by label.
    async fn scope(&self, spec: &parse::ScopeSpec) -> Result<Scope> {
        Ok(match spec {
            parse::ScopeSpec::All => Scope::All,
            parse::ScopeSpec::Port(p) => Scope::port(*p),
            parse::ScopeSpec::Group(label) => Scope::group(self.port_group(label).await?.id),
        })
    }

    async fn subject(&self, spec: &SubjectSpec) -> Result<Subject> {
        Ok(match spec {
            SubjectSpec::Anyone => Subject::Anyone,
            SubjectSpec::Peer(p) => Subject::Peer(self.peer(p).await?.id),
            SubjectSpec::Group(g) => Subject::Group(self.group(g).await?.id),
        })
    }
}

// ─── Status, networks, settings ──────────────────────────────────────────────

async fn status(c: &Ctx) -> Result<()> {
    let s = c.client.status().await?;
    c.print(&s, || render::status(&s))
}

async fn networks(c: &Ctx, cmd: NetworksCmd) -> Result<()> {
    match cmd {
        NetworksCmd::List => {
            let n = c.client.list_networks().await?;
            c.print(&n, || render::networks(&n))
        }
        NetworksCmd::Detect => {
            let s = c.client.network_setup().await?;
            c.print(&s, || render::network_setup(&s))
        }
        NetworksCmd::Setup {
            kind,
            yes,
            dry_run,
            config,
            torrc,
            pause,
            undo,
            uninstall_packages,
            stop_service_only,
        } => {
            let opts = crate::setup::Options {
                yes,
                dry_run,
                config: config.clone(),
                torrc,
            };
            let result = if undo {
                let u = crate::setup::UndoOptions {
                    yes,
                    dry_run,
                    config,
                    uninstall_packages,
                    stop_service_only,
                };
                crate::setup::undo(kind.into(), &u, &mut crate::setup::System, &c.client)
                    .await
                    .map(|()| Default::default())
            } else {
                crate::setup::run(kind.into(), &opts, &mut crate::setup::System, &c.client).await
            };
            let outcome = match result {
                Ok(changes) => {
                    if !changes.list().is_empty() {
                        println!("\nDone. Changes made:");
                        for l in changes.list() {
                            println!("  - {l}");
                        }
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("error: {e:#}");
                    Err(Reported.into())
                }
            };
            if pause {
                println!("\nPress Enter to close this window.");
                let _ = std::io::stdin().read_line(&mut String::new());
            }
            outcome
        }
        NetworksCmd::Add {
            r#type,
            interface,
            id,
            admin_endpoint,
            control,
            password,
            password_env,
            password_stdin,
        } => {
            let backend = if r#type == NetworkType::Tor {
                if interface.is_some() || admin_endpoint.is_some() {
                    bail!("tor has no --interface or --admin-endpoint");
                }
                let password = tor_password(password, password_env, password_stdin)?;
                tor_config(control, password)
            } else {
                if control.is_some()
                    || password.is_some()
                    || password_env.is_some()
                    || password_stdin
                {
                    bail!("--control and the --password options only apply to tor");
                }
                backend_config(r#type, interface, admin_endpoint)?
            };
            let saved = c.client.add_network(&NewNetwork { id, backend }).await?;
            c.warn_pending(&saved.enforcement);
            let n = saved.value;
            c.print(&n, || {
                format!(
                    "added network {}\n\n{}",
                    n.id,
                    render::networks(std::slice::from_ref(&n))
                )
            })
        }
        NetworksCmd::Rm { id, force, yes } => {
            // Removing the network removes its block: say what that leaves reachable.
            let exposure = c.client.exposure(Some(&id)).await?;
            let text = render::exposure(&exposure);
            if !text.is_empty() {
                eprintln!("{text}");
                prompt::Stdin.confirm_or_yes(
                    yes,
                    "Remove the network anyway?",
                    "removing this network leaves the host reachable over it; repeat with --yes to confirm",
                )?;
            }
            c.client.delete_network(&id, force, true).await?;
            c.done(format!("removed network {id}"))
        }
    }
}

/// The Tor control password from the option that gave it: the command line, an
/// environment variable, or the first line of stdin. Empty is an error.
fn tor_password(
    password: Option<String>,
    env: Option<String>,
    stdin: bool,
) -> Result<Option<String>> {
    let password = match (password, env, stdin) {
        (Some(p), _, _) => p,
        (None, Some(var), _) => std::env::var(&var)
            .map_err(|_| anyhow!("--password-env: {var} is not set to a text value"))?,
        (None, None, true) => read_password_line(std::io::stdin().lock())?,
        (None, None, false) => return Ok(None),
    };
    if password.is_empty() {
        bail!("the Tor control password is empty");
    }
    Ok(Some(password))
}

/// The first line of `input`, without its line ending.
fn read_password_line(mut input: impl std::io::BufRead) -> Result<String> {
    let mut line = String::new();
    input
        .read_line(&mut line)
        .context("reading the password from stdin")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// `tor [--control X] [--password P]` as the daemon's backend config.
pub fn tor_config(control: Option<String>, password: Option<String>) -> BackendConfig {
    let mut config = BackendConfig::default_tor();
    if let BackendConfig::Tor {
        control: c, auth, ..
    } = &mut config
    {
        if let Some(control) = control {
            *c = control;
        }
        if let Some(password) = password {
            *auth = TorAuth::Password(password);
        }
    }
    config
}

/// `<type> --interface X [--admin-endpoint Z]` as the daemon's backend config; not for tor.
pub fn backend_config(
    kind: NetworkType,
    interface: Option<String>,
    admin_endpoint: Option<String>,
) -> Result<BackendConfig> {
    if admin_endpoint.is_some() && kind != NetworkType::Yggdrasil {
        bail!("--admin-endpoint only applies to yggdrasil");
    }
    let required = || {
        interface
            .clone()
            .ok_or_else(|| anyhow!("--interface is required for {kind}"))
    };
    Ok(match kind {
        // Without an interface the daemon's default (loopback).
        NetworkType::Ula => match &interface {
            Some(interface) => BackendConfig::Ula {
                interface: interface.clone(),
            },
            None => BackendConfig::default(),
        },
        NetworkType::Slaac => BackendConfig::Slaac {
            interface: required()?,
            prefix: None,
        },
        NetworkType::Dhcpv6 => BackendConfig::Dhcpv6 {
            interface: required()?,
        },
        NetworkType::Yggdrasil => BackendConfig::Yggdrasil {
            interface,
            admin_endpoint,
        },
        NetworkType::Tor => bail!("tor is configured with tor_config"),
    })
}

async fn settings(c: &Ctx, cmd: SettingsCmd) -> Result<()> {
    match cmd {
        SettingsCmd::Show => {
            let s = c.client.get_settings().await?;
            c.print(&s, || render::settings(&s))
        }
    }
}

async fn protect_host(c: &Ctx, cmd: ProtectHostCmd) -> Result<()> {
    match cmd {
        ProtectHostCmd::Status => {
            let s = c.client.get_settings().await?;
            c.print(&s.protect_host_interfaces, || {
                if s.protect_host_interfaces.is_empty() {
                    "protect-host is off".to_string()
                } else {
                    format!(
                        "protect-host is on for {}",
                        s.protect_host_interfaces.join(", ")
                    )
                }
            })
        }
        ProtectHostCmd::Off => {
            let r = c
                .client
                .set_protect_host(&ProtectHostRequest {
                    interfaces: vec![],
                    force: false,
                })
                .await?;
            c.print(&r, || "protect-host is off".to_string())
        }
        ProtectHostCmd::On { interfaces, force } => {
            match set_protect_host(c, interfaces, force).await? {
                Some(r) => c.print(&r, || {
                    let mut s = format!(
                        "protect-host is on for {}",
                        r.settings.protect_host_interfaces.join(", ")
                    );
                    for risk in &r.overridden {
                        s.push_str(&format!("\nforced despite: {}", risk.message));
                    }
                    s
                }),
                None => Err(Reported.into()),
            }
        }
    }
}

/// Turn protect-host on. A refusal because of lockout risks is printed (human mode) and
/// returns `None`; in JSON mode the API error propagates.
pub(crate) async fn set_protect_host(
    c: &Ctx,
    interfaces: Vec<String>,
    force: bool,
) -> Result<Option<ProtectHostResponse>> {
    let req = ProtectHostRequest { interfaces, force };
    match c.client.set_protect_host(&req).await {
        Ok(r) => Ok(Some(r)),
        Err(ApiError::Api {
            code,
            details: Some(details),
            ..
        }) if code == error_code::PROTECT_HOST_REFUSED && !c.json => {
            let risks: Vec<LockoutRiskInfo> = serde_json::from_value(details).unwrap_or_default();
            eprintln!("{}", render::lockout_risks(&risks));
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

// ─── Apps ────────────────────────────────────────────────────────────────────

async fn apps(c: &Ctx, cmd: AppsCmd) -> Result<()> {
    match cmd {
        AppsCmd::List => {
            let a = c.client.list_apps().await?;
            c.print(&a, || render::apps(&a))
        }
        AppsCmd::Show { app } => {
            let app = c.app(&app).await?;
            let detail = c.client.get_app(&app.id).await?;
            let names = c.names().await?;
            c.print(&detail, || render::app_detail(&detail, &names))
        }
        AppsCmd::Rm { app } => {
            let app = c.app(&app).await?;
            let saved = c.client.delete_app(&app.id).await?;
            c.done_saved(
                saved,
                format!(
                    "forgot {} (it reappears as a new app if it listens again)",
                    app.name
                ),
            )
        }
        AppsCmd::Move { from, to, yes } => {
            let from = c.app(&from).await?;
            let to = c.app(&to).await?;
            if from.id == to.id {
                bail!("{} is both the source and the target", from.name);
            }
            let mut req = MoveAppRequest {
                to: to.id.clone(),
                confirm_open: yes,
            };
            let saved = match c.client.move_app(&from.id, &req).await {
                Err(e) if e.is_confirmation_required() => {
                    prompt::Stdin.confirm_or_yes(
                        false,
                        &format!(
                            "Moving {} to {} opens an app to anyone. Continue?",
                            from.name, to.name
                        ),
                        &format!(
                            "moving {} to {} would open an app to anyone; repeat with --yes to confirm",
                            from.name, to.name
                        ),
                    )?;
                    req.confirm_open = true;
                    c.client.move_app(&from.id, &req).await?
                }
                other => other?,
            };
            c.warn_pending(&saved.enforcement);
            let detail = saved.value;
            let names = c.names().await?;
            c.print(&detail, || {
                format!(
                    "moved {} to {}\n\n{}",
                    from.name,
                    to.name,
                    render::app_detail(&detail, &names)
                )
            })
        }
    }
}

async fn share(c: &Ctx, a: ShareArgs) -> Result<()> {
    let app = c.app(&a.app).await?;
    let detail = c.client.get_app(&app.id).await?;
    let mut lines = render::share_lines(&detail.app, a.network.as_deref());
    let mut tor = c.client.share_app(&app.id).await?;
    tor.tor
        .retain(|t| a.network.as_deref().is_none_or(|n| n == t.network_id));
    lines.extend(render::tor_share(&tor));
    c.print(&lines, || {
        if lines.is_empty() {
            format!(
                "{} has no address that is up: a row gets an address when a grant names it \
                 (socketguard grant {} <peer>)",
                app.name, app.name
            )
        } else {
            lines.join("\n")
        }
    })
}

// ─── Peers and groups ────────────────────────────────────────────────────────

async fn peers(c: &Ctx, cmd: PeersCmd) -> Result<()> {
    match cmd {
        PeersCmd::List => {
            let p = c.client.list_peers().await?;
            let names = c.names().await?;
            c.print(&p, || render::peers(&p, &names))
        }
        PeersCmd::Show { peer } => {
            let peer = c.peer(&peer).await?;
            let grants = c
                .client
                .list_grants(&GrantQuery {
                    peer: Some(peer.id.clone()),
                    ..Default::default()
                })
                .await?;
            let names = c.names().await?;
            c.print(&peer, || render::peer_detail(&peer, &names, &grants))
        }
        PeersCmd::Add(a) => {
            let credentials = peer_credentials(&a)?;
            let peer = c
                .client
                .create_peer(&NewPeer {
                    label: a.label,
                    credentials,
                })
                .await?;
            let names = c.names().await?;
            c.print(&peer, || {
                format!(
                    "added peer {}\n\n{}",
                    peer.label,
                    render::peers(std::slice::from_ref(&peer), &names)
                )
            })
        }
        PeersCmd::Parse { values } => {
            let parsed = c.client.parse_credentials(&values.join(" ")).await?;
            c.print(&parsed, || render::parsed_credentials(&parsed))
        }
        PeersCmd::TorKey { peer } => {
            let peer = c.peer(&peer).await?;
            let saved = c.client.generate_tor_key(&peer.id).await?;
            c.warn_pending(&saved.enforcement);
            let key = saved.value;
            c.print(&key, || render::tor_key(&peer.label, &key))
        }
        PeersCmd::Rename { peer, new_label } => {
            let peer = c.peer(&peer).await?;
            let p = c.client.update_peer(&peer.id, &new_label).await?;
            c.print(&p, || format!("renamed {} to {}", peer.label, p.label))
        }
        PeersCmd::Rm { peer } => {
            let peer = c.peer(&peer).await?;
            let saved = c.client.delete_peer(&peer.id).await?;
            c.done_saved(saved, format!("removed peer {} and its grants", peer.label))
        }
        PeersCmd::Cred(CredCmd::Add { peer, cred }) => {
            let peer = c.peer(&peer).await?;
            let cred = parse::parse_cred(&cred)?;
            let saved = c.client.add_credential(&peer.id, &cred).await?;
            c.warn_pending(&saved.enforcement);
            let added = saved.value;
            c.print(&added, || {
                format!("added {} {} to {}", added.kind, added.value, peer.label)
            })
        }
        PeersCmd::Cred(CredCmd::Rm { peer, cred_id }) => {
            let peer = c.peer(&peer).await?;
            let ids: Vec<String> = peer.credentials.iter().map(|x| x.id.clone()).collect();
            let id = resolve("credential", &ids, &cred_id)?;
            let saved = c.client.remove_credential(&peer.id, id).await?;
            c.done_saved(
                saved,
                format!("removed credential {} from {}", short(id), peer.label),
            )
        }
    }
}

/// All credentials given to `peers add`, flags first, then the bare values.
pub fn peer_credentials(a: &PeerAddArgs) -> Result<Vec<NewCredential>> {
    let mut out = Vec::new();
    if let Some(k) = &a.key {
        out.push(parse::cred(CredentialKind::YggKey, k));
    }
    if let Some(k) = &a.tor_key {
        out.push(parse::cred(CredentialKind::TorClientKey, k));
    }
    for addr in &a.addr {
        // The daemon files addresses in 200::/7 under ygg_addr.
        out.push(parse::cred(CredentialKind::Ip, addr));
    }
    if let Some(s) = &a.subnet {
        out.push(parse::cred(CredentialKind::YggSubnet, s));
    }
    if let Some(s) = &a.suffix {
        out.push(parse::cred(CredentialKind::IpSuffix, s));
    }
    for cred in &a.creds {
        out.push(parse::parse_cred(cred)?);
    }
    if !a.values.is_empty() {
        out.extend(parse::guess_credentials(&a.values.join(" "))?);
    }
    Ok(out)
}

async fn groups(c: &Ctx, cmd: GroupsCmd) -> Result<()> {
    match cmd {
        GroupsCmd::List => {
            let g = c.client.list_groups().await?;
            let names = c.names().await?;
            c.print(&g, || render::groups(&g, &names))
        }
        GroupsCmd::Show { group } => {
            let g = c.group(&group).await?;
            let names = c.names().await?;
            c.print(&g, || {
                let members = render::members(&g, &names);
                format!(
                    "{}  ({})\n  members  {}",
                    g.label,
                    g.id,
                    if members.is_empty() {
                        "none".into()
                    } else {
                        members
                    }
                )
            })
        }
        GroupsCmd::Add { label, peers } => {
            let all = c.client.list_peers().await?;
            let members = member_ids(&all, &peers)?;
            let g = c.client.create_group(&NewGroup { label, members }).await?;
            let names = c.names().await?;
            c.print(&g, || {
                format!(
                    "added group {}\n\n{}",
                    g.label,
                    render::groups(std::slice::from_ref(&g), &names)
                )
            })
        }
        GroupsCmd::Rename { group, new_label } => {
            let g = c.group(&group).await?;
            let r = c.client.update_group(&g.id, &new_label).await?;
            c.print(&r, || format!("renamed {} to {}", g.label, r.label))
        }
        GroupsCmd::Rm { group } => {
            let g = c.group(&group).await?;
            let saved = c.client.delete_group(&g.id).await?;
            c.done_saved(saved, format!("removed group {} and its grants", g.label))
        }
        GroupsCmd::Members { group, peers } => {
            let g = c.group(&group).await?;
            let all = c.client.list_peers().await?;
            let ids = member_ids(&all, &peers)?;
            let saved = c.client.set_group_members(&g.id, &ids).await?;
            c.warn_pending(&saved.enforcement);
            let r = saved.value;
            let names = c.names().await?;
            c.print(&r, || {
                format!("{} now has: {}", r.label, render::members(&r, &names))
            })
        }
    }
}

fn member_ids(all: &[Peer], queries: &[String]) -> Result<Vec<String>> {
    queries
        .iter()
        .map(|q| Ok(resolve("peer", all, q)?.id.clone()))
        .collect()
}

// ─── Tags ────────────────────────────────────────────────────────────────────

/// `<app>[:port[/proto]]` or `<app>:port-group=<label>` texts as tag members.
async fn tag_members(c: &Ctx, texts: &[String]) -> Result<Vec<TagMember>> {
    let mut out = Vec::new();
    for t in texts {
        let (app, scope) = parse::parse_target(t);
        out.push(TagMember {
            app_id: c.app(&app).await?.id,
            scope: c.scope(&scope).await?,
        });
    }
    Ok(out)
}

/// Ask before apps join a tag that has a grant to anyone, which opens them.
fn confirm_tag_open(label: &str) -> Result<()> {
    prompt::Stdin.confirm_or_yes(
        false,
        &format!("Tag {label} is open to anyone: the apps that join it will be too. Continue?"),
        &format!(
            "tag {label} is open to anyone, so this opens the apps; repeat with --yes to confirm"
        ),
    )
}

async fn tags(c: &Ctx, cmd: TagsCmd) -> Result<()> {
    match cmd {
        TagsCmd::List => {
            let t = c.client.list_tags().await?;
            let names = c.names().await?;
            c.print(&t, || render::tags(&t, &names))
        }
        TagsCmd::Show { tag } => {
            let tag = c.tag(&tag).await?;
            let grants = c
                .client
                .list_grants(&GrantQuery {
                    tag: Some(tag.id.clone()),
                    ..Default::default()
                })
                .await?;
            let names = c.names().await?;
            c.print(&tag, || render::tag_detail(&tag, &names, &grants))
        }
        TagsCmd::Add {
            label,
            members,
            patterns,
        } => {
            let members = tag_members(c, &members).await?;
            let saved = c
                .client
                .create_tag(&NewTag {
                    label,
                    patterns,
                    members,
                })
                .await?;
            c.warn_pending(&saved.enforcement);
            let tag = saved.value;
            let names = c.names().await?;
            c.print(&tag, || {
                format!(
                    "added tag {}\n\n{}",
                    tag.label,
                    render::tags(std::slice::from_ref(&tag), &names)
                )
            })
        }
        TagsCmd::Rename { tag, new_label } => {
            let tag = c.tag(&tag).await?;
            let saved = c
                .client
                .update_tag(
                    &tag.id,
                    &UpdateTag {
                        label: Some(new_label),
                        patterns: None,
                        confirm_open: false,
                    },
                )
                .await?;
            c.warn_pending(&saved.enforcement);
            let r = saved.value;
            c.print(&r, || format!("renamed {} to {}", tag.label, r.label))
        }
        TagsCmd::Patterns { tag, patterns, yes } => {
            let tag = c.tag(&tag).await?;
            let mut req = UpdateTag {
                label: None,
                patterns: Some(patterns),
                confirm_open: yes,
            };
            let saved = match c.client.update_tag(&tag.id, &req).await {
                Err(e) if e.is_confirmation_required() => {
                    confirm_tag_open(&tag.label)?;
                    req.confirm_open = true;
                    c.client.update_tag(&tag.id, &req).await?
                }
                other => other?,
            };
            c.warn_pending(&saved.enforcement);
            let r = saved.value;
            let names = c.names().await?;
            c.print(&r, || render::tag_detail(&r, &names, &[]))
        }
        TagsCmd::Rm { tag } => {
            let tag = c.tag(&tag).await?;
            let saved = c.client.delete_tag(&tag.id).await?;
            c.done_saved(saved, format!("removed tag {} and its grants", tag.label))
        }
        TagsCmd::Members(TagMembersCmd::Add { tag, members, yes }) => {
            let tag = c.tag(&tag).await?;
            let mut last = tag.clone();
            let mut confirmed = yes;
            for m in tag_members(c, &members).await? {
                let saved = match c.client.add_tag_member(&tag.id, &m, confirmed).await {
                    Err(e) if e.is_confirmation_required() => {
                        confirm_tag_open(&tag.label)?;
                        confirmed = true;
                        c.client.add_tag_member(&tag.id, &m, true).await?
                    }
                    other => other?,
                };
                c.warn_pending(&saved.enforcement);
                last = saved.value;
            }
            let names = c.names().await?;
            c.print(&last, || render::tag_detail(&last, &names, &[]))
        }
        TagsCmd::Members(TagMembersCmd::Rm { tag, members }) => {
            let tag = c.tag(&tag).await?;
            let mut last = tag.clone();
            for m in tag_members(c, &members).await? {
                let saved = c
                    .client
                    .remove_tag_member(&tag.id, &m.app_id, &m.scope)
                    .await?;
                c.warn_pending(&saved.enforcement);
                last = saved.value;
            }
            let names = c.names().await?;
            c.print(&last, || render::tag_detail(&last, &names, &[]))
        }
    }
}

// ─── Port groups ───────────────────────────────────────────────────────────

fn confirm_group_open(group: &str) -> Result<()> {
    prompt::Stdin.confirm_or_yes(
        false,
        &format!("This opens apps to anyone through port group {group}. Continue?"),
        &format!(
            "port group {group} would open an app to anyone, because a grant to anyone covers it; repeat with --yes to confirm"
        ),
    )
}

async fn port_groups(c: &Ctx, cmd: PortGroupsCmd) -> Result<()> {
    match cmd {
        PortGroupsCmd::List => {
            let g = c.client.list_port_groups().await?;
            let names = c.names().await?;
            c.print(&g, || render::port_groups(&g, &names))
        }
        PortGroupsCmd::Add {
            label,
            ports,
            apps,
            yes,
        } => {
            let ports = parse::parse_ranges(&ports)?;
            let mut app_ids = Vec::new();
            for a in &apps {
                app_ids.push(c.app(a).await?.id);
            }
            let mut req = NewPortGroup {
                label,
                ports,
                apps: app_ids,
                confirm_open: yes,
            };
            let saved = match c.client.create_port_group(&req).await {
                Err(e) if e.is_confirmation_required() => {
                    confirm_group_open(req.label.as_deref().unwrap_or("the new port group"))?;
                    req.confirm_open = true;
                    c.client.create_port_group(&req).await?
                }
                other => other?,
            };
            c.warn_pending(&saved.enforcement);
            let g = saved.value;
            let names = c.names().await?;
            c.print(&g, || render::port_groups(std::slice::from_ref(&g), &names))
        }
        PortGroupsCmd::Set {
            group,
            label,
            ports,
            yes,
        } => {
            let g = c.port_group(&group).await?;
            let mut req = UpdatePortGroup {
                label,
                ports: if ports.is_empty() {
                    None
                } else {
                    Some(parse::parse_ranges(&ports)?)
                },
                confirm_open: yes,
            };
            if req.label.is_none() && req.ports.is_none() {
                bail!("give --label and/or --port");
            }
            let saved = match c.client.update_port_group(&g.id, &req).await {
                Err(e) if e.is_confirmation_required() => {
                    confirm_group_open(&g.label)?;
                    req.confirm_open = true;
                    c.client.update_port_group(&g.id, &req).await?
                }
                other => other?,
            };
            c.warn_pending(&saved.enforcement);
            let g = saved.value;
            let names = c.names().await?;
            c.print(&g, || render::port_groups(std::slice::from_ref(&g), &names))
        }
        PortGroupsCmd::Rm { group } => {
            let g = c.port_group(&group).await?;
            let saved = c.client.delete_port_group(&g.id).await?;
            c.done_saved(saved, format!("removed port group {}", g.label))
        }
        PortGroupsCmd::Attach { group, app, yes } => {
            let g = c.port_group(&group).await?;
            let app = c.app(&app).await?;
            let saved = match c.client.attach_port_group(&g.id, &app.id, yes).await {
                Err(e) if e.is_confirmation_required() => {
                    confirm_group_open(&g.label)?;
                    c.client.attach_port_group(&g.id, &app.id, true).await?
                }
                other => other?,
            };
            c.warn_pending(&saved.enforcement);
            let g = saved.value;
            c.print(&g, || {
                format!("port group {} attached to {}", g.label, app.name)
            })
        }
        PortGroupsCmd::Detach { group, app } => {
            let g = c.port_group(&group).await?;
            let app = c.app(&app).await?;
            let saved = c.client.detach_port_group(&g.id, &app.id).await?;
            c.warn_pending(&saved.enforcement);
            let g = saved.value;
            c.print(&g, || {
                format!("port group {} detached from {}", g.label, app.name)
            })
        }
    }
}

// ─── Reservations and addresses ──────────────────────────────────────────────

impl Ctx {
    /// A binding as typed: `<app>[:port[/proto]]`, `<app>:port-group=<label>` or `tag:<label>`.
    async fn binding_target(&self, text: &str) -> Result<BindingTarget> {
        Ok(match parse::parse_target_spec(text) {
            (TargetSpec::App(q), scope) => BindingTarget::App {
                app_id: self.app(&q).await?.id,
                scope: self.scope(&scope).await?,
            },
            (TargetSpec::Tag(q), parse::ScopeSpec::All) => BindingTarget::Tag {
                tag_id: self.tag(&q).await?.id,
            },
            (TargetSpec::Tag(_), _) => {
                bail!("a tag is bound whole: {text:?} has a port; bind the apps' rows instead")
            }
            (TargetSpec::Reservation(_), _) => {
                bail!("a reservation cannot be bound to a reservation")
            }
        })
    }

    async fn binding_targets(&self, texts: &[String]) -> Result<Vec<BindingTarget>> {
        let mut out = Vec::new();
        for t in texts {
            out.push(self.binding_target(t).await?);
        }
        Ok(out)
    }
}

/// Ask before binding rows to a reservation that is open to anyone.
fn confirm_binding_open(label: &str) -> Result<()> {
    prompt::Stdin.confirm_or_yes(
        false,
        &format!("Reservation {label} is open to anyone: the rows bound to it will be too. Continue?"),
        &format!(
            "reservation {label} is open to anyone, so this opens the rows; repeat with --yes to confirm"
        ),
    )
}

async fn reservations(c: &Ctx, cmd: ReservationsCmd) -> Result<()> {
    match cmd {
        ReservationsCmd::List => {
            let r = c.client.list_reservations().await?;
            let names = c.names().await?;
            c.print(&r, || render::reservations(&r, &names))
        }
        ReservationsCmd::Add { label, bindings } => {
            let saved = c
                .client
                .create_reservation(&NewReservation {
                    label,
                    bindings: c.binding_targets(&bindings).await?,
                    confirm_open: false,
                })
                .await?;
            c.warn_pending(&saved.enforcement);
            let r = saved.value;
            let names = c.names().await?;
            c.print(&r, || {
                format!(
                    "added reservation {}\n\n{}",
                    r.reservation.label,
                    render::reservation_detail(&r, &names)
                )
            })
        }
        ReservationsCmd::Rename {
            reservation,
            new_label,
        } => {
            let res = c.reservation(&reservation).await?;
            let saved = c
                .client
                .rename_reservation(&res.reservation.id, &new_label)
                .await?;
            c.warn_pending(&saved.enforcement);
            let r = saved.value;
            c.print(&r, || {
                format!(
                    "renamed {} to {}",
                    res.reservation.label, r.reservation.label
                )
            })
        }
        ReservationsCmd::Bind {
            reservation,
            targets,
            yes,
        } => {
            let res = c.reservation(&reservation).await?;
            let mut last = res.clone();
            let mut confirmed = yes;
            for target in c.binding_targets(&targets).await? {
                let mut req = NewBinding {
                    target,
                    confirm_open: confirmed,
                };
                let saved = match c.client.add_binding(&res.reservation.id, &req).await {
                    Err(e) if e.is_confirmation_required() => {
                        confirm_binding_open(&res.reservation.label)?;
                        confirmed = true;
                        req.confirm_open = true;
                        c.client.add_binding(&res.reservation.id, &req).await?
                    }
                    other => other?,
                };
                c.warn_pending(&saved.enforcement);
                last = saved.value;
            }
            let names = c.names().await?;
            c.print(&last, || render::reservation_detail(&last, &names))
        }
        ReservationsCmd::Unbind {
            reservation,
            targets,
        } => {
            let res = c.reservation(&reservation).await?;
            let mut last = res.clone();
            for target in c.binding_targets(&targets).await? {
                let binding = res
                    .reservation
                    .bindings
                    .iter()
                    .find(|b| b.target == target)
                    .ok_or_else(|| {
                        anyhow!(
                            "{} is not bound to {}; see `socketguard reservations list`",
                            targets_text(&targets, &target),
                            res.reservation.label
                        )
                    })?;
                let saved = c
                    .client
                    .remove_binding(&res.reservation.id, &binding.id)
                    .await?;
                c.warn_pending(&saved.enforcement);
                last = saved.value;
            }
            let names = c.names().await?;
            c.print(&last, || render::reservation_detail(&last, &names))
        }
        ReservationsCmd::Release { reservation } => {
            let res = c.reservation(&reservation).await?;
            let saved = c.client.release_reservation(&res.reservation.id).await?;
            c.done_saved(
                saved,
                format!(
                    "released reservation {}: its addresses and the grants on it are gone",
                    res.reservation.label
                ),
            )
        }
    }
}

/// The text the user typed for `target`, for an error message (they are parsed in order).
fn targets_text(_texts: &[String], target: &BindingTarget) -> String {
    match target {
        BindingTarget::App { app_id, .. } => short(app_id).to_string(),
        BindingTarget::Tag { tag_id } => format!("tag {}", short(tag_id)),
    }
}

async fn addresses(c: &Ctx, cmd: AddressesCmd) -> Result<()> {
    match cmd {
        AddressesCmd::List => {
            let a = c.client.list_addresses().await?;
            let names = c.names().await?;
            c.print(&a, || render::addresses(&a, &names))
        }
        AddressesCmd::Reserve { address, label } => {
            let all = c.client.list_addresses().await?;
            let ids: Vec<String> = all.iter().map(|a| a.id.clone()).collect();
            let id = resolve("address", &ids, &address)?;
            let saved = c
                .client
                .reserve_address(id, &ReserveRequest { label })
                .await?;
            c.warn_pending(&saved.enforcement);
            let r = saved.value;
            let names = c.names().await?;
            c.print(&r, || {
                format!(
                    "reserved as {}\n\n{}",
                    r.reservation.label,
                    render::reservation_detail(&r, &names)
                )
            })
        }
    }
}

// ─── Grants ──────────────────────────────────────────────────────────────────

/// What a `grant` or `revoke` names, resolved: targets with their own port, subjects and
/// networks. Every combination is one grant.
struct GrantSpec {
    /// Target, its scope, and how the user spelled it (for questions).
    targets: Vec<(Target, Scope, String)>,
    subjects: Vec<Subject>,
    networks: Vec<Option<String>>,
}

impl GrantSpec {
    fn ops(&self, confirm_open: bool) -> Vec<ChangeOp> {
        let mut ops = Vec::new();
        for (target, scope, _) in &self.targets {
            for network_id in &self.networks {
                for subject in &self.subjects {
                    ops.push(ChangeOp::AddGrant {
                        target: target.clone(),
                        scope: scope.clone(),
                        network_id: network_id.clone(),
                        subject: subject.clone(),
                        confirm_open,
                    });
                }
            }
        }
        ops
    }

    fn names(&self) -> String {
        self.targets
            .iter()
            .map(|t| t.2.clone())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Ctx {
    async fn tag(&self, query: &str) -> Result<Tag> {
        Ok(resolve("tag", &self.client.list_tags().await?, query)?.clone())
    }

    async fn target(&self, spec: &TargetSpec) -> Result<Target> {
        Ok(match spec {
            TargetSpec::App(q) => Target::App(self.app(q).await?.id),
            TargetSpec::Tag(q) => Target::Tag(self.tag(q).await?.id),
            TargetSpec::Reservation(q) => {
                Target::Reservation(self.reservation(q).await?.reservation.id)
            }
        })
    }

    /// The targets named by the texts of a command, crossed with `--port` and
    /// `--port-group` for those that carry no scope of their own. A reservation takes
    /// neither: it is always granted whole.
    async fn targets(&self, texts: &TargetTexts<'_>) -> Result<Vec<(Target, Scope, String)>> {
        let mut extra: Vec<parse::ScopeSpec> = Vec::new();
        for p in texts.ports {
            extra.push(parse::ScopeSpec::Port(parse::parse_port(p)?));
        }
        for g in texts.port_groups {
            extra.push(parse::ScopeSpec::Group(g.clone()));
        }
        if extra.is_empty() {
            extra.push(parse::ScopeSpec::All);
        }
        let mut specs: Vec<(TargetSpec, parse::ScopeSpec, String)> = Vec::new();
        for t in texts.targets {
            let (spec, scope) = parse::parse_target_spec(t);
            specs.push((spec, scope, t.clone()));
        }
        for t in texts.tags {
            let (label, scope) = parse::parse_target(t);
            specs.push((TargetSpec::Tag(label), scope, format!("tag:{t}")));
        }
        for r in texts.reservations {
            // The label is taken whole, so that a colon in it is not read as a port.
            specs.push((
                TargetSpec::Reservation(r.clone()),
                parse::ScopeSpec::All,
                format!("reservation:{r}"),
            ));
        }
        let mut out = Vec::new();
        for (spec, own, text) in specs {
            let target = self.target(&spec).await?;
            if matches!(spec, TargetSpec::Reservation(_)) {
                if own != parse::ScopeSpec::All {
                    bail!(
                        "{text:?}: a reservation is granted whole (All ports); \
                         give no port or port group"
                    );
                }
                out.push((target, Scope::All, text));
                continue;
            }
            let scopes = if own != parse::ScopeSpec::All {
                vec![own]
            } else {
                extra.clone()
            };
            for scope in scopes {
                out.push((target.clone(), self.scope(&scope).await?, text.clone()));
            }
        }
        Ok(out)
    }

    async fn subjects(&self, to: &[String]) -> Result<Vec<Subject>> {
        let mut subjects = Vec::new();
        for s in to {
            subjects.push(self.subject(&parse::parse_subject(s)).await?);
        }
        Ok(subjects)
    }

    async fn grant_spec(
        &self,
        texts: &TargetTexts<'_>,
        to: &[String],
        networks: &[String],
    ) -> Result<GrantSpec> {
        Ok(GrantSpec {
            targets: self.targets(texts).await?,
            subjects: self.subjects(to).await?,
            networks: if networks.is_empty() {
                vec![None]
            } else {
                networks.iter().cloned().map(Some).collect()
            },
        })
    }
}

/// The target texts of `grant` and `revoke`, as typed.
struct TargetTexts<'a> {
    /// Positional or `--app` texts: `<app>[:scope]`, `tag:<label>`, `reservation:<label>`.
    targets: &'a [String],
    tags: &'a [String],
    reservations: &'a [String],
    ports: &'a [String],
    port_groups: &'a [String],
}

/// Whether `grant`/`revoke` got the flag form (several targets, subjects or ports).
fn uses_flags(texts: &TargetTexts<'_>, to: &[String]) -> bool {
    !(texts.targets.is_empty()
        && texts.tags.is_empty()
        && texts.reservations.is_empty()
        && texts.ports.is_empty()
        && texts.port_groups.is_empty()
        && to.is_empty())
}

async fn grant(c: &Ctx, a: GrantArgs) -> Result<()> {
    let flag_texts = TargetTexts {
        targets: &a.apps,
        tags: &a.tags,
        reservations: &a.reservations,
        ports: &a.ports,
        port_groups: &a.port_groups,
    };
    let flags = uses_flags(&flag_texts, &a.to);
    let (targets, to) = match (&a.target, &a.subject) {
        (Some(t), Some(s)) if !flags => (vec![t.clone()], vec![s.clone()]),
        (None, None) if flags => (a.apps.clone(), a.to.clone()),
        (Some(_), _) | (_, Some(_)) if flags => {
            bail!("give either <target> <subject> or the --app/--tag/--to flags, not both")
        }
        _ => bail!(
            "give <app> <subject>, or --to with --app, --tag and/or --reservation \
             (e.g. grant --app web --app api --port 80 --to alice)"
        ),
    };
    if flags
        && (a.to.is_empty() || a.apps.is_empty() && a.tags.is_empty() && a.reservations.is_empty())
    {
        bail!("--to and at least one of --app, --tag or --reservation are needed");
    }
    let spec = c
        .grant_spec(
            &TargetTexts {
                targets: &targets,
                ..flag_texts
            },
            &to,
            &a.networks,
        )
        .await?;
    // One grant by the positional form keeps the single-grant route and its answer.
    if !flags && spec.networks.len() == 1 && !a.dry_run {
        return grant_one(c, &a, spec).await;
    }
    let mut req = ChangesRequest {
        ops: spec.ops(a.yes),
        dry_run: a.dry_run,
    };
    let saved = match c.client.changes(&req).await {
        Err(e) if e.is_confirmation_required() => {
            let net = match spec.networks.as_slice() {
                [Some(n)] => Some(n.as_str()),
                _ => None,
            };
            prompt::Stdin.confirm_or_yes(
                false,
                &render::open_question(&spec.names(), net),
                &format!(
                    "this opens {} to every host that can reach it; repeat with --yes to confirm",
                    spec.names()
                ),
            )?;
            req.ops = spec.ops(true);
            c.client.changes(&req).await?
        }
        other => other?,
    };
    c.warn_pending(&saved.enforcement);
    let done = saved.value;
    c.print(&done, || {
        let head = if done.dry_run {
            "dry run, nothing was changed:"
        } else {
            "granted:"
        };
        format!("{head}\n{}", render::batch(&done))
    })
}

/// The positional `grant <target> <subject>`: one grant.
async fn grant_one(c: &Ctx, a: &GrantArgs, spec: GrantSpec) -> Result<()> {
    let (target, scope, text) = spec.targets[0].clone();
    let mut req = NewGrant {
        target,
        scope,
        network_id: spec.networks[0].clone(),
        subject: spec.subjects[0].clone(),
        confirm_open: a.yes,
    };
    let created = match c.client.create_grant(&req).await {
        Err(e) if e.is_confirmation_required() => {
            prompt::Stdin.confirm_or_yes(
                false,
                &render::open_question(&text, req.network_id.as_deref()),
                &format!(
                    "this opens {text} to every host that can reach it; repeat with --yes to confirm"
                ),
            )?;
            req.confirm_open = true;
            c.client.create_grant(&req).await?
        }
        other => other?,
    };
    c.warn_pending(&created.enforcement);
    let created = created.value;
    let names = c.names().await?;
    c.print(&created, || {
        format!(
            "granted\n\n{}",
            render::grants(std::slice::from_ref(&created), &names, true)
        )
    })
}

/// Grants for `app` and `scope` to `subject`; with no `network`, on any network.
pub fn find_grants<'a>(
    grants: &'a [GrantView],
    app_id: &str,
    scope: &Scope,
    subject: &Subject,
    network: Option<&str>,
) -> Vec<&'a GrantView> {
    find_target_grants(
        grants,
        &Target::App(app_id.to_string()),
        scope,
        subject,
        network,
    )
}

/// [`find_grants`] for an app or a tag.
pub fn find_target_grants<'a>(
    grants: &'a [GrantView],
    target: &Target,
    scope: &Scope,
    subject: &Subject,
    network: Option<&str>,
) -> Vec<&'a GrantView> {
    grants
        .iter()
        .filter(|g| {
            g.grant.target == *target
                && g.grant.scope == *scope
                && g.grant.subject == *subject
                && network.is_none_or(|n| g.grant.network_id.as_deref() == Some(n))
        })
        .collect()
}

async fn revoke(c: &Ctx, a: RevokeArgs) -> Result<()> {
    let all = c.client.list_grants(&GrantQuery::default()).await?;
    let flags = uses_flags(&revoke_texts(&a), &a.to);
    if flags {
        if a.target.is_some() || a.subject.is_some() {
            bail!(
                "give either <target> <subject> or the --app/--tag/--reservation/--to flags, not both"
            );
        }
        if a.to.is_empty() || a.apps.is_empty() && a.tags.is_empty() && a.reservations.is_empty() {
            bail!("--to and at least one of --app, --tag or --reservation are needed");
        }
        return revoke_many(c, &a, &all).await;
    }
    let target = a
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("give a grant id, or <target> <subject>"))?;
    let id = match &a.subject {
        None => {
            let ids: Vec<String> = all.iter().map(|g| g.grant.id.clone()).collect();
            resolve("grant", &ids, target)?.clone()
        }
        Some(subject) => {
            let (spec, scope) = parse::parse_target_spec(target);
            if matches!(spec, TargetSpec::Reservation(_)) && scope != parse::ScopeSpec::All {
                bail!("{target:?}: a reservation is granted whole (All ports); give no port");
            }
            let scope = c.scope(&scope).await?;
            let wanted = c.target(&spec).await?;
            let subject = c.subject(&parse::parse_subject(subject)).await?;
            let network = a.networks.first().map(String::as_str);
            let found = find_target_grants(&all, &wanted, &scope, &subject, network);
            match found.as_slice() {
                [one] => one.grant.id.clone(),
                [] => bail!("no such grant; see `socketguard grants`"),
                many => {
                    let names = c.names().await?;
                    bail!(
                        "{} grants match; revoke one by id:\n{}",
                        many.len(),
                        render::grants(
                            &many.iter().map(|g| (*g).clone()).collect::<Vec<_>>(),
                            &names,
                            true
                        )
                    )
                }
            }
        }
    };
    let saved = c.client.delete_grant(&id).await?;
    c.done_saved(saved, format!("revoked grant {}", short(&id)))
}

fn revoke_texts(a: &RevokeArgs) -> TargetTexts<'_> {
    TargetTexts {
        targets: &a.apps,
        tags: &a.tags,
        reservations: &a.reservations,
        ports: &a.ports,
        port_groups: &a.port_groups,
    }
}

/// `revoke --app ... --to ...`: every grant the combinations name, in one batch.
async fn revoke_many(c: &Ctx, a: &RevokeArgs, all: &[GrantView]) -> Result<()> {
    let targets = c.targets(&revoke_texts(a)).await?;
    let subjects = c.subjects(&a.to).await?;
    let mut ids: Vec<String> = Vec::new();
    for (target, scope, text) in &targets {
        for subject in &subjects {
            let found: Vec<&GrantView> = if a.networks.is_empty() {
                find_target_grants(all, target, scope, subject, None)
            } else {
                a.networks
                    .iter()
                    .flat_map(|n| find_target_grants(all, target, scope, subject, Some(n)))
                    .collect()
            };
            if found.is_empty() {
                bail!(
                    "no grant of {text} for {}; nothing was changed",
                    c.names().await?.subject(subject)
                );
            }
            for g in found {
                if !ids.contains(&g.grant.id) {
                    ids.push(g.grant.id.clone());
                }
            }
        }
    }
    let req = ChangesRequest {
        ops: ids
            .into_iter()
            .map(|grant_id| ChangeOp::RemoveGrant { grant_id })
            .collect(),
        dry_run: a.dry_run,
    };
    let saved = c.client.changes(&req).await?;
    c.warn_pending(&saved.enforcement);
    let done = saved.value;
    c.print(&done, || {
        let head = if done.dry_run {
            "dry run, nothing was changed:"
        } else {
            "revoked:"
        };
        format!("{head}\n{}", render::batch(&done))
    })
}

async fn grants(c: &Ctx, a: GrantsArgs) -> Result<()> {
    let query = GrantQuery {
        app: c.opt_app(a.app.as_deref()).await?,
        tag: match a.tag.as_deref() {
            Some(q) => Some(c.tag(q).await?.id),
            None => None,
        },
        reservation: match a.reservation.as_deref() {
            Some(q) => Some(c.reservation(q).await?.reservation.id),
            None => None,
        },
        peer: c.opt_peer(a.peer.as_deref()).await?,
        group: c.opt_group(a.group.as_deref()).await?,
    };
    let g = c.client.list_grants(&query).await?;
    let names = c.names().await?;
    c.print(&g, || render::grants(&g, &names, true))
}

// ─── Activity and events ─────────────────────────────────────────────────────

async fn activity(c: &Ctx, a: ActivityArgs) -> Result<()> {
    let query = ActivityQuery {
        kind: if a.blocked {
            Some(ActivityKind::Blocked)
        } else {
            a.kind
        },
        app_id: c.opt_app(a.app.as_deref()).await?,
        peer_id: c.opt_peer(a.peer.as_deref()).await?,
        limit: Some(a.limit),
        ..Default::default()
    };
    // Subscribe before the first fetch, so nothing falls between the two.
    let mut events = if a.follow {
        Some(c.client.events().await?)
    } else {
        None
    };
    let records = c.client.activity(&query).await?;
    let names = c.names().await?;
    if !a.follow {
        return c.print(&records, || {
            let mut oldest_first = records.clone();
            oldest_first.reverse();
            render::activity(&oldest_first, &names)
        });
    }
    let mut last = records.iter().map(|r| r.id).max().unwrap_or(0);
    print_records(c, records.iter().rev(), &names)?;
    let events = events.as_mut().expect("follow subscribed");
    while let Some(ev) = events.next().await {
        if ev? != ApiEvent::Activity {
            continue;
        }
        let mut fresh: Vec<_> = c
            .client
            .activity(&ActivityQuery {
                limit: Some(200),
                ..query.clone()
            })
            .await?
            .into_iter()
            .filter(|r| r.id > last)
            .collect();
        fresh.reverse();
        if let Some(r) = fresh.last() {
            last = r.id;
        }
        let names = c.names().await?;
        print_records(c, fresh.iter(), &names)?;
    }
    Ok(())
}

fn print_records<'a>(
    c: &Ctx,
    records: impl Iterator<Item = &'a ActivityRecord>,
    names: &Names,
) -> Result<()> {
    for r in records {
        if c.json {
            println!("{}", serde_json::to_string(r)?);
        } else {
            println!("{}", render::activity_line(r, names));
        }
    }
    Ok(())
}

async fn watch(c: &Ctx) -> Result<()> {
    let mut events = c.client.events().await?;
    while let Some(ev) = events.next().await {
        let ev = ev?;
        if c.json {
            println!("{}", serde_json::to_string(&ev)?);
        } else {
            println!("{}", render::event_line(chrono::Utc::now(), &ev));
        }
    }
    Ok(())
}

// ─── Export and apply ────────────────────────────────────────────────────────

async fn export(c: &Ctx, a: ExportArgs) -> Result<()> {
    let doc = c.client.export().await?;
    let json = c.json
        || match a.format.as_deref() {
            Some(f) => f == "json",
            None => a.output.as_ref().and_then(|p| p.extension()) == Some("json".as_ref()),
        };
    let text = document::text(&doc, json)?;
    match a.output {
        Some(path) => {
            std::fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;
            if !c.json {
                eprintln!("wrote {}", path.display());
            }
        }
        None => print!("{text}"),
    }
    Ok(())
}

async fn apply(c: &Ctx, a: ApplyArgs) -> Result<()> {
    let text = std::fs::read_to_string(&a.file)
        .with_context(|| format!("reading {}", a.file.display()))?;
    let document = document::parse(&text, &a.file)?;
    let diff = c
        .client
        .apply(&ApplyRequest {
            document: document.clone(),
            dry_run: true,
        })
        .await?;
    if a.dry_run || diff.is_empty() {
        return c.print(&diff, || render::changes(&diff));
    }
    if !c.json {
        println!("{}", render::changes(&diff));
    }
    prompt::Stdin.confirm_or_yes(
        a.yes,
        "Apply these changes?",
        &format!(
            "{} change(s) pending; repeat with --yes to apply them",
            diff.changes.len()
        ),
    )?;
    let done = c
        .client
        .apply(&ApplyRequest {
            document,
            dry_run: false,
        })
        .await?;
    c.print(&done, || {
        format!("applied {} change(s)", done.changes.len())
    })
}

// ─── Disable and enable ──────────────────────────────────────────────────────

async fn disable(c: &Ctx, a: DisableArgs) -> Result<()> {
    let text = render::exposure(&c.client.exposure(None).await?);
    if !text.is_empty() {
        eprintln!("{text}");
    }
    prompt::Stdin.confirm_or_yes(
        a.yes,
        "Remove all SocketGuard rules and addresses, opening the host?",
        "disable removes every firewall rule and address; repeat with --yes to confirm",
    )?;
    c.client.disable(true).await?;
    c.done("disabled: rules and addresses removed, and kept off until `socketguard enable`")
}

async fn enable(c: &Ctx) -> Result<()> {
    c.client.enable().await?;
    c.done("enabled: rules and addresses restored")
}

#[cfg(test)]
mod tests {
    #[test]
    fn access_needs_the_daemon_binary_next_to_the_cli() {
        let dir = std::env::temp_dir().join("sg-access-test-empty");
        std::fs::create_dir_all(&dir).unwrap();
        let err = super::daemon_next_to(&dir.join("socketguard")).unwrap_err();
        assert!(err.to_string().contains("was not found next to"), "{err}");
        let daemon = dir.join(format!(
            "socketguard-daemon{}",
            std::env::consts::EXE_SUFFIX
        ));
        std::fs::write(&daemon, b"").unwrap();
        assert_eq!(
            super::daemon_next_to(&dir.join("socketguard")).unwrap(),
            daemon
        );
        std::fs::remove_file(&daemon).unwrap();
    }

    use super::*;

    #[test]
    fn the_password_comes_from_the_option_given() {
        assert_eq!(tor_password(None, None, false).unwrap(), None);
        assert_eq!(
            tor_password(Some("pw".into()), None, false)
                .unwrap()
                .as_deref(),
            Some("pw")
        );
        std::env::set_var("SOCKETGUARD_TEST_TOR_PW", "from env");
        assert_eq!(
            tor_password(None, Some("SOCKETGUARD_TEST_TOR_PW".into()), false)
                .unwrap()
                .as_deref(),
            Some("from env")
        );
        std::env::remove_var("SOCKETGUARD_TEST_TOR_PW");
        let err = tor_password(None, Some("SOCKETGUARD_TEST_TOR_PW".into()), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("SOCKETGUARD_TEST_TOR_PW"), "{err}");
        assert!(tor_password(Some(String::new()), None, false).is_err());
    }

    #[test]
    fn the_password_is_the_first_line_of_stdin() {
        assert_eq!(
            read_password_line(&b"s3cret\r\nmore\n"[..]).unwrap(),
            "s3cret"
        );
        assert_eq!(
            read_password_line(&b"no newline"[..]).unwrap(),
            "no newline"
        );
        assert_eq!(read_password_line(&b""[..]).unwrap(), "");
    }

    #[test]
    fn network_configs_are_built_from_the_flags() {
        assert_eq!(
            backend_config(NetworkType::Ula, None, None).unwrap(),
            BackendConfig::default()
        );
        assert_eq!(
            backend_config(
                NetworkType::Yggdrasil,
                Some("ygg0".into()),
                Some("unix:///y".into())
            )
            .unwrap(),
            BackendConfig::Yggdrasil {
                interface: Some("ygg0".into()),
                admin_endpoint: Some("unix:///y".into()),
            }
        );
        assert_eq!(
            backend_config(NetworkType::Slaac, Some("eth0".into()), None).unwrap(),
            BackendConfig::Slaac {
                interface: "eth0".into(),
                prefix: None,
            }
        );
        let err = backend_config(NetworkType::Dhcpv6, None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--interface is required for dhcpv6"), "{err}");
        assert!(backend_config(NetworkType::Slaac, Some("eth0".into()), Some("x".into())).is_err());
    }
}
