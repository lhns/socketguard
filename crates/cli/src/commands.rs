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
    error_code, ApplyRequest, ChangeOp, ChangesRequest, Enforcement, LockoutRiskInfo, MergeRequest,
    NewGroup, NewNetwork, NewPeer, NewTag, ProtectHostRequest, ProtectHostResponse, SplitRequest,
    UpdateSettings, UpdateTag,
};
use socketguard_core::config::TorAuth;
use socketguard_core::{
    ActivityKind, ActivityQuery, ActivityRecord, App, BackendConfig, CredentialKind, GrantView,
    NewCredential, NewGrant, Peer, PeerGroup, PortRef, Subject, Tag, TagMember, Target,
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
        Command::Grant(a) => grant(&c, a).await,
        Command::Revoke(a) => revoke(&c, a).await,
        Command::Grants(a) => grants(&c, a).await,
        Command::Networks(cmd) => networks(&c, cmd).await,
        Command::Settings(cmd) => settings(&c, cmd).await,
        Command::ProtectHost(cmd) => protect_host(&c, cmd).await,
        Command::Activity(a) => activity(&c, a).await,
        Command::Watch => watch(&c).await,
        Command::Pending => flows::pending(&c, &mut prompt::Stdin).await,
        Command::Share(a) => share(&c, a).await,
        Command::Init => flows::init(&c, &mut prompt::Stdin).await,
        Command::Export(a) => export(&c, a).await,
        Command::Apply(a) => apply(&c, a).await,
        Command::Disable(a) => disable(&c, a).await,
        Command::Enable => enable(&c).await,
        Command::Completions { .. } => unreachable!("handled above"),
    }
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
        Ok(self.client.list_apps(false).await?)
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
        .with_tags(&self.client.list_tags().await?))
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
            let n = c.client.add_network(&NewNetwork { id, backend }).await?;
            c.print(&n, || {
                format!(
                    "added network {}\n\n{}",
                    n.id,
                    render::networks(std::slice::from_ref(&n))
                )
            })
        }
        NetworksCmd::Rm { id, force } => {
            c.client.delete_network(&id, force).await?;
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
            interface: required()?,
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
        SettingsCmd::AddressMode { mode } => {
            let s = c
                .client
                .update_settings(&UpdateSettings {
                    address_mode: Some(mode.into()),
                })
                .await?;
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
        AppsCmd::List { pending } => {
            let a = c.client.list_apps(pending).await?;
            c.print(&a, || render::apps(&a))
        }
        AppsCmd::Show { app } => {
            let app = c.app(&app).await?;
            let detail = c.client.get_app(&app.id).await?;
            let names = c.names().await?;
            c.print(&detail, || render::app_detail(&detail, &names))
        }
        AppsCmd::Review { app, unreviewed } => {
            let app = c.app(&app).await?;
            let d = c.client.review_app(&app.id, !unreviewed).await?;
            c.print(&d, || {
                format!(
                    "{} is now {}",
                    d.app.name,
                    if d.app.reviewed {
                        "reviewed"
                    } else {
                        "pending"
                    }
                )
            })
        }
        AppsCmd::Rm { app } => {
            let app = c.app(&app).await?;
            let saved = c.client.delete_app(&app.id).await?;
            c.done_saved(
                saved,
                format!(
                    "forgot {} (it reappears as pending if it listens again)",
                    app.name
                ),
            )
        }
        AppsCmd::Split { app, network, port } => {
            let app = c.app(&app).await?;
            let port = parse::parse_port(&port)?;
            let saved = c
                .client
                .split_app(
                    &app.id,
                    &SplitRequest {
                        network_id: network,
                        port: port.port,
                        proto: port.proto,
                    },
                )
                .await?;
            c.warn_pending(&saved.enforcement);
            let a = saved.value;
            c.print(&a, || {
                format!(
                    "{port} of {} now has its own address {}",
                    app.name,
                    render::locator(&a.locator)
                )
            })
        }
        AppsCmd::Merge {
            app,
            network,
            address_ids,
        } => {
            let app = c.app(&app).await?;
            let own: Vec<String> = c
                .client
                .get_app(&app.id)
                .await?
                .app
                .addresses
                .into_iter()
                .map(|a| a.id)
                .collect();
            let ids = address_ids
                .iter()
                .map(|q| Ok(resolve("address", &own, q)?.clone()))
                .collect::<Result<Vec<_>>>()?;
            let saved = c
                .client
                .merge_app(
                    &app.id,
                    &MergeRequest {
                        network_id: network,
                        address_ids: ids,
                    },
                )
                .await?;
            c.warn_pending(&saved.enforcement);
            let a = saved.value;
            c.print(&a, || {
                format!(
                    "merged into {} ({})",
                    short(&a.id),
                    render::locator(&a.locator)
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
    if lines.is_empty() && !c.json {
        bail!("{} has no address to share yet", app.name);
    }
    c.print(&lines, || lines.join("\n"))
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

/// `<app>[:port[/proto]]` texts as tag members.
async fn tag_members(c: &Ctx, texts: &[String]) -> Result<Vec<TagMember>> {
    let mut out = Vec::new();
    for t in texts {
        let (app, port) = parse::parse_target(t);
        out.push(TagMember {
            app_id: c.app(&app).await?.id,
            port,
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
                    .remove_tag_member(&tag.id, &m.app_id, m.port)
                    .await?;
                c.warn_pending(&saved.enforcement);
                last = saved.value;
            }
            let names = c.names().await?;
            c.print(&last, || render::tag_detail(&last, &names, &[]))
        }
    }
}

// ─── Grants ──────────────────────────────────────────────────────────────────

/// What a `grant` or `revoke` names, resolved: targets with their own port, subjects and
/// networks. Every combination is one grant.
struct GrantSpec {
    /// Target, its port, and how the user spelled it (for questions).
    targets: Vec<(Target, Option<PortRef>, String)>,
    subjects: Vec<Subject>,
    networks: Vec<Option<String>>,
}

impl GrantSpec {
    fn ops(&self, confirm_open: bool) -> Vec<ChangeOp> {
        let mut ops = Vec::new();
        for (target, port, _) in &self.targets {
            for network_id in &self.networks {
                for subject in &self.subjects {
                    ops.push(ChangeOp::AddGrant {
                        target: target.clone(),
                        port: *port,
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
        })
    }

    /// The targets named by positional/`--app`/`--tag` texts, crossed with `--port` for
    /// those that carry no port of their own.
    async fn targets(
        &self,
        targets: &[String],
        tags: &[String],
        ports: &[String],
    ) -> Result<Vec<(Target, Option<PortRef>, String)>> {
        let extra: Vec<Option<PortRef>> = if ports.is_empty() {
            vec![None]
        } else {
            ports
                .iter()
                .map(|p| parse::parse_port(p).map(Some))
                .collect::<Result<_>>()?
        };
        let mut specs: Vec<(TargetSpec, Option<PortRef>, String)> = Vec::new();
        for t in targets {
            let (spec, port) = parse::parse_target_spec(t);
            specs.push((spec, port, t.clone()));
        }
        for t in tags {
            let (label, port) = parse::parse_target(t);
            specs.push((TargetSpec::Tag(label), port, format!("tag:{t}")));
        }
        let mut out = Vec::new();
        for (spec, own, text) in specs {
            let target = self.target(&spec).await?;
            let ports = if own.is_some() {
                vec![own]
            } else {
                extra.clone()
            };
            for port in ports {
                out.push((target.clone(), port, text.clone()));
            }
        }
        Ok(out)
    }

    async fn grant_spec(
        &self,
        targets: &[String],
        tags: &[String],
        ports: &[String],
        to: &[String],
        networks: &[String],
    ) -> Result<GrantSpec> {
        let mut subjects = Vec::new();
        for s in to {
            subjects.push(self.subject(&parse::parse_subject(s)).await?);
        }
        Ok(GrantSpec {
            targets: self.targets(targets, tags, ports).await?,
            subjects,
            networks: if networks.is_empty() {
                vec![None]
            } else {
                networks.iter().cloned().map(Some).collect()
            },
        })
    }
}

/// Whether `grant`/`revoke` got the flag form (several targets, subjects or ports).
fn uses_flags(apps: &[String], tags: &[String], ports: &[String], to: &[String]) -> bool {
    !(apps.is_empty() && tags.is_empty() && ports.is_empty() && to.is_empty())
}

async fn grant(c: &Ctx, a: GrantArgs) -> Result<()> {
    let flags = uses_flags(&a.apps, &a.tags, &a.ports, &a.to);
    let (targets, to) = match (&a.target, &a.subject) {
        (Some(t), Some(s)) if !flags => (vec![t.clone()], vec![s.clone()]),
        (None, None) if flags => (a.apps.clone(), a.to.clone()),
        (Some(_), _) | (_, Some(_)) if flags => {
            bail!("give either <target> <subject> or the --app/--tag/--to flags, not both")
        }
        _ => bail!(
            "give <app> <subject>, or --to with --app and/or --tag \
             (e.g. grant --app web --app api --port 80 --to alice)"
        ),
    };
    if flags && (a.to.is_empty() || a.apps.is_empty() && a.tags.is_empty()) {
        bail!("--to and at least one of --app or --tag are needed");
    }
    let spec = c
        .grant_spec(&targets, &a.tags, &a.ports, &to, &a.networks)
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
    let (target, port, text) = spec.targets[0].clone();
    let mut req = NewGrant {
        target,
        port,
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

/// Grants for `app` and `port` to `subject`; with no `network`, on any network.
pub fn find_grants<'a>(
    grants: &'a [GrantView],
    app_id: &str,
    port: Option<PortRef>,
    subject: &Subject,
    network: Option<&str>,
) -> Vec<&'a GrantView> {
    find_target_grants(
        grants,
        &Target::App(app_id.to_string()),
        port,
        subject,
        network,
    )
}

/// [`find_grants`] for an app or a tag.
pub fn find_target_grants<'a>(
    grants: &'a [GrantView],
    target: &Target,
    port: Option<PortRef>,
    subject: &Subject,
    network: Option<&str>,
) -> Vec<&'a GrantView> {
    grants
        .iter()
        .filter(|g| {
            g.grant.target == *target
                && g.grant.port == port
                && g.grant.subject == *subject
                && network.is_none_or(|n| g.grant.network_id.as_deref() == Some(n))
        })
        .collect()
}

async fn revoke(c: &Ctx, a: RevokeArgs) -> Result<()> {
    let all = c.client.list_grants(&GrantQuery::default()).await?;
    let flags = uses_flags(&a.apps, &a.tags, &a.ports, &a.to);
    if flags {
        if a.target.is_some() || a.subject.is_some() {
            bail!("give either <target> <subject> or the --app/--tag/--to flags, not both");
        }
        if a.to.is_empty() || a.apps.is_empty() && a.tags.is_empty() {
            bail!("--to and at least one of --app or --tag are needed");
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
            let (spec, port) = parse::parse_target_spec(target);
            let wanted = c.target(&spec).await?;
            let subject = c.subject(&parse::parse_subject(subject)).await?;
            let network = a.networks.first().map(String::as_str);
            let found = find_target_grants(&all, &wanted, port, &subject, network);
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

/// `revoke --app ... --to ...`: every grant the combinations name, in one batch.
async fn revoke_many(c: &Ctx, a: &RevokeArgs, all: &[GrantView]) -> Result<()> {
    let spec = c.grant_spec(&[], &a.tags, &a.ports, &a.to, &[]).await?;
    // `--app` goes through the same spelling as the positional target.
    let mut targets = c.targets(&a.apps, &[], &a.ports).await?;
    targets.extend(spec.targets);
    let mut ids: Vec<String> = Vec::new();
    for (target, port, text) in &targets {
        for subject in &spec.subjects {
            let found: Vec<&GrantView> = if a.networks.is_empty() {
                find_target_grants(all, target, *port, subject, None)
            } else {
                a.networks
                    .iter()
                    .flat_map(|n| find_target_grants(all, target, *port, subject, Some(n)))
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
                interface: "ygg0".into(),
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
