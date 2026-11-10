//! What each command does: resolve names, call the client, print. The interactive flows
//! are in [`crate::flows`], export documents in [`crate::document`], output formatting in
//! [`crate::render`], parsing in [`crate::parse`].

use crate::cli::*;
use crate::document;
use crate::flows;
use crate::parse::{self, SubjectSpec};
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
    error_code, ApplyRequest, Enforcement, LockoutRiskInfo, MergeRequest, NewGroup, NewNetwork,
    NewPeer, ProtectHostRequest, ProtectHostResponse, SplitRequest, UpdateSettings,
};
use socketguard_core::config::TorAuth;
use socketguard_core::{
    ActivityKind, ActivityQuery, ActivityRecord, App, BackendConfig, CredentialKind, GrantView,
    NewCredential, NewGrant, Peer, PeerGroup, PortRef, Subject,
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
        ))
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
    let lines = render::share_lines(&detail.app, a.network.as_deref());
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

// ─── Grants ──────────────────────────────────────────────────────────────────

async fn grant(c: &Ctx, a: GrantArgs) -> Result<()> {
    let (app_q, port) = parse::parse_target(&a.target);
    let app = c.app(&app_q).await?;
    let subject = c.subject(&parse::parse_subject(&a.subject)).await?;
    let mut req = NewGrant {
        app_id: app.id.clone(),
        port,
        network_id: a.network,
        subject,
        confirm_open: a.yes,
    };
    let created = match c.client.create_grant(&req).await {
        Err(e) if e.is_confirmation_required() => {
            prompt::Stdin.confirm_or_yes(
                false,
                &render::open_question(&a.target, req.network_id.as_deref()),
                &format!(
                    "this opens {} to every host that can reach it; repeat with --yes to confirm",
                    a.target
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
    grants
        .iter()
        .filter(|g| {
            g.grant.app_id == app_id
                && g.grant.port == port
                && g.grant.subject == *subject
                && network.is_none_or(|n| g.grant.network_id.as_deref() == Some(n))
        })
        .collect()
}

async fn revoke(c: &Ctx, a: RevokeArgs) -> Result<()> {
    let all = c.client.list_grants(&GrantQuery::default()).await?;
    let id = match &a.subject {
        None => {
            let ids: Vec<String> = all.iter().map(|g| g.grant.id.clone()).collect();
            resolve("grant", &ids, &a.target)?.clone()
        }
        Some(subject) => {
            let (app_q, port) = parse::parse_target(&a.target);
            let app = c.app(&app_q).await?;
            let subject = c.subject(&parse::parse_subject(subject)).await?;
            let found = find_grants(&all, &app.id, port, &subject, a.network.as_deref());
            match found.as_slice() {
                [one] => one.grant.id.clone(),
                [] => bail!("no such grant; see `socketguard grants --app {}`", app.name),
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

async fn grants(c: &Ctx, a: GrantsArgs) -> Result<()> {
    let query = GrantQuery {
        app: c.opt_app(a.app.as_deref()).await?,
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
