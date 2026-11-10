//! What each command does: resolve names, call the client, print. Output formatting lives
//! in [`crate::render`], parsing in [`crate::parse`].

use crate::cli::*;
use crate::parse::{self, SubjectSpec};
use crate::prompt::{self, Prompter};
use crate::render::{self, Names};
use crate::resolve::{resolve, resolve_id, short};
use anyhow::{anyhow, bail, Context, Result};
use clap::CommandFactory;
use futures_util::StreamExt;
use serde::Serialize;
use socketguard_client::{ApiEvent, Client, Error as ApiError, GrantQuery, Saved};
use socketguard_core::api_types::{
    error_code, ApplyRequest, ExportDocument, LockoutRiskInfo, MergeRequest, NewGroup, NewNetwork,
    NewPeer, ProtectHostRequest, SplitRequest, UpdateSettings,
};
use socketguard_core::{
    ActivityKind, ActivityQuery, AddressMode, App, BackendConfig, CredentialKind, GrantView,
    NetworkKind, NewGrant, Peer, PortRef, Subject,
};

/// An error whose explanation was already printed; `main` only sets the exit code.
#[derive(Debug)]
pub struct Reported;

impl std::fmt::Display for Reported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failed")
    }
}

impl std::error::Error for Reported {}

struct Ctx {
    client: Client,
    json: bool,
}

pub fn client_for(socket: Option<&str>) -> Client {
    match socket {
        Some(s) => Client::new(s),
        None => Client::from_env(),
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    if let Command::Completions { shell } = &cli.command {
        let mut cmd = Cli::command();
        clap_complete::generate(*shell, &mut cmd, "socketguard", &mut std::io::stdout());
        return Ok(());
    }
    let c = Ctx {
        client: client_for(cli.socket.as_deref()),
        json: cli.json,
    };
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
        Command::Pending => pending(&c, &mut prompt::Stdin).await,
        Command::Share(a) => share(&c, a).await,
        Command::Init => init(&c, &mut prompt::Stdin).await,
        Command::Export(a) => export(&c, a).await,
        Command::Apply(a) => apply(&c, a).await,
        Command::Disable(a) => disable(&c, a).await,
        Command::Enable => enable(&c).await,
        Command::Completions { .. } => unreachable!("handled above"),
    }
}

// ─── Output and lookups ──────────────────────────────────────────────────────

impl Ctx {
    /// Print `value` as JSON, or the human form.
    fn print<T: Serialize>(&self, value: &T, human: impl FnOnce() -> String) -> Result<()> {
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
    fn warn_pending(&self, enforcement: &Option<socketguard_core::api_types::Enforcement>) {
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

    async fn group(&self, query: &str) -> Result<socketguard_core::PeerGroup> {
        Ok(resolve("group", &self.client.list_groups().await?, query)?.clone())
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
        } => {
            let backend = if r#type.eq_ignore_ascii_case("tor") {
                if interface.is_some() || admin_endpoint.is_some() {
                    bail!("tor has no --interface or --admin-endpoint");
                }
                tor_config(control, password)?
            } else {
                if control.is_some() || password.is_some() {
                    bail!("--control and --password only apply to tor");
                }
                backend_config(&r#type, interface, admin_endpoint)?
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

/// `tor [--control X] [--password P]` as the daemon's backend config.
pub fn tor_config(control: Option<String>, password: Option<String>) -> Result<BackendConfig> {
    let mut v = serde_json::json!({"type": "tor"});
    if let Some(c) = control {
        v["control"] = c.into();
    }
    if let Some(p) = password {
        v["auth"] = serde_json::json!({ "password": p });
    }
    serde_json::from_value(v).context("invalid network")
}

/// `<type> --interface X [--admin-endpoint Z]` as the daemon's backend config.
pub fn backend_config(
    kind: &str,
    interface: Option<String>,
    admin_endpoint: Option<String>,
) -> Result<BackendConfig> {
    let kind = kind.to_ascii_lowercase();
    if !["ula", "slaac", "dhcpv6", "yggdrasil"].contains(&kind.as_str()) {
        bail!("unknown network type {kind:?} (ula, slaac, dhcpv6, yggdrasil)");
    }
    if kind != "ula" && interface.is_none() {
        bail!("--interface is required for {kind}");
    }
    if admin_endpoint.is_some() && kind != "yggdrasil" {
        bail!("--admin-endpoint only applies to yggdrasil");
    }
    let mut v = serde_json::json!({"type": kind});
    if let Some(i) = interface {
        v["interface"] = i.into();
    }
    if let Some(a) = admin_endpoint {
        v["admin_endpoint"] = a.into();
    }
    serde_json::from_value(v).context("invalid network")
}

async fn settings(c: &Ctx, cmd: SettingsCmd) -> Result<()> {
    match cmd {
        SettingsCmd::Show => {
            let s = c.client.get_settings().await?;
            c.print(&s, || render::settings(&s))
        }
        SettingsCmd::AddressMode { mode } => {
            let mode: AddressMode = mode
                .replace('-', "_")
                .parse()
                .map_err(|e: String| anyhow!(e))?;
            let s = c
                .client
                .update_settings(&UpdateSettings {
                    address_mode: Some(mode),
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
async fn set_protect_host(
    c: &Ctx,
    interfaces: Vec<String>,
    force: bool,
) -> Result<Option<socketguard_core::api_types::ProtectHostResponse>> {
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
                .map(|q| Ok(resolve_id("address", &own, q)?.clone()))
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
            let id = resolve_id("credential", &ids, &cred_id)?;
            let saved = c.client.remove_credential(&peer.id, id).await?;
            c.done_saved(
                saved,
                format!("removed credential {} from {}", short(id), peer.label),
            )
        }
    }
}

/// All credentials given to `peers add`, flags first, then the bare values.
pub fn peer_credentials(a: &PeerAddArgs) -> Result<Vec<socketguard_core::NewCredential>> {
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
    for v in &a.values {
        out.push(parse::guess_credential(v)?);
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
            if !prompt::interactive() {
                bail!(
                    "this opens {} to every host that can reach it; repeat with --yes to confirm",
                    a.target
                );
            }
            if !prompt::Stdin.confirm(&format!("Open {} to anyone who can reach it?", a.target)) {
                eprintln!("not confirmed; nothing changed");
                return Err(Reported.into());
            }
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
            resolve_id("grant", &ids, &a.target)?.clone()
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
        app: match &a.app {
            Some(q) => Some(c.app(q).await?.id),
            None => None,
        },
        peer: match &a.peer {
            Some(q) => Some(c.peer(q).await?.id),
            None => None,
        },
        group: match &a.group {
            Some(q) => Some(c.group(q).await?.id),
            None => None,
        },
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
        app_id: match &a.app {
            Some(q) => Some(c.app(q).await?.id),
            None => None,
        },
        peer_id: match &a.peer {
            Some(q) => Some(c.peer(q).await?.id),
            None => None,
        },
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
    records: impl Iterator<Item = &'a socketguard_core::ActivityRecord>,
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

/// The document as TOML or JSON.
pub fn document_text(doc: &ExportDocument, json: bool) -> Result<String> {
    if json {
        Ok(serde_json::to_string_pretty(doc)? + "\n")
    } else {
        Ok(toml::to_string_pretty(doc).context("cannot write TOML")?)
    }
}

/// Parse a document; the extension picks the format, else TOML and then JSON are tried.
pub fn parse_document(text: &str, path: &std::path::Path) -> Result<ExportDocument> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => Ok(serde_json::from_str(text).context("invalid JSON document")?),
        Some("toml") => Ok(toml::from_str(text).context("invalid TOML document")?),
        _ => toml::from_str(text).or_else(|toml_err| {
            serde_json::from_str(text).map_err(|json_err| {
                anyhow!("not a TOML document ({toml_err}) nor a JSON one ({json_err})")
            })
        }),
    }
}

async fn export(c: &Ctx, a: ExportArgs) -> Result<()> {
    let doc = c.client.export().await?;
    let json = c.json
        || match a.format.as_deref() {
            Some(f) => f == "json",
            None => a.output.as_ref().and_then(|p| p.extension()) == Some("json".as_ref()),
        };
    let text = document_text(&doc, json)?;
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
    let document = parse_document(&text, &a.file)?;
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
    if !a.yes {
        if !prompt::interactive() {
            bail!(
                "{} change(s) pending; repeat with --yes to apply them",
                diff.changes.len()
            );
        }
        if !prompt::Stdin.confirm("Apply these changes?") {
            eprintln!("not confirmed; nothing changed");
            return Err(Reported.into());
        }
    }
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
    if !a.yes {
        if !prompt::interactive() {
            bail!("disable removes every firewall rule and address; repeat with --yes to confirm");
        }
        if !prompt::Stdin.confirm("Remove all SocketGuard rules and addresses, opening the host?") {
            eprintln!("not confirmed; nothing changed");
            return Err(Reported.into());
        }
    }
    c.client.disable(true).await?;
    c.done("disabled: rules and addresses removed, and kept off until `socketguard enable`")
}

async fn enable(c: &Ctx) -> Result<()> {
    c.client.enable().await?;
    c.done("enabled: rules and addresses restored")
}

// ─── Pending and init ────────────────────────────────────────────────────────

/// Pick a peer or group from a list, or create a peer by pasting a key.
async fn pick_subject(c: &Ctx, p: &mut dyn Prompter) -> Result<Option<Subject>> {
    let peers = c.client.list_peers().await?;
    let groups = c.client.list_groups().await?;
    let mut options: Vec<String> = peers.iter().map(|p| format!("peer {}", p.label)).collect();
    options.extend(groups.iter().map(|g| format!("group {}", g.label)));
    options.push("a new peer (paste a Yggdrasil key or an address)".to_string());
    options.push("cancel".to_string());
    let Some(n) = p.choose("Grant to:", &options) else {
        return Ok(None);
    };
    if n < peers.len() {
        Ok(Some(Subject::Peer(peers[n].id.clone())))
    } else if n < peers.len() + groups.len() {
        Ok(Some(Subject::Group(groups[n - peers.len()].id.clone())))
    } else if n == peers.len() + groups.len() {
        let label = p.ask("Label for the new peer:");
        let value = p.ask("Key, address or CIDR:");
        let peer = c
            .client
            .create_peer(&NewPeer {
                label,
                credentials: vec![parse::guess_credential(&value)?],
            })
            .await?;
        println!("added peer {}", peer.label);
        Ok(Some(Subject::Peer(peer.id)))
    } else {
        Ok(None)
    }
}

async fn grant_all_ports(
    c: &Ctx,
    p: &mut dyn Prompter,
    app: &App,
    port: Option<PortRef>,
    subject: Subject,
) -> Result<()> {
    let mut req = NewGrant {
        app_id: app.id.clone(),
        port,
        network_id: None,
        subject,
        confirm_open: false,
    };
    if req.subject == Subject::Anyone {
        if !p.confirm(&format!("Open {} to anyone who can reach it?", app.name)) {
            println!("skipped");
            return Ok(());
        }
        req.confirm_open = true;
    }
    let saved = c.client.create_grant(&req).await?;
    c.warn_pending(&saved.enforcement);
    c.client.review_app(&app.id, true).await?;
    println!("granted");
    Ok(())
}

async fn pending(c: &Ctx, p: &mut dyn Prompter) -> Result<()> {
    let apps = c.client.list_apps(true).await?;
    if c.json || !p.interactive() {
        return c.print(&apps, || render::apps(&apps));
    }
    if apps.is_empty() {
        println!("no pending apps");
        return Ok(());
    }
    for app in &apps {
        println!("\n{}", render::apps(std::slice::from_ref(app)));
        let options = [
            "keep closed (mark reviewed)".to_string(),
            "grant to a peer or group".to_string(),
            "open to anyone".to_string(),
            "skip".to_string(),
        ];
        let Some(choice) = p.choose(&format!("{} is listening and closed:", app.name), &options)
        else {
            break;
        };
        match choice {
            0 => {
                c.client.review_app(&app.id, true).await?;
                println!("kept closed");
            }
            1 => {
                if let Some(s) = pick_subject(c, p).await? {
                    grant_all_ports(c, p, app, None, s).await?;
                }
            }
            2 => grant_all_ports(c, p, app, None, Subject::Anyone).await?,
            _ => println!("skipped"),
        }
    }
    Ok(())
}

/// The node's address if `yggdrasilctl` answers.
fn yggdrasil_node() -> Option<String> {
    let out = std::process::Command::new("yggdrasilctl")
        .args(["-json", "getSelf"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v.get("address")?.as_str().map(str::to_string)
}

const ADMIN_PORTS: [u16; 2] = [22, 3389];

async fn init(c: &Ctx, p: &mut dyn Prompter) -> Result<()> {
    if c.json {
        bail!("init is interactive and has no --json mode");
    }
    let interactive = p.interactive();
    let status = c.client.status().await?;
    println!("{}\n", render::networks(&status.networks));

    // 1. A Yggdrasil network, if the node is running and none is configured.
    if !status
        .networks
        .iter()
        .any(|n| n.kind == NetworkKind::Yggdrasil)
    {
        if let Some(addr) = yggdrasil_node() {
            println!("A Yggdrasil node is running (address {addr}) but has no network here.");
            if interactive && p.confirm("Add a Yggdrasil network?") {
                let default = if cfg!(windows) { "Yggdrasil" } else { "ygg0" };
                let answer = p.ask(&format!("Yggdrasil tun interface [{default}]:"));
                let interface = if answer.is_empty() {
                    default.to_string()
                } else {
                    answer
                };
                let n = c
                    .client
                    .add_network(&NewNetwork {
                        id: None,
                        backend: backend_config("yggdrasil", Some(interface), None)?,
                    })
                    .await?;
                println!("added network {}", n.id);
            } else if !interactive {
                println!("Add it with: socketguard networks add yggdrasil --interface <tun>");
            }
        }
    }

    // 2. Remote-admin listeners.
    let apps = c.client.list_apps(false).await?;
    let exposed = c
        .client
        .activity(&ActivityQuery {
            kind: Some(ActivityKind::RemoteAdminExposed),
            limit: Some(200),
            ..Default::default()
        })
        .await?;
    let mut found: Vec<(App, PortRef)> = Vec::new();
    for app in &apps {
        let flagged = exposed.iter().any(|r| r.app_id.as_deref() == Some(&app.id));
        let port = app
            .ports
            .iter()
            .find(|p| ADMIN_PORTS.contains(&p.port) && p.proto == socketguard_core::Protocol::Tcp)
            .map(|p| PortRef {
                port: p.port,
                proto: p.proto,
            });
        let port = port.or_else(|| {
            flagged.then(|| {
                exposed
                    .iter()
                    .find(|r| r.app_id.as_deref() == Some(&app.id))
                    .and_then(|r| r.port)
                    .map(|port| PortRef {
                        port,
                        proto: socketguard_core::Protocol::Tcp,
                    })
            })?
        });
        let Some(port) = port else { continue };
        if c.client.get_app(&app.id).await?.grants.is_empty() {
            found.push((app.clone(), port));
        }
    }
    if found.is_empty() {
        println!("No remote-administration listener (sshd, RDP) without a grant.");
    }
    for (app, port) in found {
        println!(
            "{} listens for remote administration on {port} and nobody can reach it.",
            app.name
        );
        if !interactive {
            println!(
                "  grant it with: socketguard grant {}:{} <peer>",
                app.name, port.port
            );
            continue;
        }
        let options = [
            "grant to a peer or group".to_string(),
            "keep it closed".to_string(),
        ];
        if p.choose(&format!("What should happen to {}?", app.name), &options) == Some(0) {
            if let Some(s) = pick_subject(c, p).await? {
                grant_all_ports(c, p, &app, Some(port), s).await?;
            }
        }
    }

    // 3. Protect-host, with the lockout check.
    if status.protect_host_interfaces.is_empty() {
        println!(
            "\nWhole-host protection also closes listeners that SocketGuard has no address for."
        );
        if interactive && p.confirm("Turn on protect-host?") {
            let lan: Vec<String> = status
                .networks
                .iter()
                .filter(|n| n.kind == NetworkKind::Lan)
                .filter_map(|n| n.interface.clone())
                .collect();
            let default = lan.join(",");
            let answer = p.ask(&format!("Interfaces (comma separated) [{default}]:"));
            let list = if answer.is_empty() { default } else { answer };
            let interfaces: Vec<String> = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if interfaces.is_empty() {
                println!("no interfaces given; protect-host stays off");
            } else if set_protect_host(c, interfaces.clone(), false)
                .await?
                .is_none()
            {
                if p.confirm("Turn it on anyway (--force)?") {
                    set_protect_host(c, interfaces, true).await?;
                    println!("protect-host is on");
                }
            } else {
                println!("protect-host is on");
            }
        } else if !interactive {
            println!("Turn it on with: socketguard protect-host on <interface>...");
        }
    }
    println!("\nDone. `socketguard status` shows the result.");
    Ok(())
}

/// The `pending` flow against `client` with the given prompter (not `--json`).
pub async fn pending_flow(client: Client, p: &mut dyn Prompter) -> Result<()> {
    pending(
        &Ctx {
            client,
            json: false,
        },
        p,
    )
    .await
}

/// The `init` flow against `client` with the given prompter.
pub async fn init_flow(client: Client, p: &mut dyn Prompter) -> Result<()> {
    init(
        &Ctx {
            client,
            json: false,
        },
        p,
    )
    .await
}
