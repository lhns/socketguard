//! The interactive flows, `pending` and `init`: they talk to a [`Prompter`] so the tests
//! can script the answers. Neither has a `--json` mode.

use crate::commands::{set_protect_host, Ctx};
use crate::parse;
use crate::prompt::Prompter;
use crate::render;
use anyhow::{bail, Result};
use socketguard_core::api_types::{NewNetwork, NewPeer};
use socketguard_core::{
    ActivityKind, ActivityQuery, ActivityRecord, App, BackendConfig, NetworkKind, NewGrant,
    PortRef, Protocol, Subject, REMOTE_ADMIN_PORTS,
};

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

/// Grant `app` (one `port`, or all) to `subject` on every network, asking first for
/// Anyone. Whether it was granted; the caller decides what that means for the review.
async fn grant_to(
    c: &Ctx,
    p: &mut dyn Prompter,
    app: &App,
    port: Option<PortRef>,
    subject: Subject,
) -> Result<bool> {
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
            return Ok(false);
        }
        req.confirm_open = true;
    }
    let saved = c.client.create_grant(&req).await?;
    c.warn_pending(&saved.enforcement);
    println!("granted");
    Ok(true)
}

/// Walk through the apps without a decision.
pub async fn pending(c: &Ctx, p: &mut dyn Prompter) -> Result<()> {
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
        let mut granted = false;
        match choice {
            0 => {
                c.client.review_app(&app.id, true).await?;
                println!("kept closed");
            }
            1 => {
                if let Some(s) = pick_subject(c, p).await? {
                    granted = grant_to(c, p, app, None, s).await?;
                }
            }
            2 => granted = grant_to(c, p, app, None, Subject::Anyone).await?,
            _ => println!("skipped"),
        }
        // The decision about the whole app is made here, not by a grant of one port.
        if granted {
            c.client.review_app(&app.id, true).await?;
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

/// The remote-administration port of `app`: its TCP port 22 or 3389, else the port of the
/// activity record that flagged it.
fn admin_port(app: &App, exposed: &[ActivityRecord]) -> Option<PortRef> {
    let tcp = |port| PortRef {
        port,
        proto: Protocol::Tcp,
    };
    app.ports
        .iter()
        .find(|p| p.proto == Protocol::Tcp && REMOTE_ADMIN_PORTS.contains(&p.port))
        .map(|p| p.port_ref())
        .or_else(|| {
            exposed
                .iter()
                .find(|r| r.app_id.as_deref() == Some(&app.id))
                .and_then(|r| r.port)
                .map(tcp)
        })
}

/// First-run setup: a Yggdrasil network, remote-admin listeners, protect-host.
pub async fn init(c: &Ctx, p: &mut dyn Prompter) -> Result<()> {
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
                        backend: BackendConfig::Yggdrasil {
                            interface,
                            admin_endpoint: None,
                        },
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
        let Some(port) = admin_port(app, &exposed) else {
            continue;
        };
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
                grant_to(c, p, &app, Some(port), s).await?;
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
