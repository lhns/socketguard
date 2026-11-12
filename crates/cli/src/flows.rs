//! The interactive flow `init`: it talks to a [`Prompter`] so the tests can script the
//! answers. It has no `--json` mode.

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
        let value = p.ask("Key, address or CIDR:");
        let peer = c
            .client
            .create_peer(&NewPeer {
                label: None,
                credentials: parse::guess_credentials(&value)?,
            })
            .await?;
        socketguard_core::outln!("added peer {}", peer.label);
        Ok(Some(Subject::Peer(peer.id)))
    } else {
        Ok(None)
    }
}

/// Grant the `port` of `app` to `subject` on every network.
async fn grant_to(c: &Ctx, app: &App, port: PortRef, subject: Subject) -> Result<()> {
    let req = NewGrant {
        target: socketguard_core::Target::App(app.id.clone()),
        scope: socketguard_core::Scope::port(port),
        network_id: None,
        subject,
        confirm_open: false,
    };
    let saved = c.client.create_grant(&req).await?;
    c.warn_pending(&saved.enforcement);
    socketguard_core::outln!("granted");
    Ok(())
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

/// First-run setup: Yggdrasil and Tor networks, remote-admin listeners, protect-host.
pub async fn init(c: &Ctx, p: &mut dyn Prompter) -> Result<()> {
    if c.json {
        bail!("init is interactive and has no --json mode");
    }
    let interactive = p.interactive();
    let status = c.client.status().await?;
    socketguard_core::outln!("{}\n", render::networks(&status.networks));

    // 1. Yggdrasil and Tor: SocketGuard's own, when this build includes them and they are
    //    not added yet.
    let setup = c.client.network_setup().await?;
    for (label, kind, offer, backend) in [
        (
            "Yggdrasil",
            "yggdrasil",
            &setup.yggdrasil,
            BackendConfig::yggdrasil(vec![]),
        ),
        ("Tor", "tor", &setup.tor, BackendConfig::tor()),
    ] {
        if offer.added || !offer.available {
            continue;
        }
        if let Some(note) = &offer.reason {
            socketguard_core::outln!("{note}");
        }
        if interactive && p.confirm(&format!("Add a {label} network?")) {
            let n = c
                .client
                .add_network(&NewNetwork { id: None, backend })
                .await?;
            c.warn_pending(&n.enforcement);
            socketguard_core::outln!("added network {}", n.value.id);
        } else if !interactive {
            socketguard_core::outln!("Add it with: socketguard networks add {kind}");
        }
    }

    // 2. Remote-admin listeners.
    let apps = c.client.list_apps().await?;
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
        socketguard_core::outln!("No remote-administration listener (sshd, RDP) without a grant.");
    }
    for (app, port) in found {
        socketguard_core::outln!(
            "{} listens for remote administration on {port} and nobody can reach it.",
            app.name
        );
        if !interactive {
            socketguard_core::outln!(
                "  grant it with: socketguard grant {}:{} <peer>",
                app.name,
                port.port
            );
            continue;
        }
        let options = [
            "grant to a peer or group".to_string(),
            "keep it closed".to_string(),
        ];
        if p.choose(&format!("What should happen to {}?", app.name), &options) == Some(0) {
            if let Some(s) = pick_subject(c, p).await? {
                grant_to(c, &app, port, s).await?;
            }
        }
    }

    // 3. Protect-host, with the lockout check.
    if status.protect_host_interfaces.is_empty() {
        socketguard_core::outln!(
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
                socketguard_core::outln!("no interfaces given; protect-host stays off");
            } else if set_protect_host(c, interfaces.clone(), false)
                .await?
                .is_none()
            {
                if p.confirm("Turn it on anyway (--force)?") {
                    set_protect_host(c, interfaces, true).await?;
                    socketguard_core::outln!("protect-host is on");
                }
            } else {
                socketguard_core::outln!("protect-host is on");
            }
        } else if !interactive {
            socketguard_core::outln!("Turn it on with: socketguard protect-host on <interface>...");
        }
    }
    socketguard_core::outln!("\nDone. `socketguard status` shows the result.");
    Ok(())
}
