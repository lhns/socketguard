use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use socketguard_core::api_types::*;
use socketguard_core::Policy;
use std::net::Ipv6Addr;
use tabled::{Table, Tabled};

#[derive(Parser)]
#[command(name = "socketguard", about = "Per-socket IPv6 access control")]
struct Cli {
    /// Daemon API address
    #[arg(long, default_value = "http://127.0.0.1:9476", global = true)]
    api: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all detected sockets
    #[command(alias = "ls")]
    List,

    /// Show details for a socket
    Show {
        /// Socket ID
        id: String,
    },

    /// Manage ACL for a socket
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },

    /// Set policy for a socket
    Policy {
        /// Socket ID
        id: String,
        /// Policy: open, closed, or managed
        policy: String,
    },

    /// Check daemon status
    Status,

    /// Show daemon configuration
    Config,

    /// List available backends
    Backends,
}

#[derive(Subcommand)]
enum AclCommands {
    /// Allow an IP to access a socket
    Allow {
        /// Socket ID
        socket_id: String,
        /// IPv6 address to allow
        ip: String,
        /// Optional label
        #[arg(long)]
        label: Option<String>,
    },

    /// Remove an ACL entry
    Remove {
        /// Socket ID
        socket_id: String,
        /// ACL entry ID
        entry_id: i64,
    },

    /// List ACL entries for a socket
    List {
        /// Socket ID
        socket_id: String,
    },
}

#[derive(Tabled)]
struct SocketRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Process")]
    process: String,
    #[tabled(rename = "Port")]
    port: u16,
    #[tabled(rename = "Proto")]
    protocol: String,
    #[tabled(rename = "IPv6")]
    ipv6: String,
    #[tabled(rename = "Policy")]
    policy: String,
    #[tabled(rename = "Backend")]
    backend: String,
}

#[derive(Tabled)]
struct AclRow {
    #[tabled(rename = "ID")]
    id: i64,
    #[tabled(rename = "Allowed IP")]
    allowed_ip: String,
    #[tabled(rename = "Label")]
    label: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let base = &cli.api;

    match cli.command {
        Commands::List => {
            let resp: SocketListResponse = client
                .get(format!("{base}/api/sockets"))
                .send()
                .await
                .context("failed to connect to daemon — is it running?")?
                .json()
                .await?;

            if resp.sockets.is_empty() {
                println!("No sockets detected.");
                return Ok(());
            }

            let rows: Vec<SocketRow> = resp
                .sockets
                .into_iter()
                .map(|s| SocketRow {
                    id: s.id[..8].to_string(),
                    process: format!("{} ({})", s.process_name, s.pid),
                    port: s.port,
                    protocol: s.protocol.to_string(),
                    ipv6: s.assigned_ipv6.to_string(),
                    policy: s.policy.to_string(),
                    backend: s.backend.to_string(),
                })
                .collect();

            println!("{}", Table::new(rows));
        }

        Commands::Show { id } => {
            let resp = client
                .get(format!("{base}/api/sockets/{id}"))
                .send()
                .await
                .context("failed to connect to daemon")?;

            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                bail!("socket '{id}' not found");
            }

            let resp: SocketDetailResponse = resp.json().await?;

            let s = &resp.socket;
            println!("Socket: {}", s.id);
            println!("  Process:  {} (PID {})", s.process_name, s.pid);
            if let Some(ref exe) = s.exe_path {
                println!("  Exe:      {exe}");
            }
            if let Some(ref cmd) = s.cmdline {
                println!("  Cmdline:  {cmd}");
            }
            println!("  Port:     {}/{}", s.port, s.protocol);
            println!("  IPv6:     {}", s.assigned_ipv6);
            println!("  Backend:  {}", s.backend);
            println!("  Policy:   {}", s.policy);
            println!("  First seen: {}", s.first_seen);
            println!("  Last seen:  {}", s.last_seen);

            if resp.acl.is_empty() {
                println!("\n  ACL: (empty)");
            } else {
                println!("\n  ACL:");
                let rows: Vec<AclRow> = resp
                    .acl
                    .into_iter()
                    .map(|e| AclRow {
                        id: e.id,
                        allowed_ip: e.allowed_ip,
                        label: e.label.unwrap_or_default(),
                    })
                    .collect();
                println!("{}", Table::new(rows));
            }
        }

        Commands::Acl { command } => match command {
            AclCommands::Allow {
                socket_id,
                ip,
                label,
            } => {
                // Validate IP client-side before sending
                if ip.parse::<Ipv6Addr>().is_err() {
                    bail!("'{ip}' is not a valid IPv6 address");
                }

                let req = AllowIpRequest {
                    allowed_ip: ip.clone(),
                    label,
                };
                let resp = client
                    .post(format!("{base}/api/sockets/{socket_id}/acl/allow"))
                    .json(&req)
                    .send()
                    .await
                    .context("failed to connect to daemon")?;

                if resp.status().is_success() {
                    println!("Allowed {ip} for socket {socket_id}");
                } else {
                    let err: ApiError = resp.json().await?;
                    bail!("{}", err.error);
                }
            }

            AclCommands::Remove {
                socket_id,
                entry_id,
            } => {
                let resp = client
                    .delete(format!("{base}/api/sockets/{socket_id}/acl/{entry_id}"))
                    .send()
                    .await
                    .context("failed to connect to daemon")?;

                if resp.status().is_success() {
                    println!("Removed ACL entry {entry_id}");
                } else {
                    let err: ApiError = resp.json().await?;
                    bail!("{}", err.error);
                }
            }

            AclCommands::List { socket_id } => {
                let resp: SocketDetailResponse = client
                    .get(format!("{base}/api/sockets/{socket_id}"))
                    .send()
                    .await
                    .context("failed to connect to daemon")?
                    .json()
                    .await?;

                if resp.acl.is_empty() {
                    println!("No ACL entries for socket {socket_id}.");
                } else {
                    let rows: Vec<AclRow> = resp
                        .acl
                        .into_iter()
                        .map(|e| AclRow {
                            id: e.id,
                            allowed_ip: e.allowed_ip,
                            label: e.label.unwrap_or_default(),
                        })
                        .collect();
                    println!("{}", Table::new(rows));
                }
            }
        },

        Commands::Policy { id, policy } => {
            let policy: Policy = policy.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let req = UpdatePolicyRequest { policy };
            let resp = client
                .put(format!("{base}/api/sockets/{id}/policy"))
                .json(&req)
                .send()
                .await
                .context("failed to connect to daemon")?;

            if resp.status().is_success() {
                println!("Policy set to {policy} for socket {id}");
            } else {
                let err: ApiError = resp.json().await?;
                bail!("{}", err.error);
            }
        }

        Commands::Status => {
            match client.get(format!("{base}/api/sockets")).send().await {
                Ok(resp) => {
                    let list: SocketListResponse = resp.json().await?;
                    println!("Daemon is running on {base}");
                    println!("  {} sockets managed", list.sockets.len());
                }
                Err(_) => {
                    bail!("Daemon is not reachable at {base}");
                }
            }
        }

        Commands::Config => {
            let resp: ConfigResponse = client
                .get(format!("{base}/api/config"))
                .send()
                .await
                .context("failed to connect to daemon")?
                .json()
                .await?;

            println!("Daemon Configuration:");
            println!("  Listen:    {}:{}", resp.listen_addr, resp.listen_port);
            println!("  Backend:   {}", resp.backend);
            println!("  Interface: {}", resp.interface);
            println!("  Poll interval: {}s", resp.poll_interval_secs);
        }

        Commands::Backends => {
            let resp: BackendsResponse = client
                .get(format!("{base}/api/backends"))
                .send()
                .await
                .context("failed to connect to daemon")?
                .json()
                .await?;

            for b in resp.backends {
                let status = if b.available { "available" } else { "unavailable" };
                println!("  {} - {} [{}]", b.name, b.description, status);
            }
        }
    }

    Ok(())
}
