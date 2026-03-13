use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
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

    /// Override the API bearer token (default: read from token file)
    #[arg(long, global = true)]
    token: Option<String>,

    /// Output raw JSON instead of tables
    #[arg(long, global = true)]
    json: bool,

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
        /// Policy: open or closed
        policy: String,
    },

    /// Check daemon status
    Status,

    /// Show daemon configuration
    Config,

    /// List available backends
    Backends,

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
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

fn read_token_file() -> Result<String> {
    let path = socketguard_core::api_token_path();
    std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .with_context(|| format!(
            "failed to read API token from {} — is the daemon running?",
            path.display()
        ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let token = match &cli.token {
        Some(t) => t.clone(),
        None => read_token_file()?,
    };
    let mut default_headers = HeaderMap::new();
    default_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid token value")?,
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .default_headers(default_headers)
        .build()?;
    let base = &cli.api;
    let json_mode = cli.json;

    match cli.command {
        Commands::List => {
            let resp: SocketListResponse = client
                .get(format!("{base}/api/sockets"))
                .send()
                .await
                .context("failed to connect to daemon — is it running?")?
                .json()
                .await?;

            if json_mode {
                println!("{}", serde_json::to_string_pretty(&resp)?);
                return Ok(());
            }

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

            if json_mode {
                println!("{}", serde_json::to_string_pretty(&resp)?);
                return Ok(());
            }

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
                    if json_mode {
                        let body: serde_json::Value = resp.json().await?;
                        println!("{}", serde_json::to_string_pretty(&body)?);
                    } else {
                        println!("Allowed {ip} for socket {socket_id}");
                    }
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
                    if !json_mode {
                        println!("Removed ACL entry {entry_id}");
                    }
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

                if json_mode {
                    println!("{}", serde_json::to_string_pretty(&resp.acl)?);
                    return Ok(());
                }

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
                if !json_mode {
                    println!("Policy set to {policy} for socket {id}");
                }
            } else {
                let err: ApiError = resp.json().await?;
                bail!("{}", err.error);
            }
        }

        Commands::Status => {
            match client.get(format!("{base}/api/sockets")).send().await {
                Ok(resp) => {
                    let list: SocketListResponse = resp.json().await?;
                    if json_mode {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "status": "running",
                                "api": base,
                                "sockets": list.sockets.len()
                            }))?
                        );
                    } else {
                        println!("Daemon is running on {base}");
                        println!("  {} sockets managed", list.sockets.len());
                    }
                }
                Err(_) => {
                    if json_mode {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "status": "unreachable",
                                "api": base
                            }))?
                        );
                    } else {
                        bail!("Daemon is not reachable at {base}");
                    }
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

            if json_mode {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                use socketguard_core::config::BackendConfig;
                println!("Daemon Configuration:");
                println!("  Listen:    {}:{}", resp.listen_addr, resp.listen_port);
                println!("  Backend:   {}", resp.backend.backend_type());
                println!("  Interface: {}", resp.backend.interface());
                match &resp.backend {
                    BackendConfig::Slaac { prefix, .. } => {
                        println!("  Prefix:    {}", prefix.as_deref().unwrap_or("auto"));
                    }
                    _ => {}
                }
                println!("  Poll interval: {}s", resp.poll_interval_secs);
            }
        }

        Commands::Backends => {
            let resp: BackendsResponse = client
                .get(format!("{base}/api/backends"))
                .send()
                .await
                .context("failed to connect to daemon")?
                .json()
                .await?;

            if json_mode {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                for b in resp.backends {
                    let status = if b.available { "available" } else { "unavailable" };
                    println!("  {} - {} [{}]", b.name, b.description, status);
                }
            }
        }

        Commands::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "socketguard-cli",
                &mut std::io::stdout(),
            );
        }
    }

    Ok(())
}
