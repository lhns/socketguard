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
    List {
        /// Show all addresses (not just primary)
        #[arg(long, short)]
        verbose: bool,
    },

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

    /// Manage backend instances
    Backends {
        #[command(subcommand)]
        command: Option<BackendsCommands>,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum BackendsCommands {
    /// List active backend instances
    List,

    /// Add a new backend instance
    Add {
        /// Backend type: ula, yggdrasil, slaac, dhcpv6
        #[arg(long, short = 't')]
        backend_type: String,
        /// Network interface
        #[arg(long, short)]
        interface: String,
        /// Custom instance ID (auto-generated if omitted)
        #[arg(long)]
        id: Option<String>,
        /// IPv6 prefix (SLAAC only)
        #[arg(long)]
        prefix: Option<String>,
    },

    /// Remove a backend instance
    Remove {
        /// Backend instance ID
        id: String,
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

#[derive(Tabled)]
struct BackendInstanceRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Type")]
    backend_type: String,
    #[tabled(rename = "Interface")]
    interface: String,
}

fn read_token_file() -> Result<String> {
    let path = socketguard_core::api_token_path();
    std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .with_context(|| {
            format!(
                "failed to read API token from {} — is the daemon running?",
                path.display()
            )
        })
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
        HeaderValue::from_str(&format!("Bearer {token}")).context("invalid token value")?,
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .default_headers(default_headers)
        .build()?;
    let base = &cli.api;
    let json_mode = cli.json;

    match cli.command {
        Commands::List { verbose } => {
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
                .map(|s| {
                    let (ipv6, backend) = if verbose && s.addresses.len() > 1 {
                        let addrs: Vec<String> =
                            s.addresses.iter().map(|a| a.address.to_string()).collect();
                        let backends: Vec<String> =
                            s.addresses.iter().map(|a| a.backend_id.clone()).collect();
                        (addrs.join(", "), backends.join(", "))
                    } else if let Some(primary) = s.primary_address() {
                        let extra = if s.addresses.len() > 1 {
                            format!(" +{}", s.addresses.len() - 1)
                        } else {
                            String::new()
                        };
                        (
                            format!("{}{}", primary.address, extra),
                            primary.backend_id.clone(),
                        )
                    } else {
                        ("(none)".to_string(), "(none)".to_string())
                    };

                    SocketRow {
                        id: s.id[..8].to_string(),
                        process: format!("{} ({})", s.process_name, s.pid),
                        port: s.port,
                        protocol: s.protocol.to_string(),
                        ipv6,
                        policy: s.policy.to_string(),
                        backend,
                    }
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
            println!("  Policy:   {}", s.policy);
            println!("  First seen: {}", s.first_seen);
            println!("  Last seen:  {}", s.last_seen);

            // Show addresses grouped by backend
            if s.addresses.is_empty() {
                println!("\n  Addresses: (none)");
            } else {
                println!("\n  Addresses:");
                for addr in &s.addresses {
                    println!(
                        "    {} [{}] on {} (/{}){}",
                        addr.address,
                        addr.backend_id,
                        addr.interface,
                        addr.prefix_len,
                        addr.keypair_id
                            .as_ref()
                            .map(|k| format!(" keypair:{}", k))
                            .unwrap_or_default()
                    );
                }
            }

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

        Commands::Status => match client.get(format!("{base}/api/sockets")).send().await {
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
        },

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
                println!("Daemon Configuration:");
                println!("  Listen:    {}:{}", resp.listen_addr, resp.listen_port);
                println!("  Poll interval: {}s", resp.poll_interval_secs);
                println!("  Backends:  {} active", resp.backends.len());
                for inst in &resp.backends {
                    println!(
                        "    {} [{}] on {}",
                        inst.id,
                        inst.backend.backend_type(),
                        inst.backend.interface()
                    );
                }
            }
        }

        Commands::Backends { command } => match command {
            None | Some(BackendsCommands::List) => {
                let resp: BackendsResponse = client
                    .get(format!("{base}/api/backends"))
                    .send()
                    .await
                    .context("failed to connect to daemon")?
                    .json()
                    .await?;

                if json_mode {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }

                println!("Active backend instances:");
                if resp.active_instances.is_empty() {
                    println!("  (none)");
                } else {
                    let rows: Vec<BackendInstanceRow> = resp
                        .active_instances
                        .into_iter()
                        .map(|inst| BackendInstanceRow {
                            id: inst.id,
                            backend_type: inst.backend.backend_type().to_string(),
                            interface: inst.backend.interface().to_string(),
                        })
                        .collect();
                    println!("{}", Table::new(rows));
                }

                println!("\nAvailable backend types:");
                for b in resp.available_types {
                    let status = if b.available {
                        "available"
                    } else {
                        "unavailable"
                    };
                    let kind = if b.singleton {
                        "singleton"
                    } else {
                        "multi-instance"
                    };
                    println!("  {} - {} [{}, {}]", b.name, b.description, status, kind);
                }
            }

            Some(BackendsCommands::Add {
                backend_type,
                interface,
                id,
                prefix,
            }) => {
                use socketguard_core::config::BackendConfig;
                let backend = match backend_type.as_str() {
                    "ula" => BackendConfig::Ula { interface },
                    "yggdrasil" => BackendConfig::Yggdrasil { interface },
                    "slaac" => BackendConfig::Slaac { interface, prefix },
                    "dhcpv6" => BackendConfig::Dhcpv6 { interface },
                    other => bail!("unknown backend type: {other}"),
                };

                let req = AddBackendRequest { id, backend };
                let resp = client
                    .post(format!("{base}/api/backends"))
                    .json(&req)
                    .send()
                    .await
                    .context("failed to connect to daemon")?;

                if resp.status().is_success() {
                    if json_mode {
                        let body: serde_json::Value = resp.json().await?;
                        println!("{}", serde_json::to_string_pretty(&body)?);
                    } else {
                        let inst: socketguard_core::config::BackendInstanceConfig =
                            resp.json().await?;
                        println!(
                            "Added backend '{}' ({} on {})",
                            inst.id,
                            inst.backend.backend_type(),
                            inst.backend.interface()
                        );
                    }
                } else {
                    let err: ApiError = resp.json().await?;
                    bail!("{}", err.error);
                }
            }

            Some(BackendsCommands::Remove { id }) => {
                let resp = client
                    .delete(format!("{base}/api/backends/{id}"))
                    .send()
                    .await
                    .context("failed to connect to daemon")?;

                if resp.status().is_success() {
                    if !json_mode {
                        println!("Removed backend '{id}'");
                    }
                } else {
                    let err: ApiError = resp.json().await?;
                    bail!("{}", err.error);
                }
            }
        },

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
