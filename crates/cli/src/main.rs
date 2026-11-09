//! SocketGuard CLI. API v1 and the client crate exist (redesign phase 6); the commands that
//! cover the whole API arrive with phase 7a, so only `status` works until then.

use anyhow::{Context, Result};
use clap::Parser;
use socketguard_client::Client;

#[derive(Parser)]
#[command(name = "socketguard", about = "Per-app access control")]
struct Cli {
    /// Daemon socket path (Unix) or pipe name (Windows)
    #[arg(long, env = "SOCKETGUARD_SOCKET", global = true)]
    socket: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Check daemon status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = match cli.socket {
        Some(s) => Client::new(s),
        None => Client::from_env(),
    };

    match cli.command {
        Commands::Status => {
            let status = client.status().await.context("cannot reach the daemon")?;
            println!("daemon {} is running", status.version);
        }
    }
    Ok(())
}
