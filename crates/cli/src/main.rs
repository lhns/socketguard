//! SocketGuard CLI. The model changed (ADR 0027) and API v1 has not landed yet (redesign
//! phase 6), so only `status` works until the CLI is rewritten.

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use socketguard_core::api_types::StatusResponse;

#[derive(Parser)]
#[command(name = "socketguard", about = "Per-app access control")]
struct Cli {
    /// Daemon API address
    #[arg(long, default_value = "http://127.0.0.1:9476", global = true)]
    api: String,

    /// Override the API bearer token (default: read from token file)
    #[arg(long, global = true)]
    token: Option<String>,

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
    let token = match cli.token {
        Some(t) => t,
        None => {
            let path = socketguard_core::api_token_path();
            std::fs::read_to_string(&path)
                .with_context(|| {
                    format!(
                        "failed to read API token from {} - is the daemon running?",
                        path.display()
                    )
                })?
                .trim()
                .to_string()
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).context("invalid token value")?,
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    match cli.command {
        Commands::Status => {
            let resp = client
                .get(format!("{}/api/status", cli.api))
                .send()
                .await
                .context("cannot reach the daemon")?
                .error_for_status()?;
            let status: StatusResponse = resp.json().await?;
            println!("daemon {} is running", status.version);
        }
    }
    Ok(())
}
