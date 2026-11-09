use clap::Parser;
use socketguard_cli::{cli::Cli, commands, report};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match commands::run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            report(&e, json);
            std::process::ExitCode::FAILURE
        }
    }
}
