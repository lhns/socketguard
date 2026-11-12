use clap::Parser;
use socketguard_cli::{cli::Cli, commands, report};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // `--portable` (ADR 0054) is read before the arguments are parsed, like the marker file.
    let mut args: Vec<String> = std::env::args().collect();
    socketguard_core::portable::strip_flag(&mut args);
    if let Err(e) = socketguard_core::portable::ensure_supported() {
        eprintln!("error: {e}");
        return std::process::ExitCode::from(2);
    }
    let cli = Cli::parse_from(args);
    let json = cli.json;
    match commands::run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            report(&e, json);
            std::process::ExitCode::FAILURE
        }
    }
}
