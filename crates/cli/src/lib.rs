//! The `socketguard` command line (ADR 0033): the primary frontend, covering the whole API
//! through `socketguard-client`. The binary is `src/main.rs`; the pieces are a library so
//! the tests can reach them.

pub mod cli;
pub mod commands;
pub mod parse;
pub mod prompt;
pub mod render;
pub mod resolve;
pub mod routes;

pub use routes::CLI_ROUTES;

/// Print an error the way the CLI shows it, and say whether anything was printed.
pub fn report(err: &anyhow::Error, json: bool) {
    if err.downcast_ref::<commands::Reported>().is_some() {
        return;
    }
    if let Some(socketguard_client::Error::Api {
        code,
        message,
        details,
        ..
    }) = err.downcast_ref::<socketguard_client::Error>()
    {
        if json {
            let body = serde_json::json!({"error": {"code": code, "message": message, "details": details}});
            eprintln!("{body}");
        } else {
            eprintln!("error: {code}: {message}");
        }
    } else if json {
        eprintln!(
            "{}",
            serde_json::json!({"error": {"message": format!("{err:#}")}})
        );
    } else {
        eprintln!("error: {err:#}");
    }
}
