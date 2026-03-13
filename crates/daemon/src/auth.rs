use anyhow::{Context, Result};
use rand::Rng;
use std::fmt::Write;
use std::fs;

/// Generates a random 256-bit token (64 hex chars), writes it to the shared
/// token file, and returns the token string.
pub fn generate_and_store_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    let mut token = String::with_capacity(64);
    for b in &bytes {
        write!(token, "{b:02x}").unwrap();
    }

    let path = socketguard_core::api_token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create token directory: {}", parent.display()))?;
    }
    fs::write(&path, &token)
        .with_context(|| format!("failed to write token file: {}", path.display()))?;

    tracing::info!("API token written to {}", path.display());
    Ok(token)
}

/// Removes the token file. Best-effort — logs but does not fail on error.
pub fn cleanup_token_file() {
    let path = socketguard_core::api_token_path();
    match fs::remove_file(&path) {
        Ok(()) => tracing::info!("API token file removed"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("Failed to remove token file: {e}"),
    }
}
