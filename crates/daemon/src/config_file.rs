//! The daemon's config file: where it is, and writing the network list back to it.

use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use std::path::{Path, PathBuf};

/// `SOCKETGUARD_CONFIG`, else `socketguard.json` in the working directory.
pub fn config_path() -> PathBuf {
    std::env::var_os("SOCKETGUARD_CONFIG")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("socketguard.json"))
}

/// Write `config.backends` to the `backends` key of the file at `path`, keeping its other
/// keys. A missing file is created from the full `config`. The write goes to a temp file
/// in the same directory and is renamed over the original, so a crash leaves either the
/// old or the new file. A file that is not a JSON object is left alone and reported.
pub fn persist_backends(path: &Path, config: &DaemonConfig) -> anyhow::Result<()> {
    use anyhow::Context;
    let mut doc = match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) if v.is_object() => v,
            _ => anyhow::bail!(
                "{} is not a JSON object; not overwriting it",
                path.display()
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::to_value(config)?,
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    // On load `backends` wins over the legacy `backend` and `interface` keys, which stay.
    doc.as_object_mut().expect("checked above").insert(
        "backends".to_string(),
        serde_json::to_value::<&[BackendInstanceConfig]>(&config.backends)?,
    );

    // Unique per call: concurrent writers in one process must not share a temp file.
    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut text = serde_json::to_string_pretty(&doc)?;
    text.push('\n');
    let result = std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing {}", path.display()))
}
