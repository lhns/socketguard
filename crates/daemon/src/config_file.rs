//! The daemon's config file: where it is, and writing the network list back to it.

use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use std::path::{Path, PathBuf};

/// `SOCKETGUARD_CONFIG`, else the fixed location of this system (ADR 0050); never the
/// working directory.
pub fn config_path() -> PathBuf {
    socketguard_core::paths::config_path()
}

/// Whether the config file is in the default place (no `SOCKETGUARD_CONFIG`).
pub fn is_default_location(path: &Path) -> bool {
    path == socketguard_core::paths::default_config_path()
}

/// The file's text without a leading UTF-8 BOM, which Windows tools (PowerShell 5.1's
/// `Set-Content -Encoding utf8`, Notepad) write and serde_json rejects.
pub fn read(path: &Path) -> std::io::Result<String> {
    let text = std::fs::read_to_string(path)?;
    Ok(match text.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_string(),
        None => text,
    })
}

/// Running on defaults instead would act on the wrong networks and state (even `--disable`).
const FIX_HINT: &str = "fix it, or point SOCKETGUARD_CONFIG at the right file";

/// The config at `path`; None if there is no file. A file that cannot be read or parsed is
/// an error.
pub fn load(path: &Path) -> anyhow::Result<Option<DaemonConfig>> {
    use anyhow::Context;
    let text = match read(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("cannot read config {}; {FIX_HINT}", path.display()))
        }
    };
    serde_json::from_str(&text)
        .map(Some)
        .with_context(|| format!("invalid config {}; {FIX_HINT}", path.display()))
}

/// Write `config.backends` to the `backends` key of the file at `path`, keeping its other
/// keys. A missing file is created from the full `config`. The write goes to a temp file
/// in the same directory and is renamed over the original, so a crash leaves either the
/// old or the new file. A file that is not a JSON object is left alone and reported.
pub fn persist_backends(path: &Path, config: &DaemonConfig) -> anyhow::Result<()> {
    use anyhow::Context;
    let mut doc = match read(path) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_with_a_bom_is_read() {
        let dir = std::env::temp_dir().join(format!("sg-config-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("socketguard.json");
        std::fs::write(&path, "\u{feff}{\"poll_interval_secs\": 7}").unwrap();
        let config = load(&path).unwrap().unwrap();
        assert_eq!(config.poll_interval_secs, 7);
        persist_backends(&path, &config).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_config_is_none_and_an_invalid_one_an_error() {
        let dir = std::env::temp_dir().join(format!("sg-config-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("socketguard.json");
        assert!(load(&path).unwrap().is_none());
        std::fs::write(&path, "{\"backends\": [{\"type\": \"nope\"}]}").unwrap();
        let err = load(&path).unwrap_err();
        assert!(format!("{err:#}").contains("invalid config"), "{err:#}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
