//! The daemon's config file: where it is, and writing the network list back to it.

use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use std::path::{Path, PathBuf};

/// `SOCKETGUARD_CONFIG`, else the fixed location of this system (ADR 0050); never the
/// working directory.
pub fn config_path() -> PathBuf {
    socketguard_core::paths::config_path()
}

/// The config as the daemon uses it: where it is, what it says and the database it names.
pub struct Resolved {
    pub config_path: PathBuf,
    /// Loaded from the file, else the defaults; `db_path` is the resolved absolute path.
    pub config: DaemonConfig,
    pub file_exists: bool,
    pub db_path: PathBuf,
}

/// Load the config at `path` (defaults when there is no file) and resolve its database
/// path: absolute as is, relative to the config file's directory, empty the fixed default.
pub fn resolve_at(path: &Path) -> anyhow::Result<Resolved> {
    let (config, file_exists) = match load(path)? {
        Some(c) => (c, true),
        None => (DaemonConfig::default(), false),
    };
    Ok(resolved(path, config, file_exists))
}

fn resolved(path: &Path, mut config: DaemonConfig, file_exists: bool) -> Resolved {
    let db_path = socketguard_core::paths::resolve_db_path(path, &config.db_path);
    config.db_path = db_path.to_string_lossy().into_owned();
    Resolved {
        config_path: path.to_path_buf(),
        config,
        file_exists,
        db_path,
    }
}

/// [`resolve_at`] for the config in use (`SOCKETGUARD_CONFIG`, else the fixed location).
pub fn resolve() -> anyhow::Result<Resolved> {
    resolve_at(&config_path())
}

/// Like [`resolve_at`] for the commands that take SocketGuard off a host (`--disable`,
/// `uninstall`), which must not depend on the config parsing: a file that cannot be read or
/// parsed gives the built-in defaults at the same config path, and a warning to print. The
/// daemon's own start stays strict ([`resolve_at`]).
pub fn resolve_for_removal_at(path: &Path) -> (Resolved, Option<String>) {
    match resolve_at(path) {
        Ok(r) => (r, None),
        Err(e) => {
            let r = resolved(path, DaemonConfig::default(), true);
            let warning = format!(
                "warning: {e:#}
                 Going on with the built-in default configuration (database {}, API socket {}).                  Networks, a database path and an API socket named only in {} are not known,                  so those networks cannot be listed and a database elsewhere is not found.                  What the database at the default path, the install record and the address                  ledger name is still removed.",
                r.db_path.display(),
                r.config.api_socket,
                path.display()
            );
            (r, Some(warning))
        }
    }
}

/// [`resolve_for_removal_at`] for the config in use; the warning is printed to stderr.
pub fn resolve_for_removal() -> Resolved {
    let (r, warning) = resolve_for_removal_at(&config_path());
    if let Some(w) = warning {
        eprintln!("socketguard-daemon: {w}");
    }
    r
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

/// Running on defaults instead would act on the wrong networks and state; only the commands
/// that remove SocketGuard accept that ([`resolve_for_removal_at`]).
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
    let config: DaemonConfig = serde_json::from_str(&text)
        .with_context(|| format!("invalid config {}; {FIX_HINT}", path.display()))?;
    Ok(Some(config))
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut v = serde_json::to_value(config)?;
            // The resolved database path is not a setting: leave it to the default.
            if let Some(o) = v.as_object_mut() {
                o.remove("db_path");
            }
            v
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    // Only `backends` is written; the rest of the file stays as it is.
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

    #[test]
    fn a_stale_key_fails_the_load_and_names_the_key_and_the_file() {
        let dir = std::env::temp_dir().join(format!("sg-config-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("socketguard.json");
        for (text, key) in [
            (r#"{"backend": "ula"}"#, "backend"),
            (
                r#"{"backends": [{"type": "tor", "managed": true}]}"#,
                "managed",
            ),
            (
                r#"{"backends": [{"type": "tor", "control": "127.0.0.1:9051"}]}"#,
                "control",
            ),
            (
                r#"{"backends": [{"type": "yggdrasil", "interface": "ygg0"}]}"#,
                "interface",
            ),
        ] {
            std::fs::write(&path, text).unwrap();
            let err = format!("{:#}", load(&path).unwrap_err());
            assert!(
                err.contains(key) && err.contains("socketguard.json"),
                "{key}: {err}"
            );
        }
        std::fs::write(&path, r#"{"backends": [{"type": "tor"}]}"#).unwrap();
        assert!(load(&path).unwrap().is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn taking_socketguard_off_goes_on_with_defaults_when_the_config_does_not_parse() {
        let dir = std::env::temp_dir().join(format!("sg-config-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("socketguard.json");
        // No file, or a good one: as `resolve_at`, no warning.
        let (r, warning) = resolve_for_removal_at(&path);
        assert!(warning.is_none() && !r.file_exists);
        std::fs::write(&path, r#"{"poll_interval_secs": 7}"#).unwrap();
        let (r, warning) = resolve_for_removal_at(&path);
        assert!(warning.is_none() && r.file_exists && r.config.poll_interval_secs == 7);
        // An unknown key: the defaults at the same paths, and a warning that names the file,
        // the error and what cannot be known.
        std::fs::write(&path, r#"{"stale_setting": 1}"#).unwrap();
        assert!(resolve_at(&path).is_err());
        let (r, warning) = resolve_for_removal_at(&path);
        let warning = warning.expect("a warning");
        assert!(warning.contains("socketguard.json"), "{warning}");
        assert!(warning.contains("stale_setting"), "{warning}");
        assert!(warning.contains("built-in default"), "{warning}");
        assert!(warning.contains("networks"), "{warning}");
        assert_eq!(r.config_path, path);
        assert!(r.file_exists);
        assert_eq!(r.config.backends, DaemonConfig::default().backends);
        assert_eq!(
            r.db_path,
            socketguard_core::paths::resolve_db_path(&path, "")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
