//! Where SocketGuard keeps its state (ADR 0050): one fixed place per system, never the
//! working directory. `SOCKETGUARD_CONFIG` and the config's `db_path` override.

use std::path::{Path, PathBuf};

pub const CONFIG_FILE: &str = "socketguard.json";
pub const DB_FILE: &str = "socketguard.db";
pub const SETUP_LOG_FILE: &str = "setup-log.json";

/// The default locations of one system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locations {
    /// Directory of the config file and the setup log.
    pub config_dir: PathBuf,
    /// Directory of the database.
    pub state_dir: PathBuf,
}

impl Locations {
    pub fn config(&self) -> PathBuf {
        self.config_dir.join(CONFIG_FILE)
    }
    pub fn db(&self) -> PathBuf {
        self.state_dir.join(DB_FILE)
    }
    /// Both directories, config first (one entry when they are the same).
    pub fn dirs(&self) -> Vec<PathBuf> {
        let mut v = vec![self.config_dir.clone()];
        if self.state_dir != self.config_dir {
            v.push(self.state_dir.clone());
        }
        v
    }
}

/// The default locations for `os` (`std::env::consts::OS`). `program_data` is the value of
/// `%ProgramData%` (Windows only).
pub fn locations_for(os: &str, program_data: Option<&str>) -> Locations {
    match os {
        "windows" => {
            let base = PathBuf::from(program_data.unwrap_or(r"C:\ProgramData")).join("SocketGuard");
            Locations {
                config_dir: base.clone(),
                state_dir: base,
            }
        }
        "macos" => {
            let base = PathBuf::from("/Library/Application Support/SocketGuard");
            Locations {
                config_dir: base.clone(),
                state_dir: base,
            }
        }
        _ => Locations {
            config_dir: PathBuf::from("/etc/socketguard"),
            state_dir: PathBuf::from("/var/lib/socketguard"),
        },
    }
}

/// The default locations of this system.
pub fn default_locations() -> Locations {
    let pd = std::env::var("ProgramData").ok();
    locations_for(std::env::consts::OS, pd.as_deref())
}

pub fn default_config_path() -> PathBuf {
    default_locations().config()
}

pub fn default_db_path() -> PathBuf {
    default_locations().db()
}

/// The config file in use: `SOCKETGUARD_CONFIG`, else the default location.
pub fn config_path() -> PathBuf {
    std::env::var_os("SOCKETGUARD_CONFIG")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_config_path)
}

/// The database of the config file `config`, whose `db_path` setting is `db_path`: an
/// absolute path as is, a relative one against the config file's directory (never the
/// working directory), none at all the default location when the config is the default one
/// and `socketguard.db` next to it otherwise.
pub fn resolve_db_path(config: &Path, db_path: &str) -> PathBuf {
    let dir = config.parent().filter(|p| !p.as_os_str().is_empty());
    if db_path.is_empty() {
        if config == default_config_path() {
            return default_db_path();
        }
        return dir.unwrap_or_else(|| Path::new(".")).join(DB_FILE);
    }
    let p = Path::new(db_path);
    if p.is_absolute() || db_path == ":memory:" {
        return p.to_path_buf();
    }
    match dir {
        Some(d) => d.join(p),
        None => p.to_path_buf(),
    }
}

/// The setup log / install record next to the config file.
pub fn setup_log_path(config: &Path) -> PathBuf {
    config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(SETUP_LOG_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_locations_per_system() {
        let w = locations_for("windows", Some(r"D:\PD"));
        assert_eq!(
            w.config(),
            PathBuf::from(r"D:\PD")
                .join("SocketGuard")
                .join("socketguard.json")
        );
        assert_eq!(
            w.db(),
            PathBuf::from(r"D:\PD")
                .join("SocketGuard")
                .join("socketguard.db")
        );
        let l = locations_for("linux", None);
        assert_eq!(
            l.config(),
            PathBuf::from("/etc/socketguard/socketguard.json")
        );
        assert_eq!(l.db(), PathBuf::from("/var/lib/socketguard/socketguard.db"));
        assert_eq!(l.dirs().len(), 2);
        let m = locations_for("macos", None);
        assert_eq!(
            m.config(),
            PathBuf::from("/Library/Application Support/SocketGuard/socketguard.json")
        );
        assert_eq!(m.dirs().len(), 1);
    }

    #[test]
    fn relative_db_path_is_against_the_config_directory() {
        let cfg = Path::new("/srv/x/sg.json");
        assert_eq!(
            resolve_db_path(cfg, "a.db"),
            Path::new("/srv/x").join("a.db")
        );
        assert_eq!(
            resolve_db_path(cfg, ""),
            Path::new("/srv/x").join("socketguard.db")
        );
        assert_eq!(resolve_db_path(cfg, ":memory:"), PathBuf::from(":memory:"));
        assert_eq!(
            resolve_db_path(&default_config_path(), ""),
            default_db_path()
        );
    }
}
