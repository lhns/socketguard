//! The one-time move of state from the working directory (where the daemon kept it before
//! ADR 0050) to the fixed location. All or nothing: a move that cannot be completed is
//! undone and the daemon stops with an error instead of running on half of its state.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Move {
    pub from: PathBuf,
    pub to: PathBuf,
}

/// What would move: only when nothing is at the fixed location yet and the working
/// directory holds a config or a database.
pub fn plan(cwd: &Path, config_to: &Path, db_to: &Path) -> Vec<Move> {
    if config_to.exists() || db_to.exists() {
        return vec![];
    }
    let cfg = cwd.join(socketguard_core::paths::CONFIG_FILE);
    let db = cwd.join(socketguard_core::paths::DB_FILE);
    if !cfg.is_file() && !db.is_file() {
        return vec![];
    }
    let mut v = vec![];
    let mut add = |from: PathBuf, to: PathBuf| {
        if from.is_file() {
            v.push(Move { from, to });
        }
    };
    add(cfg, config_to.to_path_buf());
    for suffix in ["", "-wal", "-shm"] {
        add(
            PathBuf::from(format!("{}{suffix}", db.display())),
            PathBuf::from(format!("{}{suffix}", db_to.display())),
        );
    }
    add(
        cwd.join(socketguard_core::paths::SETUP_LOG_FILE),
        socketguard_core::paths::setup_log_path(config_to),
    );
    v
}

fn move_one(m: &Move) -> Result<bool> {
    // Returns true when it was copied (the source still exists).
    match std::fs::rename(&m.from, &m.to) {
        Ok(()) => Ok(false),
        Err(_) => {
            std::fs::copy(&m.from, &m.to)?;
            Ok(true)
        }
    }
}

/// Perform the moves. On any failure everything already moved goes back.
pub fn execute(moves: &[Move]) -> Result<()> {
    for m in moves {
        if m.to.exists() {
            bail!("{} exists already; not overwriting it with {}", m.to.display(), m.from.display());
        }
    }
    let mut done: Vec<(&Move, bool)> = vec![];
    for m in moves {
        match move_one(m).with_context(|| format!("moving {} to {}", m.from.display(), m.to.display())) {
            Ok(copied) => done.push((m, copied)),
            Err(e) => {
                for (d, copied) in done.iter().rev() {
                    if *copied {
                        let _ = std::fs::remove_file(&d.to);
                    } else {
                        let _ = std::fs::rename(&d.to, &d.from);
                    }
                }
                return Err(e).context("the state in the working directory could not be moved to its fixed location; nothing was changed");
            }
        }
    }
    for (m, copied) in done {
        if copied {
            let _ = std::fs::remove_file(&m.from);
        }
    }
    Ok(())
}

/// A moved config that named the database relative to the old working directory would now
/// resolve it against its own directory. The plain default name is dropped (the moved
/// database sits at the fixed location); any other relative path becomes the absolute
/// path it meant, so the daemon keeps using that file.
pub fn fix_moved_config(config: &Path, old_cwd: &Path) {
    let Ok(text) = std::fs::read_to_string(config) else { return };
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text.strip_prefix('\u{feff}').unwrap_or(&text)) else {
        return;
    };
    let Some(db) = v.get("db_path").and_then(|d| d.as_str()).map(str::to_string) else {
        return;
    };
    if Path::new(&db).is_absolute() || db == ":memory:" {
        return;
    }
    let obj = v.as_object_mut().unwrap();
    if db == socketguard_core::paths::DB_FILE {
        obj.remove("db_path");
    } else {
        obj.insert(
            "db_path".into(),
            serde_json::Value::String(old_cwd.join(&db).to_string_lossy().into_owned()),
        );
    }
    if let Ok(mut out) = serde_json::to_string_pretty(&v) {
        out.push('\n');
        let _ = std::fs::write(config, out);
    }
}

/// Move the state in `cwd` to the fixed location if it applies; the moves made.
pub fn migrate(cwd: &Path, config_to: &Path, db_to: &Path) -> Result<Vec<Move>> {
    let moves = plan(cwd, config_to, db_to);
    if moves.is_empty() {
        return Ok(moves);
    }
    execute(&moves)?;
    if moves.iter().any(|m| m.to == config_to) {
        fix_moved_config(config_to, cwd);
    }
    Ok(moves)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("sg-legacy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn everything_moves_and_the_default_relative_db_path_is_dropped() {
        let d = tmp();
        let (cwd, to) = (d.join("cwd"), d.join("fixed"));
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&to).unwrap();
        std::fs::write(cwd.join("socketguard.json"), r#"{"db_path":"socketguard.db","poll_interval_secs":7}"#).unwrap();
        for f in ["socketguard.db", "socketguard.db-wal", "socketguard.db-shm", "setup-log.json", "other.txt"] {
            std::fs::write(cwd.join(f), f).unwrap();
        }
        let moves = migrate(&cwd, &to.join("socketguard.json"), &to.join("socketguard.db")).unwrap();
        assert_eq!(moves.len(), 5);
        assert!(!cwd.join("socketguard.db").exists());
        assert!(cwd.join("other.txt").exists(), "unrelated files stay");
        assert_eq!(std::fs::read_to_string(to.join("socketguard.db-wal")).unwrap(), "socketguard.db-wal");
        let cfg = std::fs::read_to_string(to.join("socketguard.json")).unwrap();
        assert!(!cfg.contains("db_path") && cfg.contains("poll_interval_secs"));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn nothing_moves_when_the_fixed_location_has_state_or_the_cwd_has_none() {
        let d = tmp();
        let (cwd, to) = (d.join("cwd"), d.join("fixed"));
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&to).unwrap();
        assert!(migrate(&cwd, &to.join("socketguard.json"), &to.join("socketguard.db")).unwrap().is_empty());
        std::fs::write(cwd.join("socketguard.db"), "old").unwrap();
        std::fs::write(to.join("socketguard.db"), "new").unwrap();
        assert!(migrate(&cwd, &to.join("socketguard.json"), &to.join("socketguard.db")).unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(cwd.join("socketguard.db")).unwrap(), "old");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_move_that_fails_half_way_is_undone() {
        let d = tmp();
        let (cwd, to) = (d.join("cwd"), d.join("fixed"));
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&to).unwrap();
        std::fs::write(cwd.join("socketguard.json"), "{}").unwrap();
        std::fs::write(cwd.join("socketguard.db"), "db").unwrap();
        // The target of the database cannot be written: its parent does not exist.
        let err = migrate(&cwd, &to.join("socketguard.json"), &to.join("missing").join("socketguard.db")).unwrap_err();
        assert!(format!("{err:#}").contains("nothing was changed"), "{err:#}");
        assert!(cwd.join("socketguard.json").exists() && cwd.join("socketguard.db").exists());
        assert!(!to.join("socketguard.json").exists(), "the config went back");
        std::fs::remove_dir_all(d).unwrap();
    }
}
