//! macOS has no parent-death signal, so a child that outlives a crashed daemon is found
//! again at the next start through `child.pid` in its data directory: the pid and the
//! process start time. Only a process with both matching is killed, so a pid that the
//! system reused for something else is left alone.
//!
//! The decision is pure (it takes the lookups as functions) so it is tested everywhere; the
//! callers pass the real ones on macOS.

use std::path::{Path, PathBuf};

pub const FILE: &str = "child.pid";

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE)
}

/// `pid` and `start` (any text that identifies the start time) as the file's content.
pub fn render(pid: u32, start: &str) -> String {
    format!("{pid} {start}\n")
}

pub fn parse(text: &str) -> Option<(u32, String)> {
    let (pid, start) = text.trim().split_once(' ')?;
    let start = start.trim();
    if start.is_empty() {
        return None;
    }
    Some((pid.parse().ok()?, start.to_string()))
}

/// Kill the leftover child recorded in `data_dir`, if the process with that pid still
/// started at the recorded time. Returns the pid killed. The file is removed either way.
pub fn kill_stale(
    data_dir: &Path,
    start_of: &dyn Fn(u32) -> Option<String>,
    kill: &dyn Fn(u32),
) -> Option<u32> {
    let file = path(data_dir);
    let text = std::fs::read_to_string(&file).ok()?;
    let _ = std::fs::remove_file(&file);
    let (pid, start) = parse(&text)?;
    if start_of(pid).as_deref() == Some(start.as_str()) {
        kill(pid);
        Some(pid)
    } else {
        None
    }
}

/// The start time of `pid` as `ps` prints it (`Tue Nov 11 10:00:00 2026`).
#[cfg(unix)]
pub fn process_start_time(pid: u32) -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("sg-pidfile-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_file_round_trips() {
        assert_eq!(
            parse(&render(42, "Tue Nov 11 10:00:00 2026")),
            Some((42, "Tue Nov 11 10:00:00 2026".to_string()))
        );
        assert_eq!(parse("garbage"), None);
        assert_eq!(parse("x y"), None);
        assert_eq!(parse("7 "), None);
    }

    #[test]
    fn only_a_process_with_the_recorded_start_time_is_killed() {
        let d = dir();
        let killed = RefCell::new(vec![]);
        let kill = |p| killed.borrow_mut().push(p);

        // Same pid, other start time: the system reused the pid.
        std::fs::write(path(&d), render(42, "then")).unwrap();
        assert_eq!(kill_stale(&d, &|_| Some("now".into()), &kill), None);
        assert!(killed.borrow().is_empty());
        assert!(!path(&d).exists(), "the stale file goes either way");

        // Gone.
        std::fs::write(path(&d), render(42, "then")).unwrap();
        assert_eq!(kill_stale(&d, &|_| None, &kill), None);

        // Ours.
        std::fs::write(path(&d), render(42, "then")).unwrap();
        assert_eq!(kill_stale(&d, &|_| Some("then".into()), &kill), Some(42));
        assert_eq!(*killed.borrow(), [42]);

        // No file, nothing to do.
        assert_eq!(kill_stale(&d, &|_| Some("then".into()), &kill), None);
    }
}
