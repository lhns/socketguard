//! A child that outlives a crashed daemon is found again at the next start through
//! `child.pid` in its data directory: the pid and the process start time. Only a process
//! with both matching is killed, so a pid that the system reused for something else is left
//! alone. macOS needs this because it has no parent-death signal; on Linux the signal is
//! cleared when a child changes its user id, which Yggdrasil does after creating its tun.
//!
//! The decision is pure (it takes the lookups as functions) so it is tested everywhere; the
//! callers pass the real ones on Unix.

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

/// The data directory may belong to the unprivileged account the child runs as, so the
/// file is only believed when it is a regular file of the daemon's own user, and it is
/// written fresh and never through a link.
#[cfg(unix)]
fn read_trusted(file: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(file).ok()?;
    // SAFETY: geteuid has no preconditions.
    let own = unsafe { libc::geteuid() };
    if !meta.is_file() || meta.uid() != own {
        return None;
    }
    std::fs::read_to_string(file).ok()
}

#[cfg(not(unix))]
fn read_trusted(file: &Path) -> Option<String> {
    std::fs::read_to_string(file).ok()
}

/// Record `pid` and its start time in `data_dir`.
pub fn write(data_dir: &Path, pid: u32, start: &str) {
    use std::io::Write;
    let file = path(data_dir);
    let _ = std::fs::remove_file(&file);
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    }
    if let Ok(mut f) = open.open(&file) {
        let _ = f.write_all(render(pid, start).as_bytes());
    }
}

/// Kill the leftover child recorded in `data_dir`, if the process with that pid still
/// started at the recorded time. Returns the pid killed. The file is removed either way.
pub fn kill_stale(
    data_dir: &Path,
    start_of: &dyn Fn(u32) -> Option<String>,
    kill: &dyn Fn(u32),
) -> Option<u32> {
    let file = path(data_dir);
    let text = read_trusted(&file);
    let _ = std::fs::remove_file(&file);
    let text = text?;
    let (pid, start) = parse(&text)?;
    if start_of(pid).as_deref() == Some(start.as_str()) {
        kill(pid);
        Some(pid)
    } else {
        None
    }
}

/// The start time of `pid` in clock ticks since boot (field 22 of `/proc/<pid>/stat`).
#[cfg(target_os = "linux")]
pub fn process_start_time(pid: u32) -> Option<String> {
    stat_start_time(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Field 22 of a `/proc/<pid>/stat` line. The command name (field 2) may hold spaces and
/// parentheses, so the fields are counted from the last `)`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_start_time(stat: &str) -> Option<String> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19).map(str::to_string)
}

/// The start time of `pid` as `ps` prints it (`Tue Nov 11 10:00:00 2026`).
#[cfg(all(unix, not(target_os = "linux")))]
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
    fn the_start_time_is_field_22_of_proc_stat() {
        let line = "4242 (a (weird) name) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        assert_eq!(stat_start_time(line).as_deref(), Some("987654"));
        assert_eq!(stat_start_time("garbage"), None);
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
