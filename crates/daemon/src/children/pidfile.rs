//! A child that outlives a crashed daemon is found again at the next start through a pid
//! file: the pid and the process start time. Only a process with the start time matching
//! AND the executable the daemon started is killed, so a pid that the system reused for
//! something else is left alone. macOS needs this because it has no parent-death signal;
//! on Linux the signal is cleared when a child changes its user id, which Yggdrasil does
//! after creating its tun (the child guard covers that, see `guard`).
//!
//! The file lives in `<state dir>/run/`, a directory only the daemon can write (never in a
//! directory a child owns: a compromised child could otherwise make the daemon, which is
//! root, kill any process). One file per child id.
//!
//! The decision is pure (it takes the lookups as functions) so it is tested everywhere; the
//! callers pass the real ones on Unix.

use std::path::{Path, PathBuf};

/// The directory of the pid files under the state directory.
pub const RUN_DIR: &str = "run";

/// `<state dir>/run/<id>.pid`; anything but letters, digits, `-` and `_` in `id` becomes `_`.
pub fn path(state_dir: &Path, id: &str) -> PathBuf {
    let safe: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    state_dir.join(RUN_DIR).join(format!("{safe}.pid"))
}

/// The second file of a guarded child: the program the guard started (`ygg.pid` ->
/// `ygg.child`).
pub fn child_path(file: &Path) -> PathBuf {
    file.with_extension("child")
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

/// Create the directory of `file` for the daemon alone (0700). On Unix an existing one
/// that is not the daemon's is an error.
pub fn prepare_dir(file: &Path) -> std::io::Result<()> {
    let Some(dir) = file.parent() else {
        return Ok(());
    };
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions.
        let own = unsafe { libc::geteuid() };
        let meta = std::fs::symlink_metadata(dir)?;
        if !meta.is_dir() || meta.uid() != own {
            return Err(std::io::Error::other(format!(
                "{} is not the daemon's own directory",
                dir.display()
            )));
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Only a regular file of the daemon's own user, in a directory that is the daemon's and
/// closed to others, is believed; it is never read through a link.
#[cfg(unix)]
fn read_trusted(file: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    let own = unsafe { libc::geteuid() };
    let dir = std::fs::symlink_metadata(file.parent()?).ok()?;
    if !dir.is_dir() || dir.uid() != own || dir.mode() & 0o022 != 0 {
        return None;
    }
    let meta = std::fs::symlink_metadata(file).ok()?;
    if !meta.is_file() || meta.uid() != own {
        return None;
    }
    std::fs::read_to_string(file).ok()
}

#[cfg(not(unix))]
fn read_trusted(file: &Path) -> Option<String> {
    std::fs::read_to_string(file).ok()
}

/// Record `pid` and its start time in `file` (written fresh, never through a link).
pub fn write(file: &Path, pid: u32, start: &str) {
    use std::io::Write;
    let _ = std::fs::remove_file(file);
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    if let Ok(mut f) = open.open(file) {
        let _ = f.write_all(render(pid, start).as_bytes());
    }
}

/// The lookups [`kill_stale`] needs, so a test can stand in for the system.
pub struct Probe<'a> {
    pub start_of: &'a dyn Fn(u32) -> Option<String>,
    pub exe_of: &'a dyn Fn(u32) -> Option<PathBuf>,
    pub kill: &'a dyn Fn(u32),
}

/// Kill the leftover child recorded in `file`, if the process with that pid still started at
/// the recorded time AND runs `expected_exe`. Returns the pid killed. The file is removed
/// either way.
pub fn kill_stale(file: &Path, expected_exe: &Path, probe: &Probe) -> Option<u32> {
    let text = read_trusted(file);
    let _ = std::fs::remove_file(file);
    let (pid, start) = parse(&text?)?;
    if (probe.start_of)(pid).as_deref() != Some(start.as_str()) {
        return None;
    }
    if !same_file((probe.exe_of)(pid)?, expected_exe) {
        return None;
    }
    (probe.kill)(pid);
    Some(pid)
}

/// Whether both name the same executable (links resolved where the files exist).
fn same_file(a: PathBuf, b: &Path) -> bool {
    let a = std::fs::canonicalize(&a).unwrap_or(a);
    let b = std::fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf());
    a == b
}

/// The executable of `pid` (`/proc/<pid>/exe`).
#[cfg(target_os = "linux")]
pub fn process_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// The executable of `pid` (`proc_pidpath`).
#[cfg(target_os = "macos")]
pub fn process_exe(pid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut buf = vec![0u8; 4096];
    // SAFETY: the buffer is valid for the size passed.
    let n = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

/// No way to ask: nothing is killed on other systems.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub fn process_exe(_pid: u32) -> Option<PathBuf> {
    None
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

    fn probe_for<'a>(
        start: &'a dyn Fn(u32) -> Option<String>,
        exe: &'a dyn Fn(u32) -> Option<PathBuf>,
        kill: &'a dyn Fn(u32),
    ) -> Probe<'a> {
        Probe {
            start_of: start,
            exe_of: exe,
            kill,
        }
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
    fn only_a_process_with_the_recorded_start_time_and_executable_is_killed() {
        let d = dir();
        let file = path(&d, "tor");
        prepare_dir(&file).unwrap();
        let bundled = Path::new("/opt/sg/third_party/tor/tor");
        let killed = RefCell::new(vec![]);
        let kill = |p| killed.borrow_mut().push(p);
        let then = |_| Some("then".to_string());
        let now = |_| Some("now".to_string());
        let gone = |_| None;
        let ours = |_| Some(bundled.to_path_buf());
        let other = |_| Some(PathBuf::from("/usr/bin/sshd"));
        let unreadable = |_| None;
        let run = |start: &dyn Fn(u32) -> Option<String>, exe: &dyn Fn(u32) -> Option<PathBuf>| {
            std::fs::write(&file, render(42, "then")).unwrap();
            let r = kill_stale(&file, bundled, &probe_for(start, exe, &kill));
            assert!(!file.exists(), "the file goes either way");
            r
        };

        // Same pid, other start time: the system reused the pid.
        assert_eq!(run(&now, &ours), None);
        // Same start time but another program: never killed.
        assert_eq!(run(&then, &other), None);
        // The executable cannot be read.
        assert_eq!(run(&then, &unreadable), None);
        // Gone.
        assert_eq!(run(&gone, &ours), None);
        assert!(killed.borrow().is_empty());
        // Ours.
        assert_eq!(run(&then, &ours), Some(42));
        assert_eq!(*killed.borrow(), [42]);

        // No file, nothing to do.
        let probe = probe_for(&then, &ours, &kill);
        assert_eq!(kill_stale(&file, bundled, &probe), None);
    }

    /// A file the child could write in its own directory is not where the daemon looks.
    #[test]
    fn a_forged_file_in_the_childs_directory_is_ignored() {
        let state = dir();
        let child_dir = state.join("tor");
        std::fs::create_dir_all(&child_dir).unwrap();
        std::fs::write(child_dir.join("child.pid"), render(1, "then")).unwrap();
        let file = path(&state, "tor");
        assert!(!file.starts_with(&child_dir));
        prepare_dir(&file).unwrap();
        let killed = RefCell::new(vec![]);
        let kill = |p| killed.borrow_mut().push(p);
        let start = |_| Some("then".to_string());
        let exe = |_| Some(PathBuf::from("/x/tor"));
        let probe = probe_for(&start, &exe, &kill);
        assert_eq!(kill_stale(&file, Path::new("/x/tor"), &probe), None);
        assert!(killed.borrow().is_empty());
    }

    #[test]
    fn the_file_name_is_made_of_safe_characters() {
        let p = path(Path::new("/var/lib/sg"), "../etc/x y");
        assert_eq!(p, Path::new("/var/lib/sg/run/___etc_x_y.pid"));
        assert_eq!(
            child_path(&path(Path::new("/s"), "ygg")),
            Path::new("/s").join("run").join("ygg.child")
        );
    }

    /// A pid file in a directory that others can write to, or behind a link, is not believed.
    #[cfg(unix)]
    #[test]
    fn an_open_directory_or_a_link_is_not_believed() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let file = path(&d, "x");
        prepare_dir(&file).unwrap();
        let start = |_| Some("then".to_string());
        let exe = |_| Some(PathBuf::from("/x/tor"));
        let killed = RefCell::new(vec![]);
        let kill = |p| killed.borrow_mut().push(p);
        let probe = probe_for(&start, &exe, &kill);
        let mode = |m| std::fs::Permissions::from_mode(m);

        std::fs::write(&file, render(42, "then")).unwrap();
        std::fs::set_permissions(file.parent().unwrap(), mode(0o777)).unwrap();
        assert_eq!(kill_stale(&file, Path::new("/x/tor"), &probe), None);

        std::fs::set_permissions(file.parent().unwrap(), mode(0o700)).unwrap();
        let real = d.join("real");
        std::fs::write(&real, render(42, "then")).unwrap();
        std::os::unix::fs::symlink(&real, &file).unwrap();
        assert_eq!(kill_stale(&file, Path::new("/x/tor"), &probe), None);
        assert!(killed.borrow().is_empty());
    }
}
