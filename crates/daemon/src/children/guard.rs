//! `socketguard-daemon child-guard -- <program> <args...>` (Unix): the parent of a child
//! that drops its privileges, which clears the parent-death signal (Yggdrasil's `-user`).
//!
//! The daemon starts the guard (with the parent-death signal set to SIGTERM, since the guard
//! never drops privileges) and keeps the write end of the guard's stdin open. The guard
//! starts the real program and ends it when stdin closes (the daemon is gone, however it
//! went) or when its own parent changes, passes SIGTERM on, and exits with the program's
//! status. It reads nothing from stdin and prints nothing itself except a failure to start.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

/// How long the program gets to end after SIGTERM before it is killed.
const GRACE: Duration = Duration::from_secs(5);

static CHILD: AtomicI32 = AtomicI32::new(0);
static TERMINATED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: libc::c_int) {
    TERMINATED.store(true, Ordering::SeqCst);
    let pid = CHILD.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill is async-signal-safe.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

/// SIGTERM the program, and SIGKILL it if it is still there after [`GRACE`].
fn end_child(pid: i32) {
    // SAFETY: plain signals to our own child; the guard exits as soon as it is reaped, which
    // ends this thread before a reused pid could be hit.
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    std::thread::sleep(GRACE);
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

/// Run `program args...` until it ends; returns the exit code for the guard.
pub fn run(pid_file: Option<&std::path::Path>, program: &str, args: &[String]) -> i32 {
    // SAFETY: getppid has no preconditions.
    let parent = unsafe { libc::getppid() };
    // SAFETY: the handler only touches atomics and calls kill.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            on_term as extern "C" fn(libc::c_int) as usize,
        );
    }
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot start {program}: {e}");
            return 127;
        }
    };
    let pid = child.id() as i32;
    CHILD.store(pid, Ordering::SeqCst);
    // For the next start of the daemon, should only the guard be killed.
    if let (Some(f), Some(start)) = (pid_file, super::pidfile::process_start_time(pid as u32)) {
        super::pidfile::write(f, pid as u32, &start);
    }
    if TERMINATED.load(Ordering::SeqCst) {
        // SIGTERM came before the pid was known.
        // SAFETY: plain signal to our own child.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }

    // The daemon holds the write end of our stdin: EOF means it is gone.
    std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        loop {
            match std::io::Read::read(&mut std::io::stdin(), &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        end_child(pid);
    });
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        // SAFETY: as above.
        if unsafe { libc::getppid() } != parent {
            end_child(pid);
            return;
        }
    });

    let code = match child.wait() {
        Ok(status) => exit_code(&status),
        Err(_) => 1,
    };
    if let Some(f) = pid_file {
        let _ = std::fs::remove_file(f);
    }
    code
}

/// The code a shell would report: the exit code, or 128 plus the signal.
pub(super) fn exit_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn the_exit_code_is_the_childs_or_128_plus_the_signal() {
        assert_eq!(exit_code(&ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(&ExitStatus::from_raw(9)), 137);
        assert_eq!(exit_code(&ExitStatus::from_raw(0)), 0);
    }
}
