//! The real [`Spawner`]: starts the child with tokio, ties it to the daemon's life and
//! relays its output. Platform specifics are small and local: who it runs as, and how it
//! dies with the daemon.
//!
//! - Linux: `prctl(PR_SET_PDEATHSIG, SIGKILL)` in the child before `exec`. The signal fires
//!   when the *thread* that forked ends, so children are spawned from the runtime's worker
//!   threads (they live as long as the runtime), never from `spawn_blocking`.
//! - Unix: a pid file in `<state dir>/run/` (see `pidfile`); a leftover child is killed
//!   at the next start. macOS has no parent-death signal at all, and on Linux the signal is
//!   lost when a child changes its user id (Yggdrasil's `-user`): such a child is started
//!   through `child-guard` (see `guard`), which ends it when the daemon's pipe closes.
//!   (Untested on a real Mac.)
//! - Windows: a job object with `KILL_ON_JOB_CLOSE` (see `windows`).

use super::*;
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

/// Starts real processes.
pub struct SystemSpawner;

impl Spawner for SystemSpawner {
    fn spawn<'a>(
        &'a self,
        spec: &'a ChildSpec,
        out: mpsc::Sender<Line>,
    ) -> BoxFuture<'a, io::Result<Box<dyn ChildProc>>> {
        Box::pin(async move { spawn(spec, out).await })
    }
}

/// A started process, as the supervisor sees it.
pub(super) struct Proc {
    pid: u32,
    exit: watch::Receiver<Option<ExitInfo>>,
    runs_as: Option<String>,
    /// What to signal: the pid on Unix, the process handle on Windows. None once the
    /// process was reaped, so a reused pid or handle is never touched.
    target: Arc<Mutex<Option<usize>>>,
}

impl Proc {
    pub(super) fn new(
        pid: u32,
        exit: watch::Receiver<Option<ExitInfo>>,
        runs_as: Option<String>,
        target: Arc<Mutex<Option<usize>>>,
    ) -> Self {
        Self {
            pid,
            exit,
            runs_as,
            target,
        }
    }

    fn signal(&self, hard: bool) {
        let guard = self.target.lock().unwrap();
        let Some(t) = *guard else { return };
        #[cfg(unix)]
        {
            let sig = if hard { libc::SIGKILL } else { libc::SIGTERM };
            // SAFETY: plain signal to a child we started and have not reaped (`target` is
            // cleared under this lock before the pid can be reused).
            unsafe {
                libc::kill(t as libc::pid_t, sig);
            }
        }
        #[cfg(windows)]
        {
            let _ = hard;
            super::win::terminate(t);
        }
        #[cfg(not(any(unix, windows)))]
        let _ = (t, hard);
    }
}

impl ChildProc for Proc {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn runs_as(&self) -> Option<String> {
        self.runs_as.clone()
    }

    fn wait(&self) -> BoxFuture<'_, ExitInfo> {
        let mut rx = self.exit.clone();
        Box::pin(async move {
            match rx.wait_for(|v| v.is_some()).await {
                Ok(v) => v.clone().expect("waited for Some"),
                Err(_) => ExitInfo {
                    description: "lost track of the process".into(),
                },
            }
        })
    }

    fn terminate(&self) {
        self.signal(false);
    }

    fn kill(&self) {
        self.signal(true);
    }
}

pub(super) fn describe_exit(status: &std::process::ExitStatus) -> ExitInfo {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return ExitInfo {
                description: format!("signal {sig}"),
            };
        }
    }
    ExitInfo {
        description: match status.code() {
            Some(c) => format!("exit code {c}"),
            None => "ended".into(),
        },
    }
}

/// Forward the lines of `r` to `out` until it ends.
pub(super) fn pump<R: AsyncRead + Unpin + Send + 'static>(
    r: R,
    out: mpsc::Sender<Line>,
    stderr: bool,
) {
    tokio::spawn(async move {
        let mut r = BufReader::new(r);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            // A line without an end is cut after 8 KiB.
            match (&mut r).take(8192).read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let text = String::from_utf8_lossy(&buf).trim_end().to_string();
                    let line = Line { text, stderr };
                    if out.send(line).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

async fn spawn(spec: &ChildSpec, out: mpsc::Sender<Line>) -> io::Result<Box<dyn ChildProc>> {
    #[cfg(windows)]
    if spec.run_as == RunAs::LocalService {
        return super::win::spawn_local_service(spec, out).await;
    }
    spawn_tokio(spec, out)
}

/// Start the child with tokio's `Command`, as the daemon's own account or (Unix, daemon
/// is root) as the unprivileged account.
fn spawn_tokio(spec: &ChildSpec, out: mpsc::Sender<Line>) -> io::Result<Box<dyn ChildProc>> {
    // What the process we start really is: the program, or (guarded) the daemon itself.
    #[cfg(unix)]
    let (program, args) = if spec.guarded {
        let me = std::env::current_exe()?;
        let mut a = vec!["child-guard".to_string()];
        if let Some(file) = &spec.pid_file {
            // The guard records the program it starts, to be found should only it die.
            a.push("--pid-file".into());
            a.push(pidfile::child_path(file).display().to_string());
        }
        a.push("--".into());
        a.push(spec.program.display().to_string());
        a.extend(spec.args.iter().cloned());
        (me, a)
    } else {
        (spec.program.clone(), spec.args.clone())
    };
    #[cfg(not(unix))]
    let (program, args) = (spec.program.clone(), spec.args.clone());

    #[cfg(unix)]
    if let Some(file) = &spec.pid_file {
        if let Err(e) = pidfile::prepare_dir(file) {
            warn!("Cannot keep the pid file of {}: {e}", spec.name);
        }
        let probe = pidfile::Probe {
            start_of: &pidfile::process_start_time,
            exe_of: &pidfile::process_exe,
            kill: &|p| {
                // SAFETY: plain signal; pid, start time and executable matched the file the
                // daemon wrote.
                unsafe {
                    libc::kill(p as libc::pid_t, libc::SIGKILL);
                }
            },
        };
        if let Some(pid) = pidfile::kill_stale(file, &program, &probe) {
            warn!(
                "Stopped a leftover {} (pid {pid}) of an earlier run",
                spec.name
            );
        }
        if spec.guarded {
            // The program the guard started.
            let child_file = pidfile::child_path(file);
            if let Some(pid) = pidfile::kill_stale(&child_file, &spec.program, &probe) {
                warn!(
                    "Stopped a leftover {} (pid {pid}) of an earlier run",
                    spec.name
                );
            }
        }
    }

    let mut cmd = tokio::process::Command::new(&program);
    cmd.args(&args)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        // The guard ends the program when this pipe closes, which it does with the daemon.
        .stdin(if spec.guarded {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }
    #[cfg(windows)]
    {
        // No console window, and the system variables Windows programs need.
        cmd.creation_flags(0x0800_0000);
        for var in ["SystemRoot", "windir", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(var) {
                cmd.env(var, v);
            }
        }
    }
    #[cfg(unix)]
    {
        if let RunAs::Account { uid, gid, .. } = &spec.run_as {
            cmd.uid(*uid).gid(*gid);
        }
        // SAFETY: the closure only calls async-signal-safe functions (prctl, getppid,
        // setsid, _exit).
        #[cfg(target_os = "linux")]
        let parent = std::process::id() as libc::pid_t;
        // The guard must get to end its program: SIGTERM, not SIGKILL.
        #[cfg(target_os = "linux")]
        let death_signal = if spec.guarded {
            libc::SIGTERM
        } else {
            libc::SIGKILL
        };
        unsafe {
            cmd.pre_exec(move || {
                #[cfg(target_os = "linux")]
                {
                    libc::prctl(libc::PR_SET_PDEATHSIG, death_signal);
                    // The daemon may have died between fork and here.
                    if libc::getppid() != parent {
                        libc::_exit(1);
                    }
                }
                // Its own session: a Ctrl+C at the daemon's terminal does not reach it.
                libc::setsid();
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn()?;
    let pid = child.id().unwrap_or(0);
    #[cfg(windows)]
    let handle = child.raw_handle().map(|h| h as usize);
    #[cfg(windows)]
    if let Some(h) = handle {
        super::win::assign_to_job(h);
    }
    #[cfg(unix)]
    let handle = Some(pid as usize);

    #[cfg(unix)]
    if let (Some(file), Some(start)) = (&spec.pid_file, pidfile::process_start_time(pid)) {
        pidfile::write(file, pid, &start);
    }
    // Held until the process ends: its closing is the guard's signal that the daemon is gone.
    #[cfg(unix)]
    let guard_pipe = child.stdin.take();

    if let Some(s) = child.stdout.take() {
        pump(s, out.clone(), false);
    }
    if let Some(s) = child.stderr.take() {
        pump(s, out, true);
    }
    let target = Arc::new(Mutex::new(handle));
    let (exit_tx, exit_rx) = watch::channel(None);
    let reaped = target.clone();
    #[cfg(unix)]
    let pid_file = spec.pid_file.clone();
    tokio::spawn(async move {
        let info = match child.wait().await {
            Ok(st) => describe_exit(&st),
            Err(e) => ExitInfo {
                description: format!("wait failed: {e}"),
            },
        };
        *reaped.lock().unwrap() = None;
        #[cfg(unix)]
        {
            drop(guard_pipe);
            if let Some(f) = pid_file {
                let _ = std::fs::remove_file(pidfile::child_path(&f));
                let _ = std::fs::remove_file(f);
            }
        }
        let _ = exit_tx.send(Some(info));
    });
    Ok(Box::new(Proc::new(pid, exit_rx, None, target)))
}
