//! The real [`Spawner`]: starts the child with tokio, ties it to the daemon's life and
//! relays its output. Platform specifics are small and local: who it runs as, and how it
//! dies with the daemon.
//!
//! - Linux: `prctl(PR_SET_PDEATHSIG, SIGKILL)` in the child before `exec`. The signal fires
//!   when the *thread* that forked ends, so children are spawned from the runtime's worker
//!   threads (they live as long as the runtime), never from `spawn_blocking`.
//! - macOS: `child.pid` in the data directory (see `pidfile`); a leftover child is killed
//!   at the next start. (Untested on a real Mac.)
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
        out: mpsc::Sender<String>,
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
pub(super) fn pump<R: AsyncRead + Unpin + Send + 'static>(r: R, out: mpsc::Sender<String>) {
    tokio::spawn(async move {
        let mut r = BufReader::new(r);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            // A line without an end is cut after 8 KiB.
            match (&mut r).take(8192).read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf).trim_end().to_string();
                    if out.send(line).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

async fn spawn(spec: &ChildSpec, out: mpsc::Sender<String>) -> io::Result<Box<dyn ChildProc>> {
    #[cfg(windows)]
    if spec.run_as == RunAs::LocalService {
        return super::win::spawn_local_service(spec, out).await;
    }
    spawn_tokio(spec, out)
}

/// Start the child with tokio's `Command`, as the daemon's own account or (Unix, daemon
/// is root) as the unprivileged account.
fn spawn_tokio(spec: &ChildSpec, out: mpsc::Sender<String>) -> io::Result<Box<dyn ChildProc>> {
    #[cfg(target_os = "macos")]
    if let Some(pid) = pidfile::kill_stale(&spec.data_dir, &pidfile::process_start_time, &|p| {
        // SAFETY: plain signal; the pid and start time matched the file we wrote.
        unsafe {
            libc::kill(p as libc::pid_t, libc::SIGKILL);
        }
    }) {
        warn!(
            "Stopped a leftover {} (pid {pid}) of an earlier run",
            spec.name
        );
    }

    let mut cmd = tokio::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::null())
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
        unsafe {
            cmd.pre_exec(move || {
                #[cfg(target_os = "linux")]
                {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
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

    #[cfg(target_os = "macos")]
    if let Some(start) = pidfile::process_start_time(pid) {
        let _ = std::fs::write(pidfile::path(&spec.data_dir), pidfile::render(pid, &start));
    }

    if let Some(s) = child.stdout.take() {
        pump(s, out.clone());
    }
    if let Some(s) = child.stderr.take() {
        pump(s, out);
    }
    let target = Arc::new(Mutex::new(handle));
    let (exit_tx, exit_rx) = watch::channel(None);
    let reaped = target.clone();
    #[cfg(target_os = "macos")]
    let pid_file = pidfile::path(&spec.data_dir);
    tokio::spawn(async move {
        let info = match child.wait().await {
            Ok(st) => describe_exit(&st),
            Err(e) => ExitInfo {
                description: format!("wait failed: {e}"),
            },
        };
        *reaped.lock().unwrap() = None;
        #[cfg(target_os = "macos")]
        let _ = std::fs::remove_file(pid_file);
        let _ = exit_tx.send(Some(info));
    });
    Ok(Box::new(Proc::new(pid, exit_rx, None, target)))
}
