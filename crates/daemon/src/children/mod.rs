//! The child-process supervisor (ADR 0052): runs the programs SocketGuard ships (Tor, and
//! Yggdrasil) as children of the daemon.
//!
//! The engine only declares what it wants ([`Supervisor::set`]) and reads the outcome
//! ([`Supervisor::status`]); both return at once. Each child lives in its own task that
//! spawns it, waits for it, restarts it after a pause that doubles from one second to a
//! minute (and starts over after a minute of healthy running), relays its output to the log
//! at a bounded rate, and stops it when it is no longer wanted.
//!
//! Everything that touches the system is behind [`Spawner`] and [`ChildProc`], so the tests
//! drive the supervisor with a fake and with tokio's paused clock. The real spawner is in
//! `system`; children die with the daemon (Linux: parent-death signal; Windows: a job
//! object; macOS, and a child that changes its user id: a pid file that is checked at the
//! next start).

#[cfg(unix)]
pub mod guard;
#[cfg_attr(not(unix), allow(dead_code))]
mod pidfile;
mod rate;
mod system;
#[cfg(windows)]
mod win;

#[cfg(any(test, feature = "test-support"))]
pub mod fake;

pub use pidfile::RUN_DIR;
pub use system::SystemSpawner;
#[cfg(windows)]
pub(crate) use win::check_local_service_logon;

/// Where the pid file of the child `id` goes: `<state dir>/run/<id>.pid`.
pub fn pid_file(state_dir: &std::path::Path, id: &str) -> PathBuf {
    pidfile::path(state_dir, id)
}

use rate::{RateLimiter, Take};
use socketguard_core::ChildState;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Consecutive failed health checks (while the process lives) after which the failure is
/// logged at warn and shown as the child's detail.
pub const FAILURES_BEFORE_DETAIL: u32 = 5;
/// After that, the failure is logged again every this many checks.
const REPEAT_WARN_EVERY: u32 = 60;

/// One line a child printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub text: String,
    /// It came from the child's stderr (which a program uses for what is wrong).
    pub stderr: bool,
}

impl Line {
    pub fn stdout(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            stderr: false,
        }
    }

    pub fn stderr(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            stderr: true,
        }
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Who the child runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunAs {
    /// The daemon's own account; `note` says why it could not be an unprivileged one.
    Daemon { note: Option<String> },
    /// Unix: a dedicated unprivileged account.
    Account { name: String, uid: u32, gid: u32 },
    /// Unix: started as the daemon's account (root), and the program drops to the named
    /// account itself once it has what needs the privilege (Yggdrasil's `-user`).
    DropsTo { name: String },
    /// Windows: the LocalService account.
    LocalService,
    /// Windows, portable mode (ADR 0054): there is no installer and so no account for the
    /// child; it runs as the elevated account that runs the portable daemon. LocalService is
    /// never tried (the daemon is not SYSTEM, and a logon attempt would only fail).
    Portable,
}

impl RunAs {
    /// The account in words, for the network card.
    pub fn describe(&self) -> String {
        match self {
            RunAs::Daemon { note: None } => "the daemon's account".into(),
            RunAs::Daemon { note: Some(n) } => format!("the daemon's account ({n})"),
            RunAs::Account { name, .. } | RunAs::DropsTo { name } => name.clone(),
            RunAs::LocalService => "LocalService".into(),
            RunAs::Portable => "the account running portable SocketGuard".into(),
        }
    }
}

/// How a process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    /// "exit code 1", "signal 9".
    pub description: String,
}

/// A running child.
pub trait ChildProc: Send + Sync {
    fn pid(&self) -> Option<u32>;
    /// The account it really runs as, when that differs from what was asked (a fallback).
    fn runs_as(&self) -> Option<String> {
        None
    }
    /// Resolves when the process has ended (also when asked again after it ended).
    fn wait(&self) -> BoxFuture<'_, ExitInfo>;
    /// Ask it to end (SIGTERM; Windows has no gentle way and ends it at once).
    fn terminate(&self);
    /// End it now.
    fn kill(&self);
}

/// Starts processes. `out` receives every line the child prints (stdout and stderr).
pub trait Spawner: Send + Sync {
    fn spawn<'a>(
        &'a self,
        spec: &'a ChildSpec,
        out: mpsc::Sender<Line>,
    ) -> BoxFuture<'a, std::io::Result<Box<dyn ChildProc>>>;
}

/// What a health check found out about a running child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildHealth {
    /// Not answering yet, and nothing is wrong that could be named.
    Starting,
    /// The check itself failed: why it cannot tell. Normal in the first moments of a start;
    /// after [`FAILURES_BEFORE_DETAIL`] in a row it is shown as the child's detail.
    NotReady(String),
    /// Tor: percent bootstrapped.
    Bootstrapping(u8),
    /// Ready.
    Up,
}

/// Decides when a running child counts as `Up`. Blocking (the supervisor runs it on a
/// blocking thread, once per `probe_every` until it says `Up`, and gives up on it after
/// `Timing::probe_timeout`: a check cannot hold the supervisor).
pub trait HealthCheck: Send + Sync {
    fn check(&self) -> ChildHealth;
}

/// Runs before each start, on a blocking thread: write the generated configuration, prepare
/// the data directory. An error keeps the child from starting and is shown as its detail.
pub type BeforeStart = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

/// Runs when a process ended on its own: how long it ran and the last line it printed.
pub type OnExit = Arc<dyn Fn(Duration, Option<&str>) + Send + Sync>;

/// Runs when a running child is still not up at its start deadline. Returns whether the
/// next start will differ (it changed something): then the child is restarted; if not, the
/// child is left running and the deadline is not asked again.
pub type OnDeadline = Arc<dyn Fn() -> bool + Send + Sync>;

/// One child process to keep running.
#[derive(Clone)]
pub struct ChildSpec {
    /// Short name: the log prefix (`[tor]`) and the pid file's owner.
    pub name: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The only environment the child gets.
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    pub run_as: RunAs,
    /// The child's data directory.
    pub data_dir: PathBuf,
    /// Unix: where the daemon records the pid and start time of the process, to stop a
    /// leftover of an earlier run. In a directory only the daemon can write, never in
    /// `data_dir` (see `pidfile`). None: nothing is recorded.
    pub pid_file: Option<PathBuf>,
    /// Unix: start the program through `socketguard-daemon child-guard`, which ends it when
    /// the daemon dies (for a program that drops its privileges and with them the
    /// parent-death signal).
    pub guarded: bool,
    /// Output lines containing one of these (case-sensitive) are logged at debug instead of
    /// info, unless they are warnings or errors (`[warn]`, `[err]`) or come from stderr.
    pub quiet_patterns: Vec<String>,
    /// Without one the child counts as up as soon as it runs.
    pub health: Option<Arc<dyn HealthCheck>>,
    pub before_start: Option<BeforeStart>,
    pub on_exit: Option<OnExit>,
    /// A child that is alive but not up this long after its start is handed to
    /// `on_deadline`.
    pub start_deadline: Option<Duration>,
    pub on_deadline: Option<OnDeadline>,
    /// A child that is not up yet and whose bootstrap progress has not advanced for this long
    /// is restarted (Tor stalls mid-bootstrap now and then). It only covers the start: once
    /// the child has been up, losing its connectivity later never triggers it.
    pub stall_limit: Option<Duration>,
    /// What else makes this a different launch although the command line is the same (a
    /// generated configuration file): a changed tag restarts the child.
    pub config_tag: String,
}

impl ChildSpec {
    /// Whether both start the same process the same way (the callbacks do not count).
    pub fn same_launch(&self, other: &ChildSpec) -> bool {
        self.name == other.name
            && self.config_tag == other.config_tag
            && self.program == other.program
            && self.args == other.args
            && self.env == other.env
            && self.cwd == other.cwd
            && self.run_as == other.run_as
            && self.data_dir == other.data_dir
            && self.pid_file == other.pid_file
            && self.guarded == other.guarded
            && self.quiet_patterns == other.quiet_patterns
            && self.start_deadline == other.start_deadline
            && self.stall_limit == other.stall_limit
    }

    /// "Tor" for `tor`: how messages name the child.
    fn label(&self) -> String {
        let mut c = self.name.chars();
        match c.next() {
            Some(f) => f.to_uppercase().chain(c).collect(),
            None => String::new(),
        }
    }
}

impl std::fmt::Debug for ChildSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildSpec")
            .field("name", &self.name)
            .field("program", &self.program)
            .field("args", &self.args)
            .field("run_as", &self.run_as)
            .finish_non_exhaustive()
    }
}

/// What the engine wants of a child.
#[derive(Clone)]
pub enum Desired {
    /// Run it, and restart it when it ends.
    Run(Box<ChildSpec>),
    /// Not running on purpose.
    Stopped,
    /// Held back; the sentence says until what.
    Waiting(String),
    /// Cannot run in this build or on this system; the sentence says why.
    Unavailable(String),
}

impl Desired {
    fn same(&self, other: &Desired) -> bool {
        match (self, other) {
            (Desired::Run(a), Desired::Run(b)) => a.same_launch(b),
            (Desired::Stopped, Desired::Stopped) => true,
            (Desired::Waiting(a), Desired::Waiting(b)) => a == b,
            (Desired::Unavailable(a), Desired::Unavailable(b)) => a == b,
            _ => false,
        }
    }
}

/// How a child stands, readable at any time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildStatus {
    pub state: ChildState,
    /// Why it waits or is unavailable, or what an exited child printed last.
    pub detail: Option<String>,
    pub pid: Option<u32>,
    /// How often it ended on its own since it was last started on purpose.
    pub restarts: u32,
    pub runs_as: Option<String>,
    /// The last non-empty line it printed (of the last run).
    pub last_line: Option<String>,
    /// Tor: percent bootstrapped, while `Bootstrapping`.
    pub progress: Option<u8>,
}

impl Default for ChildStatus {
    fn default() -> Self {
        Self {
            state: ChildState::Stopped,
            detail: None,
            pid: None,
            restarts: 0,
            runs_as: None,
            last_line: None,
            progress: None,
        }
    }
}

impl ChildStatus {
    /// A process exists or is about to be restarted.
    pub fn alive(&self) -> bool {
        matches!(
            self.state,
            ChildState::Starting | ChildState::Bootstrapping | ChildState::Up | ChildState::Exited
        )
    }
}

/// A shared, cheaply readable [`ChildStatus`].
#[derive(Clone)]
pub struct StatusHandle(Arc<watch::Sender<ChildStatus>>);

impl Default for StatusHandle {
    fn default() -> Self {
        Self(Arc::new(watch::channel(ChildStatus::default()).0))
    }
}

impl StatusHandle {
    pub fn get(&self) -> ChildStatus {
        self.0.borrow().clone()
    }

    fn update(&self, f: impl FnOnce(&mut ChildStatus)) {
        self.0.send_modify(f);
    }

    fn subscribe(&self) -> watch::Receiver<ChildStatus> {
        self.0.subscribe()
    }
}

/// The pauses and limits of the supervisor; tests shrink them.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// A run at least this long starts the backoff over.
    pub healthy_after: Duration,
    pub probe_every: Duration,
    /// The longest one health check may take, connect to answer.
    pub probe_timeout: Duration,
    /// After a stop request: how long to wait for a graceful end before killing.
    pub stop_grace: Duration,
    /// Lines per second relayed to the log.
    pub lines_per_sec: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            healthy_after: Duration::from_secs(60),
            probe_every: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(20),
            stop_grace: Duration::from_secs(5),
            lines_per_sec: 20,
        }
    }
}

struct Slot {
    tx: watch::Sender<Desired>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct Inner {
    cells: HashMap<String, StatusHandle>,
    slots: HashMap<String, Slot>,
    closed: bool,
}

/// Keeps the children running that the engine asked for.
pub struct Supervisor {
    spawner: Arc<dyn Spawner>,
    timing: Timing,
    inner: Mutex<Inner>,
}

impl Supervisor {
    pub fn new(spawner: Arc<dyn Spawner>) -> Self {
        Self::with_timing(spawner, Timing::default())
    }

    pub fn with_timing(spawner: Arc<dyn Spawner>, timing: Timing) -> Self {
        Self {
            spawner,
            timing,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The real thing.
    pub fn system() -> Self {
        Self::new(Arc::new(SystemSpawner))
    }

    /// Declare the child `id`: `Some(spec)` runs it (a changed spec restarts it), `None`
    /// stops it. Returns at once; [`Supervisor::wait_stopped`] waits for a stop.
    pub fn set(&self, id: &str, spec: Option<ChildSpec>) {
        self.set_desired(
            id,
            spec.map_or(Desired::Stopped, |s| Desired::Run(Box::new(s))),
        );
    }

    /// [`Supervisor::set`] for the other wishes: held back, or unavailable.
    pub fn set_desired(&self, id: &str, desired: Desired) {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return;
        }
        if !inner.slots.contains_key(id) {
            // Nothing runs and nothing is asked: no task needed (the status shows the wish).
            if matches!(desired, Desired::Stopped) {
                return;
            }
            let Ok(rt) = tokio::runtime::Handle::try_current() else {
                warn!("Cannot supervise '{id}': no async runtime");
                return;
            };
            let cell = inner.cells.entry(id.to_string()).or_default().clone();
            let (tx, rx) = watch::channel(Desired::Stopped);
            let task = rt.spawn(supervise(rx, cell, self.spawner.clone(), self.timing));
            inner.slots.insert(id.to_string(), Slot { tx, task });
        }
        let cell = inner.cells[id].clone();
        let changed = inner.slots[id].tx.send_if_modified(|cur| {
            if cur.same(&desired) {
                false
            } else {
                *cur = desired.clone();
                true
            }
        });
        if changed {
            // The task catches up in a moment; what a reader sees meanwhile is already the
            // wish, not the state before it (a new network would read "turned off").
            cell.update(|s| {
                if s.alive() {
                    return;
                }
                let (state, detail) = match &desired {
                    Desired::Run(_) => (ChildState::Starting, None),
                    Desired::Stopped => (ChildState::Stopped, None),
                    Desired::Waiting(d) => (ChildState::Waiting, Some(d.clone())),
                    Desired::Unavailable(d) => (ChildState::Unavailable, Some(d.clone())),
                };
                s.state = state;
                s.detail = detail;
                if let Desired::Run(spec) = &desired {
                    s.runs_as = Some(spec.run_as.describe());
                }
            });
        }
    }

    /// The status of `id` (stopped when it was never declared).
    pub fn status(&self, id: &str) -> ChildStatus {
        self.handle(id).get()
    }

    /// A handle that reads the status of `id` for as long as it is held, also before the
    /// child is first declared. A network keeps one.
    pub fn handle(&self, id: &str) -> StatusHandle {
        self.inner
            .lock()
            .unwrap()
            .cells
            .entry(id.to_string())
            .or_default()
            .clone()
    }

    /// Wait until `id` has no process and nothing to restart (after `set(id, None)`).
    pub async fn wait_stopped(&self, id: &str) {
        let mut rx = self.handle(id).subscribe();
        let _ = rx.wait_for(|s| !s.alive()).await;
    }

    /// Stop `id`, wait for it, and drop everything kept for it.
    pub async fn remove(&self, id: &str) {
        self.set(id, None);
        self.wait_stopped(id).await;
        let mut inner = self.inner.lock().unwrap();
        inner.slots.remove(id);
        inner.cells.remove(id);
    }

    /// Stop every child (gracefully, then by force) and refuse new ones. The daemon's
    /// shutdown path.
    pub async fn shutdown(&self) {
        let ids: Vec<String> = {
            let mut inner = self.inner.lock().unwrap();
            inner.closed = true;
            for slot in inner.slots.values() {
                slot.tx.send_replace(Desired::Stopped);
            }
            inner.slots.keys().cloned().collect()
        };
        let limit = self.timing.stop_grace * 3 + Duration::from_secs(1);
        for id in ids {
            let waited = tokio::time::timeout(limit, self.wait_stopped(&id)).await;
            if waited.is_err() {
                warn!("Child '{id}' did not stop in time");
            }
        }
        let slots: Vec<Slot> = self
            .inner
            .lock()
            .unwrap()
            .slots
            .drain()
            .map(|(_, s)| s)
            .collect();
        for s in slots {
            s.task.abort();
        }
    }
}

struct Task {
    spawner: Arc<dyn Spawner>,
    timing: Timing,
    status: StatusHandle,
    rx: watch::Receiver<Desired>,
}

enum End {
    /// The wish changed; the process (if any) is stopped.
    Changed,
    Exited {
        ran_for: Duration,
    },
}

async fn supervise(
    rx: watch::Receiver<Desired>,
    status: StatusHandle,
    spawner: Arc<dyn Spawner>,
    timing: Timing,
) {
    let mut t = Task {
        spawner,
        timing,
        status,
        rx,
    };
    let mut backoff = timing.backoff_initial;
    loop {
        let desired = t.rx.borrow_and_update().clone();
        match desired {
            Desired::Run(spec) => match t.run_once(&spec).await {
                End::Changed => backoff = timing.backoff_initial,
                End::Exited { ran_for } => {
                    if ran_for >= timing.healthy_after {
                        backoff = timing.backoff_initial;
                    }
                    let pause = backoff;
                    backoff = (backoff * 2).min(timing.backoff_max);
                    tokio::select! {
                        _ = tokio::time::sleep(pause) => {}
                        r = t.rx.changed() => if r.is_err() { return },
                    }
                }
            },
            other => {
                backoff = timing.backoff_initial;
                let (state, detail) = match other {
                    Desired::Waiting(d) => (ChildState::Waiting, Some(d)),
                    Desired::Unavailable(d) => (ChildState::Unavailable, Some(d)),
                    _ => (ChildState::Stopped, None),
                };
                t.status.update(|s| {
                    s.state = state;
                    s.detail = detail;
                    s.pid = None;
                    s.progress = None;
                    s.restarts = 0;
                });
                if t.rx.changed().await.is_err() {
                    return;
                }
            }
        }
    }
}

impl Task {
    /// A start that did not happen counts as an exit.
    fn failed(&self, label: &str, why: String) -> End {
        warn!("{label}: {why}");
        self.status.update(|s| {
            s.state = ChildState::Exited;
            s.detail = Some(why);
            s.pid = None;
            s.progress = None;
            s.restarts += 1;
        });
        End::Exited {
            ran_for: Duration::ZERO,
        }
    }

    async fn run_once(&mut self, spec: &ChildSpec) -> End {
        let label = spec.label();
        self.status.update(|s| {
            s.state = ChildState::Starting;
            s.detail = None;
            s.pid = None;
            s.progress = None;
            s.last_line = None;
            s.runs_as = Some(spec.run_as.describe());
        });
        if let Some(prepare) = spec.before_start.clone() {
            match tokio::task::spawn_blocking(move || prepare()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    return self.failed(&label, format!("could not prepare {}: {e}", spec.name))
                }
                Err(e) => {
                    return self.failed(&label, format!("could not prepare {}: {e}", spec.name))
                }
            }
        }
        let (out, mut lines) = mpsc::channel::<Line>(256);
        let proc = match self.spawner.spawn(spec, out).await {
            Ok(p) => p,
            Err(e) => return self.failed(&label, format!("could not start {}: {e}", spec.name)),
        };
        let started = Instant::now();
        let mut up = spec.health.is_none();
        self.status.update(|s| {
            s.pid = proc.pid();
            if let Some(r) = proc.runs_as() {
                s.runs_as = Some(r);
            }
            if up {
                s.state = ChildState::Up;
            }
        });

        let exit = proc.wait();
        tokio::pin!(exit);
        let mut limiter = RateLimiter::new(self.timing.lines_per_sec, started);
        let mut last_line: Option<String> = None;
        let mut probe: Option<Pin<Box<dyn Future<Output = ChildHealth> + Send>>> = None;
        let mut failures = 0u32;
        let mut shown_detail = false;
        let mut tick = tokio::time::interval(self.timing.probe_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Not asked again once it declined to restart.
        let mut deadline = spec
            .start_deadline
            .filter(|_| !up && spec.on_deadline.is_some())
            .map(|d| started + d);
        // The highest bootstrap progress seen, and when the stall limit runs out unless it
        // advances.
        let mut best: Option<u8> = None;
        let mut stall_at = spec.stall_limit.filter(|_| !up).map(|l| started + l);

        loop {
            tokio::select! {
                info = &mut exit => {
                    // What it printed last is the reason; give the readers a moment.
                    while let Ok(Some(l)) =
                        tokio::time::timeout(Duration::from_millis(200), lines.recv()).await
                    {
                        relay(spec, &mut limiter, &mut last_line, l);
                    }
                    relay_flush(&spec.name, &mut limiter);
                    let detail = match &last_line {
                        Some(l) => format!("{label} exited: {l}"),
                        None => format!("{label} exited ({})", info.description),
                    };
                    warn!("{detail}");
                    let ran_for = started.elapsed();
                    if let Some(on_exit) = &spec.on_exit {
                        on_exit(ran_for, last_line.as_deref());
                    }
                    self.status.update(|s| {
                        s.state = ChildState::Exited;
                        s.detail = Some(detail);
                        s.pid = None;
                        s.progress = None;
                        s.restarts += 1;
                        s.last_line = last_line.clone();
                    });
                    return End::Exited { ran_for };
                }
                Some(l) = lines.recv() => relay(spec, &mut limiter, &mut last_line, l),
                _ = self.rx.changed() => {
                    stop(proc.as_ref(), &mut exit, self.timing.stop_grace).await;
                    relay_flush(&spec.name, &mut limiter);
                    return End::Changed;
                }
                _ = async { tokio::time::sleep_until(deadline.expect("guarded")).await },
                    if !up && deadline.is_some() =>
                {
                    deadline = None;
                    // It may ask the child over a socket: not on the runtime's threads.
                    let ask = spec.on_deadline.clone();
                    let restart = tokio::task::spawn_blocking(move || ask.is_some_and(|f| f()))
                        .await
                        .unwrap_or(false);
                    if restart {
                        let secs = spec.start_deadline.map_or(0, |d| d.as_secs());
                        warn!("{label} was not ready after {secs} s; restarting it");
                        stop(proc.as_ref(), &mut exit, self.timing.stop_grace).await;
                        relay_flush(&spec.name, &mut limiter);
                        let ran_for = started.elapsed();
                        self.status.update(|s| {
                            s.state = ChildState::Exited;
                            s.detail = Some(format!("{label} was not ready after {secs} s"));
                            s.pid = None;
                            s.progress = None;
                            s.restarts += 1;
                        });
                        return End::Exited { ran_for };
                    }
                }
                _ = async { tokio::time::sleep_until(stall_at.expect("guarded")).await },
                    if !up && stall_at.is_some() =>
                {
                    let minutes = spec.stall_limit.map_or(0, |l| l.as_secs() / 60);
                    let last = match best {
                        Some(p) => format!("last progress {p}%"),
                        None => "no progress reported".to_string(),
                    };
                    warn!(
                        "{label} made no bootstrap progress for {minutes} min ({last}); \
                         restarting it"
                    );
                    stop(proc.as_ref(), &mut exit, self.timing.stop_grace).await;
                    relay_flush(&spec.name, &mut limiter);
                    let ran_for = started.elapsed();
                    self.status.update(|s| {
                        s.state = ChildState::Exited;
                        s.detail = Some(format!(
                            "{label} made no bootstrap progress for {minutes} min ({last})"
                        ));
                        s.pid = None;
                        s.progress = None;
                        s.restarts += 1;
                    });
                    return End::Exited { ran_for };
                }
                _ = tick.tick(), if !up && probe.is_none() => {
                    if let Some(h) = spec.health.clone() {
                        probe = Some(bounded_probe(h, self.timing.probe_timeout));
                    }
                }
                res = async { probe.as_mut().expect("guarded").await }, if probe.is_some() => {
                    probe = None;
                    if let ChildHealth::NotReady(why) = &res {
                        failures += 1;
                        if failures < FAILURES_BEFORE_DETAIL {
                            debug!("{label}: health check failed ({failures}): {why}");
                        } else {
                            if (failures - FAILURES_BEFORE_DETAIL).is_multiple_of(REPEAT_WARN_EVERY) {
                                warn!(
                                    "{label} is running but its health check has failed \
                                     {failures} times in a row: {why}"
                                );
                            }
                            shown_detail = true;
                            self.status.update(|s| s.detail = Some(why.clone()));
                        }
                        continue;
                    }
                    if failures >= FAILURES_BEFORE_DETAIL {
                        info!("{label}: the health check works again (after {failures} failures)");
                    }
                    failures = 0;
                    if std::mem::take(&mut shown_detail) {
                        self.status.update(|s| s.detail = None);
                    }
                    match res {
                        ChildHealth::Up => {
                            up = true;
                            self.status.update(|s| {
                                s.state = ChildState::Up;
                                s.progress = None;
                            });
                        }
                        ChildHealth::Bootstrapping(p) => {
                            if best.is_none_or(|b| p > b) {
                                best = Some(p);
                                stall_at = spec.stall_limit.map(|l| Instant::now() + l);
                            }
                            self.status.update(|s| {
                                s.state = ChildState::Bootstrapping;
                                s.progress = Some(p);
                            });
                        }
                        ChildHealth::Starting | ChildHealth::NotReady(_) => {}
                    }
                }
            }
        }
    }
}

/// One health check on a blocking thread, ended after `limit` whatever it is doing (the
/// thread is left to give up on its own socket timeouts). The one place that bounds a probe.
fn bounded_probe(
    check: Arc<dyn HealthCheck>,
    limit: Duration,
) -> Pin<Box<dyn Future<Output = ChildHealth> + Send>> {
    Box::pin(async move {
        let run = tokio::task::spawn_blocking(move || check.check());
        match tokio::time::timeout(limit, run).await {
            Ok(Ok(health)) => health,
            Ok(Err(e)) => ChildHealth::NotReady(format!("the health check failed: {e}")),
            Err(_) => {
                ChildHealth::NotReady(format!("the health check did not answer within {limit:?}"))
            }
        }
    })
}

/// End the process: ask, wait `grace`, then force.
async fn stop(
    proc: &dyn ChildProc,
    exit: &mut (impl Future<Output = ExitInfo> + Unpin),
    grace: Duration,
) {
    proc.terminate();
    if tokio::time::timeout(grace, &mut *exit).await.is_err() {
        proc.kill();
        let _ = tokio::time::timeout(grace, &mut *exit).await;
    }
}

/// Whether a line is routine noise for the log: it matches one of the spec's quiet patterns
/// and is neither a warning or error line (`[warn]`, `[err]`) nor from stderr.
fn is_quiet(spec: &ChildSpec, line: &Line) -> bool {
    !line.stderr
        && !line.text.contains("[warn]")
        && !line.text.contains("[err]")
        && spec.quiet_patterns.iter().any(|p| line.text.contains(p))
}

fn relay(spec: &ChildSpec, limiter: &mut RateLimiter, last: &mut Option<String>, line: Line) {
    let name = spec.name.as_str();
    let text = line.text.trim_end();
    if text.trim().is_empty() {
        return;
    }
    if is_quiet(spec, &line) {
        // Neither counted against the rate limit nor taken for the reason it exited.
        debug!("[{name}] {text}");
        return;
    }
    let line = text;
    *last = Some(line.to_string());
    match limiter.take(Instant::now()) {
        Take::Pass { dropped } => {
            if dropped > 0 {
                warn!("[{name}] {dropped} lines were dropped (too much output)");
            }
            if line.contains("[err]") {
                tracing::error!("[{name}] {line}");
            } else if line.contains("[warn]") {
                warn!("[{name}] {line}");
            } else {
                info!("[{name}] {line}");
            }
        }
        Take::Drop => {}
    }
}

/// Report lines dropped at the end of a burst.
fn relay_flush(name: &str, limiter: &mut RateLimiter) {
    let dropped = limiter.take_dropped();
    if dropped > 0 {
        warn!("[{name}] {dropped} lines were dropped (too much output)");
    }
}

#[cfg(test)]
mod tests;
