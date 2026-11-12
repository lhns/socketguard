//! A [`Spawner`] that starts no processes, for the supervisor's and the engine's tests (a
//! stand-in for the real one, like the other mocks in `test_support`). Tests see what was
//! started and make the "processes" print and end.

use super::*;
use std::io;

/// One fake process.
#[derive(Clone)]
pub struct FakeProc {
    pub spec: ChildSpec,
    pub pid: u32,
    exit: Arc<watch::Sender<Option<ExitInfo>>>,
    out: Arc<Mutex<Option<mpsc::Sender<Line>>>>,
    signals: Arc<Mutex<Vec<&'static str>>>,
    stubborn: bool,
}

impl FakeProc {
    /// The process prints `line`.
    pub fn print(&self, line: &str) {
        if let Some(out) = self.out.lock().unwrap().as_ref() {
            let _ = out.try_send(Line::stdout(line));
        }
    }

    /// The process ends on its own.
    pub fn exit(&self, how: &str) {
        // Its output ends with it; what it printed is still read.
        self.out.lock().unwrap().take();
        self.exit.send_replace(Some(ExitInfo {
            description: how.to_string(),
        }));
    }

    pub fn has_exited(&self) -> bool {
        self.exit.borrow().is_some()
    }

    /// "term" and "kill", in the order the supervisor sent them.
    pub fn signals(&self) -> Vec<&'static str> {
        self.signals.lock().unwrap().clone()
    }
}

impl ChildProc for FakeProc {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn wait(&self) -> BoxFuture<'_, ExitInfo> {
        let mut rx = self.exit.subscribe();
        Box::pin(async move {
            rx.wait_for(|v| v.is_some())
                .await
                .map(|v| v.clone().expect("Some"))
                .unwrap_or(ExitInfo {
                    description: "gone".into(),
                })
        })
    }

    fn terminate(&self) {
        self.signals.lock().unwrap().push("term");
        if !self.stubborn {
            self.exit("signal 15");
        }
    }

    fn kill(&self) {
        self.signals.lock().unwrap().push("kill");
        self.exit("signal 9");
    }
}

#[derive(Default)]
struct Inner {
    procs: Vec<FakeProc>,
    fail_next: Vec<String>,
    stubborn: bool,
}

/// Starts [`FakeProc`]s.
#[derive(Default, Clone)]
pub struct FakeSpawner(Arc<Mutex<Inner>>);

impl FakeSpawner {
    /// How many processes were started so far.
    pub fn started(&self) -> usize {
        self.0.lock().unwrap().procs.len()
    }

    /// The `n`th process started (from 0).
    pub fn proc(&self, n: usize) -> FakeProc {
        self.0.lock().unwrap().procs[n].clone()
    }

    pub fn last(&self) -> FakeProc {
        self.0
            .lock()
            .unwrap()
            .procs
            .last()
            .cloned()
            .expect("a process")
    }

    /// Processes that have not ended.
    pub fn running(&self) -> Vec<FakeProc> {
        self.0
            .lock()
            .unwrap()
            .procs
            .iter()
            .filter(|p| !p.has_exited())
            .cloned()
            .collect()
    }

    /// The next start fails with `why`.
    pub fn fail_next(&self, why: &str) {
        self.0.lock().unwrap().fail_next.push(why.to_string());
    }

    /// New processes ignore the polite stop and end only when killed.
    pub fn set_stubborn(&self, stubborn: bool) {
        self.0.lock().unwrap().stubborn = stubborn;
    }
}

impl Spawner for FakeSpawner {
    fn spawn<'a>(
        &'a self,
        spec: &'a ChildSpec,
        out: mpsc::Sender<Line>,
    ) -> BoxFuture<'a, io::Result<Box<dyn ChildProc>>> {
        Box::pin(async move {
            let mut inner = self.0.lock().unwrap();
            if !inner.fail_next.is_empty() {
                return Err(io::Error::other(inner.fail_next.remove(0)));
            }
            let proc = FakeProc {
                spec: spec.clone(),
                pid: 1000 + inner.procs.len() as u32,
                exit: Arc::new(watch::channel(None).0),
                out: Arc::new(Mutex::new(Some(out))),
                signals: Arc::default(),
                stubborn: inner.stubborn,
            };
            inner.procs.push(proc.clone());
            Ok(Box::new(proc) as Box<dyn ChildProc>)
        })
    }
}
