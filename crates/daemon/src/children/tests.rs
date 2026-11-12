use super::fake::FakeSpawner;
use super::*;
use std::collections::VecDeque;

fn spec(args: &[&str]) -> ChildSpec {
    ChildSpec {
        name: "tor".into(),
        program: "/opt/tor".into(),
        args: args.iter().map(|a| a.to_string()).collect(),
        env: vec![],
        cwd: None,
        run_as: RunAs::Daemon { note: None },
        data_dir: "/tmp/tor".into(),
        pid_file: None,
        guarded: false,
        quiet_patterns: vec![],
        health: None,
        before_start: None,
        on_exit: None,
        start_deadline: None,
        on_deadline: None,
        stall_limit: None,
        config_tag: String::new(),
    }
}

fn supervisor() -> (Supervisor, FakeSpawner) {
    let fake = FakeSpawner::default();
    (Supervisor::new(Arc::new(fake.clone())), fake)
}

/// Let the tasks run, and move the paused clock on by `by`.
async fn pass(by: Duration) {
    tokio::time::sleep(by).await;
}

const TICK: Duration = Duration::from_millis(1);

#[tokio::test(start_paused = true)]
async fn a_declared_child_starts_and_is_up() {
    let (sup, fake) = supervisor();
    assert_eq!(sup.status("t").state, ChildState::Stopped);
    sup.set("t", Some(spec(&["-f", "x"])));
    pass(TICK).await;
    assert_eq!(fake.started(), 1);
    assert_eq!(fake.last().spec.args, ["-f", "x"]);
    let s = sup.status("t");
    assert_eq!(s.state, ChildState::Up);
    assert_eq!(s.pid, Some(1000));
    assert_eq!(s.runs_as.as_deref(), Some("the daemon's account"));
    assert_eq!(s.restarts, 0);
}

#[tokio::test(start_paused = true)]
async fn an_exited_child_is_restarted_with_a_doubling_pause() {
    let (sup, fake) = supervisor();
    sup.set("t", Some(spec(&[])));
    pass(TICK).await;

    fake.proc(0).print("[notice] bootstrapped 5%");
    fake.proc(0).print("[err] cannot open the data directory");
    fake.proc(0).print("");
    fake.proc(0).exit("exit code 1");
    pass(TICK).await;
    let s = sup.status("t");
    assert_eq!(s.state, ChildState::Exited);
    assert_eq!(
        s.detail.as_deref(),
        Some("Tor exited: [err] cannot open the data directory")
    );
    assert_eq!((s.restarts, s.pid), (1, None));
    assert_eq!(fake.started(), 1, "it waits first");

    pass(Duration::from_millis(990)).await;
    assert_eq!(fake.started(), 1);
    pass(Duration::from_millis(20)).await;
    assert_eq!(fake.started(), 2, "restarted after 1 s");
    assert_eq!(sup.status("t").state, ChildState::Up);

    // Silent this time: the detail falls back to how it ended.
    fake.proc(1).exit("exit code 2");
    pass(TICK).await;
    assert_eq!(
        sup.status("t").detail.as_deref(),
        Some("Tor exited (exit code 2)")
    );
    pass(Duration::from_millis(1990)).await;
    assert_eq!(fake.started(), 2, "the second pause is 2 s");
    pass(Duration::from_millis(20)).await;
    assert_eq!(fake.started(), 3);
}

#[tokio::test(start_paused = true)]
async fn the_pause_is_capped_and_starts_over_after_a_healthy_run() {
    let (sup, fake) = supervisor();
    sup.set("t", Some(spec(&[])));
    pass(TICK).await;
    // 1, 2, 4, 8, 16, 32, 60, 60 s.
    let mut waits = vec![];
    for n in 0..8 {
        fake.proc(n).exit("x");
        let before = tokio::time::Instant::now();
        while fake.started() == n + 1 {
            pass(Duration::from_millis(500)).await;
        }
        waits.push(before.elapsed().as_secs());
    }
    assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60]);

    // A run of a minute is healthy: the next pause is 1 s again.
    pass(Duration::from_secs(61)).await;
    fake.proc(8).exit("x");
    pass(Duration::from_millis(1100)).await;
    assert_eq!(fake.started(), 10);
}

#[tokio::test(start_paused = true)]
async fn removing_the_wish_stops_the_child_and_waits_for_it() {
    let (sup, fake) = supervisor();
    sup.set("t", Some(spec(&[])));
    pass(TICK).await;
    sup.set("t", None);
    sup.wait_stopped("t").await;
    assert_eq!(fake.proc(0).signals(), ["term"]);
    let s = sup.status("t");
    assert_eq!((s.state, s.pid), (ChildState::Stopped, None));
    pass(Duration::from_secs(120)).await;
    assert_eq!(fake.started(), 1, "a stopped child is not restarted");

    // Wanted again.
    sup.set("t", Some(spec(&[])));
    pass(TICK).await;
    assert_eq!(fake.started(), 2);
    assert_eq!(sup.status("t").state, ChildState::Up);
}

#[tokio::test(start_paused = true)]
async fn a_child_that_ignores_the_polite_stop_is_killed() {
    let (sup, fake) = supervisor();
    fake.set_stubborn(true);
    sup.set("t", Some(spec(&[])));
    pass(TICK).await;
    sup.set("t", None);
    sup.wait_stopped("t").await;
    assert_eq!(fake.proc(0).signals(), ["term", "kill"]);
    assert!(fake.running().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_changed_spec_restarts_and_an_unchanged_one_does_not() {
    let (sup, fake) = supervisor();
    sup.set("t", Some(spec(&["a"])));
    pass(TICK).await;
    sup.set("t", Some(spec(&["a"])));
    pass(TICK).await;
    assert_eq!(fake.started(), 1);

    sup.set("t", Some(spec(&["b"])));
    pass(TICK).await;
    assert_eq!(fake.started(), 2);
    assert_eq!(fake.proc(0).signals(), ["term"]);
    assert_eq!(fake.proc(1).spec.args, ["b"]);
    assert_eq!(fake.running().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn waiting_and_unavailable_children_do_not_run_and_say_why() {
    let (sup, fake) = supervisor();
    sup.set_desired("t", Desired::Waiting("the block is not in force".into()));
    pass(TICK).await;
    let s = sup.status("t");
    assert_eq!(s.state, ChildState::Waiting);
    assert_eq!(s.detail.as_deref(), Some("the block is not in force"));

    sup.set_desired("t", Desired::Unavailable("not part of this build".into()));
    pass(TICK).await;
    assert_eq!(sup.status("t").state, ChildState::Unavailable);

    sup.set_desired("t", Desired::Run(Box::new(spec(&[]))));
    pass(TICK).await;
    assert_eq!(sup.status("t").state, ChildState::Up);
    assert_eq!(sup.status("t").detail, None);

    // Held back again: the running child is stopped.
    sup.set_desired("t", Desired::Waiting("later".into()));
    sup.wait_stopped("t").await;
    pass(TICK).await;
    assert_eq!(sup.status("t").state, ChildState::Waiting);
    assert!(fake.running().is_empty());
    assert_eq!(fake.started(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_start_that_fails_is_retried_like_an_exit() {
    let (sup, fake) = supervisor();
    fake.fail_next("no such file");
    sup.set("t", Some(spec(&[])));
    pass(TICK).await;
    let s = sup.status("t");
    assert_eq!(s.state, ChildState::Exited);
    assert_eq!(
        s.detail.as_deref(),
        Some("could not start tor: no such file")
    );
    assert_eq!(s.restarts, 1);
    pass(Duration::from_millis(1100)).await;
    assert_eq!(sup.status("t").state, ChildState::Up);
}

#[tokio::test(start_paused = true)]
async fn before_start_runs_on_every_start_and_can_refuse() {
    let (sup, fake) = supervisor();
    let calls = Arc::new(Mutex::new(0u32));
    let c = calls.clone();
    let mut s = spec(&[]);
    s.before_start = Some(Arc::new(move || {
        let mut n = c.lock().unwrap();
        *n += 1;
        if *n == 1 {
            Err("disk full".into())
        } else {
            Ok(())
        }
    }));
    sup.set("t", Some(s));
    pass(TICK).await;
    assert_eq!(fake.started(), 0);
    assert_eq!(
        sup.status("t").detail.as_deref(),
        Some("could not prepare tor: disk full")
    );
    pass(Duration::from_millis(1100)).await;
    assert_eq!(fake.started(), 1);
    fake.proc(0).exit("x");
    pass(Duration::from_millis(2100)).await;
    assert_eq!(*calls.lock().unwrap(), 3);
    assert_eq!(fake.started(), 2);
}

struct Scripted(Mutex<VecDeque<ChildHealth>>);

impl HealthCheck for Scripted {
    fn check(&self) -> ChildHealth {
        let mut q = self.0.lock().unwrap();
        if q.len() > 1 {
            q.pop_front().unwrap()
        } else {
            q.front().cloned().unwrap_or(ChildHealth::Starting)
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_checked_child_goes_through_starting_and_bootstrapping_to_up() {
    let (sup, _fake) = supervisor();
    let mut s = spec(&[]);
    s.health = Some(Arc::new(Scripted(Mutex::new(
        [
            ChildHealth::Starting,
            ChildHealth::Bootstrapping(10),
            ChildHealth::Bootstrapping(60),
            ChildHealth::Up,
        ]
        .into(),
    ))));
    sup.set("t", Some(s));
    pass(TICK).await;
    assert_eq!(sup.status("t").state, ChildState::Starting);

    let mut seen = vec![];
    for _ in 0..8 {
        pass(Duration::from_millis(1000)).await;
        let st = sup.status("t");
        if seen.last() != Some(&(st.state, st.progress)) {
            seen.push((st.state, st.progress));
        }
    }
    assert_eq!(
        seen,
        [
            (ChildState::Bootstrapping, Some(10)),
            (ChildState::Bootstrapping, Some(60)),
            (ChildState::Up, None),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_stops_every_child_and_refuses_new_ones() {
    let (sup, fake) = supervisor();
    sup.set("a", Some(spec(&[])));
    sup.set("b", Some(spec(&[])));
    pass(TICK).await;
    assert_eq!(fake.running().len(), 2);
    sup.shutdown().await;
    assert!(fake.running().is_empty());
    assert_eq!(sup.status("a").state, ChildState::Stopped);
    sup.set("a", Some(spec(&[])));
    pass(Duration::from_secs(5)).await;
    assert_eq!(fake.started(), 2, "nothing starts after shutdown");
}

#[tokio::test(start_paused = true)]
async fn a_network_can_hold_the_status_before_the_child_is_declared() {
    let (sup, _fake) = supervisor();
    let handle = sup.handle("t");
    assert_eq!(handle.get().state, ChildState::Stopped);
    sup.set("t", Some(spec(&[])));
    pass(TICK).await;
    assert_eq!(handle.get().state, ChildState::Up, "the same cell");
    sup.remove("t").await;
    assert_eq!(handle.get().state, ChildState::Stopped);
}

#[test]
fn routine_lines_are_quiet_unless_they_are_warnings_errors_or_stderr() {
    let mut s = spec(&[]);
    s.quiet_patterns = vec!["New control connection opened".into()];
    let quiet = |l: Line| is_quiet(&s, &l);
    assert!(quiet(Line::stdout(
        "Nov 12 [notice] New control connection opened."
    )));
    assert!(!quiet(Line::stdout("Nov 12 [notice] Bootstrapped 5%")));
    assert!(!quiet(Line::stdout(
        "[warn] New control connection opened from a stranger"
    )));
    assert!(!quiet(Line::stdout("[err] New control connection opened")));
    assert!(!quiet(Line::stderr("New control connection opened")));
    // Without patterns nothing is quiet.
    s.quiet_patterns.clear();
    assert!(!is_quiet(
        &s,
        &Line::stdout("New control connection opened")
    ));
}

#[tokio::test(start_paused = true)]
async fn a_quiet_line_is_not_taken_for_the_reason_it_exited() {
    let (sup, fake) = supervisor();
    let mut s = spec(&[]);
    s.quiet_patterns = vec!["New control connection opened".into()];
    sup.set("t", Some(s));
    pass(TICK).await;
    fake.proc(0).print("[err] cannot bind");
    for _ in 0..100 {
        fake.proc(0)
            .print("[notice] New control connection opened.");
    }
    fake.proc(0).exit("exit code 1");
    pass(TICK).await;
    assert_eq!(
        sup.status("t").detail.as_deref(),
        Some("Tor exited: [err] cannot bind")
    );
}

/// A check stuck on a socket: it waits until the test drops the sender (or two real
/// seconds pass, so no thread outlives the test).
struct Hanging(Mutex<std::sync::mpsc::Receiver<()>>);

impl HealthCheck for Hanging {
    fn check(&self) -> ChildHealth {
        let _ = self
            .0
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(2));
        ChildHealth::Up
    }
}

#[tokio::test(start_paused = true)]
async fn failing_checks_are_named_after_a_few_and_cleared_when_they_work_again() {
    let (sup, _fake) = supervisor();
    let mut s = spec(&[]);
    let mut steps: Vec<ChildHealth> = (0..6)
        .map(|_| ChildHealth::NotReady("cannot ask Tor over its control port: refused".into()))
        .collect();
    steps.extend([ChildHealth::Bootstrapping(30), ChildHealth::Up]);
    s.health = Some(Arc::new(Scripted(Mutex::new(steps.into()))));
    sup.set("t", Some(s));
    pass(TICK).await;

    // The first check runs at once: four failures by 3 s, only the log (at debug) knows.
    pass(Duration::from_millis(3100)).await;
    assert_eq!(sup.status("t").detail, None);
    assert_eq!(sup.status("t").state, ChildState::Starting);

    // The fifth in a row is shown.
    pass(Duration::from_millis(1000)).await;
    assert_eq!(
        sup.status("t").detail.as_deref(),
        Some("cannot ask Tor over its control port: refused")
    );
    assert_eq!(sup.status("t").state, ChildState::Starting);

    // It works again: the detail goes.
    pass(Duration::from_millis(2000)).await;
    let st = sup.status("t");
    assert_eq!(st.detail, None);
    assert_eq!(st.state, ChildState::Bootstrapping);
    assert_eq!(st.progress, Some(30));
    pass(Duration::from_millis(1000)).await;
    assert_eq!(sup.status("t").state, ChildState::Up);
}

/// Real time: the paused clock does not advance while a blocking thread is busy.
#[tokio::test]
async fn a_check_that_never_returns_is_given_up_on_and_named() {
    let (release, rx) = std::sync::mpsc::channel::<()>();
    let started = std::time::Instant::now();
    let health = bounded_probe(
        Arc::new(Hanging(Mutex::new(rx))),
        Duration::from_millis(200),
    )
    .await;
    assert_eq!(
        health,
        ChildHealth::NotReady("the health check did not answer within 200ms".into())
    );
    assert!(started.elapsed() < Duration::from_millis(1500));
    drop(release);
}

/// Progress `1, 2, ..., cap` (one more per check), then no more: a bootstrap that stalls.
struct Climbing {
    cap: u8,
    calls: std::sync::atomic::AtomicU8,
}

impl HealthCheck for Climbing {
    fn check(&self) -> ChildHealth {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ChildHealth::Bootstrapping(n.saturating_add(1).min(self.cap))
    }
}

const STALL: Duration = Duration::from_secs(180);

fn stalling(health: Arc<dyn HealthCheck>) -> ChildSpec {
    let mut s = spec(&[]);
    s.health = Some(health);
    s.stall_limit = Some(STALL);
    s
}

#[tokio::test(start_paused = true)]
async fn a_bootstrap_that_stops_advancing_restarts_the_child() {
    let (sup, fake) = supervisor();
    // Climbs to 50% in 50 s, then nothing.
    sup.set(
        "t",
        Some(stalling(Arc::new(Climbing {
            cap: 50,
            calls: Default::default(),
        }))),
    );
    pass(Duration::from_secs(60)).await;
    let st = sup.status("t");
    assert_eq!(
        (st.state, st.progress),
        (ChildState::Bootstrapping, Some(50))
    );

    // Still within the limit, counted from the last advance (about 50 s).
    pass(Duration::from_secs(160)).await;
    assert_eq!(
        fake.started(),
        1,
        "220 s in, but only 170 s without progress"
    );
    assert_eq!(sup.status("t").restarts, 0);

    // The limit ran out at about 229 s (180 s after the last advance).
    pass(Duration::from_millis(9500)).await;
    assert_eq!(fake.proc(0).signals(), ["term"], "stopped");
    let st = sup.status("t");
    assert_eq!(st.restarts, 1, "counts as a restart");
    assert_eq!(st.state, ChildState::Exited);
    assert_eq!(
        st.detail.as_deref(),
        Some("Tor made no bootstrap progress for 3 min (last progress 50%)")
    );

    // Back after the usual pause, and the new run is watched from its own start.
    pass(Duration::from_secs(2)).await;
    assert_eq!(fake.started(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_bootstrap_that_keeps_advancing_is_left_alone() {
    let (sup, fake) = supervisor();
    // 1% a second, up to 99%: it never goes 180 s without advancing.
    sup.set(
        "t",
        Some(stalling(Arc::new(Climbing {
            cap: 99,
            calls: Default::default(),
        }))),
    );
    pass(Duration::from_secs(150)).await;
    assert_eq!(fake.started(), 1);
    assert_eq!(sup.status("t").progress, Some(99));
    assert_eq!(sup.status("t").restarts, 0);
}

#[tokio::test(start_paused = true)]
async fn once_it_has_been_up_losing_connectivity_never_restarts_it() {
    let (sup, fake) = supervisor();
    let steps = [
        ChildHealth::Bootstrapping(40),
        ChildHealth::Bootstrapping(80),
        ChildHealth::Up,
    ];
    sup.set(
        "t",
        Some(stalling(Arc::new(Scripted(Mutex::new(steps.into()))))),
    );
    pass(Duration::from_secs(10)).await;
    assert_eq!(sup.status("t").state, ChildState::Up);
    // Hours later the process still runs: the start-up watchdog is over.
    pass(Duration::from_secs(6 * 3600)).await;
    assert_eq!(fake.started(), 1);
    assert_eq!(sup.status("t").state, ChildState::Up);
    assert_eq!(sup.status("t").restarts, 0);
}

#[tokio::test(start_paused = true)]
async fn a_child_that_never_reports_progress_is_restarted_too() {
    let (sup, fake) = supervisor();
    let steps = [ChildHealth::NotReady("cannot ask Tor".into())];
    sup.set(
        "t",
        Some(stalling(Arc::new(Scripted(Mutex::new(steps.into()))))),
    );
    pass(STALL + Duration::from_millis(500)).await;
    assert_eq!(fake.proc(0).signals(), ["term"]);
    assert_eq!(
        sup.status("t").detail.as_deref(),
        Some("Tor made no bootstrap progress for 3 min (no progress reported)")
    );
}
