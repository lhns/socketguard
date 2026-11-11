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
        health: None,
        before_start: None,
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
            q.front().copied().unwrap_or(ChildHealth::Starting)
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
