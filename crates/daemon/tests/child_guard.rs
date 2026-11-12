//! `socketguard-daemon child-guard` (Linux): the real binary, with a real child. The guard
//! ends its program when the pipe the daemon holds closes, forwards SIGTERM, and passes the
//! exit code on.
#![cfg(target_os = "linux")]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn guard(program_and_args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_socketguard-daemon"))
        .args(["child-guard", "--"])
        .args(program_and_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the guard")
}

/// The pid of the guard's only child, once it exists.
fn child_of(guard: &Child) -> u32 {
    let pid = guard.id();
    let file = format!("/proc/{pid}/task/{pid}/children");
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(c) = std::fs::read_to_string(&file)
            .ok()
            .and_then(|t| t.split_whitespace().next().and_then(|c| c.parse().ok()))
        {
            return c;
        }
        assert!(Instant::now() < end, "the guard started no program");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn wait_code(guard: &mut Child) -> Option<i32> {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = guard.try_wait().unwrap() {
            return status.code();
        }
        assert!(Instant::now() < end, "the guard did not end");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn closing_the_pipe_ends_the_program_and_the_guard() {
    let mut g = guard(&["sleep", "600"]);
    let program = child_of(&g);
    assert!(alive(program));
    // The daemon is gone: its end of the pipe closes.
    drop(g.stdin.take());
    assert_eq!(
        wait_code(&mut g),
        Some(128 + 15),
        "the program died of SIGTERM"
    );
    assert!(!alive(program));
}

#[test]
fn the_program_is_recorded_for_the_next_start_and_the_record_goes_with_it() {
    let dir = std::env::temp_dir().join(format!("sg-guard-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("p.child");
    let mut g = Command::new(env!("CARGO_BIN_EXE_socketguard-daemon"))
        .args(["child-guard", "--pid-file"])
        .arg(&file)
        .args(["--", "sleep", "600"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("start the guard");
    let program = child_of(&g);
    let end = Instant::now() + Duration::from_secs(5);
    while !file.exists() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    let text = std::fs::read_to_string(&file).expect("the record");
    assert!(text.starts_with(&format!("{program} ")), "{text}");
    drop(g.stdin.take());
    wait_code(&mut g);
    assert!(!file.exists(), "removed when the program ended");
}

#[test]
fn sigterm_is_passed_on_to_the_program() {
    let mut g = guard(&["sleep", "600"]);
    let program = child_of(&g);
    // SAFETY: plain signal to the child we started.
    unsafe {
        libc::kill(g.id() as libc::pid_t, libc::SIGTERM);
    }
    assert_eq!(wait_code(&mut g), Some(128 + 15));
    assert!(!alive(program));
}

#[test]
fn the_exit_code_of_the_program_is_the_guards() {
    let mut g = guard(&["sh", "-c", "exit 7"]);
    assert_eq!(wait_code(&mut g), Some(7));
    let mut missing = guard(&["/nonexistent/program"]);
    assert_eq!(wait_code(&mut missing), Some(127));
}
