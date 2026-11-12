//! A reader that stops reading (`socketguard ... | head -1`) must not make the CLI panic
//! ("failed printing to stdout", exit status 101): it ends quietly.

use std::io::Read;
use std::process::{Command, Stdio};

#[test]
fn a_closed_stdout_ends_the_program_without_a_panic() {
    // The completion script is large, so the CLI is still writing when the pipe closes.
    for _ in 0..20 {
        let mut child = Command::new(env!("CARGO_BIN_EXE_socketguard"))
            .args(["completions", "bash"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the CLI");
        let mut stdout = child.stdout.take().unwrap();
        let mut first = [0u8; 16];
        stdout.read_exact(&mut first).expect("some output");
        drop(stdout);
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let status = child.wait().unwrap();
        assert!(!stderr.contains("panicked"), "panic message: {stderr}");
        assert_ne!(
            status.code(),
            Some(101),
            "exit status 101; stderr: {stderr}"
        );
        assert!(stderr.is_empty(), "stderr: {stderr}");
    }
}
