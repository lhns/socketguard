//! What the install, access and uninstall commands do to the host, behind one trait so the
//! command sequences are tested with a fake (ADR 0050): run a program, ask whether we have
//! administrator rights, talk to the terminal. Files are touched directly (tests use temp
//! directories).

use anyhow::{Context, Result};

/// What a program printed and how it ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

pub trait Host {
    fn os(&self) -> &'static str;
    fn is_elevated(&self) -> bool;
    /// Run a program (no shell) and capture its output. An error only when it cannot be
    /// started; a non-zero exit is in the [`Output`].
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output>;
    /// A line for the person running the command.
    fn say(&mut self, line: &str);
    /// stdin and stdout are a terminal.
    fn interactive(&self) -> bool;
    /// Ask a yes/no question (default no); only called when `interactive()`.
    fn confirm(&mut self, question: &str) -> bool;

    /// Run and require success.
    fn run_ok(&mut self, program: &str, args: &[&str]) -> Result<Output> {
        let out = self.run(program, args)?;
        if !out.ok() {
            anyhow::bail!(
                "`{} {}` failed ({}): {}",
                program,
                args.join(" "),
                out.code,
                out.stderr.trim().lines().next().unwrap_or(out.stdout.trim())
            );
        }
        Ok(out)
    }
}

/// Refuse unless elevated, with the instruction for this system.
pub fn require_admin(host: &dyn Host, what: &str) -> Result<()> {
    if host.is_elevated() {
        return Ok(());
    }
    anyhow::bail!(
        "{what} needs administrator rights: {}",
        if host.os() == "windows" {
            "run it from an elevated terminal (Run as administrator)"
        } else {
            "run it with sudo"
        }
    )
}

/// [`Host`] for this machine.
pub struct SystemHost;

impl Host for SystemHost {
    fn os(&self) -> &'static str {
        std::env::consts::OS
    }

    fn is_elevated(&self) -> bool {
        elevated()
    }

    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output> {
        let out = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .with_context(|| format!("cannot run {program}"))?;
        Ok(Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn say(&mut self, line: &str) {
        println!("{line}");
    }

    fn interactive(&self) -> bool {
        use std::io::IsTerminal;
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
    }

    fn confirm(&mut self, question: &str) -> bool {
        use std::io::Write;
        print!("{question} ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }
}

#[cfg(unix)]
fn elevated() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut e = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut e as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && e.TokenIsElevated != 0
    }
}

/// A scripted [`Host`] for tests: records every command and answers from a script.
#[cfg(any(test, feature = "test-support"))]
pub mod fake {
    use super::*;
    use std::collections::VecDeque;

    pub struct FakeHost {
        pub os: &'static str,
        pub elevated: bool,
        pub interactive: bool,
        pub answers_yes: bool,
        /// `program args...` of every command run, in order.
        pub commands: Vec<String>,
        pub said: Vec<String>,
        pub questions: Vec<String>,
        /// Exit codes by command prefix (first match wins); default 0.
        pub exit: Vec<(String, Output)>,
        /// Outputs consumed in order for commands that match the prefix.
        pub queue: Vec<(String, VecDeque<Output>)>,
    }

    impl FakeHost {
        pub fn new(os: &'static str) -> Self {
            Self {
                os,
                elevated: true,
                interactive: false,
                answers_yes: false,
                commands: vec![],
                said: vec![],
                questions: vec![],
                exit: vec![],
                queue: vec![],
            }
        }
        /// Commands starting with `prefix` answer with `out`.
        pub fn answer(&mut self, prefix: &str, code: i32, stdout: &str) {
            self.exit.push((
                prefix.to_string(),
                Output {
                    code,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                },
            ));
        }
        /// Commands starting with `prefix` answer from `outs`, one per call (then as
        /// `answer`, or success).
        pub fn answer_in_order(&mut self, prefix: &str, outs: Vec<Output>) {
            self.queue.push((prefix.to_string(), outs.into()));
        }
        pub fn ran(&self, prefix: &str) -> bool {
            self.commands.iter().any(|c| c.starts_with(prefix))
        }
    }

    impl Host for FakeHost {
        fn os(&self) -> &'static str {
            self.os
        }
        fn is_elevated(&self) -> bool {
            self.elevated
        }
        fn run(&mut self, program: &str, args: &[&str]) -> Result<Output> {
            let line = std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            self.commands.push(line.clone());
            for (prefix, q) in &mut self.queue {
                if line.starts_with(prefix.as_str()) {
                    if let Some(o) = q.pop_front() {
                        return Ok(o);
                    }
                }
            }
            for (prefix, out) in &self.exit {
                if line.starts_with(prefix.as_str()) {
                    return Ok(out.clone());
                }
            }
            Ok(Output::default())
        }
        fn say(&mut self, line: &str) {
            self.said.push(line.to_string());
        }
        fn interactive(&self) -> bool {
            self.interactive
        }
        fn confirm(&mut self, question: &str) -> bool {
            self.questions.push(question.to_string());
            self.answers_yes
        }
    }
}
