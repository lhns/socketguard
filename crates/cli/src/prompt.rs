//! Interactive prompts. The flows (`init`, `pending`) talk to a [`Prompter`]; [`Stdin`] asks
//! on stdin/stderr and the tests script the answers. Interactive flows run only on a
//! terminal; scripts use `--yes`.

use crate::Reported;
use anyhow::{bail, Result};
use std::io::{BufRead, IsTerminal, Write};

/// Questions a flow can ask. Closed input (ctrl-D) means "no answer": `ask` returns an
/// empty string, `confirm` is no, `choose` is `None` (cancel).
pub trait Prompter {
    /// Whether anyone can answer (a terminal). Flows print instructions instead when not.
    fn interactive(&self) -> bool;
    /// A line of free text, trimmed.
    fn ask(&mut self, question: &str) -> String;
    /// `question [y/N]`; anything but y/yes is no.
    fn confirm(&mut self, question: &str) -> bool;
    /// A numbered choice; the index of the option, or `None` when input is closed.
    fn choose(&mut self, question: &str, options: &[String]) -> Option<usize>;

    /// Ask `question` unless `yes` was given. Nobody to ask is an error saying `refusal`;
    /// a "no" is the already-reported [`Reported`] error.
    fn confirm_or_yes(&mut self, yes: bool, question: &str, refusal: &str) -> Result<()> {
        if yes {
            return Ok(());
        }
        if !self.interactive() {
            bail!("{refusal}");
        }
        if !self.confirm(question) {
            eprintln!("not confirmed; nothing changed");
            return Err(Reported.into());
        }
        Ok(())
    }
}

/// Prompts on stderr, answers from stdin.
pub struct Stdin;

/// Whether both stdin and stdout are a terminal.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

impl Stdin {
    /// `None` at end of input.
    fn read_line(question: &str) -> Option<String> {
        let mut err = std::io::stderr();
        let _ = write!(err, "{question} ");
        let _ = err.flush();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim().to_string()),
        }
    }
}

impl Prompter for Stdin {
    fn interactive(&self) -> bool {
        interactive()
    }

    fn ask(&mut self, question: &str) -> String {
        Self::read_line(question).unwrap_or_default()
    }

    fn confirm(&mut self, question: &str) -> bool {
        let answer = Self::read_line(&format!("{question} [y/N]")).unwrap_or_default();
        matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes")
    }

    /// Asks again until the answer is a valid number.
    fn choose(&mut self, question: &str, options: &[String]) -> Option<usize> {
        let mut err = std::io::stderr();
        let _ = writeln!(err, "{question}");
        for (i, o) in options.iter().enumerate() {
            let _ = writeln!(err, "  {}) {o}", i + 1);
        }
        loop {
            let answer = Self::read_line(&format!("choose 1-{}:", options.len()))?;
            match answer.parse::<usize>() {
                Ok(n) if (1..=options.len()).contains(&n) => return Some(n - 1),
                _ => {
                    let _ = writeln!(err, "not a valid choice");
                }
            }
        }
    }
}
