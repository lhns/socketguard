//! Minimal terminal prompts on stdin/stderr. Interactive flows run only on a terminal;
//! scripts use `--yes`.

use anyhow::{bail, Result};
use std::io::{BufRead, IsTerminal, Write};

/// Whether both stdin and stdout are a terminal.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

pub fn read_line(question: &str) -> Result<String> {
    let mut err = std::io::stderr();
    write!(err, "{question} ")?;
    err.flush()?;
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        bail!("input closed");
    }
    Ok(line.trim().to_string())
}

/// `question [y/N]`; anything but y/yes is no.
pub fn confirm(question: &str) -> Result<bool> {
    let answer = read_line(&format!("{question} [y/N]"))?;
    Ok(matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// Numbered choice; asks again until the answer is a valid number.
pub fn choose(question: &str, options: &[String]) -> Result<usize> {
    let mut err = std::io::stderr();
    writeln!(err, "{question}")?;
    for (i, o) in options.iter().enumerate() {
        writeln!(err, "  {}) {o}", i + 1)?;
    }
    loop {
        let answer = read_line(&format!("choose 1-{}:", options.len()))?;
        match answer.parse::<usize>() {
            Ok(n) if (1..=options.len()).contains(&n) => return Ok(n - 1),
            _ => writeln!(err, "not a valid choice")?,
        }
    }
}
