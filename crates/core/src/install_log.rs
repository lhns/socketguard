//! The install record (ADR 0050, ADR 0052): what the service installer and the Tor and Yggdrasil
//! networks found and created on the host, with what is needed to reverse each change.
//! One file, `setup-log.json` next to the config file, shared by the daemon binary and the
//! CLI. Removal reverses exactly this record, newest first, and nothing else.

use serde::{Deserialize, Serialize};

/// One change, with what is needed to reverse it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    // ── service install (ADR 0050) ──
    /// The SocketGuard service was registered with the system.
    ServiceRegistered { name: String, manager: String },
    /// The access group: `created` is false when it existed already (then it is never
    /// removed).
    AccessGroup { name: String, created: bool },
    /// A directory SocketGuard created. Removed only when empty.
    DirectoryCreated { path: String },
    /// A directory SocketGuard created solely for a child process it runs (its own Tor or
    /// Yggdrasil). `uninstall --purge` may remove the whole tree, but only when the path is
    /// strictly inside the state directory.
    OwnedDirectory { path: String },
    /// macOS: the `anchor` line of `/etc/pf.conf` and pf itself. Only what was missing was
    /// added and is undone.
    PfAnchor {
        conf: String,
        line: String,
        line_added: bool,
        pf_enabled_before: bool,
        pf_enabled_by_us: bool,
    },
    /// Windows: the WFP engine option `FWPM_ENGINE_COLLECT_NET_EVENTS` before the daemon
    /// first set it. `prior` is None when it could not be read (then it is not restored).
    WfpEngineOption { option: String, prior: Option<u32> },

    // ── Tor and Yggdrasil networks (ADR 0052) ──
    /// Unix: the unprivileged system account the children run as. Removed only when
    /// `created`.
    UnprivilegedAccount { name: String, created: bool },
    /// Windows: whether the Wintun driver was in the driver store before the first
    /// Yggdrasil start. Purge removes it only if it was not (and nothing else uses it).
    WintunDriver { present_before: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub time: String,
    #[serde(flatten)]
    pub change: Change,
}

impl Entry {
    pub fn now(change: Change) -> Self {
        Self {
            time: chrono::Utc::now().to_rfc3339(),
            change,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LogFile {
    #[serde(default)]
    entries: Vec<Entry>,
}

/// Parse the text of a setup log.
pub fn parse(text: &str) -> Result<Vec<Entry>, serde_json::Error> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    Ok(serde_json::from_str::<LogFile>(text)?.entries)
}

/// The text of a setup log holding `entries`.
pub fn render(entries: &[Entry]) -> String {
    let mut text = serde_json::to_string_pretty(&LogFile {
        entries: entries.to_vec(),
    })
    .expect("a log serialises");
    text.push('\n');
    text
}

/// Read the log file at `path`; a missing file is an empty log.
pub fn read_file(path: &std::path::Path) -> Result<Vec<Entry>, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => parse(&t).map_err(|e| format!("{} is not a setup log: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// Write the log through a temp file and a rename.
pub fn write_file(path: &std::path::Path, entries: &[Entry]) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, render(entries))
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("cannot write {}: {e}", path.display())
        })
}

/// `text` without the lines `lines` that were appended to it: the last occurrence of each,
/// everything else byte for byte.
pub fn remove_lines(text: &str, lines: &[String]) -> String {
    let mut parts: Vec<&str> = text.split_inclusive('\n').collect();
    for l in lines.iter().rev() {
        if let Some(i) = parts
            .iter()
            .rposition(|p| p.trim_end_matches(['\r', '\n']) == l)
        {
            parts.remove(i);
        }
    }
    parts.concat()
}
