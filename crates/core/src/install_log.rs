//! The install record (ADR 0048, ADR 0050): what `networks setup` and the service
//! installer found and created on the host, with what is needed to reverse each change.
//! One file, `setup-log.json` next to the config file, shared by the daemon binary and the
//! CLI. Removal reverses exactly this record, newest first, and nothing else.

use crate::setup::SetupKind;
use serde::{Deserialize, Serialize};

/// One change, with what is needed to reverse it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    // ── networks setup (ADR 0048) ──
    /// A package that setup itself installed (never one that was there before).
    PackageInstalled {
        manager: String,
        package: String,
        install: String,
        uninstall: Vec<String>,
    },
    /// A service setup started (it was not running) or enabled.
    ServiceStarted {
        service: String,
        previous_state: String,
        previous_enabled: Option<bool>,
        undo: Vec<String>,
    },
    /// Lines appended to another program's configuration file.
    FileEdited {
        path: String,
        lines: Vec<String>,
        backup: Option<String>,
    },
    /// The network entry written to SocketGuard's config file.
    ConfigEntryWritten { path: String, id: String },
    /// The network added to the running daemon.
    NetworkAdded { id: String },

    // ── service install (ADR 0050) ──
    /// The SocketGuard service was registered with the system.
    ServiceRegistered { name: String, manager: String },
    /// The access group: `created` is false when it existed already (then it is never
    /// removed).
    AccessGroup { name: String, created: bool },
    /// A directory SocketGuard created. Removed only when empty.
    DirectoryCreated { path: String },
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub time: String,
    /// The network setup this belongs to; none for the service install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SetupKind>,
    #[serde(flatten)]
    pub change: Change,
}

impl Entry {
    pub fn now(kind: Option<SetupKind>, change: Change) -> Self {
        Self {
            time: chrono::Utc::now().to_rfc3339(),
            kind,
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

/// Append one entry to the log file.
pub fn append(path: &std::path::Path, entry: Entry) -> Result<(), String> {
    let mut all = read_file(path)?;
    all.push(entry);
    write_file(path, &all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_old_log_without_install_entries_still_parses() {
        let old = r#"{"entries":[{"time":"t","kind":"tor","type":"network_added","id":"tor"}]}"#;
        let e = parse(old).unwrap();
        assert_eq!(e[0].kind, Some(SetupKind::Tor));
        let text = render(&[Entry::now(
            None,
            Change::AccessGroup {
                name: "socketguard".into(),
                created: true,
            },
        )]);
        assert!(!text.contains("\"kind\""));
        assert_eq!(parse(&text).unwrap().len(), 1);
    }
}
