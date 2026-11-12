//! The session record of a portable run (ADR 0054): that a daemon is running, how the last
//! run ended, and the one fact about the Wintun driver that has to outlive a kill.

use crate::wintun::PresenceLog;
use anyhow::{bail, Result};
use socketguard_core::portable::{last_exit_line, LAST_EXIT_FILE};
use std::path::Path;
use std::time::Duration;

/// Written while a daemon runs; one found at start was left by a daemon that did not end
/// cleanly.
pub const SESSION_FILE: &str = "session.json";

// ─── What the last run left ──────────────────────────────────────────────────

/// Record how the run ended, in `data_dir`. Best effort: the exit goes on regardless.
pub fn write_last_exit(data_dir: &Path, left: &[String]) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = last_exit_line(secs, left);
    if let Err(e) = std::fs::write(data_dir.join(LAST_EXIT_FILE), format!("{line}\n")) {
        tracing::warn!("Could not write {LAST_EXIT_FILE}: {e}");
    }
    // A clean end leaves no session record; a kill leaves it, and the next start says so.
    let _ = std::fs::remove_file(data_dir.join(SESSION_FILE));
}

/// Note that a daemon is running, and warn about a record a killed one left.
///
/// What a killed daemon recorded about the Wintun driver is carried over: the driver it
/// installed is still there, and the next clean exit removes it.
pub fn write_session(data_dir: &Path, owner_pid: Option<u32>) {
    let file = data_dir.join(SESSION_FILE);
    let carried = SessionLog::new(data_dir).recorded().ok().flatten();
    if file.exists() {
        tracing::warn!(
            "{} was left by a daemon that did not end cleanly; addresses it added are removed \
             now",
            file.display()
        );
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut body = serde_json::json!({
        "pid": std::process::id(),
        "owner_pid": owner_pid,
        "started": secs,
    });
    if let Some(present_before) = carried {
        body[WINTUN_KEY] = present_before.into();
    }
    if let Err(e) = std::fs::write(&file, body.to_string()) {
        tracing::warn!("Could not write {}: {e}", file.display());
    }
}

// ─── The Wintun driver ───────────────────────────────────────────────────────

/// The key of the session record that says whether Wintun was in the driver store before the
/// first Yggdrasil start of this run (or of a killed run it carries over from).
const WINTUN_KEY: &str = "wintun_present_before";

/// How often a refused driver removal is tried again at the end of a run.
const DRIVER_RETRIES: u32 = 3;

/// The session record as the place for the "driver was there before" fact (portable mode has
/// no install record, ADR 0054).
pub struct SessionLog {
    file: std::path::PathBuf,
}

impl SessionLog {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            file: data_dir.join(SESSION_FILE),
        }
    }

    fn read(&self) -> Result<Option<serde_json::Value>> {
        match std::fs::read_to_string(&self.file) {
            Ok(text) => Ok(Some(serde_json::from_str(&text)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

impl crate::wintun::PresenceLog for SessionLog {
    fn recorded(&self) -> Result<Option<bool>> {
        Ok(self
            .read()?
            .and_then(|v| v.get(WINTUN_KEY).and_then(serde_json::Value::as_bool)))
    }

    fn record(&self, present_before: bool) -> Result<()> {
        let mut body = self.read()?.unwrap_or_else(|| serde_json::json!({}));
        if !body.is_object() {
            bail!("{} is not a JSON object", self.file.display());
        }
        // The first answer stands.
        if body.get(WINTUN_KEY).is_some() {
            return Ok(());
        }
        body[WINTUN_KEY] = present_before.into();
        std::fs::write(&self.file, body.to_string())?;
        Ok(())
    }
}

/// The session record of the running portable daemon; None when not portable (tests, and the
/// installed daemon, which has its install record).
pub fn session_log() -> Option<SessionLog> {
    if !socketguard_core::portable::is_portable() {
        return None;
    }
    socketguard_core::portable::data_dir().map(|d| SessionLog::new(&d))
}

/// On a clean exit, after the children have ended: remove the Wintun driver if it was not in
/// the driver store before this run and Windows lets it go without force. A killed daemon
/// does not get here, so the driver stays then (nothing runs; the card says so). Returns what
/// is left, as a sentence, for `last-exit.log`.
///
/// Windows refuses the removal while the adapter still exists, and the adapter goes a moment
/// after `yggdrasil.exe` ends: a refusal is tried again [`DRIVER_RETRIES`] times, `pause`
/// apart, before the driver counts as shared with other software and is kept. (The session
/// record goes with the clean exit either way, so a driver kept here is not removed later.)
pub fn remove_wintun_driver(
    host: &mut dyn crate::host::Host,
    data_dir: &Path,
    pause: Duration,
) -> Option<String> {
    let present_before = match SessionLog::new(data_dir).recorded() {
        // Yggdrasil never started: the driver was never put there by us.
        Ok(None) => return None,
        Ok(Some(p)) => p,
        Err(e) => {
            // Not knowing, the driver stays: it may be shared with other software.
            tracing::warn!("Wintun driver kept, the session record cannot be read: {e:#}");
            return None;
        }
    };
    let mut report = crate::wintun::undo(host, present_before);
    let kept = |r: &crate::report::Report| {
        r.items
            .iter()
            .any(|i| matches!(i.outcome, crate::report::Outcome::Kept(_)))
    };
    for _ in 0..DRIVER_RETRIES {
        if present_before || !kept(&report) {
            break;
        }
        std::thread::sleep(pause);
        report = crate::wintun::undo(host, present_before);
    }
    tracing::info!("Wintun driver:\n{}", report.render());
    let left: Vec<String> = report
        .left_items()
        .iter()
        .filter_map(|i| match &i.outcome {
            crate::report::Outcome::Left(why) => Some(format!("{}: {why}", i.what)),
            _ => None,
        })
        .collect();
    (!left.is_empty()).then(|| left.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_record_marks_a_run_and_a_clean_exit_removes_it() {
        let dir = std::env::temp_dir().join(format!("sg-portable-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        write_session(&dir, Some(7));
        assert!(dir.join(SESSION_FILE).is_file());
        write_last_exit(&dir, &[]);
        assert!(!dir.join(SESSION_FILE).exists());
        let text = std::fs::read_to_string(dir.join(LAST_EXIT_FILE)).unwrap();
        assert!(text.contains("clean"), "{text}");
        write_last_exit(&dir, &["address fd00::1 on Ethernet".into()]);
        let text = std::fs::read_to_string(dir.join(LAST_EXIT_FILE)).unwrap();
        assert!(text.contains("LEFT"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_data_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sg-portable-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const WITH_WINTUN: &str =
        "Published Name:     oem12.inf\nOriginal Name:      wintun.inf\nProvider Name:      WireGuard LLC\n";
    const WITHOUT_WINTUN: &str =
        "Published Name:     oem3.inf\nOriginal Name:      prnms009.inf\nProvider Name:      Microsoft\n";

    fn pnputil(host: &mut crate::host::fake::FakeHost, outputs: &[&str]) {
        host.answer_in_order(
            "pnputil /enum-drivers",
            outputs
                .iter()
                .map(|o| crate::host::Output {
                    code: 0,
                    stdout: (*o).into(),
                    stderr: String::new(),
                })
                .collect(),
        );
    }

    /// The first Yggdrasil start asks the driver store once and keeps the answer in
    /// the session record, not in an install record.
    #[test]
    fn the_wintun_fact_goes_into_the_session_record_once() {
        let dir = temp_data_dir();
        write_session(&dir, Some(7));
        let log = SessionLog::new(&dir);
        assert_eq!(log.recorded().unwrap(), None);

        let mut host = crate::host::fake::FakeHost::new("windows");
        pnputil(&mut host, &[WITHOUT_WINTUN]);
        crate::wintun::record_present_before(&mut host, &log).unwrap();
        assert_eq!(log.recorded().unwrap(), Some(false));
        // The driver is in the store now (the start installed it): not asked again, and the
        // first answer stands.
        let mut host = crate::host::fake::FakeHost::new("windows");
        pnputil(&mut host, &[WITH_WINTUN]);
        crate::wintun::record_present_before(&mut host, &log).unwrap();
        assert!(host.commands.is_empty(), "{:?}", host.commands);
        assert_eq!(log.recorded().unwrap(), Some(false));
        // The other fields of the record are kept.
        let text = std::fs::read_to_string(dir.join(SESSION_FILE)).unwrap();
        assert!(text.contains("\"owner_pid\":7"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A kill leaves the session record, and with it the fact that the driver was put there
    /// by this folder; the next run keeps it, so its clean exit removes the driver.
    #[test]
    fn a_killed_run_hands_the_wintun_fact_to_the_next_one() {
        let dir = temp_data_dir();
        write_session(&dir, None);
        SessionLog::new(&dir).record(false).unwrap();
        // The process is killed: no write_last_exit.
        write_session(&dir, None);
        assert_eq!(SessionLog::new(&dir).recorded().unwrap(), Some(false));
        write_last_exit(&dir, &[]);
        assert!(!dir.join(SESSION_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_clean_exit_removes_a_driver_that_was_absent_before_without_force() {
        let dir = temp_data_dir();
        write_session(&dir, None);
        SessionLog::new(&dir).record(false).unwrap();
        let mut host = crate::host::fake::FakeHost::new("windows");
        pnputil(&mut host, &[WITH_WINTUN, WITHOUT_WINTUN]);
        assert_eq!(remove_wintun_driver(&mut host, &dir, Duration::ZERO), None);
        assert!(host.ran("pnputil /delete-driver oem12.inf"));
        assert!(!host.commands.iter().any(|c| c.contains("/force")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The adapter goes a moment after the child: the first delete is refused, the retry works.
    #[test]
    fn a_refused_driver_removal_is_tried_again() {
        let dir = temp_data_dir();
        write_session(&dir, None);
        SessionLog::new(&dir).record(false).unwrap();
        let mut host = crate::host::fake::FakeHost::new("windows");
        // Per attempt: list, delete, list again.
        pnputil(
            &mut host,
            &[WITH_WINTUN, WITH_WINTUN, WITH_WINTUN, WITHOUT_WINTUN],
        );
        host.answer_in_order(
            "pnputil /delete-driver",
            vec![
                crate::host::Output {
                    code: 1,
                    ..Default::default()
                },
                crate::host::Output::default(),
            ],
        );
        assert_eq!(remove_wintun_driver(&mut host, &dir, Duration::ZERO), None);
        let deletes = host
            .commands
            .iter()
            .filter(|c| c.starts_with("pnputil /delete-driver"))
            .count();
        assert_eq!(deletes, 2, "{:?}", host.commands);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_clean_exit_keeps_a_driver_that_was_there_before_or_was_never_recorded() {
        let dir = temp_data_dir();
        write_session(&dir, None);
        // Yggdrasil never started: nothing was recorded, nothing is run.
        let mut host = crate::host::fake::FakeHost::new("windows");
        assert_eq!(remove_wintun_driver(&mut host, &dir, Duration::ZERO), None);
        assert!(host.commands.is_empty(), "{:?}", host.commands);
        // There before: shared with other software.
        SessionLog::new(&dir).record(true).unwrap();
        assert_eq!(remove_wintun_driver(&mut host, &dir, Duration::ZERO), None);
        assert!(host.commands.is_empty(), "{:?}", host.commands);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Windows refusing the removal (an adapter or other software still uses it) is not an
    /// error of the exit; an unreadable driver store is named as left.
    #[test]
    fn a_driver_windows_will_not_delete_is_kept_and_an_unreadable_store_is_left() {
        let dir = temp_data_dir();
        write_session(&dir, None);
        SessionLog::new(&dir).record(false).unwrap();
        let mut host = crate::host::fake::FakeHost::new("windows");
        host.answer("pnputil /enum-drivers", 0, WITH_WINTUN);
        host.answer("pnputil /delete-driver", 1, "");
        assert_eq!(remove_wintun_driver(&mut host, &dir, Duration::ZERO), None);

        let mut host = crate::host::fake::FakeHost::new("windows");
        host.answer("pnputil", 1, "");
        let left = remove_wintun_driver(&mut host, &dir, Duration::ZERO).expect("named as left");
        assert!(left.contains("Wintun driver"), "{left}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
