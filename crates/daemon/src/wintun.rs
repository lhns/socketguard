//! Windows: the Wintun driver that Yggdrasil's adapter needs (ADR 0052). `wintun.dll` (shipped
//! beside `yggdrasil.exe`) installs the driver into the driver store the first time it
//! creates an adapter. SocketGuard records once, before the first managed start, whether
//! the driver was already in the store, and `uninstall --purge` removes it only if it was
//! not and nothing else holds it.
//!
//! Everything goes through the [`Host`] trait (`pnputil`), so the parsing and the decisions
//! are tested with a fake host on every system.

use crate::host::{Host, SystemHost};
use crate::install::Record;
use crate::report::Report;
use anyhow::{Context, Result};
use socketguard_core::install_log::{Change, Entry};

/// The original file name of Wintun's driver package in the driver store.
const ORIGINAL_NAME: &str = "wintun.inf";

/// One driver package of `pnputil /enum-drivers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverPackage {
    /// The name in the driver store, `oem12.inf`.
    pub published: String,
    /// The file name it was published from, `wintun.inf`.
    pub original: String,
    pub provider: String,
}

fn is_published_name(v: &str) -> bool {
    let v = v.to_ascii_lowercase();
    v.strip_prefix("oem")
        .and_then(|r| r.strip_suffix(".inf"))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The packages in the output of `pnputil /enum-drivers`: blocks separated by blank lines
/// of `Label: value` lines. The labels are translated on other languages of Windows, so the
/// values are recognised by their shape (`oemNN.inf` is the published name, another `.inf`
/// the original name, a value with "WireGuard" the provider).
pub fn parse_enum_drivers(text: &str) -> Vec<DriverPackage> {
    let mut out = Vec::new();
    let mut block: Vec<&str> = Vec::new();
    let mut flush = |block: &mut Vec<&str>| {
        let mut p = DriverPackage {
            published: String::new(),
            original: String::new(),
            provider: String::new(),
        };
        for line in block.drain(..) {
            let Some((_, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if is_published_name(value) && p.published.is_empty() {
                p.published = value.to_string();
            } else if value.to_ascii_lowercase().ends_with(".inf") && p.original.is_empty() {
                p.original = value.to_string();
            } else if value.contains("WireGuard") && p.provider.is_empty() {
                p.provider = value.to_string();
            }
        }
        if !p.published.is_empty() {
            out.push(p);
        }
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            flush(&mut block);
        } else {
            block.push(line);
        }
    }
    flush(&mut block);
    out
}

/// The store name (`oem12.inf`) of Wintun's package, if it is installed.
pub fn find_wintun(packages: &[DriverPackage]) -> Option<String> {
    packages
        .iter()
        .find(|p| p.original.eq_ignore_ascii_case(ORIGINAL_NAME))
        .map(|p| p.published.clone())
}

fn installed(host: &mut dyn Host) -> Result<Option<String>> {
    let out = host
        .run_ok("pnputil", &["/enum-drivers"])
        .context("cannot list the driver store")?;
    Ok(find_wintun(&parse_enum_drivers(&out.stdout)))
}

/// Where the fact "Wintun was in the driver store before SocketGuard" is kept: the install
/// record of an installed SocketGuard, the session record of a portable one (ADR 0054, which
/// has no install record).
pub trait PresenceLog {
    /// What was recorded, if anything was.
    fn recorded(&self) -> Result<Option<bool>>;
    /// Record it; the first answer stands.
    fn record(&self, present_before: bool) -> Result<()>;
}

impl PresenceLog for Record {
    fn recorded(&self) -> Result<Option<bool>> {
        Ok(self.entries()?.iter().find_map(|e| match e.change {
            Change::WintunDriver { present_before } => Some(present_before),
            _ => None,
        }))
    }

    fn record(&self, present_before: bool) -> Result<()> {
        self.push_once(
            |c| matches!(c, Change::WintunDriver { .. }),
            Entry::now(Change::WintunDriver { present_before }),
        )
    }
}

/// Record whether Wintun is in the driver store, unless that was recorded already. An
/// answer that cannot be had is not recorded (and tried again at the next start): guessing
/// "absent" could remove a driver that other software needs.
pub fn record_present_before(host: &mut dyn Host, log: &dyn PresenceLog) -> Result<()> {
    if log.recorded()?.is_some() {
        return Ok(());
    }
    log.record(installed(host)?.is_some())
}

/// Before the first managed Yggdrasil start on Windows: into the session record when portable,
/// else the install record. A daemon without either (tests) does nothing.
pub fn record_before_first_start() {
    let result = if let Some(log) = crate::portable::session_log() {
        record_present_before(&mut SystemHost, &log)
    } else if let Some(record) = crate::install::record() {
        record_present_before(&mut SystemHost, &record)
    } else {
        return;
    };
    if let Err(e) = result {
        tracing::warn!("Could not record whether the Wintun driver was installed: {e:#}");
    }
}

/// Reverse a [`Change::WintunDriver`]: the driver is removed only when it was not in the
/// store before SocketGuard and removing it without force succeeds (Windows refuses while
/// an adapter or other software uses it).
pub fn undo(host: &mut dyn Host, present_before: bool) -> Report {
    let mut r = Report::default();
    let what = "Wintun driver";
    if present_before {
        r.kept(
            what,
            "it was installed before SocketGuard (shared with other software)",
        );
        return r;
    }
    match installed(host) {
        Err(e) => r.left(what, format!("{e:#}")),
        Ok(None) => r.absent(what),
        Ok(Some(published)) => {
            let deleted = host.run_ok("pnputil", &["/delete-driver", &published]);
            match (deleted, installed(host)) {
                (Ok(_), Ok(None)) => r.removed(what),
                _ => r.kept(what, "shared with other software"),
            }
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;
    use crate::host::Output;
    use crate::install::tests_support::tmp;

    /// Written by hand after the layout of `pnputil /enum-drivers` on Windows 11 (not
    /// captured from a machine): blocks of `Label:   value`, a blank line between them.
    const ENUM: &str = "Microsoft PnP Utility\r\n\
\r\n\
Published Name:     oem3.inf\r\n\
Original Name:      prnms009.inf\r\n\
Provider Name:      Microsoft\r\n\
Class Name:         Printers\r\n\
Driver Version:     06/21/2006 10.0.26100.1\r\n\
Signer Name:        Microsoft Windows\r\n\
\r\n\
Published Name:     oem12.inf\r\n\
Original Name:      wintun.inf\r\n\
Provider Name:      WireGuard LLC\r\n\
Class Name:         Network adapters\r\n\
Class GUID:         {4d36e972-e325-11ce-bfc1-08002be10318}\r\n\
Driver Version:     06/21/2021 0.14.1.0\r\n\
Signer Name:        Microsoft Windows Hardware Compatibility Publisher\r\n\
\r\n\
Published Name:     oem13.inf\r\n\
Original Name:      wireguard.inf\r\n\
Provider Name:      WireGuard LLC\r\n\
Class Name:         Network adapters\r\n";

    const ENUM_WITHOUT: &str = "Microsoft PnP Utility\r\n\r\nPublished Name:     oem3.inf\r\nOriginal Name:      prnms009.inf\r\nProvider Name:      Microsoft\r\n";

    #[test]
    fn the_driver_store_listing_is_parsed() {
        let p = parse_enum_drivers(ENUM);
        assert_eq!(p.len(), 3);
        assert_eq!(p[1].published, "oem12.inf");
        assert_eq!(p[1].original, "wintun.inf");
        assert_eq!(p[1].provider, "WireGuard LLC");
        assert_eq!(find_wintun(&p).as_deref(), Some("oem12.inf"));
        // WireGuard's own driver has the same provider and is not Wintun.
        assert_eq!(p[2].original, "wireguard.inf");
        assert_eq!(find_wintun(&parse_enum_drivers(ENUM_WITHOUT)), None);
        assert_eq!(find_wintun(&parse_enum_drivers("")), None);
    }

    #[test]
    fn translated_labels_do_not_matter() {
        let de = "Veröffentlichter Name: oem7.inf\nOriginalname:          WINTUN.INF\nAnbietername:          WireGuard LLC\n";
        assert_eq!(
            find_wintun(&parse_enum_drivers(de)).as_deref(),
            Some("oem7.inf")
        );
    }

    fn host_with(listing: &str) -> FakeHost {
        let mut h = FakeHost::new("windows");
        h.answer("pnputil /enum-drivers", 0, listing);
        h
    }

    #[test]
    fn the_driver_is_recorded_once_before_the_first_start() {
        let d = tmp();
        let rec = Record::new(d.join("setup-log.json"));
        let mut h = host_with(ENUM_WITHOUT);
        record_present_before(&mut h, &rec).unwrap();
        // The driver store has it now (the first start installed it); the record stays.
        let mut h = host_with(ENUM);
        record_present_before(&mut h, &rec).unwrap();
        assert!(h.commands.is_empty(), "not asked again: {:?}", h.commands);
        let entries = rec.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].change,
            Change::WintunDriver {
                present_before: false
            }
        );
    }

    #[test]
    fn a_driver_that_was_there_is_recorded_as_such() {
        let d = tmp();
        let rec = Record::new(d.join("setup-log.json"));
        record_present_before(&mut host_with(ENUM), &rec).unwrap();
        assert_eq!(
            rec.entries().unwrap()[0].change,
            Change::WintunDriver {
                present_before: true
            }
        );
    }

    #[test]
    fn an_unreadable_driver_store_is_not_guessed_at() {
        let d = tmp();
        let rec = Record::new(d.join("setup-log.json"));
        let mut h = FakeHost::new("windows");
        h.answer("pnputil", 1, "");
        assert!(record_present_before(&mut h, &rec).is_err());
        assert!(rec.entries().unwrap().is_empty());
    }

    #[test]
    fn purge_removes_a_driver_that_was_absent_before_and_goes_without_force() {
        let mut h = FakeHost::new("windows");
        h.answer_in_order(
            "pnputil /enum-drivers",
            vec![
                Output {
                    code: 0,
                    stdout: ENUM.into(),
                    stderr: String::new(),
                },
                Output {
                    code: 0,
                    stdout: ENUM_WITHOUT.into(),
                    stderr: String::new(),
                },
            ],
        );
        let r = undo(&mut h, false);
        assert!(r.render().contains("removed"), "{}", r.render());
        assert!(h.ran("pnputil /delete-driver oem12.inf"));
        assert!(!h.commands.iter().any(|c| c.contains("/force")));
    }

    #[test]
    fn purge_keeps_a_driver_that_windows_will_not_delete() {
        let mut h = host_with(ENUM);
        h.answer("pnputil /delete-driver", 1, "");
        let r = undo(&mut h, false);
        assert!(
            r.render().contains("shared with other software"),
            "{}",
            r.render()
        );
        assert!(r.complete());
    }

    #[test]
    fn purge_keeps_a_driver_that_was_there_before_and_one_that_is_gone() {
        let mut h = FakeHost::new("windows");
        let r = undo(&mut h, true);
        assert!(r.render().contains("shared with other software"));
        assert!(h.commands.is_empty(), "nothing is run: {:?}", h.commands);

        let mut h = host_with(ENUM_WITHOUT);
        let r = undo(&mut h, false);
        assert!(!h.ran("pnputil /delete-driver"));
        assert!(r.complete());
    }
}
