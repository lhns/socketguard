//! Process details via the `sysinfo` crate, for the platforms without /proc (Windows,
//! macOS): the executable path, the full command line and the owning user.

use socketguard_core::ListeningSocket;
use std::collections::{BTreeSet, HashMap};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

pub struct ProcDetails {
    pub exe_path: Option<String>,
    /// argv, `argv[0]` first; None when the process hides it or exited.
    pub cmdline: Option<Vec<String>>,
    /// The uid on macOS, the owner SID string on Windows.
    pub uid: Option<String>,
    /// The working directory, when the platform lets us read it.
    pub cwd: Option<String>,
}

/// Look up `pids` in one refresh.
pub fn lookup(pids: &[u32]) -> HashMap<u32, ProcDetails> {
    let sys_pids: Vec<Pid> = pids.iter().map(|p| Pid::from_u32(*p)).collect();
    let Ok(mut sys) = System::new() else {
        return HashMap::new();
    };
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&sys_pids),
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always)
            .with_cwd(UpdateKind::Always)
            .with_user(UpdateKind::Always),
    );
    pids.iter()
        .filter_map(|pid| {
            let p = sys.process(Pid::from_u32(*pid))?;
            let cmd: Vec<String> = p
                .cmd()
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            Some((
                *pid,
                ProcDetails {
                    exe_path: p.exe().map(|e| e.to_string_lossy().into_owned()),
                    cmdline: (!cmd.is_empty()).then_some(cmd),
                    uid: p
                        .effective_user_id()
                        .or_else(|| p.user_id())
                        .map(|u| (**u).to_string()),
                    cwd: p.cwd().map(|c| c.to_string_lossy().into_owned()),
                },
            ))
        })
        .collect()
}

/// Fill the command line, working directory and owner of `sockets` from one lookup of
/// their processes. The executable path is only replaced when `override_exe` is set (the
/// caller's own source is less reliable); it is filled in when missing either way.
pub fn apply(sockets: &mut [ListeningSocket], override_exe: bool) {
    let pids: Vec<u32> = sockets
        .iter()
        .map(|s| s.pid)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let details = lookup(&pids);
    for s in sockets {
        let Some(d) = details.get(&s.pid) else {
            continue;
        };
        s.cmdline = d.cmdline.clone();
        s.cwd = d.cwd.clone();
        s.uid = d.uid.clone();
        if d.exe_path.is_some() && (override_exe || s.exe_path.is_none()) {
            s.exe_path = d.exe_path.clone();
        }
    }
}
