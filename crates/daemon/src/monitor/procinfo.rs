//! Process details via the `sysinfo` crate, for the platforms without /proc (Windows,
//! macOS): the executable path and the full command line.

use std::collections::HashMap;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

pub struct ProcDetails {
    pub exe_path: Option<String>,
    /// argv, `argv[0]` first; None when the process hides it or exited.
    pub cmdline: Option<Vec<String>>,
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
            .with_exe(UpdateKind::Always),
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
                },
            ))
        })
        .collect()
}
