//! Windows specifics of the real spawner (untested on a real service host, see the report):
//! a job object that ends every child when the daemon goes, and starting a child with the
//! LocalService token. Thin FFI; the rest is in `system`.

use super::system::{pump, Proc};
use super::*;
use ::windows::core::{w, PCWSTR, PWSTR};
use ::windows::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
};
use ::windows::Win32::Security::{
    LogonUserW, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, SECURITY_ATTRIBUTES,
};
use ::windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use ::windows::Win32::System::Pipes::CreatePipe;
use ::windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, INFINITE, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
};
use std::io;
use std::os::windows::io::FromRawHandle;
use std::sync::OnceLock;

/// The job every child belongs to. It is never closed by us: it closes with the daemon, and
/// Windows then ends all processes in it.
fn job() -> Option<usize> {
    static JOB: OnceLock<Option<usize>> = OnceLock::new();
    *JOB.get_or_init(|| {
        // SAFETY: plain job object calls; the info struct is valid for the call.
        unsafe {
            let job = CreateJobObjectW(None, PCWSTR::null()).ok()?;
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let set = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if set.is_err() {
                let _ = CloseHandle(job);
                return None;
            }
            Some(job.0 as usize)
        }
    })
}

/// Put the process into the job. A failure is logged: the child then outlives a crashed
/// daemon (its own watch on the daemon still ends it: Tor's owning-process option).
pub(super) fn assign_to_job(process: usize) {
    let Some(job) = job() else {
        warn!("Could not create the job object; children will not end with the daemon");
        return;
    };
    // SAFETY: both are valid handles for the call.
    let r = unsafe { AssignProcessToJobObject(HANDLE(job as *mut _), HANDLE(process as *mut _)) };
    if let Err(e) = r {
        warn!("Could not put a child into the job object: {e}");
    }
}

pub(super) fn terminate(process: usize) {
    // SAFETY: `process` is a live handle held by the caller (see `Proc::signal`).
    unsafe {
        let _ = TerminateProcess(HANDLE(process as *mut _), 1);
    }
}

fn os_error(what: &str, e: windows::core::Error) -> io::Error {
    io::Error::other(format!("{what}: {e}"))
}

/// `"program" arg ...` with the quoting `CommandLineToArgvW` undoes.
fn command_line(spec: &ChildSpec) -> Vec<u16> {
    fn quote(a: &str) -> String {
        if !a.is_empty() && !a.contains([' ', '\t', '"']) {
            return a.to_string();
        }
        let mut out = String::from("\"");
        let mut backslashes = 0;
        for c in a.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    out.push_str(&"\\".repeat(backslashes * 2 + 1));
                    out.push('"');
                    backslashes = 0;
                }
                c => {
                    out.push_str(&"\\".repeat(backslashes));
                    out.push(c);
                    backslashes = 0;
                }
            }
        }
        out.push_str(&"\\".repeat(backslashes * 2));
        out.push('"');
        out
    }
    let mut line = quote(&spec.program.display().to_string());
    for a in &spec.args {
        line.push(' ');
        line.push_str(&quote(a));
    }
    line.encode_utf16().chain(Some(0)).collect()
}

/// `KEY=value\0...\0\0`, sorted as Windows wants.
fn environment(spec: &ChildSpec) -> Vec<u16> {
    let mut vars: Vec<(String, String)> = spec.env.clone();
    for var in ["SystemRoot", "windir"] {
        if let Ok(v) = std::env::var(var) {
            vars.push((var.to_string(), v));
        }
    }
    // LocalService has its own profile: its temp directory is not ours.
    vars.sort_by_key(|(k, _)| k.to_uppercase());
    let mut block: Vec<u16> = vars
        .iter()
        .flat_map(|(k, v)| format!("{k}={v}\0").encode_utf16().collect::<Vec<_>>())
        .collect();
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    block
}

fn pipe() -> io::Result<(HANDLE, HANDLE)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
    // SAFETY: the out pointers are valid for the call.
    unsafe {
        CreatePipe(&mut read, &mut write, Some(&sa), 0).map_err(|e| os_error("CreatePipe", e))?;
    }
    Ok((read, write))
}

/// Start the child with the LocalService token (needs a daemon that may log it on, in
/// practice SYSTEM). Whether that works is checked beforehand, when the account is chosen
/// (`tor_child::resolve_run_as`); a spec with `RunAs::LocalService` is not started any
/// other way.
pub(super) async fn spawn_local_service(
    spec: &ChildSpec,
    out: mpsc::Sender<Line>,
) -> io::Result<Box<dyn ChildProc>> {
    let spec_owned = spec.clone();
    let started = tokio::task::spawn_blocking(move || start_as_local_service(&spec_owned))
        .await
        .map_err(io::Error::other)?;
    match started {
        Ok((pid, process, stdout)) => {
            pump(tokio::fs::File::from_std(stdout), out, false);
            let target = Arc::new(Mutex::new(Some(process)));
            let (exit_tx, exit_rx) = watch::channel(None);
            let reaped = target.clone();
            // The wait blocks a thread of its own until the process ends.
            std::thread::spawn(move || {
                // SAFETY: `process` is a live handle owned by this thread until closed below.
                let info = unsafe {
                    let h = HANDLE(process as *mut _);
                    WaitForSingleObject(h, INFINITE);
                    let mut code = 0u32;
                    let ok = GetExitCodeProcess(h, &mut code).is_ok();
                    ExitInfo {
                        description: if ok {
                            format!("exit code {code}")
                        } else {
                            "ended".into()
                        },
                    }
                };
                let mut t = reaped.lock().unwrap();
                *t = None;
                // SAFETY: closed once, after the lock keeps `terminate` away from it.
                unsafe {
                    let _ = CloseHandle(HANDLE(process as *mut _));
                }
                drop(t);
                let _ = exit_tx.send(Some(info));
            });
            Ok(Box::new(Proc::new(
                pid,
                exit_rx,
                Some("LocalService".into()),
                target,
            )))
        }
        // No fallback here: whether LocalService is used was decided before the directory
        // was prepared for it (`Accounts::local_service_logon`), and the start just fails
        // and is tried again.
        Err(why) => Err(io::Error::other(format!(
            "could not start {} as LocalService: {why}",
            spec.name
        ))),
    }
}

/// A token of the LocalService account (the caller closes it).
fn logon_local_service() -> Result<HANDLE, String> {
    let mut token = HANDLE::default();
    // SAFETY: the out pointer is valid for the call.
    unsafe {
        LogonUserW(
            w!("LocalService"),
            w!("NT AUTHORITY"),
            PCWSTR::null(),
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    }
    .map_err(|e| format!("LogonUser: {e}"))?;
    Ok(token)
}

/// Whether this process may log LocalService on, which decides whether a child is started
/// as it (and so what the data directory is prepared for and whose files are trusted).
pub(crate) fn check_local_service_logon() -> Result<(), String> {
    let token = logon_local_service()?;
    // SAFETY: the token was just made and is closed once.
    unsafe {
        let _ = CloseHandle(token);
    }
    Ok(())
}

/// The blocking part: log on, make the pipes, `CreateProcessAsUserW`, join the job.
/// Returns the pid, the process handle and the read end of the output pipe.
fn start_as_local_service(spec: &ChildSpec) -> Result<(u32, usize, std::fs::File), String> {
    let token = logon_local_service()?;
    // SAFETY: every handle is closed on every path below; buffers outlive the calls.
    unsafe {
        let close_all = |hs: &[HANDLE]| {
            for h in hs {
                let _ = CloseHandle(*h);
            }
        };
        let (out_r, out_w) = pipe().map_err(|e| {
            close_all(&[token]);
            e.to_string()
        })?;
        let (in_r, in_w) = pipe().map_err(|e| {
            close_all(&[token, out_r, out_w]);
            e.to_string()
        })?;
        // Our ends of the pipes must not be inherited by the child.
        let _ = SetHandleInformation(out_r, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
        let _ = SetHandleInformation(in_w, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: in_r,
            hStdOutput: out_w,
            hStdError: out_w,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd = command_line(spec);
        let env = environment(spec);
        let program: Vec<u16> = spec
            .program
            .display()
            .to_string()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let cwd: Option<Vec<u16>> = spec.cwd.as_ref().map(|c| {
            c.display()
                .to_string()
                .encode_utf16()
                .chain(Some(0))
                .collect()
        });
        let created = CreateProcessAsUserW(
            Some(token),
            PCWSTR(program.as_ptr()),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            Some(env.as_ptr().cast()),
            cwd.as_ref().map_or(PCWSTR::null(), |c| PCWSTR(c.as_ptr())),
            &si,
            &mut pi,
        );
        // The child has its ends; ours of those are done either way.
        close_all(&[token, out_w, in_r, in_w]);
        if let Err(e) = created {
            close_all(&[out_r]);
            return Err(format!("CreateProcessAsUser: {e}"));
        }
        let _ = CloseHandle(pi.hThread);
        assign_to_job(pi.hProcess.0 as usize);
        let file = std::fs::File::from_raw_handle(out_r.0);
        Ok((pi.dwProcessId, pi.hProcess.0 as usize, file))
    }
}
