//! The things that end a portable daemon on Windows: the owner watch, the console and
//! session handlers, and the hidden window's message loop.

use super::{request_stop, wait_done, AccountKind};
use anyhow::{bail, Result};
use std::time::Duration;
use windows::core::{w, BOOL, HSTRING, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
    CTRL_SHUTDOWN_EVENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
    TranslateMessage, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_ENDSESSION, WM_QUERYENDSESSION,
    WNDCLASSW,
};

struct Owner(HANDLE);
// SAFETY: a process handle may be waited on from any thread.
unsafe impl Send for Owner {}

/// Stop the daemon when process `pid` is gone. A process that cannot be watched is an
/// error: the daemon would outlive its window and leave the rules in place.
pub fn watch_owner(pid: u32) -> Result<()> {
    // SAFETY: plain handle calls; the handle is closed by the thread that waits on it.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }.map_err(|e| {
        anyhow::anyhow!("cannot watch the owner process {pid}: {e} (is it still running?)")
    })?;
    let owner = Owner(handle);
    std::thread::Builder::new()
        .name("owner-watch".into())
        .spawn(move || {
            let owner = owner;
            // SAFETY: the handle is valid until closed below.
            unsafe {
                WaitForSingleObject(owner.0, INFINITE);
                let _ = CloseHandle(owner.0);
            }
            tracing::info!("The owner process {pid} ended");
            request_stop();
        })
        .map_err(|e| anyhow::anyhow!("cannot start the owner watch: {e}"))?;
    Ok(())
}

/// Windows ends a console process a few seconds after it calls the handler, so close,
/// logoff and shutdown wait here for the teardown to finish before returning.
unsafe extern "system" fn on_console_event(kind: u32) -> BOOL {
    match kind {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            request_stop();
            BOOL(1)
        }
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            request_stop();
            wait_done(Duration::from_secs(4));
            BOOL(1)
        }
        _ => BOOL(0),
    }
}

unsafe extern "system" fn on_window_message(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        // Do not veto: protection ending with the session is the point.
        WM_QUERYENDSESSION => LRESULT(1),
        // wParam false: another program vetoed and the session goes on.
        WM_ENDSESSION if wparam.0 != 0 => {
            request_stop();
            wait_done(Duration::from_secs(20));
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Console events through the control handler; logoff and shutdown through a hidden
/// top-level window on a thread of its own (a message-only window gets no broadcast
/// messages, and creating any window makes the console handler stop receiving those
/// two events).
pub fn install_handlers() {
    // SAFETY: registers a handler with a static lifetime.
    if let Err(e) = unsafe { SetConsoleCtrlHandler(Some(on_console_event), true) } {
        tracing::warn!("Cannot register the console control handler: {e}");
    }
    let started = std::thread::Builder::new()
        .name("end-session".into())
        .spawn(|| {
            if let Err(e) = message_loop() {
                tracing::warn!("The logoff/shutdown watch is not running: {e:#}");
            }
        });
    if let Err(e) = started {
        tracing::warn!("Cannot start the logoff/shutdown watch: {e}");
    }
}

fn message_loop() -> Result<()> {
    // SAFETY: the usual window-class and message-loop calls; every pointer is to a
    // static string or a local that outlives the call.
    unsafe {
        let instance: HINSTANCE = GetModuleHandleW(None)?.into();
        let class = w!("SocketGuardPortableEndSession");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(on_window_message),
            hInstance: instance,
            lpszClassName: class,
            ..Default::default()
        };
        if RegisterClassW(&wc) == 0 {
            bail!("RegisterClassW failed");
        }
        // Never shown: no WS_VISIBLE, no ShowWindow.
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            w!("SocketGuard"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance),
            None,
        )?;
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    // The loop only ends if the window is destroyed; the handlers above keep working.
    Ok(())
}

/// What the SID names, by `LookupAccountSidW` (the local machine first, then its domain).
pub fn account_kind(sid: &str) -> AccountKind {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::{
        LookupAccountSidW, SidTypeAlias, SidTypeGroup, SidTypeUser, SidTypeWellKnownGroup, PSID,
        SID_NAME_USE,
    };
    // SAFETY: the SID comes from ConvertStringSidToSidW and is freed with LocalFree; the
    // buffers are sized by the lengths passed.
    unsafe {
        let mut psid = PSID::default();
        if ConvertStringSidToSidW(PCWSTR(HSTRING::from(sid).as_ptr()), &mut psid).is_err() {
            return AccountKind::Unresolved;
        }
        let mut name = vec![0u16; 512];
        let mut domain = vec![0u16; 512];
        let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
        let mut kind = SID_NAME_USE(0);
        let found = LookupAccountSidW(
            PCWSTR::null(),
            psid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        );
        let _ = LocalFree(Some(HLOCAL(psid.0)));
        if found.is_err() {
            return AccountKind::Unresolved;
        }
        if kind == SidTypeUser {
            AccountKind::User
        } else if kind == SidTypeGroup || kind == SidTypeAlias || kind == SidTypeWellKnownGroup {
            AccountKind::Group
        } else {
            AccountKind::Other
        }
    }
}
