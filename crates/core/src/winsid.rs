//! Windows: the SID of the account a process runs as.

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The SID string of the account running this process (its own token, not an elevated one
/// it may have started a child with), or none when the token cannot be read.
pub fn current_user_sid() -> Option<String> {
    // SAFETY: token queries on the current process; the buffer is sized by the first call.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let sid = if len > 0
            && GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                len,
                &mut len,
            )
            .is_ok()
        {
            let user = (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            let mut out = PWSTR::null();
            ConvertSidToStringSidW(user, &mut out).ok().and_then(|()| {
                let s = out.to_string().ok();
                let _ = LocalFree(Some(HLOCAL(out.0.cast())));
                s
            })
        } else {
            None
        };
        let _ = CloseHandle(token);
        sid
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_current_account_has_a_user_sid() {
        let sid = super::current_user_sid().expect("the token of this process is readable");
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }
}
