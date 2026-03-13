pub mod api_types;
pub mod config;
pub mod types;

pub use config::{BackendConfig, ProcessFilter};
pub use types::*;

use std::path::PathBuf;

/// Returns the path to the API token file shared by daemon, CLI, and UI.
pub fn api_token_path() -> PathBuf {
    #[cfg(windows)]
    {
        // %LOCALAPPDATA%\SocketGuard\api-token — inherits user-only ACLs from LOCALAPPDATA
        let local_app_data = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| {
                let home = std::env::var("USERPROFILE").expect("neither LOCALAPPDATA nor USERPROFILE set");
                format!("{home}\\AppData\\Local")
            });
        PathBuf::from(local_app_data).join("SocketGuard").join("api-token")
    }
    #[cfg(not(windows))]
    {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join("socketguard").join("api-token")
        } else {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/socketguard-{uid}")).join("api-token")
        }
    }
}
