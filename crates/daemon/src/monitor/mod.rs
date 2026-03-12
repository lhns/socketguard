use anyhow::Result;
use socketguard_core::ListeningSocket;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Trait for platform-specific socket monitoring
pub trait SocketMonitor: Send + Sync {
    fn list_listening_sockets(&self) -> Result<Vec<ListeningSocket>>;
}

/// Create the platform-appropriate socket monitor
pub fn create_monitor() -> Box<dyn SocketMonitor> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxSocketMonitor)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsSocketMonitor)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosSocketMonitor)
    }
}
