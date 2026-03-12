# ADR-0010: Tauri Desktop App with React Frontend

## Status

Accepted

## Date

2026-03-12

## Context

SocketGuard needs a desktop GUI for users who prefer graphical management over the CLI. Options:

1. **Electron**: Mature, large ecosystem, but bundles Chromium (~150MB).
2. **Tauri v2**: Uses the system webview (WebView2 on Windows, WebKit on macOS/Linux), Rust backend, much smaller binaries (~5-10MB).
3. **Native GUI (egui, gtk-rs)**: No web tech, but less flexible for complex UIs and smaller ecosystem for UI components.
4. **Web-only dashboard**: No desktop app — serve a web UI from the daemon. Simpler but loses native integration (system tray, notifications).

## Decision

Use **Tauri v2** with a **React** (TypeScript) frontend.

### Architecture

The Tauri app is a thin layer:
- **Backend** (`src-tauri/src/main.rs`): Defines Tauri commands (`list_sockets`, `get_socket`, `allow_ip`, `remove_acl_entry`, `set_policy`, `get_config`) that use `reqwest` to call the daemon's REST API.
- **Frontend** (`src/`): React components that invoke Tauri commands via `@tauri-apps/api/core`.

The Tauri app does **not** embed the daemon — it connects to a separately running daemon process. This separation means:
- The daemon can run as a system service without a GUI.
- Multiple UI instances can connect to the same daemon.
- The UI doesn't need elevated privileges (the daemon does).

### Frontend Components

- `SocketList`: Table of detected sockets with auto-refresh (5s polling). Shows process name, port, IPv6, policy, and backend.
- `SocketDetail`: Detail view with policy toggle (closed/managed/open) and ACL editor (add/remove allowed IPs).
- `Settings`: Displays daemon configuration (read-only in initial version).

### Build Tooling

- Vite for frontend bundling
- TypeScript for type safety
- No CSS framework — inline styles for simplicity in the initial version

## Consequences

- Small binary size compared to Electron (~10x smaller).
- System webview dependency — WebView2 is pre-installed on Windows 10+, WebKit on macOS/Linux.
- Tauri v2 supports all three target platforms from a single codebase.
- The daemon must be running for the UI to function — the UI shows connection errors if the daemon is unreachable.
- Future enhancements: system tray integration, notifications on new socket detection, dark mode.
