# Known Issues & Future Work

Tracked issues that are documented for later resolution. Organized by severity.

## Security

### Private keys stored unencrypted
- **Location**: `crates/daemon/src/state.rs` — `save_keypair()`
- **Issue**: The `keypairs` table column is named `private_key_encrypted` but stores raw Ed25519 private key bytes. Anyone with read access to the SQLite file gets the keys.
- **Mitigation**: Database file permissions should be restricted (0600). The daemon runs as root so the file is owned by root.
- **Fix**: Encrypt private keys at rest using a passphrase or OS keychain (Windows DPAPI / macOS Keychain / Linux secret-tool).

### No API authentication
- **Location**: `crates/daemon/src/api.rs`
- **Issue**: The REST API has no authentication. Any process on localhost can modify ACLs and policies. `CorsLayer::permissive()` is used.
- **Mitigation**: The API binds to `127.0.0.1` only, so it's not network-accessible by default.
- **Fix**: Add token-based auth or Unix socket with peer credential checking. Restrict CORS to the Tauri app origin.

### Daemon runs as root
- **Issue**: The daemon needs root/admin to manage firewall rules and interface addresses. If the unauthenticated API is exploited, the attacker gains root-level network control.
- **Fix**: Split into a privileged helper (firewall + network ops only) and an unprivileged daemon (API + state). Or use capabilities (CAP_NET_ADMIN on Linux) instead of full root.

## Platform Gaps

### macOS: PF may not be enabled
- **Location**: `crates/daemon/src/firewall/pf.rs`
- **Issue**: Modern macOS uses Application Firewall (socketfilterfw), not PF. PF rules may have no effect unless `pfctl -e` has been run.
- **Fix**: Detect PF state on startup, warn if disabled, optionally enable it.

### macOS/Windows: exe_path not resolved
- **Location**: `crates/daemon/src/monitor/macos.rs`, `windows.rs`
- **Issue**: `exe_path` is `None` on macOS and Windows. Only Linux resolves it via `/proc/{pid}/exe`.
- **Fix**: macOS: use `proc_pidpath()`. Windows: use `QueryFullProcessImageNameW` via windows-rs.

### Linux: nftables may not be installed
- **Location**: `crates/daemon/src/firewall/nftables.rs`
- **Issue**: Some Linux distros use iptables-legacy. No detection or fallback.
- **Fix**: Check for `nft` on startup. Optionally add an iptables backend.

### Windows: tasklist spawned per socket
- **Location**: `crates/daemon/src/monitor/windows.rs` — `get_process_info()`
- **Issue**: Each detected socket spawns a `tasklist` subprocess to resolve the process name. With 50 sockets, that's 50 processes per poll cycle.
- **Fix**: Use `GetExtendedTcpTable` / `GetExtendedUdpTable` via windows-rs which return PID + name in one call. Or batch the tasklist query.

## Architecture

### Config changes don't propagate to engine
- **Location**: `crates/daemon/src/api.rs` — `update_config()`
- **Issue**: `PUT /api/config` updates the `RwLock<DaemonConfig>` but the engine holds its own `Box<dyn Ipv6Backend>`, `Box<dyn Firewall>`, etc. created at startup. Changing the backend or interface via the API has no effect until restart. Existing IPv6 addresses aren't migrated to a new interface.
- **Fix**: Either restart the engine subsystems on config change, or make the engine re-read config each cycle (it already reads `interface` from config, but not `backend`).

### No graceful shutdown
- **Issue**: The daemon has no signal handling. On SIGTERM/Ctrl+C, firewall rules and IPv6 addresses are orphaned.
- **Fix**: Add a signal handler that cleans up all managed rules and addresses before exit.

### Firewall rule orphaning on crash
- **Issue**: If the daemon crashes, firewall rules and IPv6 addresses remain on the system. On restart, old rules may conflict with new ones.
- **Fix**: On startup, scan for rules matching the `sg_*` / `SocketGuard_*` naming pattern and clean them up. Add a `--cleanup` CLI flag.

## UX

### UI: no confirmation for destructive actions
- **Location**: `ui/src/components/SocketDetail.tsx`
- **Issue**: Clicking a policy button immediately applies it. Switching to "open" exposes the service without confirmation.
- **Fix**: Add a confirmation dialog for policy changes to "open" and for ACL deletions.

### UI: no feedback on success/failure
- **Issue**: After adding an ACL entry or changing policy, there's no visual feedback (toast/notification).
- **Fix**: Add a toast notification system.

### UI: Settings page is read-only
- **Location**: `ui/src/components/Settings.tsx`
- **Issue**: Displays config but can't edit it.
- **Fix**: Add form inputs that `PUT /api/config`.

### CLI: no JSON output mode
- **Issue**: The CLI only outputs human-readable tables. Not scriptable.
- **Fix**: Add `--json` flag that outputs raw JSON responses.

### CLI: no shell completions
- **Issue**: No tab completion for bash/zsh/fish.
- **Fix**: Use clap's `clap_complete` crate to generate completion scripts.
