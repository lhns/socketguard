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

### Linux: nftables may not be installed
- **Location**: `crates/daemon/src/firewall/nftables.rs`
- **Issue**: Some Linux distros use iptables-legacy. No detection or fallback.
- **Fix**: Check for `nft` on startup. Package a statically linked iptables as fallback, or add an iptables backend.

## Infrastructure

### No CI/CD
- **Issue**: No automated build/test pipeline.
- **Fix**: Add GitHub Actions (or Gitea Actions) with Linux, Windows, macOS runners.

### No service integration
- **Issue**: No systemd unit, launchd plist, or Windows service registration.
- **Fix**: Add install/service management to the CLI (`socketguard-cli install`).

