# SocketGuard

## Building

Always use the unified build script:

    ./build.sh            # Release build (frontend + all crates)
    ./build.sh --debug    # Debug build

NEVER run `cargo build` or `npm run build` separately. The script ensures
correct order (frontend first, then Rust) and uses release mode by default.

On fresh clone: run `cd ui && npm install` once first.

## Project structure

- crates/core/    — Domain model (apps, peers, grants, reach), config, API types
- crates/daemon/  — Daemon: engine/ (reconcile, addresses, enforcement, mutations),
                    state/ (SQLite schema, settings, file protection), monitor, iface/
                    (addresses on the OS interfaces), networks/ (ip/: Local, LAN,
                    Yggdrasil, DHCPv6; tor), ruleset producer, firewall/ (nftables, pf,
                    wfp/: plan + Windows FFI), local API, telemetry
- crates/client/  — Typed client for the local API (shared by CLI and UI)
- crates/cli/     — `socketguard` CLI, the primary frontend
- ui/             — Tauri v2 desktop app (React frontend + Rust backend);
                    ui/src/generated is produced by `cargo test -p socketguard-core --features ts export_bindings`
- installer/      — packages (ADR 0050): windows/ (WiX MSI), linux/ (nfpm deb+rpm), macos/ (pkg), payload/ (bundled third-party files); docs/packaging.md
- deploy/e2e/     — Docker end-to-end tests (Yggdrasil, Tor); deploy/otel/ — telemetry stack

## Testing

    cargo test --workspace --exclude socketguard-ui
    cd ui && npm run lint && npm run typecheck && npm test
    SOCKETGUARD_NETNS_TESTS=1 cargo test -p socketguard-daemon --test netns   # Linux, root
    deploy/e2e/ygg-e2e.sh; deploy/e2e/tor-e2e.sh                              # Docker
    deploy/ci/macos-smoke.sh  # macOS, sudo; run by GitHub CI
    # packages: .github/workflows/packages.yml builds each and installs it on a runner (test/msi.ps1, test/deb.sh, test/rpm.sh, test/pkg.sh)

## ADRs

Architecture decisions are in docs/adr/. Document new decisions there.
