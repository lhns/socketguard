# SocketGuard

Instructions for coding agents. What the project is and how to use it: README.md.

## Building

Always use the unified build script:

    ./build.sh                  # Release build (frontend + all crates)
    ./build.sh --debug          # Debug build
    ./build.sh --with-bundled   # also fetch the pinned Tor, Yggdrasil, Wintun (network, git, Go)

NEVER run `cargo build` or `npm run build` separately. The script checks versions, builds the
frontend first, then the Rust crates (release by default).

On fresh clone: run `cd ui && npm install` once first. `cargo test`, `clippy`, `check` and `fmt` are
fine to run directly.

## Project structure

- crates/core/    — Domain model (apps, peers, grants, reach), scope, addressing, config, paths,
                    portable, install_log, API types
- crates/daemon/  — The daemon and its admin commands:
    - engine/     reconcile, addresses, enforcement, mutations, reservations, tags, port groups
    - state/      SQLite schema and migrations, settings, file protection
    - networks/   ip/ (Local, LAN, Yggdrasil, DHCPv6), tor, managed children (managed.rs, *_managed.rs)
    - children/   the child processes of managed networks (guard, pidfile)
    - firewall/   nftables, pf, wfp/ (plan + Windows FFI); iface/ (addresses on OS interfaces); monitor/
    - service, install, uninstall, access, account, disable, portable (ADR 0050, 0054); ruleset,
      local API (api.rs), telemetry
- crates/client/  — Typed client for the local API (shared by CLI and UI)
- crates/cli/     — `socketguard` CLI, the primary frontend
- ui/             — React frontend; ui/src-tauri is the Tauri v2 Rust backend (crate socketguard-ui);
                    ui/src/generated is produced by `cargo test -p socketguard-core --features ts export_bindings`
- installer/      — windows/ (WiX MSI, portable zip), linux/ (nfpm deb/rpm), macos/ (pkg), payload/
                    (bundled third-party files per platform)
- deploy/         — bundle/ (fetch pinned Tor/Yggdrasil/Wintun), ci/ (version and footprint checks,
                    macOS smoke), e2e/ (Docker tests), otel/ (telemetry stack), systemd/
- test/           — Package tests: msi.ps1, portable.ps1, deb.sh, rpm.sh, rpm-systemd.sh, pkg.sh, managed.sh, managed-helpers.ps1 (sourced by the others)
- docs/           — adr/, api.md, cli.md, footprint.md, packaging.md, manual-checks.md
- .github/workflows/ — ci, packages (builds and installs each package), e2e (nightly/dispatch),
                    release (tags); .forgejo/workflows/ci.yml

## Testing

    cargo test --workspace --exclude socketguard-ui
    cd ui && npm run lint && npm run typecheck && npm test
    cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --all --check
    SOCKETGUARD_NETNS_TESTS=1 cargo test -p socketguard-daemon --test netns   # Linux, root
    deploy/e2e/ygg-e2e.sh; deploy/e2e/tor-e2e.sh                              # Docker (also managed-*-e2e.sh)
    deploy/ci/macos-smoke.sh                                                  # macOS, sudo; run by GitHub CI
    cargo test -p socketguard-daemon --test perf -- --ignored --nocapture     # performance harness
    cargo test -p socketguard-daemon --test locks                             # lock-order stress test

The package tests in test/ install real packages and run only in CI (packages.yml).

## Conventions

- ADRs are in docs/adr/ (`NNNN-short-title.md`: Status, Context, Decision, Consequences) and indexed
  in docs/adr/README.md. Document new decisions there. Amend or supersede an accepted decision with
  a new ADR; never rewrite it.
- docs/footprint.md must list everything SocketGuard puts on a host, with what removes it; update it
  with any change that adds a file, rule, account or setting on the host.
- One version: `[workspace.package]` in Cargo.toml; `deploy/ci/check-version.sh` (run by build.sh)
  checks that every crate, ui/package.json and tauri.conf.json agree.
- Every API route has a client method and a CLI command: the coverage tests in crates/daemon/tests
  and crates/cli/tests fail otherwise (ADR 0033). The UI covers the API too (ADR 0042).
- User-visible wording: "All ports", "port", "port group", "reserved address"; never "socket" or
  "whole app" for those concepts.
- LF line endings.
