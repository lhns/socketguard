# SocketGuard

## Building

Always use the unified build script:

    ./build.sh            # Release build (frontend + all crates)
    ./build.sh --debug    # Debug build

NEVER run `cargo build` or `npm run build` separately. The script ensures
correct order (frontend first, then Rust) and uses release mode by default.

On fresh clone: run `cd ui && npm install` once first.

## Project structure

- crates/core/    — Shared types, API types
- crates/daemon/  — System daemon
- crates/cli/     — CLI client
- ui/             — Tauri v2 desktop app (React frontend + Rust backend)
- cargo.sh        — Legacy cargo wrapper (superseded by build.sh)

## ADRs

Architecture decisions are in docs/adr/. Document new decisions there.
