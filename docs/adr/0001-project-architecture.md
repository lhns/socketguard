# ADR-0001: Project Architecture

## Status

Accepted

## Date

2026-03-12

## Context

Applications open TCP/UDP ports that are accessible to anyone on the network. Overlay networks like Yggdrasil create IPv6 addresses derived from public keys, making IPs usable as identity. But installing Yggdrasil exposes all application ports to the entire overlay network with no per-socket granularity.

We need a system that:
- Detects listening sockets on the host
- Assigns each socket its own unique IPv6 address
- Enforces per-socket access control lists via the OS firewall
- Provides a CLI and desktop GUI for management

## Decision

Adopt a **daemon + client** architecture with three Rust crates in a Cargo workspace:

```
socketguard/
├── crates/
│   ├── core/       # Shared types, traits, config, API types
│   ├── daemon/     # Long-running daemon (monitor, backends, firewall, REST API)
│   └── cli/        # CLI client that talks to the daemon via HTTP
└── ui/             # Tauri desktop app (React frontend)
```

- **core** is a pure library crate with no platform-specific code. It defines all shared types (`ListeningSocket`, `ManagedSocket`, `AclEntry`, `Policy`, `Protocol`, `BackendType`) and REST API request/response structs.
- **daemon** is the system service. It contains platform-specific modules behind `#[cfg(target_os)]` gates for socket monitoring, firewall management, and network interface control. It exposes a REST API via axum for clients.
- **cli** is a thin HTTP client that formats daemon responses for terminal output.
- **ui** is a Tauri v2 app with a React frontend, invoking Tauri commands that call the daemon API.

The daemon uses a **reconciliation loop** pattern: it periodically polls for listening sockets, compares against its database, and converges toward the desired state (each socket has an IPv6, firewall rules match the ACL).

## Consequences

- Clear separation between shared types (core), system logic (daemon), and user interfaces (cli, ui).
- The daemon is the single source of truth and authority. Clients are stateless.
- Platform-specific code is isolated behind traits, making it testable with mocks.
- The workspace structure allows independent compilation and testing of each crate.
- Adding new clients (e.g., a web dashboard) only requires speaking the REST API.
