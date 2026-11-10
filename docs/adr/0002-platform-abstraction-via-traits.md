# ADR-0002: Platform Abstraction via Traits

## Status

Accepted

## Date

2026-03-12

## Context

SocketGuard must run on Linux, Windows, and macOS. Each platform has different APIs for:
- **Socket monitoring**: Linux uses `/proc/net/tcp6`, Windows uses `GetExtendedTcpTable` (via `netstat` as fallback), macOS uses `lsof`/`proc_pidinfo`.
- **Firewall management**: Linux uses nftables, macOS uses pf, Windows uses WFP (via `netsh advfirewall`).
- **Network interface management**: Linux uses `ip addr`, macOS uses `ifconfig`, Windows uses `netsh interface ipv6`.

We considered:
1. A single monolithic module with `#[cfg]` blocks scattered throughout
2. Trait-based abstraction with per-platform implementations in separate files
3. Separate platform-specific binaries

## Decision

Use **trait-based abstraction** with conditional compilation. Each subsystem defines a trait in its `mod.rs` and provides platform-specific implementations in separate files:

```
monitor/
├── mod.rs       # trait SocketMonitor + create_monitor()
├── linux.rs     # LinuxSocketMonitor
├── windows.rs   # WindowsSocketMonitor
└── macos.rs     # MacosSocketMonitor
```

Four traits are defined:
- `SocketMonitor` — `list_listening_sockets() -> Vec<ListeningSocket>`
- `Ipv6Backend` — `allocate_address() -> AllocatedAddress`, `release_address()`
- `Firewall` — `apply_acl()`, `remove_acl()`, `block_all()`, `allow_all()`
- `InterfaceManager` — `add_address()`, `remove_address()`

Each module provides a `create_*()` factory function that returns `Box<dyn Trait>`, selected at compile time via `#[cfg(target_os)]`.

## Consequences

- Each platform file is self-contained and can be understood in isolation.
- New platform support is added by implementing the trait and adding a `#[cfg]` branch.
- The engine and API code are platform-agnostic — they only interact with trait objects.
- Testing can use mock implementations without needing the real OS APIs.
- Only the relevant platform code is compiled into each binary.
