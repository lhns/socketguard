# SocketGuard

Per-socket IPv6 access control. Assign each listening socket its own unique IPv6 address with granular, per-socket firewall rules.

## Problem

Applications open TCP ports that are accessible to anyone on the network. Overlay networks like Yggdrasil create IPv6 addresses derived from public keys, making IPs usable as identity — but installing Yggdrasil exposes **all** application ports to the entire overlay network.

SocketGuard solves this by giving each listening socket its own unique IPv6 address with independent access control.

## How It Works

```
1. DETECT   — Daemon polls the OS for listening sockets (process, PID, port)
2. ASSIGN   — Each new socket gets a unique IPv6 (ULA or Yggdrasil-derived)
3. BIND     — The IPv6 address is added to the network interface
4. FIREWALL — Rules block all traffic to that address:port by default
5. MANAGE   — User configures per-socket ACLs via CLI or desktop app
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Tauri App   │────▶│   Daemon     │────▶│  OS Firewall    │
│  (Desktop)   │     │  (REST API)  │     │  (nft/pf/wfp)   │
└─────────────┘     │              │     └─────────────────┘
┌─────────────┐     │  - Socket    │     ┌─────────────────┐
│    CLI       │────▶│    Monitor   │────▶│  Network Iface  │
└─────────────┘     │  - IPv6 Mgmt │     │  (add/rm IPv6)  │
                    │  - ACL Engine│     └─────────────────┘
                    │  - Config DB │     ┌─────────────────┐
                    └──────┬───────┘────▶│  IPv6 Backend   │
                           │             │  (Yggdrasil/ULA)│
                           ▼             └─────────────────┘
                    ┌──────────────┐
                    │  SQLite DB   │
                    └──────────────┘
```

The project is a Cargo workspace with three crates plus a Tauri desktop app:

| Crate | Description |
|-------|-------------|
| `socketguard-core` | Shared types, config, API types |
| `socketguard-daemon` | System daemon with monitoring, IPv6 backends, firewall, REST API |
| `socketguard-cli` | CLI client for managing sockets and ACLs |
| `socketguard-ui` | Tauri v2 desktop app with React frontend |

## Building

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs))
- On Windows: Visual Studio Build Tools + Windows SDK
- On Linux: `nft` (nftables) for firewall rules
- On macOS: `pfctl` (built-in)

### Build

```bash
# Build all crates (daemon + CLI)
cargo build --release

# The daemon binary
./target/release/socketguard-daemon

# The CLI binary
./target/release/socketguard-cli
```

### Tauri Desktop App

The `custom-protocol` feature (enabled by default) embeds frontend assets into the exe.
The build.rs automatically rebuilds the frontend (`npm run build`) when source files
change, using content hashing to detect changes. On a fresh clone, install dependencies
first:

```bash
cd ui
npm install

# Then build via cargo (frontend rebuild is automatic)
cd ..
cargo build --release -p socketguard-ui

# Or use the Tauri CLI directly
cd ui
npm run tauri build
```

> **Note:** `cargo build --release` works because `custom-protocol` is a default feature.
> For dev mode with hot reload, use `npm run tauri dev` (which disables it automatically).

## Usage

### Start the Daemon

The daemon requires elevated privileges to manage firewall rules and network interfaces.

```bash
# Linux/macOS
sudo ./target/release/socketguard-daemon

# Windows (run as Administrator)
.\target\release\socketguard-daemon.exe
```

The daemon starts a REST API on `127.0.0.1:9476` and begins polling for listening sockets every 2 seconds (configurable via `poll_interval_secs`).

On startup, the daemon cleans up any stale firewall rules left by a previous crash and re-applies rules from the database. On shutdown (Ctrl+C or SIGTERM), it removes all managed firewall rules and IPv6 addresses.

### CLI

All commands support `--json` for machine-readable output and `--api <url>` to connect to a non-default daemon address.

```bash
# List all detected sockets
socketguard-cli list

# Show details for a socket (use ID from list output)
socketguard-cli show <socket-id>

# Set a socket's policy to managed
socketguard-cli policy <socket-id> managed

# Allow a specific IPv6 to connect
socketguard-cli acl allow <socket-id> fd12:3456::1 --label "my-laptop"

# Remove an ACL entry
socketguard-cli acl remove <socket-id> <entry-id>

# View current ACL
socketguard-cli acl list <socket-id>

# Check if daemon is running
socketguard-cli status

# Show daemon config
socketguard-cli config

# List available IPv6 backends
socketguard-cli backends

# Generate shell completions
socketguard-cli completions bash   # also: zsh, fish, powershell
```

### Policies

Each socket has one of three policies:

| Policy | Behavior |
|--------|----------|
| `closed` | Block all incoming connections (default for new sockets) |
| `managed` | Allow only IPs in the socket's ACL |
| `open` | Allow all incoming connections |

### Desktop App

Launch the Tauri app to get a graphical interface for:
- Viewing all detected sockets with their assigned IPv6 addresses
- Toggling policies per socket
- Adding/removing ACL entries
- Viewing and editing daemon configuration

## Configuration

The daemon reads `socketguard.json` (or the path in `$SOCKETGUARD_CONFIG`) on startup:

```json
{
  "listen_addr": "127.0.0.1",
  "listen_port": 9476,
  "backend": "ula",
  "interface": "lo",
  "poll_interval_secs": 2,
  "db_path": "socketguard.db",
  "log_level": "info"
}
```

| Field | Description | Default |
|-------|-------------|---------|
| `listen_addr` | REST API bind address | `127.0.0.1` |
| `listen_port` | REST API port | `9476` |
| `backend` | IPv6 backend: `ula` or `yggdrasil` | `ula` |
| `interface` | Network interface for IPv6 addresses | `lo` (Linux), `lo0` (macOS), `Loopback Pseudo-Interface 1` (Windows) |
| `poll_interval_secs` | Socket polling interval | `2` |
| `db_path` | SQLite database path | `socketguard.db` |
| `log_level` | Log level: `trace`, `debug`, `info`, `warn`, `error` | `info` |

## IPv6 Backends

### ULA (default)

Generates random addresses in the `fd00::/8` range. No external dependencies. Suitable for local use and testing.

### Yggdrasil

Generates Ed25519 keypairs and derives addresses in the `200::/7` range using Yggdrasil's address derivation algorithm. This enables identity-based access control — allowing a Yggdrasil address is equivalent to allowing the holder of the corresponding private key.

## REST API

The daemon exposes a REST API on `127.0.0.1:9476`:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/sockets` | List all sockets |
| `GET` | `/api/sockets/:id` | Socket detail + ACL |
| `PUT` | `/api/sockets/:id/acl` | Replace ACL entries |
| `POST` | `/api/sockets/:id/acl/allow` | Add allowed IP |
| `DELETE` | `/api/sockets/:id/acl/:entry_id` | Remove ACL entry |
| `PUT` | `/api/sockets/:id/policy` | Set policy |
| `GET` | `/api/config` | Get config |
| `PUT` | `/api/config` | Update config |
| `GET` | `/api/backends` | List backends |
| `GET` | `/api/events` | SSE stream (push notifications) |

## Platform Support

| Component | Linux | Windows | macOS |
|-----------|-------|---------|-------|
| Socket Monitor | `/proc/net/tcp6` | `GetExtendedTcpTable` | `lsof` |
| Firewall | nftables (`nft`) | `netsh advfirewall` | `pfctl` |
| Network Interface | `ip addr` | `netsh interface ipv6` | `ifconfig` |

## Architecture Decisions

Detailed architecture decisions are documented as ADRs in [`docs/adr/`](docs/adr/).

## License

MIT
