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
| `socketguard-client` | Typed client for the local API (used by the CLI and the UI) |
| `socketguard-cli` | The `socketguard` command line, the primary frontend |
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
./target/release/socketguard
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

The daemon serves a local API on a Unix socket (`/run/socketguard.sock`) or, on Windows, the named pipe `\\.\pipe\socketguard` (see [docs/api.md](docs/api.md) for access control), and begins polling for listening sockets every 2 seconds (configurable via `poll_interval_secs`).

On startup, the daemon cleans up any stale firewall rules left by a previous crash and re-applies rules from the database. On shutdown (Ctrl+C or SIGTERM) rules and addresses stay in place, so the host stays protected; `socketguard disable` (or `socketguard-daemon --disable` with the daemon stopped) removes them and keeps them off until `socketguard enable`.

### CLI

`socketguard` covers the whole API. `--json` prints the API types as JSON for every command; `--socket <path>` (or `SOCKETGUARD_SOCKET`) selects a non-default daemon. Apps, peers and groups can be named by id, unique id prefix or name. Errors print `error: <code>: <message>` and exit 1. Details are in [docs/api.md](docs/api.md) and ADR 0033.

```bash
socketguard init                              # first-run setup (networks, sshd/RDP grants, protect-host)
socketguard status                            # daemon, networks, protect-host, counts
socketguard pending                           # new apps; interactive on a terminal
socketguard apps list [--pending]             # also: show, review, rm, split, merge
socketguard apps show nginx                   # addresses, ports, grants with reach, counters
socketguard share nginx                       # [addr]:port and http(s):// URLs

socketguard peers add alice <ygg-key>         # bare values: 64 hex = ygg_key, IP/CIDR = ip
socketguard peers add bob --addr 2001:db8::7 --cred wg_key=<base64>
socketguard peers list                        # also: show, rename, rm, cred add|rm
socketguard groups add team alice bob         # also: list, show, rename, rm, members

socketguard grant nginx:80 alice              # or group:team, or anyone (asks, or --yes)
socketguard grant sshd:22 alice --network ygg
socketguard revoke nginx:80 alice             # or: revoke <grant-id>
socketguard grants [--app A] [--peer P] [--group G]

socketguard networks list                     # also: add <type> --interface X, rm <id>
socketguard settings address-mode per-port    # or per-app; `settings show`
socketguard protect-host on eth0              # refused if sshd/RDP would be cut off; --force
socketguard activity --blocked [--follow]     # also: --app, --peer, --kind, --limit
socketguard watch                             # every push event, one line each

socketguard export -o socketguard.toml        # TOML, or JSON with a .json name / --format json
socketguard apply -f socketguard.toml         # shows the diff, asks; --dry-run, --yes
socketguard disable --yes                     # remove all rules and addresses, keep them off
socketguard enable
socketguard completions bash                  # also: zsh, fish, powershell, elvish
```

Reach is shown per network as `verified`, `whole subnet`, `IP only`, `open` or `not reachable`. Completions are static (subcommands and options, not app or peer names).

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
  "backend": "ula",
  "interface": "lo",
  "poll_interval_secs": 2,
  "db_path": "socketguard.db",
  "log_level": "info"
}
```

| Field | Description | Default |
|-------|-------------|---------|
| `api_socket` | Unix socket of the local API | `/run/socketguard.sock` |
| `api_pipe` | Windows named pipe of the local API | `\\.\pipe\socketguard` |
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

### Tor (onion services)

A Tor network publishes each app as an onion service through Tor's control port, so peers behind
NAT can reach it without any open port. Access is enforced by Tor client authorization: an app is
not published until it is granted, and a grant to a peer holding a `tor_client_key` (the base32
x25519 public key from `authorized_clients`) lets only that client in.

```bash
# tor with: ControlPort 9051 and CookieAuthentication 1
socketguard networks add tor                    # --control 127.0.0.1:9051 [--password ...]
socketguard peers add bob --tor-key <base32>    # the key bob's Tor client generated
socketguard grant myapp:8080 bob
socketguard apps show myapp                     # prints the .onion name
socketguard share myapp                         # http://<id>.onion:8080
```

The service keys live in the daemon's database (mode 0600 on Unix; on Windows keep it where only
the service account and Administrators have access). See ADR 0037 and 0039. A Docker end-to-end
test is in `deploy/e2e/tor-e2e.sh`.

## API

The daemon exposes a local REST API with server-sent events on a Unix socket or Windows named
pipe; there is no network listener. Routes, error codes, events, access control and the export
format are in [docs/api.md](docs/api.md).

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
