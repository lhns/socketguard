# SocketGuard

Secure by default, without NAT. Every app on a host gets its own IPv6 address per network,
everything is closed until you grant access, and access is granted to *peers* (ideally
identified by public key), not to IP strings.

## Why

Without NAT, every listening port is reachable by anyone who can route to the host. Overlay
networks like Yggdrasil make this worse — installing one exposes every port to the whole
overlay — but they also make source addresses provable: on Yggdrasil a packet's source is
cryptographically bound to the sender's key. SocketGuard builds on that:

- **Apps, not ports.** Listening processes are grouped into apps (interpreter-aware, stable
  across upgrades). Each app gets an address per network; ports can be split onto their own
  address or merged.
- **Peers, not IPs.** A peer is a label plus credentials: a Yggdrasil key or address, an IP or
  CIDR, a Tor client key. Each grant shows per network whether it is `verified` by key,
  `IP only`, or `not reachable` there.
- **Closed by default.** All SocketGuard addresses and the whole Yggdrasil interface deny
  inbound traffic unless a grant allows it. Whole-host protection is opt-in, with a guard
  against locking yourself out of SSH/RDP.
- **Frozen on stop.** Stopping the daemon keeps rules and addresses in place;
  `socketguard disable` is the only way to remove them.

## Networks

| Network | Addresses | Identity of sources |
|---|---|---|
| Local (ULA on loopback) | `fd..::/48`, this machine only | — |
| LAN (SLAAC, DHCPv6) | from the LAN's global or ULA `/64` | IP only |
| Yggdrasil | `/128`s from the node's `300::/64` | verified by key |
| Tor | one onion service per address | verified by Tor client key |

WireGuard (existing interfaces) and an mTLS gateway are planned; see ADR 0036/0037.

## Architecture

```
socketguard (CLI) ─┐                    ┌─▶ firewall: nftables / pf / WFP (atomic desired state)
                   ├─▶ local API ─▶ daemon ─▶ interfaces: add/remove addresses
desktop UI (Tauri) ┘  (Unix socket /    ├─▶ networks: Local, LAN, Yggdrasil, Tor
                       named pipe)      └─▶ SQLite (schema v2) + activity log + OpenTelemetry
```

| Crate | Description |
|-------|-------------|
| `socketguard-core` | Domain model, credentials and reach rules, config, API types |
| `socketguard-daemon` | Monitor, networks, ruleset producer, firewall backends, API |
| `socketguard-client` | Typed client for the local API (used by the CLI and the UI) |
| `socketguard-cli` | The `socketguard` command line, the primary frontend |
| `socketguard-ui` | Tauri v2 desktop app (Apps, Peers, Activity, Settings) |

## Building

Prerequisites: Rust (via [rustup](https://rustup.rs)) and Node.js; on Windows the Visual
Studio Build Tools; at runtime `nft` on Linux, `pfctl` on macOS. On a fresh clone run
`cd ui && npm install` once, then:

```bash
./build.sh            # release build: frontend, then all crates
./build.sh --debug    # debug build
```

Binaries: `target/<profile>/socketguard-daemon`, `socketguard` (CLI) and `socketguard-ui`.

## Usage

The daemon needs root / Administrator to manage firewall rules and addresses:

```bash
sudo ./target/release/socketguard-daemon            # Linux/macOS
.\target\release\socketguard-daemon.exe             # Windows, as Administrator
```

On Linux, install `deploy/systemd/socketguard.service` (to `/etc/systemd/system/`, binary in `/usr/local/bin`): the daemon then applies the stored state before networking comes up.

It serves the local API on `/run/socketguard.sock` or the named pipe `\.\pipe\socketguard`.
To use the CLI or UI without elevation, join the `socketguard` group (Unix) or the local group
`SocketGuard Users` (Windows) — see [docs/api.md](docs/api.md). On start it applies the stored
state; on stop everything stays in place until `socketguard disable` (or
`socketguard-daemon --disable` while it is stopped), which keeps it off until `socketguard enable`.

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

### Desktop app

The Tauri app covers the everyday flows: review new apps, grant and revoke with reach badges,
manage peers, follow the activity feed (including blocked attempts, with "grant this source"),
and toggle whole-host protection. Everything else is in the CLI.

## Configuration

The daemon reads `socketguard.json` (or `$SOCKETGUARD_CONFIG`). Networks added with
`socketguard networks add` are written back to this file.

```json
{
  "poll_interval_secs": 2,
  "db_path": "socketguard.db",
  "backends": [
    { "type": "ula" },
    { "type": "slaac", "interface": "eth0" },
    { "type": "yggdrasil", "interface": "ygg0" },
    { "type": "tor", "control": "127.0.0.1:9051" }
  ]
}
```

| Field | Description | Default |
|-------|-------------|---------|
| `backends` | Networks; `id` is optional (`ula`, `slaac-eth0`, …) | Local only |
| `api_socket` / `api_pipe` | Local API endpoint | `/run/socketguard.sock` / `\.\pipe\socketguard` |
| `poll_interval_secs` | Socket polling interval | `2` |
| `db_path` | SQLite database (an old pre-v1 database is renamed to `.pre-v1`) | `socketguard.db` |
| `process_filter` | `{"mode": "allowlist"\|"denylist", "patterns": ["nginx*"]}` | deny nothing |
| `log_level` | `trace` … `error` | `info` |

Telemetry is exported over OTLP when the standard `OTEL_EXPORTER_OTLP_*` variables are set;
`deploy/otel/` has a local collector, Jaeger and Prometheus stack.

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

The daemon sends your onion keys to whatever answers on the control address, and any local
user can bind the default `127.0.0.1:9051` while Tor is down. Therefore:

- **Prefer a Unix control socket** (`ControlSocket /run/tor/control` in torrc, then
  `--control unix:/run/tor/control`). Only Tor's account can own that path, and `auth: none` is
  accepted only there. `expect_tor_uid` additionally checks the uid serving the socket (Linux).
- With the default `auth: cookie` the daemon uses SAFECOOKIE: it verifies that the control port
  knows the cookie before it sends anything, and never sends the cookie. Plain COOKIE is
  refused; `auth: cookie_insecure` accepts it for a Tor without SAFECOOKIE.
- The cookie file must be a regular, 32-byte file (no symlink, not writable by others) owned by
  root, by `expect_tor_uid` or by the owner of `cookie_dir` (default: the directory of
  `cookie_path`). Set `cookie_path` (for example `/var/lib/tor/control_auth_cookie`) to pin the
  file PROTOCOLINFO may name. These are keys of the tor entry in `backends` in the config file.
- Revoking access never fails open: if Tor is down the removal is remembered and retried, the
  change returns HTTP 202 with `enforcement: pending` (the CLI warns), and onion services we
  created whose address is gone are removed on the next pass. Services we did not create are
  left alone.

The service keys live in the daemon's database (mode 0600 on Unix; on Windows keep it where only
the service account and Administrators have access). See ADR 0037 and 0039. A Docker end-to-end
test is in `deploy/e2e/tor-e2e.sh`.

## Testing

- `cargo test --workspace --exclude socketguard-ui` and `cd ui && npm test` — unit, golden,
  engine and API tests (CI: `.forgejo/workflows/ci.yml`).
- `SOCKETGUARD_NETNS_TESTS=1 cargo test -p socketguard-daemon --test netns` — real nftables in
  network namespaces (Linux, root).
- `deploy/e2e/ygg-e2e.sh`, `deploy/e2e/tor-e2e.sh` — Docker end-to-end tests against real
  Yggdrasil and Tor.

## Platform support

| Component | Linux | Windows | macOS |
|-----------|-------|---------|-------|
| Socket monitor | `/proc` | `GetExtendedTcpTable` | `lsof` |
| Firewall | nftables (`inet` table) | Windows Filtering Platform | pf anchor (untested) |
| Addresses | `ip addr` | IP Helper API | `ifconfig` |

## Architecture decisions

Architecture decisions are recorded as ADRs in [`docs/adr/`](docs/adr/); the current design is
ADR 0026–0039.

## License

MIT
