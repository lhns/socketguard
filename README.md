# SocketGuard

Secure by default, without NAT. Every app you open gets its own IPv6 address per network,
everything is closed until you grant access, and access is granted to *peers* (ideally
identified by public key), not to IP strings.

## Why

Without NAT, every listening port is reachable by anyone who can route to the host. Overlay
networks like Yggdrasil make this worse — installing one exposes every port to the whole
overlay — but they also make source addresses provable: on Yggdrasil a packet's source is
cryptographically bound to the sender's key. SocketGuard builds on that:

- **Apps, not ports.** Listening processes are grouped into apps (interpreter-aware, stable
  across upgrades). An app has no address until a grant names it; then it gets one per network,
  plus one for each port or port group a grant names. When the last grant goes, the address leaves
  the interface (it is remembered and comes back unchanged). A *reservation* is a named,
  permanent address you assemble from ports of several apps and grant access to as a whole.
- **Peers, not IPs.** A peer is a label plus credentials: a Yggdrasil key or address, an IP or
  CIDR, a Tor client key. Each grant shows per network whether it is `verified` by key,
  `IP only`, or `not reachable` there.
- **Closed by default.** Nothing closed has an address, and the whole Yggdrasil interface
  denies inbound traffic unless a grant allows it. Whole-host protection is opt-in, with a guard
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

### Adding networks

SocketGuard runs its own Tor and Yggdrasil: nothing is installed or changed on your system, and
the programs stop when SocketGuard stops (ADR 0052; also when the daemon is killed: on Linux and macOS a small guard process ends Yggdrasil, whose adapter then goes, behind the unchanged firewall rules). So this is the default:

```bash
socketguard networks add tor                      # SocketGuard's own Tor
socketguard networks add yggdrasil --peer tls://host:port    # its own Yggdrasil node, --peer repeatable
socketguard networks peers yggdrasil              # show the peers
socketguard networks peers yggdrasil --add tls://host:port --rm tls://old:1
```

If you already run a node, add it as it is with `--existing` (the desktop app calls it "Use my
existing one"): `socketguard networks add yggdrasil --existing`, or for Tor
`socketguard networks add tor --existing` (with `--control` and `--password-env` if needed).
Peers belong to SocketGuard's own Yggdrasil; an existing node keeps its own configuration.

`socketguard networks detect` (and the desktop app's Settings screen) shows what this machine
offers for each network: the LAN interfaces, whether SocketGuard's own Tor and Yggdrasil are
available in this build (`socketguard status` lists the bundled programs), and whether an
existing node is ready to be added. A build without the bundled files only offers `--existing`.

**Third-party software.** The installers ship unmodified Tor (BSD 3-clause, with libevent, OpenSSL and
zlib), Yggdrasil (LGPLv3 with an exception for combined works; it runs as a separate process) and, on
Windows, Wintun. Versions and checksums are pinned in `deploy/bundle/versions.toml`; the licences are
in `third_party/licenses/` next to the daemon and in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md),
which also links the source of the pinned Yggdrasil build. `deploy/bundle/fetch.sh` fetches and verifies
the files (Tor against the Tor Project's signed checksums); `./build.sh --with-bundled` puts them next
to a local build.

## Architecture

```
socketguard (CLI) ─┐                    ┌─▶ firewall: nftables / pf / WFP (atomic desired state)
                   ├─▶ local API ─▶ daemon ─▶ interfaces: add/remove addresses
desktop UI (Tauri) ┘  (Unix socket /    ├─▶ networks: Local, LAN, Yggdrasil, Tor
                       named pipe)      └─▶ SQLite + activity log + OpenTelemetry
```

| Crate | Description |
|-------|-------------|
| `socketguard-core` | Domain model, credentials and reach rules, config, API types |
| `socketguard-daemon` | Monitor, networks, ruleset producer, firewall backends, API |
| `socketguard-client` | Typed client for the local API (used by the CLI and the UI) |
| `socketguard-cli` | The `socketguard` command line, the primary frontend |
| `socketguard-ui` | Tauri v2 desktop app (Apps, Peers, Activity, Settings) |

Daemon modules: `monitor/` (listening sockets), `iface/` (addresses on the OS interfaces), `networks/` (`ip/` for Local, LAN, Yggdrasil and DHCPv6; `tor`), `firewall/` (nftables, pf, `wfp/`), `engine/` (reconcile loop), `api`.

## Install

Packages are attached to each [release](https://github.com/lhns/socketguard/releases) with a
`SHA256SUMS` file. They are **not signed yet**, so each system warns once (below). Every package
does the same thing with the daemon's own commands (`socketguard-daemon service install`, ADR 0050;
details in [docs/packaging.md](docs/packaging.md)): it installs the three programs
(`socketguard-daemon`, `socketguard`, `socketguard-ui`), registers SocketGuard as a service that
starts with the system, and starts it. The firewall rules and addresses survive stopping or
removing the service; removing SocketGuard is a separate step.

**Windows** (`SocketGuard-<version>-x64.msi`). Installs to `C:\Program Files\SocketGuard`, puts it
on `PATH`, adds a Start menu entry. The installer asks whether *your* account may manage
SocketGuard without administrator rights (box ticked by default; it joins the local group
`SocketGuard Users`; **sign out and in again** before it applies). Silent install:
`msiexec /i SocketGuard-<version>-x64.msi /qn ALLOWUSER=PC\alice` (without `ALLOWUSER` nobody is
added). The desktop app needs the Microsoft Edge WebView2 Runtime (included in Windows 11; the
installer tells you if it is missing). *Unsigned:* SmartScreen shows "Windows protected your PC";
choose *More info*, *Run anyway*. Upgrade: run the newer MSI; settings and rules stay and the
service is restarted. Uninstall: Apps & features, or `msiexec /x`; this **keeps** settings and
keys. To delete them too run `socketguard-daemon uninstall --purge` first (an administrator
terminal), or use the app's "Remove SocketGuard...".

**Portable (Windows)** (`SocketGuard-portable-windows-x64.zip`, ADR 0054). Unzip anywhere, even to a
removable drive, and run `socketguard-ui.exe`; it asks for administrator rights at every start.
Everything it keeps is in the `data` folder next to the programs; nothing is installed and no
service or group is created. **Protection ends with the window**: the rules and addresses are
removed when you close SocketGuard, sign out or shut down, and a crash or a kill leaves the
machine open, as it was before SocketGuard started, not closed. Use the MSI to protect a computer
permanently. It does not start beside the installed service. Remove it by deleting the folder.
Only Local and LAN networks (and the managed Tor and Yggdrasil) are offered; an existing Tor or
Yggdrasil node cannot be added. The folder is writable by you, so anything running as you can change
what then runs with administrator rights: keep it where only you can write.

**Debian, Ubuntu** (`socketguard_<version>-1_amd64.deb`): `sudo apt install ./socketguard_*.deb`.
**Fedora, RHEL** (`socketguard-<version>-1.x86_64.rpm`): `sudo dnf install ./socketguard-*.rpm`.
Both need systemd and pull in nftables, iproute2, conntrack, WebKitGTK and GTK. Nobody is added to
the `socketguard` group: run `sudo socketguard-daemon access allow $USER` (or use the app's "allow
my account"), then **sign out and in again**. Upgrade: install the newer package; the service is
restarted onto it. `apt remove socketguard` / `dnf remove socketguard` stops the service and
removes the rules and the unit but **keeps** settings and keys; `apt purge socketguard` deletes
them too. rpm has no purge: run `sudo socketguard-daemon uninstall --purge` before erasing it.

**macOS** (`SocketGuard-<version>-arm64.pkg` for Apple silicon, `-x86_64.pkg` for Intel). Installs `socketguard-daemon` and `socketguard` in
`/usr/local/bin` and `SocketGuard.app` in `/Applications`, and starts the launchd daemon. *Unsigned:*
macOS refuses to open a downloaded pkg; use *Open* from its context menu, or *System Settings >
Privacy & Security > Open Anyway*. Run `sudo socketguard-daemon access allow $USER` (or the app's
"allow my account") and sign out and in. A pkg has no uninstaller: run
`sudo socketguard-daemon uninstall` (`--purge` also deletes settings and keys; the app's "Remove
SocketGuard..." does the same), then delete `/Applications/SocketGuard.app`,
`/usr/local/bin/socketguard*` and `/usr/local/lib/socketguard`, and `sudo pkgutil --forget
de.lhns.socketguard`.

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

SocketGuard runs as a system service (ADR 0050). From an administrator terminal (Windows) or with sudo:

```bash
socketguard-daemon service install      # registers and starts it: Windows service, systemd unit, launchd daemon
socketguard-daemon service status       # installed? running?   (also: start, stop, uninstall)
socketguard-daemon access allow alice   # lets an account use SocketGuard without administrator rights
socketguard-daemon uninstall            # stops, disables, undoes what install changed; asks before deleting settings and keys
```

`uninstall --purge` also deletes the database and config, `--keep-data` keeps them, `--export <file>` writes the
settings first (onion private keys are not in the export). Config, database and setup log live in one fixed place:
Windows `%ProgramData%\SocketGuard`, Linux `/etc/socketguard` and `/var/lib/socketguard`, macOS
`/Library/Application Support/SocketGuard`. `$SOCKETGUARD_CONFIG` (and `db_path`, relative to the config file's
directory) override; nothing uses the working directory. A daemon that finds state in its working directory
and none at the fixed place moves it once. For a test run without installing, set `SOCKETGUARD_CONFIG`
and start `socketguard-daemon` yourself as root / Administrator.

The service applies the stored state before networking comes up (the systemd unit is `deploy/systemd/socketguard.service`). On Linux the unit is `Type=notify`: the service is ready, and `systemctl start` returns, once its rules are applied, so the network comes up behind them.

It serves the local API on `/run/socketguard.sock` (macOS: `/var/run/socketguard.sock`) or the named pipe `\.\pipe\socketguard`.
To use the CLI or UI without elevation, join the `socketguard` group (Unix) or the local group
`SocketGuard Users` (Windows): `socketguard-daemon access allow <account>`, see [docs/api.md](docs/api.md). On start it applies the stored
state; on stop everything stays in place until `socketguard disable` (or
`socketguard-daemon --disable` while it is stopped), which keeps it off until `socketguard enable`.

### CLI

`socketguard` covers the whole API. `--json` prints the API types as JSON for every command; `--socket <path>` (or `SOCKETGUARD_SOCKET`) selects a non-default daemon. Apps, peers and groups can be named by id, unique id prefix or name. Errors print `error: <code>: <message>` and exit 1. Details are in [docs/api.md](docs/api.md) and ADR 0033.

```bash
socketguard init                              # first-run setup (networks, sshd/RDP grants, protect-host)
socketguard status                            # daemon, networks, protect-host, counts
socketguard apps list                         # also: show, move, rm
socketguard apps show nginx                   # addresses (up or not), ports, grants with reach, counters
socketguard apps move old-nginx nginx [-y]    # a program that came back under a new identity: addresses, grants, tags and bindings move
socketguard share nginx                       # [addr]:port and http(s):// URLs

socketguard peers add --label alice <ygg-key> # bare values: 64 hex = ygg_key, IP/CIDR = ip
socketguard peers add --label bob --addr 2001:db8::7 --cred wg_key=<base64>
socketguard peers list                        # also: show, rename, rm, cred add|rm
socketguard groups add team alice bob         # also: list, show, rename, rm, members

socketguard grant nginx:80 alice              # or group:team, or anyone (asks, or --yes)
socketguard grant sshd:22 alice --network ygg
socketguard revoke nginx:80 alice             # or: revoke <grant-id>
socketguard grants [--app A] [--tag T] [--peer P] [--group G]
# Many at once (one batch: all or nothing, one firewall update; --dry-run shows the diff):
socketguard grant --app web --app api --port 80 --port 443 --to alice --to group:team [--network lan]
socketguard revoke --app web --to alice

socketguard tags add dev --match 'python*' --match node   # apps matching join now and when they start
socketguard tags members add dev web:80                    # an app, one port or a port group (web:port-group=passive); also: members rm, show, list, patterns, rename, rm
socketguard grant tag:dev group:team                       # covers every member, present and future

# Port groups: ports and ranges that belong together (ADR 0047), attached to apps, usable as a scope
# (the command is still `port-groups`)
socketguard port-groups add 21/tcp 50000-51000/tcp --label passive --app ftpd   # also: list, set, rm, attach, detach
socketguard grant ftpd:port-group=passive alice          # or: grant --app ftpd --port-group passive --to alice

# Addresses and reservations (ADR 0047): an address exists once a grant names its row
socketguard addresses list                    # every address, automatic and reserved, up or not
socketguard addresses reserve <address-id> web-public     # keep an automatic address under a name
socketguard reservations add public-web web:80/tcp tag:dev   # targets: app[:port[/proto]|:port-group=<label>] or tag:<label>
socketguard reservations list                 # also: rename, bind, unbind, release (bind asks before opening to Anyone; -y)
socketguard grant reservation:public-web alice   # covers every bound row, All ports; also --reservation <label>

socketguard networks list                     # also: add <type> --interface X, rm <id>
socketguard settings show                     # whole-host protection
socketguard protect-host on eth0              # refused if sshd/RDP would be cut off; --force
socketguard activity --blocked [--follow]     # also: --app, --peer, --kind, --limit
socketguard watch                             # every push event, one line each

socketguard export -o socketguard.toml        # TOML, or JSON with a .json name / --format json
socketguard apply -f socketguard.toml         # shows the diff, asks; --dry-run, --yes
socketguard disable --yes                     # remove all rules and addresses, keep them off
socketguard enable
socketguard completions bash                  # also: zsh, fish, powershell, elvish
```

Reach is shown per network as `verified`, `whole subnet`, `IP only`, `open` or `not reachable`; a note gives the reason where it is not what the grant suggests. Completions are static (subcommands and options, not app or peer names).

### Desktop app

The Tauri app covers the everyday flows: see what each app lets in, grant and revoke with reach badges,
manage peers, follow the activity feed (including blocked attempts, with "grant this source"),
and toggle whole-host protection. Everything else is in the CLI.

## Configuration

The daemon reads `socketguard.json` in its fixed directory (or `$SOCKETGUARD_CONFIG`). Networks added with
`socketguard networks add` are written back to this file.

```json
{
  "poll_interval_secs": 2,
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
| `db_path` | SQLite database: absolute, or relative to the config file's directory (an old pre-v1 database is renamed to `.pre-v1`) | `socketguard.db` in the state directory |
| `process_filter` | `{"mode": "allowlist"\|"denylist", "patterns": ["nginx*"]}` | deny nothing |
| `log_level` | `trace` … `error` | `info` |

Telemetry is exported over OTLP when the standard `OTEL_EXPORTER_OTLP_*` variables are set;
`deploy/otel/` has a local collector, Jaeger and Prometheus stack.

### Tor (onion services)

A Tor network publishes each app as an onion service through Tor's control port, so peers behind
NAT can reach it without any open port. Access is enforced by Tor client authorization: an app is
not published until it is granted, and a grant to a peer holding a `tor_client_key` (the base32
x25519 public key from `authorized_clients`) lets only that client in. A reservation is opened
as a whole on Tor: only a grant on the reservation itself admits clients to its onion address,
and a grant on a single bound port has no effect there (the CLI shows the reason).

```bash
socketguard networks add tor                    # SocketGuard's own Tor; for yours: --existing [--control 127.0.0.1:9051] [--password-env VAR | --password-stdin]
socketguard peers add --label bob --tor-key <base32>    # the key bob's Tor client generated
# or let the daemon generate the key pair (the private key is stored like the onion keys):
socketguard peers add --label bob && socketguard peers tor-key bob
socketguard grant myapp:8080 bob
socketguard apps show myapp                     # prints the .onion name
socketguard share myapp                         # http://<id>.onion:8080, and for a generated key
                                                # the <id>:descriptor:x25519:<key> line for bob's
                                                # ClientOnionAuthDir (a file ending in .auth_private)
```

With `--existing`, the daemon sends your onion keys to whatever answers on the control address, so:

- Prefer a Unix control socket (`ControlSocket /run/tor/control` in torrc, then
  `--control unix:/run/tor/control`); a TCP control address must be loopback.
- Authentication is SAFECOOKIE by default: the daemon checks that the control port knows the
  cookie before it sends anything. The cookie file is vetted (owner, permissions, no symlink);
  on Windows set `cookie_path` (and `cookie_owner`) in the config file.
- Revoking access never fails open: if Tor is down, the removal is remembered and retried, the
  change returns HTTP 202 `enforcement: pending` (the CLI warns), and removing the network is
  refused (409) until it is confirmed, unless forced.
- Tor networks created through the API may only be managed or use the default or config-file
  settings; anything else belongs in the config file, which only an administrator can edit.

The service keys live in the daemon's database (mode 0600 on Unix, a protected ACL on Windows).
See [ADR 0040](docs/adr/0040-onion-service-lifecycle-consolidated.md) for the full decision
and `deploy/e2e/tor-e2e.sh` for the Docker end-to-end test.

## Testing

- `cargo test --workspace --exclude socketguard-ui` and `cd ui && npm test` — unit, golden,
  engine and API tests (CI: `.github/workflows/ci.yml` on GitHub, `.forgejo/workflows/ci.yml` on Forgejo; GitHub also runs the netns tests as root and `deploy/ci/macos-smoke.sh` on macOS).
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
ADR 0026–0047.

## License

Apache License 2.0, see [LICENSE](LICENSE).
