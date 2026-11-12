# SocketGuard

Secure by default, without NAT. Every app and every port on a host is closed until you grant
access. Access goes to *peers*, identified by a key or an address, not to bare IP strings. Each
granted port, port group or "All ports" of an app gets its own address on each network, so you
can see and share exactly what is reachable. A *reserved address* is a named address that stays
the same while the apps behind it change.

Networks: Local (this machine), LAN, Yggdrasil and Tor. SocketGuard bundles Tor and Yggdrasil and
runs them itself; nothing is installed on your system for them.

A daemon (a system service) does the work: it finds listening apps, keeps firewall rules (nftables,
pf, Windows Filtering Platform) and addresses in step with your grants, and serves a local API.
The `socketguard` command line and the desktop app are two frontends for that API.

## Install

Packages are attached to each [release](https://github.com/lhns/socketguard/releases) with a
`SHA256SUMS` file. They are **not signed yet**, so each system warns once. Each package installs
`socketguard-daemon`, `socketguard` and `socketguard-ui`, registers a service that starts with the
system, and starts it. Details: [docs/packaging.md](docs/packaging.md).

**Windows** (`SocketGuard-<version>-x64.msi`). Installs to `C:\Program Files\SocketGuard` and adds
it to `PATH`. A box in the installer (ticked by default) lets *your* account use SocketGuard without
administrator rights by adding it to the local group `SocketGuard Users`; **sign out and in again**
before it applies. Silent install: `msiexec /i SocketGuard-<version>-x64.msi /qn ALLOWUSER=PC\alice`
(without `ALLOWUSER` nobody is added). The app needs the Edge WebView2 Runtime (part of Windows 11).
*Unsigned:* SmartScreen shows "Windows protected your PC"; choose *More info*, *Run anyway*.

**Portable (Windows)** (`SocketGuard-portable-windows-x64.zip`): see [Portable mode](#portable-mode).

**Debian, Ubuntu** (`socketguard_<version>-1_amd64.deb`): `sudo apt install ./socketguard_*.deb`.
**Fedora, RHEL** (`socketguard-<version>-1.x86_64.rpm`): `sudo dnf install ./socketguard-*.rpm`.
Both need systemd. Nobody is added to the `socketguard` group: run
`sudo socketguard-daemon access allow $USER` (or use the app's "allow my account"), then **sign out
and in again**.

**macOS** (`SocketGuard-<version>-arm64.pkg` for Apple silicon, `-x86_64.pkg` for Intel). Installs the
programs and `SocketGuard.app` and starts a launchd daemon. *Unsigned:* macOS refuses to open a
downloaded pkg; use *Open* from its context menu, or *System Settings > Privacy & Security > Open
Anyway*. Then `sudo socketguard-daemon access allow $USER` and sign out and in.

Upgrading is installing the newer package; settings and rules stay and the service restarts.

## First steps

Nothing is reachable until you grant it, so start by letting one peer reach one app.

**In the desktop app.** The *Apps* page lists what listens on this host; all of it is closed. Open
an app, choose *Add access* on "All ports" or on one port, pick who (a peer you add by key or
address, or a peer group) and confirm. The app now has an address on each network that takes the
grant; the inspector shows it and, per network, whether the peer is `verified` by key or `IP only`.
*Reserved* holds named addresses, *Peers* the peers and groups, *Activity* the feed (including
blocked attempts), *Settings* the networks and whole-host protection.

**On the command line.**

```bash
socketguard init                              # first run: networks, remote-admin grants, protect-host
socketguard networks list                     # what is configured; `networks detect` shows what can be added
socketguard apps list
socketguard peers add --label alice <ygg-key> # bare values: 64 hex = Yggdrasil key, IP/CIDR = address
socketguard grant nginx:80 alice              # an app[:port[/proto]]; or group:team, or anyone (asks)
socketguard apps show nginx                   # its addresses, ports, grants and their reach
socketguard share nginx                       # the connection strings to give to alice
socketguard activity --blocked --follow       # what was refused
socketguard revoke nginx:80 alice
```

`socketguard --help` lists everything: tags (`tags`), port groups (`port-groups`), reserved addresses
(`reservations`, `addresses`), peer groups (`groups`), batch `grant`/`revoke`, `export`/`apply`,
`protect-host`, `disable`/`enable`. `--json` prints the API types as JSON; apps, peers and groups can be
named by id, unique id prefix or name. Reach is shown per network as `verified`, `whole subnet`,
`IP only`, `open` or `not reachable`. See [docs/api.md](docs/api.md) and ADR 0033.

## Networks

| Network | Addresses | Identity of sources |
|---|---|---|
| Local | ULA on loopback, this machine only | none |
| LAN | from the LAN's `/64` (SLAAC, DHCPv6) | IP only |
| Yggdrasil | `/128`s from the node's `300::/64` | verified by key |
| Tor | one onion service per address | verified by Tor client key |

Tor and Yggdrasil are **managed** by default: SocketGuard runs its own copy as a child process with
its own data, so nothing on your system is installed or changed, and the copies stop when SocketGuard
stops (ADR 0052).

```bash
socketguard networks add tor
socketguard networks add yggdrasil --peer tls://host:port      # --peer is repeatable
socketguard networks peers yggdrasil --add tls://host:port --rm tls://old:1
```

If you already run a node, add it as it is with `--existing` (the app calls it "Use my existing
one"): `socketguard networks add yggdrasil --existing`, or `socketguard networks add tor --existing`
(with `--control` and `--password-env` if needed). An existing node keeps its own configuration;
SocketGuard never installs, starts or reconfigures software it did not ship. `socketguard networks
detect` and the app's Settings page show what this machine offers. Tor access control is described
in [ADR 0040](docs/adr/0040-onion-service-lifecycle-consolidated.md).

## Configuration

The daemon reads `socketguard.json` from its fixed directory (Windows `%ProgramData%\SocketGuard`,
Linux `/etc/socketguard`, macOS `/Library/Application Support/SocketGuard`), or from
`$SOCKETGUARD_CONFIG`. Networks added with `socketguard networks add` are written to it. The other
keys are `api_socket`, `api_pipe`, `poll_interval_secs`, `db_path`, `log_level` and `process_filter`
(`DaemonConfig` in `crates/core/src/config.rs`). Telemetry is exported over OTLP when the standard
`OTEL_EXPORTER_OTLP_*` variables are set; `deploy/otel/` has a local collector stack.

## Uninstall and purge

Removing SocketGuard stops the service and takes its firewall rules, addresses and service
registration off the host but **keeps** settings and keys. A purge deletes those too.

- Windows: Apps & features or `msiexec /x` removes; for a purge run
  `socketguard-daemon uninstall --purge` first (administrator terminal), or use the app's
  "Remove SocketGuard...".
- Debian/Ubuntu: `apt remove socketguard` removes, `apt purge socketguard` purges.
- Fedora/RHEL: `dnf remove socketguard` removes; run `sudo socketguard-daemon uninstall --purge` before
  erasing it to purge.
- macOS: a pkg has no uninstaller. Run `sudo socketguard-daemon uninstall` (`--purge` also deletes
  settings and keys), then delete `/Applications/SocketGuard.app`, `/usr/local/bin/socketguard*` and
  `/usr/local/lib/socketguard`, and `sudo pkgutil --forget de.lhns.socketguard`.

`uninstall` also takes `--keep-data`, `--yes`, `--export <file>` and `--force`. Stopping the daemon
removes nothing on purpose, so a stopped host stays closed; `socketguard disable` (or
`socketguard-daemon --disable` while it is stopped) removes the rules and addresses and keeps them off
until `socketguard enable`. [docs/footprint.md](docs/footprint.md) lists everything SocketGuard puts
on a host and what removes it.

## Portable mode

`SocketGuard-portable-windows-x64.zip` (ADR 0054). Unzip anywhere, even to a removable drive, and
run `socketguard-ui.exe`; it asks for administrator rights at every start. Everything it keeps is in
the `data` folder next to the programs; no service, group or installed files. A file named
`portable` next to the daemon, or `socketguard-daemon --portable`, selects the mode.

**The trade-off.** Protection ends with the window: rules and addresses are removed when you close
SocketGuard, sign out or shut down. A crash or a kill leaves the machine open, as it was before
SocketGuard started, **not closed**. Use the MSI to protect a computer permanently. Portable mode
does not start beside the installed service, offers only Local, LAN and the managed Tor and
Yggdrasil, and trusts the folder: anything running as you can change what then runs with
administrator rights, so keep it where only you can write. Delete the folder to remove it. To try
the UI or CLI against a daemon without installing, use this mode.

## Building from source

Prerequisites: Rust ([rustup](https://rustup.rs)) and Node.js; on Windows the Visual Studio Build
Tools; at runtime `nft` on Linux and `pfctl` on macOS. On a fresh clone run `cd ui && npm install`
once, then:

```bash
./build.sh                 # release build: frontend, then all crates
./build.sh --debug         # debug build
./build.sh --with-bundled  # also fetch the pinned Tor, Yggdrasil and Wintun next to the build
```

`--with-bundled` needs network access, git and Go (`deploy/bundle/fetch.sh`). Binaries land in
`target/<profile>/`: `socketguard-daemon`, `socketguard` and `socketguard-ui`. Always use
`./build.sh`, not `cargo build` or `npm run build` alone.

## Testing

- `cargo test --workspace --exclude socketguard-ui`, and `cd ui && npm run lint && npm run typecheck
  && npm test`: unit, golden, engine, API and UI tests. CI (`.github/workflows/ci.yml`; Forgejo has
  its own in `.forgejo/`) also runs the UI crate, the netns tests as root and
  `deploy/ci/macos-smoke.sh`.
- `SOCKETGUARD_NETNS_TESTS=1 cargo test -p socketguard-daemon --test netns`: real nftables in network
  namespaces (Linux, root).
- `deploy/e2e/ygg-e2e.sh`, `tor-e2e.sh` and the `managed-*` scripts: Docker end-to-end tests with real
  Yggdrasil and Tor.
- The package tests in `test/` run in `.github/workflows/packages.yml`; checklist for the dialogs CI
  cannot click: [docs/manual-checks.md](docs/manual-checks.md).

## Where the decisions live

- [docs/adr/](docs/adr/): architecture decisions; the current design is ADR 0026 onward.
- [docs/footprint.md](docs/footprint.md): what SocketGuard puts on a host and what removes it.
- [docs/api.md](docs/api.md): the local API, its endpoint and who may use it.
- [docs/packaging.md](docs/packaging.md): packages, install, upgrade and removal per platform.
- [docs/manual-checks.md](docs/manual-checks.md): manual installer checks per release.

## Licence

Apache License 2.0, see [LICENSE](LICENSE). The installers ship unmodified Tor, Yggdrasil and, on
Windows, Wintun; their licences and sources are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and, installed, in `third_party/licenses/`.
Versions and checksums are pinned in `deploy/bundle/versions.toml`.
