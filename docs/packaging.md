# Packages and releases (ADR 0050)

Every package only calls commands of the daemon binary, so the logic is tested once and the
packages stay thin. Definitions: `installer/windows/` (WiX), `installer/linux/` (nfpm),
`installer/macos/` (pkgbuild). CI: `.github/workflows/packages.yml` builds each, installs it on a
real runner and checks the host from outside with `deploy/ci/footprint-check.*`;
`release.yml` reuses it.

| | Install | Upgrade | Remove | Purge |
|---|---|---|---|---|
| **MSI** (Windows, per machine) | `service install`; `access allow <ALLOWUSER>` when given | the same, after the old version is removed without `uninstall`; the service is restarted | `uninstall --keep-data --yes` | `socketguard-daemon uninstall --purge` (the MSI never deletes data) |
| **deb** | postinst `configure`: `service install` | the same (`configure` runs again); a running daemon is restarted | prerm `remove`: `uninstall --keep-data --yes` | postrm `purge`: deletes the named files (`apt purge`) |
| **rpm** | `%post`: `service install` | the same (`$1` is 2); restarted | `%preun` with `$1` = 0: `uninstall --keep-data --yes` | none: run `socketguard-daemon uninstall --purge` before erasing |
| **pkg** (macOS) | postinstall: `service install` | the same; restarted | no uninstaller: `sudo socketguard-daemon uninstall`, then delete the files (README) | `sudo socketguard-daemon uninstall --purge` |

An upgrade is never an uninstall: `uninstall` and `--disable` do not run on one, in any package.
The deb and the rpm tell them apart by the maintainer-script argument (`remove` / `$1 = 0`), the
MSI by `REMOVE AND NOT UPGRADINGPRODUCTCODE` (the one feature can only be removed whole).

`service install` restarts a daemon that is already running (systemd `restart`, launchd
`kickstart -k`), so the process after an upgrade is the new binary. The Windows installer stops the
service before replacing the file (`ServiceControl`, stop only) and `service install` starts it.

## Windows

- Per machine, `C:\Program Files\SocketGuard`, the three binaries, the install folder appended to
  the system `PATH`, a Start menu shortcut for the app, an Add/Remove Programs entry.
  `UpgradeCode` `F3E0B72B-FD6F-4C59-878D-68BA159A16B3` must never change.
- **Who may use SocketGuard.** The dialog has a box, ticked by default: "Let *account* manage
  SocketGuard without administrator rights". The account is the one that started the installer,
  read by the interface sequence (which runs as that user even when the install is elevated with an
  administrator's credentials). Silent installs add nobody unless
  `msiexec /i SocketGuard.msi /qn ALLOWUSER=PC\alice` (public property `ALLOWUSER`). The account
  must sign out and in again before the group applies.
- **WebView2.** The app needs the Microsoft Edge WebView2 Runtime. Windows 11 ships it; that Windows
  10 receives it through Windows Update and Edge is from memory, not checked. Tauri's own bundler
  defaults to downloading a bootstrapper at install time (`WebviewInstallMode::default()` is
  `DownloadBootstrapper { silent: true }` in tauri-utils 2.8.3, `config.rs`), which a firewall's installer should not do; the MSI instead looks
  for the runtime (`pv` under `EdgeUpdate\Clients\{F3017226-...}`, machine or user) and the dialog
  says when it is missing. The service and the CLI do not need it.
- **A removal that leaves something fails** (the daemon exits 1: persistent filters would outlive
  the program that can remove them) and is rolled back. `msiexec /x SocketGuard.msi FORCEREMOVE=1`
  adds `--force` and ignores the failure.
- Log: `msiexec /i SocketGuard.msi /l*v install.log`; the daemon's own output for each action is
  in it.
- Unsigned: SmartScreen shows "Windows protected your PC / Unknown publisher"; *More info*, *Run
  anyway*.

## Linux

- One tool for both formats: **nfpm** (one YAML, per-format scripts and dependencies; a single
  static binary, pinned and checksum-verified in CI). `cargo-deb` plus `cargo-generate-rpm` would be
  two descriptions of the same thing and a Rust toolchain step each.
- Files: `/usr/bin/{socketguard-daemon,socketguard,socketguard-ui}`, a `.desktop` file, an icon.
  The systemd unit is **not** a package file: `service install` writes it from the text the daemon
  embeds (`deploy/systemd/socketguard.service`) with `ExecStart=/usr/bin/socketguard-daemon`, so a
  second copy cannot drift.
- Dependencies: nftables, iproute2, conntrack, libwebkit2gtk-4.1, GTK 3 (Fedora names in the rpm).
- No systemd (a container): the scripts print a note and do nothing; run
  `socketguard-daemon service install` where systemd runs.
- `SOCKETGUARD_FORCE_REMOVE=1` makes the remove scripts pass `--force` and ignore a failure.
- The deb `postrm` cannot run the daemon (the file is gone at purge). It deletes the same named
  files; `the_debian_postrm_names_what_purge_deletes` (crates/daemon/src/uninstall.rs) fails when
  the list and `named_files` differ.
- Built on Ubuntu 22.04 (glibc 2.35) so the binaries run on it and on newer systems.

## macOS

- `pkgbuild` and `productbuild`. `/usr/local/bin/{socketguard-daemon,socketguard}` and
  `/Applications/SocketGuard.app`, assembled by hand (the binary, `Info.plist`, `icon.icns`, an
  ad-hoc signature). Tauri's bundler would need `@tauri-apps/cli`, a `bundle` section and a second
  build path beside `build.sh` for the same two files. The app finds the CLI and the daemon in
  `/usr/local/bin` (`sibling_candidates` in `ui/src-tauri/src/main.rs`); the launchd plist names
  `/usr/local/bin/socketguard-daemon`, a stable path.
- A pkg has no uninstaller. **To remove:** `sudo socketguard-daemon uninstall` (add `--purge` to
  delete settings and keys), then
  `sudo rm -rf /Applications/SocketGuard.app /usr/local/bin/socketguard-daemon /usr/local/bin/socketguard /usr/local/lib/socketguard`
  and `sudo pkgutil --forget de.lhns.socketguard`. The app's "Remove SocketGuard..." runs the first
  command.
- Unsigned: Gatekeeper blocks a downloaded pkg ("cannot be opened because it is from an
  unidentified developer"). Open it from the context menu (*Open*), or *System Settings > Privacy &
  Security > Open Anyway*, or `xattr -d com.apple.quarantine SocketGuard-*.pkg`.

## Releases

Push a tag `v<version>` (the workspace version in `Cargo.toml`). `release.yml` checks they match,
builds and tests all packages, and creates a **draft** release with the MSI, deb, rpm, pkg and
`SHA256SUMS`. *Run workflow* on a branch is a dry run: the same files, uploaded as a workflow
artifact, no release.

### Signing and notarization (not done)

Provide these repository secrets and add the marked steps (`SIGN` comments in
`installer/macos/build.sh` and `.github/workflows/release.yml`); then pass them with
`secrets: inherit`.

| Secret | Used for |
|---|---|
| `WINDOWS_SIGNING_CERT_PFX` (base64), `WINDOWS_SIGNING_CERT_PASSWORD` | `signtool sign /fd sha256 /tr <timestamp> ...` on the three exes before `build.ps1` and on the MSI after |
| `APPLE_SIGNING_IDENTITY` ("Developer ID Application: ...") | `codesign --options runtime --timestamp` of the `.app` and `/usr/local/bin/*` |
| `APPLE_INSTALLER_IDENTITY` ("Developer ID Installer: ...") | `productbuild --sign` |
| `APPLE_CERTIFICATE_P12` (base64), `APPLE_CERTIFICATE_PASSWORD` | import both identities into a temporary keychain |
| `APPLE_NOTARY_APPLE_ID`, `APPLE_NOTARY_TEAM_ID`, `APPLE_NOTARY_PASSWORD` (app-specific) | `xcrun notarytool submit ... --wait`, `xcrun stapler staple` |
| `GPG_SIGNING_KEY` (optional) | detached signature of the deb, rpm and `SHA256SUMS` |

## What CI proves, and what it does not

`packages.yml` on every push to `installers`, `redesign` and `main`, and for each release:

- **MSI** (Windows runner): silent install with `ALLOWUSER`; service running; the pipe answers; the
  group has the account; WFP provider, sublayer and filters present; a LAN network on a ULA /64
  with a granted port range: one `FWP_MATCH_RANGE` filter and a connection from a second local
  address to a granted port succeeds while a port outside the range is refused (`netsh wfp`
  dumps and net events are uploaded as `msi-test-output`); upgrade (restarted daemon, same
  database file, same stored state, no `uninstall`); removal (service, filters and group gone, data
  kept); `uninstall --purge` with the daemon copied aside; `footprint-check.ps1` from outside after
  each step.
- **deb** (Ubuntu 22.04 VM with systemd): install, unit active and enabled, socket answers, nft
  table, upgrade restarts onto the new binary and keeps the database inode and state, remove, purge.
- **rpm**: dependency resolution, file list, scriptlets and library check in a Fedora container
  without systemd, plus the full life cycle in one that runs systemd.
- **rpm on systemd** (`rpm-systemd` job, Fedora container with systemd as PID 1 on the Ubuntu VM, `test/rpm-systemd.sh`): install, unit active, socket, nft table, upgrade restart, `dnf remove`, then purge by command and erase.
- **pkg** (macOS runners `macos-latest` = arm64 and `macos-15-intel` = x86_64, per GitHub's runner table; same test on both): install, launchd daemon answering, pf anchor line, upgrade restart,
  `uninstall --purge` restores `/etc/pf.conf`, then the manual removal.

Not covered: the installer dialogs (CI installs silently; the access dialog, the WebView2 note and
the `FORCEREMOVE` path are built but never clicked or run), a standard user elevating with an
administrator's credentials, Windows 10, Linux distributions other than Ubuntu 22.04 and Fedora,
signing, and every dialog (see docs/manual-checks.md for the checklist a person runs once).
