# ADR 0065: The macOS Programs Live Where Only Root Can Write

## Status

Accepted (refines 0050)

## Date

2026-11-13

## Context

The macOS package put the daemon in `/usr/local/bin` and the bundled Tor and Yggdrasil in
`/usr/local/lib/socketguard`. launchd runs the daemon as root, and the daemon starts the bundled
programs. Homebrew on Intel Macs makes `/usr/local/bin` and `/usr/local/lib` writable by the user
who installed it, so that user (or anything running as them) could replace what root runs.

## Decision

- The pkg installs the daemon, the CLI and `third_party/` to
  `/Library/Application Support/SocketGuard/` (root:wheel, 755; the state directory of ADR 0050 is the
  same directory). `/usr/local/bin/socketguard` is a symlink to the CLI there; the daemon has no link.
- The LaunchDaemon names the daemon in that directory; the bundled files are found next to the
  executable first, as before. The desktop UI looks for the CLI and the daemon there when they are
  not beside the window.
- `service install` on macOS and Linux refuses when the daemon's executable, or any directory above
  it, is not owned by root or is writable by group or others (a sticky directory passes). The message
  names the path. This also covers a hand-copied daemon.
- `uninstall --purge` removes the data it lists; the programs are the pkg's, so the directory stays
  and the README removal command deletes it.

## Consequences

- A user cannot swap the root-run programs through a user-owned prefix.
- `/usr/local/bin/socketguard` keeps the CLI on the PATH; scripts calling `socketguard-daemon` by that
  path must use the new directory.
- An existing install keeps the old files in `/usr/local` until removed by hand; the new
  `service install` rewrites the plist to the new path.
- Running the daemon from a user-owned build directory as a service is refused; development uses
  `sudo` with a foreground run instead.
