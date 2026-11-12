# ADR 0056: Only SocketGuard's Own Tor and Yggdrasil

## Status

Accepted. Supersedes ADR 0040 (control-port trust and who may configure Tor) and the "existing software, as it is" part of ADR 0052. Supersedes in ADR 0051 what concerned a node the user runs themselves: the whole-range block, the exposure shown when leaving, and "added only while it answers". Supersedes what remained of ADR 0048's detection of installed software.

## Date

2026-11-12

## Context

Since ADR 0052 SocketGuard ships and runs its own Tor and Yggdrasil. Support for a node the user runs themselves stayed as an option, and it is what a large part of the network code exists for: administrator-only Tor control settings with password and plain-cookie authentication and the rule that the API accepts them only when the config file already holds them; detection of installed software; the shell-out to `yggdrasilctl`; a block over the whole Yggdrasil range that is unproven on Windows; and the exposure report and confirmations for a node that keeps running when SocketGuard leaves. For Tor the option adds nothing but a process, because the onion keys are SocketGuard's either way.

## Decision

- A Tor or Yggdrasil network is always SocketGuard's own. There is no setting for it: the `managed` flag, the external Tor fields (`control`, `auth`, `cookie_path`, `cookie_dir`, `expect_tor_uid`, `cookie_owner`, `allow_remote_control`) and the external Yggdrasil fields (`interface`, `admin_endpoint`) are removed from the config, the API, the CLI and the UI.
- Removed with them: the check that an API request's Tor settings match the config file, password and plain-cookie authentication, remote control addresses, detection of installed Tor and Yggdrasil, the `yggdrasilctl` path, the whole-range block, the exposure route with its confirmations, and the rule that keeps existing nodes out of portable mode.
- Kept, because SocketGuard's own children need them: cookie authentication with the vetting of the cookie file, built from paths SocketGuard chose; the block of the node's own address and subnet, applied and verified before the node starts; and the check that no other Yggdrasil node runs on the host.
- A host that already runs its own Yggdrasil node cannot use Yggdrasil in SocketGuard while that node runs (one node per host, ADR 0052). The network card says so.

## Consequences

- No configuration of Tor or Yggdrasil can weaken SocketGuard any more; there is none to make. The trust boundary of ADR 0040 has nothing left to guard.
- Every network SocketGuard manages is closed first by construction; the windows of exposure that existed only for nodes of the user are gone.
- Someone who wants their existing node's identity cannot bring it. Importing a key is not offered.
- Roughly two thousand lines of code and tests go.
