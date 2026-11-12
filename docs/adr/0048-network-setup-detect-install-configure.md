# ADR 0048: Networks Are Set Up by Detect, Install, Configure

## Status

Accepted. Extends ADR 0038 (networks in the config file) and ADR 0040 (who may configure Tor); changes neither. Its install and configure steps are superseded by ADR 0052.

The detection states named below were reduced by ADR 0052 to ready, added and absent.

What remained (detection of installed Tor and Yggdrasil) is superseded by ADR 0056.

## Date

2026-11-11

## Context

Adding a network meant typing an interface name, and for Yggdrasil and Tor it meant installing and configuring third-party software first, which nothing said. The Yggdrasil interface was never checked, so a wrong name gave a network that showed "up" while no address landed. On Windows a Tor network could not be added from a frontend at all: cookie authentication needs `cookie_path`, and the API accepts only default Tor settings from callers who are not administrators.

## Decision

- **Detect.** The daemon reports, per kind of network, whether it can be added as is and what it found: `ready`, `not_configured`, `not_running` or `not_installed`. For a LAN it lists the host's interfaces. For Yggdrasil the interface is the one that holds the node's address. Detection only reads.
- **Add without input** when ready. Typed settings remain as an advanced form.
- **Install and configure are administrator actions.** They are one command, `socketguard networks setup <kind>`, which must run with administrator rights and shows each change before making it. A frontend starts it through the system's elevation prompt. The daemon never installs or configures software on a request to its API.
- **Install** uses the system's package manager where a package exists. Where none does (a Tor daemon on Windows), the frontend links to the official download.
- **Third-party defaults are kept.** Yggdrasil's configuration is not edited. Tor gets only what the control connection needs (`ControlPort`, `CookieAuthentication`), and the Tor network with its cookie path is written to SocketGuard's config file by that same administrator command, which is what ADR 0040 requires.
- **Status is honest.** A network whose interface is missing is Down, and the reason names what is missing.

## Consequences

- A network that is present on the host is one click; a missing one is at most three (install, configure, add), each explained.
- Tor on Windows still needs a manual download. Running Tor or Yggdrasil as SocketGuard's own child process would remove that step and is left for a later decision.
- Setup depends on package managers and service layouts that differ per system; what cannot be verified for a system falls back to a link.
- The setup command edits another program's configuration (torrc). It changes only the two lines named above, keeps everything else, and records the change in the activity log.
