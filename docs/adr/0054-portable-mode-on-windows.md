# ADR 0054: A Portable Mode on Windows That Leaves Nothing Behind

## Status

Accepted. A scoped exception to ADR 0026 (fail closed when the daemon stops) and ADR 0050 (fixed locations, service); neither is changed for the installed product.

Amended below.

## Date

2026-11-12

## Context

The owner wants to run SocketGuard on Windows without installing it, from a folder that can sit on a removable drive. SocketGuard's work is system state: firewall filters and addresses on adapters. The installed product makes that state persistent on purpose, so the host stays closed when the daemon stops, and removes it through `disable`, which needs the database. A portable folder can leave the machine while the daemon is dead. Persistent filters would then stay with nothing able to find the addresses they belong to, and SocketGuard's permit filters override the system firewall.

## Decision

- **Mode.** A file named `portable` next to the binaries, or `--portable`, selects portable mode. It exists on Windows only.
- **Everything in the folder.** Config, database, logs of what it did and the data of managed networks live under `data\` in the program's folder. Nothing is read from or written to `%ProgramData%`, no state is moved there, and the one-time move of old state is off.
- **Nothing on the host outlives the process.** Firewall objects are created in a session that Windows removes when the daemon's process ends, however it ends. Addresses are added without persistence and removed on exit; after a kill they are gone at the latest with the next start from the same folder or a reboot. No service, no access group, no install record on the host.
- **The price is stated.** In portable mode a crash or kill leaves the machine open as it was before SocketGuard started, not closed. Portable mode is for using SocketGuard on a machine for a while, not for protecting it permanently.
- **Lifetime.** The UI starts the daemon with administrator rights and the daemon ends when the UI ends, on logoff and on shutdown. Ending always runs the same teardown as "turn off": rules and addresses removed, managed networks stopped.
- **Access.** The daemon's pipe admits administrators and the account that started the UI; that account is passed by the UI at start.
- **Not beside an installed copy.** Portable mode refuses to start when the SocketGuard service is installed, and the installed service refuses while a portable daemon runs.
- **Trust.** The folder is writable by the user, so anything running as that user can change what then runs elevated. That is inherent in portable software and is stated in the documentation. For that reason portable mode offers only networks that need no trusted configuration: Local, LAN and the managed Tor and Yggdrasil. Existing Tor or Yggdrasil nodes cannot be added.
- **Volumes without permissions.** On a file system without access control the database cannot be protected; portable mode says so once and runs.
- **Shared driver.** The managed Yggdrasil needs the Wintun driver, which is system-wide. Portable mode removes it on exit only if it was absent before and nothing else uses it; after a kill it stays, and the network card says so.
- **Distribution.** A zip beside the MSI with the programs, the bundled third-party files and the marker file.
- **Proof.** A Windows CI job: a clean exit leaves nothing on the host, including under `%ProgramData%`; a killed daemon leaves no SocketGuard filters; portable mode refuses beside the installed service.

## Consequences

- SocketGuard can be tried or carried without installing, and removing the folder removes it.
- Protection in portable mode ends with the process. The UI says "portable" wherever it says the daemon is running.
- Two firewall code paths exist on Windows: persistent objects for the installed product and session objects for portable mode.
- Every start asks for administrator rights.

## Amendment (2026-11-12): what the first real runs showed

- **Rules after a kill:** none remain; Windows removes the session's objects. Verified on a real machine in CI.
- **Addresses after a kill:** Windows offers no choice of store. Addresses added this way do not survive a reboot, but they stay on the adapter after a kill until the next start from the same folder sweeps them, or the machine restarts.
- **The folder's data** is readable, not writable, by the account that started the UI: a writable database would let that account change what the elevated daemon trusts.
- **Logoff and shutdown** are handled through a hidden window, as Windows recommends for processes that load the user interface libraries. Only the owner-process and kill paths are exercised in CI.
- **Besides `data\`** the folder holds `ui-data\` for the UI's own storage.
