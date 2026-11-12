# Third-party software

SocketGuard releases ship unmodified copies of the programs below, started by SocketGuard as separate processes (ADR 0052). Their licence texts are installed in `third_party/licenses/<name>.txt` next to the programs. The pinned versions and checksums are in `deploy/bundle/versions.toml`; the installed `third_party/VERSIONS` names what a given build contains.

Which programs are present depends on the system: the Tor bundle carries lyrebird (a static Go program) on every system, libevent (a dynamic library on Linux and macOS, built into `tor.exe` on Windows) and OpenSSL (dynamic libraries on Linux, statically linked on macOS and Windows) and uses the system zlib on Linux and macOS; Wintun is Windows only.

| Component | Used for | Copyright | Licence | Licence text |
|---|---|---|---|---|
| Tor | `tor/tor` | The Tor Project, Inc., Roger Dingledine, Nick Mathewson | BSD 3-clause | `licenses/tor.txt` |
| lyrebird (obfs4) | `tor/pluggable_transports/lyrebird` (the transport helper for bridges) | The Tor Project; Yawning Angel | BSD 2-clause (Go dependencies: BSD, MIT, Apache-2.0, MPL-2.0 and others) | `licenses/lyrebird.txt` (lists every licence) |
| libevent | Tor dependency | Niels Provos, Nick Mathewson and contributors | BSD 3-clause | `licenses/libevent.txt` |
| OpenSSL 3.x | Tor dependency | The OpenSSL Project Authors | Apache-2.0 | `licenses/openssl.txt` |
| zlib | Tor dependency (statically linked on Windows) | Jean-loup Gailly, Mark Adler | zlib licence | `licenses/zlib.txt` (when shipped with the bundle) |
| Yggdrasil | `yggdrasil/yggdrasil` | Yggdrasil Network contributors | LGPL-3.0 with a combined-work exception | `licenses/yggdrasil.txt` |
| Wintun | `yggdrasil/wintun.dll` (Windows) | WireGuard LLC | Prebuilt Binaries License | `licenses/wintun.txt` |

`licenses/tor.txt` also lists the licences of the smaller components inside Tor.

## Tor, libevent, OpenSSL, zlib

Tor Expert Bundle 16.0.1 from https://www.torproject.org, taken unmodified from https://dist.torproject.org/torbrowser/16.0.1/ after checking its SHA-256 and the signature of the Tor Project's signed checksum file. The bundle's obfs4 transport helper, lyrebird (https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird), is shipped with it and started by Tor only when the user has set bridges; SocketGuard enables obfs4 only, although lyrebird also speaks meek, obfs2, obfs3, scramblesuit, snowflake and webtunnel. Its licence text covers its Go dependencies. conjure-client is not shipped. Tor's source is at https://gitlab.torproject.org/tpo/core/tor.

## Yggdrasil

Yggdrasil v0.5.15 is licensed under the GNU Lesser General Public License version 3, with an exception that lets a combined work link to it without the source and installation information of LGPL section 4. SocketGuard does not link to it: the unmodified program, built from the pinned source, runs as a separate process and talks to SocketGuard over its admin socket. The complete source of the shipped binary is:

- https://github.com/yggdrasil-network/yggdrasil-go/tree/2c7f050fc5398ecd8ac5f77e9bb5bd91aa2e9e35 (tag `v0.5.15`)
- https://github.com/yggdrasil-network/yggdrasil-go/archive/refs/tags/v0.5.15.tar.gz

It is built with `deploy/bundle/fetch.sh --build-yggdrasil` (Go, `-trimpath`, CGO off). Its Go module dependencies are listed in the `go.mod` and `go.sum` of that source.

## Wintun

Wintun 0.14.1, Copyright (C) WireGuard LLC, https://www.wintun.net. `wintun.dll` is shipped unmodified, as downloaded from https://www.wintun.net/builds/wintun-0.14.1.zip, and used only through its published API, as the Prebuilt Binaries License allows. The licence forbids using the name of WireGuard LLC or the Wintun project to promote SocketGuard.
