# Command line reference

`socketguard` is the primary frontend of the local API ([api.md](api.md), ADR 0033).
`socketguard --help` and `socketguard <command> --help` are the authority; this page groups the
commands by task.

Global options, valid anywhere: `--json` prints the API types as JSON; `--socket <path>` (Unix
socket or pipe name, or `SOCKETGUARD_SOCKET`) selects a daemon other than the default. Apps, peers,
groups, tags and port groups can be named by id, unique id prefix or name. `-y` / `--yes` skips a
question. Network ids are the ones `networks list` shows (`--network` takes them, repeatable).

## Status and activity

```
status                                  daemon, networks, protect-host, counts, bundled programs
init                                    first-run setup: networks, remote-admin grants, protect-host
activity [--app A] [--peer P] [--kind K] [--blocked] [--limit N] [-f]
                                        --blocked = --kind blocked; -f/--follow keeps printing
watch                                   every event the daemon pushes, one line each
settings show                           the settings
completions bash|zsh|fish|powershell|elvish
```

## Apps and sharing

```
apps list
apps show nginx                         addresses, ports, grants with reach, counters
apps rm nginx                           forget it (it reappears as a new app if it listens again)
apps move old-nginx nginx [-y]          after an upgrade changed the path: grants, tags, addresses, bindings move
share nginx [--network N]               connection strings to give to a peer
```

## Access: grant and revoke

A target is `<app>[:port[/proto]]`, `<app>:port-group=<label>`, `tag:<label>[:port[/proto]]` or
`reservation:<label>`. Without a port it is "All ports". A subject is a peer label,
`group:<label>` or `anyone` (asks first unless `-y`).

```
grant nginx:80 alice                    one app port to one peer
grant nginx:80/tcp group:team --network lan
grant ftpd:port-group=passive alice     a port group attached to the app
grant tag:dev group:team                every member, present and future
grant reservation:public-web alice      every row bound to the reservation (All ports)
revoke nginx:80 alice                   or: revoke <grant-id>
grants [--app A] [--tag T] [--reservation R] [--peer P] [--group G]
```

Many at once (one batch, all or nothing, one firewall update). The flags repeat; `--dry-run` shows
the diff and changes nothing:

```
grant --app web --app api --port 80 --port 443 --to alice --to group:team [--network lan] [--dry-run]
grant --app ftpd --port-group passive --to alice
grant --tag dev --reservation public-web --to anyone -y
revoke --app web --to alice [--network lan] [--dry-run]
```

`--app`, `--tag` take `<name>[:port[/proto]]`; `--reservation` takes a label and no port; `--port`
and `--port-group` limit the apps and tags.

## Peers and groups

```
peers list | show P | rename P NEW | rm P
peers add --label alice <ygg-key>       bare values are guessed: 64 hex = Yggdrasil key, IP/CIDR = address,
                                        52 base32 (or a descriptor:x25519: line) = Tor client key
peers add --label bob --addr 2001:db8::7 --cred wg_key=<base64>
peers add -n carol --key K --tor-key T --subnet 300:1:2:3::/64 --suffix ::a:b:c:d
peers parse <values...>                 show what pasted credentials are, add nothing
peers tor-key bob                       generate a Tor client key for bob (replaces the old one)
peers cred add P kind=value | cred rm P <cred-id>
groups list | show G | rename G NEW | rm G
groups add team alice bob               group:team in grants
groups members team alice bob           replaces the members
```

Credential kinds for `--cred`: `ygg_key`, `ygg_addr`, `ygg_subnet`, `ip`, `ip_suffix`, `wg_key`,
`tor_client_key`, `tls_spki`. A peer without a label is named after its first credential.

## Tags and port groups

```
tags list | show T | rename T NEW | rm T [-y]
tags add dev web:80 --match 'python*' --match node     members and/or globs on process name or path
tags patterns dev 'python*' [-y]                       replace the patterns (none: clear); asks on a tag open to anyone,
                                                        also when no app matches yet
tags members add dev redis [-y]                        an app, one port or web:port-group=passive
tags members rm dev redis [-y]                         a pattern-matched app stays out afterwards

port-groups list | rm G
port-groups add 21/tcp 50000-51000/tcp -n passive --app ftpd [-y]
port-groups set passive [--label NEW] [--port 21/tcp --port 50000-52000/tcp] [-y]   --port replaces the ports
port-groups attach passive ftpd [-y] | detach passive ftpd
```

## Reserved addresses

A reservation is a named address that keeps its place while the apps behind it change (ADR 0047).

```
addresses list                          every address, automatic and reserved, up or not
addresses reserve <address-id> web-public   keep an automatic address under a name
reservations list | rename R NEW | release R [-y]
reservations add public-web web:80/tcp tag:dev          bindings: app[:port[/proto]], app:port-group=L, tag:L
reservations bind R redis [-y] | unbind R redis [-y]    bind asks before opening to anyone; unbind, release,
                                                        tags rm and tags members rm ask when freeing rows
                                                        opens them to anyone on Tor (a bound row is inert there)
```

## Networks

```
networks list
networks detect                         what this host offers: LAN interfaces, Tor and Yggdrasil
networks add tor                        SocketGuard's own Tor
networks add yggdrasil --peer tls://host:port           SocketGuard's own Yggdrasil; --peer repeats
networks add ula|slaac|dhcpv6 [--interface eth0] [--id ID]
networks peers yggdrasil [--add URI] [--rm URI]         show or change the peers of the Yggdrasil node
networks lan-discovery yggdrasil [on|off] [-y]          show, or turn on or off, finding Yggdrasil nodes on the
                                        local network (off by default; on lets other computers on the LAN
                                        connect to the node and asks first; the node restarts)
networks bridges tor [--add LINE] [--rm LINE] [--clear]   show or change the obfs4 bridges of Tor;
                                        LINE is `[Bridge ]obfs4 IP:port FINGERPRINT cert=CERT iat-mode=0` (other
                                        transports are refused); changing them restarts Tor; --clear turns them off
networks rm ID [--force]                --force: remove a Tor network Tor cannot confirm is clean
```

Tor and Yggdrasil are always SocketGuard's own (ADR 0056): they have no settings but the peers and
the bridges. A host that runs its own Yggdrasil node cannot use Yggdrasil in SocketGuard while that
node runs; `networks add yggdrasil` still works and the network waits.

## Whole-host protection

```
protect-host on eth0 [eth1...] [--force]    refused if sshd/RDP would be cut off, unless --force
protect-host off | status
```

## Backup and restore

```
export -o socketguard.toml              TOML, or JSON by the .json name or --format json; stdout without -o
apply -f socketguard.toml [--dry-run] [-y]   shows the diff, asks (asks specifically when
                                        changes affect what Anyone can reach; -y confirms those too)
```

## Switching off

```
disable [-y]                            remove all rules and addresses and keep them off
enable                                  put them back
shutdown                                portable mode: stop the daemon, removing rules and addresses
```

## Access to the service

`socketguard access allow|deny <account>` and `access list` run `socketguard-daemon access` and
need administrator rights.

## The daemon binary

`socketguard-daemon` with no command runs the daemon (the service manager does this). Others, from
an administrator terminal or with sudo (ADR 0050):

```
service install [--no-start]            register and start the service (systemd, launchd, Windows service)
service start | stop | uninstall
service status [--json]                 installed? running?
access group ensure                     create the access group (socketguard / SocketGuard Users)
access allow|deny <account> | access list
uninstall [--purge | --keep-data] [--yes] [--export FILE] [--force]
--disable [--force]                     while stopped: remove rules, addresses and onion services
--portable [--owner-pid PID] [--allow-user SID]   portable mode (Windows)
```

`--owner-pid` and `--allow-user` belong to portable mode (the app passes them) and go with no other
command. `--allow-user` takes the SID of one account (`S-1-5-21-...` or `S-1-12-1-...`), not a group
such as Everyone. A file named `portable` next to the program also selects portable mode. In portable mode
`service` (except `status`), `access` and `uninstall` are refused. `child-guard` is internal.

The daemon refuses to start on a config file that does not parse (an unknown key is an error).
`uninstall` and `--disable` must work anyway, so they print a warning naming the file and the error
and go on with the built-in default configuration at the same paths: what the database, the install
record and the address ledger name is removed; networks, a database path and an API socket named
only in the unreadable file are not known (a database elsewhere is not found, so a plain run
refuses, and `--force` removes the firewall rules by name).
