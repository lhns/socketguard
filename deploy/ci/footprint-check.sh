#!/usr/bin/env bash
# Looks from OUTSIDE (never through the SocketGuard CLI or daemon) for every item of
# docs/footprint.md that exists on Linux or macOS.
#
#   footprint-check.sh expect-absent  [--ledger-export FILE]   after uninstall --purge
#   footprint-check.sh expect-present [--ledger-export FILE]   right after install
#   footprint-check.sh expect-present --require nft-table-inet   also require named items
#   footprint-check.sh expect-absent --allow-data                 the data may remain (after remove, before purge)
#   footprint-check.sh --self-test                             parse embedded samples only
#
# Output: one line per item, `PRESENT <item>` or `ABSENT <item>` (or `UNKNOWN <item>` when the
# tool refused, e.g. not root), then a summary line. Exit 1 on any mismatch, 2 on usage errors.
#
# expect-absent: every item must be ABSENT, including the config and data directories
#   themselves (install created them, so a purge removes them).
# expect-present: only the install items are required, because firewall objects, addresses,
#   database, socket and setup log appear only after the first start:
#     Linux:  systemd unit file, group `socketguard`, /etc/socketguard
#     macOS:  /Library/LaunchDaemons/de.lhns.socketguard.plist, group `socketguard`,
#             "/Library/Application Support/SocketGuard"
#   Every other item is printed with its state and marked "(not required)".
#
# Ledger export (--ledger-export): a JSON file listing the IPv6 addresses the daemon owned,
# either an array of strings or an object with an `addresses` array of strings. Any IPv6-looking
# string in the file is compared (lower-cased, textual) with the host's addresses; if it is still
# configured, the item `ledger-addresses` is PRESENT. Never required.
#
# Address baseline: `--save-addresses FILE` writes the IPv6 addresses SocketGuard could add (ULA
# fc00::/7 and /128 host addresses; link-local, ::1 and temporary/privacy ones are ignored, they
# are the OS's own) and exits. A later `expect-... --baseline FILE` adds the item `new-addresses`,
# PRESENT when such an address is on an interface that the file did not list. Package tests save
# before the first install and pass the file to every expect-absent.
#
# Tor and Yggdrasil (ADR 0052) add: the programs `tor` and `yggdrasil` running from a
# `third_party` directory, the directories <state dir>/tor and <state dir>/yggdrasil, the
# account `socketguard-net`, the Linux adapter `sgygg0` (a macOS utun goes with its process)
# and the `third_party` directory of the shipped programs (SOCKETGUARD_THIRD_PARTY, else the
# places the packages put it).
#
# The firewall pieces need root (nft, pfctl); without it they are reported UNKNOWN and fail.

set -uo pipefail

ITEMS=()   # "STATE|name|detail"
REQUIRED=" "
rec() { ITEMS+=("$1|$2|${3:-}"); }

denied() { grep -Eqi 'operation not permitted|permission denied|must be root|you need to be root' <<<"$1"; }

# ---- pure check functions: command output in, state out ------------------------------------

# nft list table <family> socketguard. A missing table prints an error that echoes the command
# ("list table inet socketguard"), so only a line that starts with `table` counts.
state_nft_table() { # family output
    if denied "$2"; then echo UNKNOWN
    elif grep -Eq "^table $1 socketguard( |\{|$)" <<<"$2"; then echo PRESENT
    else echo ABSENT; fi
}

# nft list tables: `table inet socketguard`, one line per table of every family. Any table whose
# name contains socketguard counts, in any family (a renamed or second table is a leftover too).
state_nft_tables() {
    if denied "$1"; then echo UNKNOWN
    elif grep -Eqi '^table [a-z0-9]+ .*socketguard' <<<"$1"; then echo PRESENT
    else echo ABSENT; fi
}

# getent group socketguard -> `socketguard:x:998:`
state_group_getent() { grep -Eq '^socketguard:' <<<"$1" && echo PRESENT || echo ABSENT; }

# dscl . -read /Groups/socketguard -> `RecordName: socketguard`; missing: eDSRecordNotFound
state_group_dscl() { grep -Eq '^RecordName:[[:space:]]+socketguard([[:space:]]|$)' <<<"$1" && echo PRESENT || echo ABSENT; }

# pfctl -a socketguard -sr: any rule line means the anchor holds rules.
state_pf_anchor_rules() {
    if denied "$1"; then echo UNKNOWN
    elif grep -Eq '^[[:space:]]*(block|pass|match|anchor)[[:space:]]' <<<"$1"; then echo PRESENT
    else echo ABSENT; fi
}

# /etc/pf.conf text: an uncommented anchor "socketguard" line (also `load anchor "socketguard"`).
state_pf_conf_line() { grep -Eq '^[[:space:]]*(load[[:space:]]+)?anchor[[:space:]]+"socketguard"' <<<"$1" && echo PRESENT || echo ABSENT; }

# `ps -eo args`: is there a process of the program `$1` (tor, yggdrasil) that runs from a
# `third_party` directory, i.e. one SocketGuard shipped and started?
state_child_ps() { # name output
    grep -Eq "(^|[[:space:]])[^[:space:]]*/third_party/$1/$1([[:space:]]|\$)" <<<"$2" && echo PRESENT || echo ABSENT
}

# The obfs4 helper that Tor starts (ADR 0052). Tor runs it by a name relative to its own
# directory, so `ps` may show `./pluggable_transports/lyrebird` instead of the full path.
state_helper_ps() { # output
    grep -Eq "(^|[[:space:]])([^[:space:]]*/third_party/tor/|\\./)pluggable_transports/lyrebird([[:space:]]|\$)" <<<"$1" && echo PRESENT || echo ABSENT
}

# getent passwd socketguard-net -> `socketguard-net:x:997:997::/nonexistent:/usr/sbin/nologin`
state_account_getent() { grep -Eq '^socketguard-net:' <<<"$1" && echo PRESENT || echo ABSENT; }

# dscl . -read /Users/socketguard-net -> `RecordName: socketguard-net`
state_account_dscl() { grep -Eq '^RecordName:[[:space:]]+socketguard-net([[:space:]]|$)' <<<"$1" && echo PRESENT || echo ABSENT; }

# ip -o link show sgygg0 -> `5: sgygg0: <POINTOPOINT,...>`; missing: `Device "sgygg0" does not exist.`
state_link_ip() { grep -Eq '^[0-9]+: sgygg0[:@]' <<<"$1" && echo PRESENT || echo ABSENT; }

# A newline list of existing paths and an ERE: PRESENT if any path matches.
state_listed() { grep -Eq -- "$2" <<<"$1" && echo PRESENT || echo ABSENT; }

# Addresses: first column `inet6`, second the address (strip /len and %zone).
iface_addrs() { awk '$1=="inet6"{a=$2; sub(/[\/%].*/,"",a); print tolower(a)}' | sort -u; }
# Every IPv6-looking string in a JSON text.
ledger_addrs() { grep -oE '[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}' | tr 'A-F' 'a-f' | sort -u; }
# Addresses in both: ledger text, interface output.
ledger_still_present() { comm -12 <(ledger_addrs <<<"$1") <(iface_addrs <<<"$2"); }

# The addresses SocketGuard could have added, from `ip -6 addr` or `ifconfig` text: ULA
# (fc00::/7) and /128 host addresses. Ignored on purpose, because the OS adds, rotates and
# removes them by itself: link-local (fe80::), ::1, temporary/privacy addresses, and the /64
# addresses SLAAC derives from a router advertisement (not ULA, not /128).
addr_candidates() {
    awk '$1=="inet6" {
        a=$2; len=""
        if (a ~ /\//) { split(a, p, "/"); a=p[1]; len=p[2] } else if ($3=="prefixlen") len=$4
        sub(/%.*/, "", a); a=tolower(a)
        if ($0 ~ /temporary/ || a ~ /^fe80:/ || a == "::1") next
        if (a ~ /^f[cd]/ || len == 128) print a
    }' | sort -u
}
# new_addresses BASELINE-LIST CURRENT-TEXT: candidate addresses now that the baseline lacked.
new_addresses() { comm -13 <(grep -v '^$' <<<"$1" | sort -u) <(addr_candidates <<<"$2"); }
# The host's IPv6 addresses as text; status 1 when the tool is not installed.
live_addrs() {
    case "$(uname -s)" in
        Linux) command -v ip >/dev/null 2>&1 && ip -6 addr ;;
        Darwin) command -v ifconfig >/dev/null 2>&1 && ifconfig ;;
        *) return 1 ;;
    esac
}
add_baseline_item() { # baseline file
    local cur new
    if ! cur=$(live_addrs); then rec UNKNOWN new-addresses "no ip/ifconfig"; return; fi
    new=$(new_addresses "$(cat "$1")" "$cur" | tr '\n' ' ')
    if [ -n "${new// /}" ]; then rec PRESENT new-addresses "$new"; else rec ABSENT new-addresses; fi
}

# ---- item tables ---------------------------------------------------------------------------
# name|regex over the path list. Same regexes on both systems; directories differ.
FILE_ITEMS=(
    "config-json|/socketguard\.json$"
    "database|/socketguard\.db$"
    "database-wal|/socketguard\.db-wal$"
    "database-shm|/socketguard\.db-shm$"
    "setup-log|/setup-log\.json$"
    "temp-file|/socketguard\.tmp-"
    "dir-tor|/tor$"
    "dir-yggdrasil|/yggdrasil$"
    "dir-run|/run$"
)

add_file_items() { # path list
    local e
    for e in "${FILE_ITEMS[@]}"; do rec "$(state_listed "$1" "${e#*|}")" "${e%%|*}"; done
}

add_ledger_item() { # ledger text, interface output
    local hits
    hits=$(ledger_still_present "$1" "$2" | tr '\n' ' ')
    if [ -n "${hits// /}" ]; then rec PRESENT ledger-addresses "$hits"; else rec ABSENT ledger-addresses; fi
}

# ---- live collection (only reached outside --self-test) ------------------------------------

# probe STATE-FN NAME [ARG...] -- CMD...: runs CMD and records STATE-FN ARG... OUTPUT as NAME.
# A tool that is not installed is UNKNOWN, never ABSENT: empty output would read as "nothing
# there" and hide a leftover. Every tool used here exists on the system it is used on (nft, ip,
# getent, ps, find on Linux; pfctl, dscl, ps, find on macOS), so a missing one is a broken test
# machine. The only by-design gap is the split by system itself: nft, ip and getent are never
# asked on macOS, pfctl and dscl never on Linux.
probe() {
    local fn=$1 name=$2 args=()
    shift 2
    while [ "$1" != -- ]; do args+=("$1"); shift; done
    shift
    if ! command -v "$1" >/dev/null 2>&1; then rec UNKNOWN "$name" "$1 is not installed"; return; fi
    rec "$("$fn" ${args[@]+"${args[@]}"} "$("$@" 2>&1 || true)")" "$name"
}

# The processes and the shipped files, the same on both systems.
add_network_items() { # third_party candidate directories...
    local ps_out n
    if command -v ps >/dev/null 2>&1; then
        ps_out=$(ps -eo args 2>&1 || true)
        rec "$(state_child_ps tor "$ps_out")" child-tor
        rec "$(state_child_ps yggdrasil "$ps_out")" child-yggdrasil
        rec "$(state_helper_ps "$ps_out")" child-obfs4-helper
    else
        for n in child-tor child-yggdrasil child-obfs4-helper; do rec UNKNOWN "$n" "ps is not installed"; done
    fi
    local dirs=()
    [ -n "${SOCKETGUARD_THIRD_PARTY:-}" ] && dirs+=("$SOCKETGUARD_THIRD_PARTY")
    dirs+=("$@")
    rec "$(state_listed "$(existing "${dirs[@]}")" '/third_party$')" third-party-files
}
# Existing paths, a dangling symlink included (the enable link of a unit points into /etc or /usr
# and outlives the unit file it names).
existing() { local p; for p in "$@"; do if [ -e "$p" ] || [ -L "$p" ]; then printf '%s\n' "$p"; fi; done; return 0; }
# find is part of the base system; without it the data files cannot be listed, so say UNKNOWN.
need_find() { command -v find >/dev/null 2>&1 || rec UNKNOWN tool-find "find is not installed"; }

collect_linux() {
    local paths
    need_find
    paths=$(existing /lib/systemd/system/socketguard.service /usr/lib/systemd/system/socketguard.service \
                     /etc/systemd/system/socketguard.service \
                     /etc/systemd/system/multi-user.target.wants/socketguard.service \
                     /etc/socketguard /var/lib/socketguard /run/socketguard.sock
            find /etc/socketguard /var/lib/socketguard -mindepth 1 -maxdepth 1 2>/dev/null)
    probe state_nft_table nft-table-inet inet -- nft list table inet socketguard
    probe state_nft_tables nft-tables-socketguard -- nft list tables
    rec "$(state_listed "$paths" 'systemd/system/socketguard\.service$')" systemd-unit
    rec "$(state_listed "$paths" 'multi-user\.target\.wants/socketguard\.service$')" systemd-enable-link
    probe state_group_getent group -- getent group socketguard
    rec "$(state_listed "$paths" '^/etc/socketguard$')" config-dir
    rec "$(state_listed "$paths" '^/var/lib/socketguard$')" data-dir
    add_file_items "$paths"
    rec "$(state_listed "$paths" '^/run/socketguard\.sock$')" socket
    probe state_account_getent account-socketguard-net -- getent passwd socketguard-net
    probe state_link_ip adapter-sgygg0 -- ip -o link show sgygg0
    add_network_items /usr/bin/third_party /usr/local/bin/third_party /usr/lib/socketguard/third_party /opt/socketguard/third_party
    REQUIRED=" systemd-unit group config-dir "
}

collect_macos() {
    local paths d="/Library/Application Support/SocketGuard"
    need_find
    paths=$(existing /Library/LaunchDaemons/de.lhns.socketguard.plist "$d" /var/run/socketguard.sock
            find "$d" -mindepth 1 -maxdepth 1 2>/dev/null)
    probe state_pf_anchor_rules pf-anchor-rules -- pfctl -a socketguard -sr
    # /etc/pf.conf ships with macOS; unreadable is UNKNOWN, not "no anchor line".
    if [ -r /etc/pf.conf ]; then rec "$(state_pf_conf_line "$(cat /etc/pf.conf)")" pf-conf-anchor-line
    else rec UNKNOWN pf-conf-anchor-line "/etc/pf.conf is not readable"; fi
    rec "$(state_listed "$paths" 'LaunchDaemons/de\.lhns\.socketguard\.plist$')" launchd-plist
    probe state_group_dscl group -- dscl . -read /Groups/socketguard
    rec "$(state_listed "$paths" '^/Library/Application Support/SocketGuard$')" config-dir
    add_file_items "$paths"
    rec "$(state_listed "$paths" '^/var/run/socketguard\.sock$')" socket
    probe state_account_dscl account-socketguard-net -- dscl . -read /Users/socketguard-net
    add_network_items /usr/local/bin/third_party /usr/local/lib/socketguard/third_party "$d/third_party"
    REQUIRED=" launchd-plist group config-dir "
}

# ---- verdict -------------------------------------------------------------------------------

# evaluate <absent|present>: prints the lines, returns the number of mismatches.
evaluate() {
    local mode=$1 bad=0 item state name detail note missing=() found=()
    for item in "${ITEMS[@]}"; do
        state=${item%%|*}; name=${item#*|}; detail=${name#*|}; name=${name%%|*}
        note=""
        if [ "$mode" = present ] && [[ "$REQUIRED" != *" $name "* ]]; then
            note=" (not required)"
        elif [ "$mode" = present ] && [ "$state" != PRESENT ]; then
            bad=$((bad + 1)); missing+=("$name")
        elif [ "$mode" = absent ] && [ "$state" = PRESENT ] && [[ "$ALLOWED" == *" $name "* ]]; then
            note=" (data, kept)"
        elif [ "$mode" = absent ] && [ "$state" != ABSENT ]; then
            bad=$((bad + 1)); found+=("$name")
        fi
        echo "$state $name${detail:+ ($detail)}$note"
    done
    if [ "$mode" = absent ]; then
        [ "$bad" = 0 ] && echo "OK: nothing of SocketGuard found" || echo "FAIL: found or unverifiable: ${found[*]}"
    else
        [ "$bad" = 0 ] && echo "OK: all install items present" || echo "FAIL: missing or unverifiable: ${missing[*]}"
    fi
    return "$bad"
}

# ---- self test: no system access -----------------------------------------------------------

SELF_FAIL=0
expect() { # label expected actual
    if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected '$2', got '$3'"; SELF_FAIL=1; fi
}

self_test() {
    local nft_present nft_missing nft_denied
    nft_present=$'table inet socketguard {\n\tcounter c1 {\n\t}\n\tchain input {\n\t}\n}'
    nft_missing=$'Error: No such file or directory\nlist table inet socketguard\n                  ^^^^^^^^^^^'
    nft_denied=$'Operation not permitted (you must be root)'
    expect nft-present PRESENT "$(state_nft_table inet "$nft_present")"
    expect nft-error-echoing-command ABSENT "$(state_nft_table inet "$nft_missing")"
    expect nft-empty ABSENT "$(state_nft_table ip6 "")"
    expect nft-wrong-family ABSENT "$(state_nft_table ip6 "$nft_present")"
    expect nft-denied UNKNOWN "$(state_nft_table inet "$nft_denied")"

    # every table of every family: any name containing socketguard is a leftover
    expect nft-tables-inet PRESENT "$(state_nft_tables $'table inet filter\ntable inet socketguard')"
    expect nft-tables-other-family PRESENT "$(state_nft_tables $'table ip filter\ntable ip6 socketguard')"
    expect nft-tables-renamed PRESENT "$(state_nft_tables $'table netdev my_SocketGuard_old')"
    expect nft-tables-none ABSENT "$(state_nft_tables $'table inet filter\ntable ip nat')"
    expect nft-tables-empty ABSENT "$(state_nft_tables '')"
    expect nft-tables-denied UNKNOWN "$(state_nft_tables 'Operation not permitted (you must be root)')"

    # a tool that is not installed is UNKNOWN, never ABSENT
    ITEMS=(); probe state_group_getent group -- sg-no-such-tool-xyz group socketguard
    expect missing-tool-is-unknown "UNKNOWN|group|sg-no-such-tool-xyz is not installed" "${ITEMS[0]}"
    ITEMS=(); probe state_group_getent group -- echo ""
    expect present-tool-empty-output-is-absent "ABSENT|group|" "${ITEMS[0]}"
    ITEMS=(); probe state_nft_table nft-table-inet inet -- echo "table inet socketguard {"
    expect probe-passes-state-args PRESENT "${ITEMS[0]%%|*}"
    ITEMS=(); rec UNKNOWN nft-table-inet "nft is not installed"
    evaluate absent >/dev/null; expect verdict-missing-tool-fails 1 $?

    # the enable symlink counts even when it dangles
    local sgtmp; sgtmp=$(mktemp -d)
    ln -s "$sgtmp/no-such-unit" "$sgtmp/socketguard.service"
    expect existing-dangling-symlink "$sgtmp/socketguard.service" "$(existing "$sgtmp/socketguard.service" "$sgtmp/none")"
    expect enable-link-regex PRESENT "$(state_listed "$(existing "$sgtmp/socketguard.service")" 'socketguard\.service$')"
    expect enable-link-regex-wants PRESENT "$(state_listed $'/etc/systemd/system/multi-user.target.wants/socketguard.service' 'multi-user\.target\.wants/socketguard\.service$')"
    expect enable-link-regex-other-unit ABSENT "$(state_listed $'/etc/systemd/system/multi-user.target.wants/other.service' 'multi-user\.target\.wants/socketguard\.service$')"
    expect unit-regex-ignores-wants ABSENT "$(state_listed $'/etc/systemd/system/multi-user.target.wants/socketguard.service' 'systemd/system/socketguard\.service$')"
    rm -rf "$sgtmp"

    expect getent-present PRESENT "$(state_group_getent 'socketguard:x:998:alice')"
    expect getent-absent ABSENT "$(state_group_getent '')"
    expect getent-other-group ABSENT "$(state_group_getent 'socketguard2:x:5:')"

    expect dscl-present PRESENT "$(state_group_dscl $'PrimaryGroupID: 401\nRecordName: socketguard')"
    expect dscl-absent ABSENT "$(state_group_dscl '<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)')"

    expect pf-rules-present PRESENT "$(state_pf_anchor_rules $'block drop in quick inet6 proto tcp to fd00::1 port = 8080\npass out quick all')"
    expect pf-rules-empty ABSENT "$(state_pf_anchor_rules '')"
    expect pf-rules-no-anchor ABSENT "$(state_pf_anchor_rules 'pfctl: Anchor socketguard does not exist')"
    expect pf-denied UNKNOWN "$(state_pf_anchor_rules 'pfctl: /dev/pf: Permission denied')"

    expect pf-conf-present PRESENT "$(state_pf_conf_line $'scrub-anchor "com.apple/*"\nanchor "socketguard"\n')"
    expect pf-conf-commented ABSENT "$(state_pf_conf_line $'# anchor "socketguard"\nanchor "com.apple/*"')"
    expect pf-conf-absent ABSENT "$(state_pf_conf_line $'anchor "com.apple/*"')"

    local list=$'/etc/socketguard\n/etc/socketguard/socketguard.json\n/var/lib/socketguard/socketguard.db-wal\n/var/lib/socketguard/socketguard.tmp-12-abc\n/etc/systemd/system/socketguard.service'
    expect list-config PRESENT "$(state_listed "$list" '/socketguard\.json$')"
    expect list-db-not-wal ABSENT "$(state_listed "$list" '/socketguard\.db$')"
    expect list-wal PRESENT "$(state_listed "$list" '/socketguard\.db-wal$')"
    expect list-shm ABSENT "$(state_listed "$list" '/socketguard\.db-shm$')"
    expect list-tmp PRESENT "$(state_listed "$list" '/socketguard\.tmp-')"
    expect list-unit PRESENT "$(state_listed "$list" 'systemd/system/socketguard\.service$')"
    expect list-dir-exact ABSENT "$(state_listed "$list" '^/var/lib/socketguard$')"
    local mlist=$'/var/lib/socketguard/tor\n/var/lib/socketguard/yggdrasil\n/var/lib/socketguard/run'
    expect list-tor-dir PRESENT "$(state_listed "$mlist" '/tor$')"
    expect list-ygg-dir PRESENT "$(state_listed "$mlist" '/yggdrasil$')"
    expect list-run-dir PRESENT "$(state_listed "$mlist" '/run$')"
    expect list-run-dir-needs-exact-name ABSENT "$(state_listed "$list" '/run$')"
    expect list-tor-dir-needs-exact-name ABSENT "$(state_listed "$list" '/tor$')"
    expect list-third-party PRESENT "$(state_listed "/usr/lib/socketguard/third_party" '/third_party$')"

    local ps_ours=$'/sbin/init\n/usr/lib/socketguard/third_party/tor/tor -f /var/lib/socketguard/tor/torrc\n/usr/lib/socketguard/third_party/yggdrasil/yggdrasil -useconffile /var/lib/socketguard/yggdrasil/yggdrasil.conf -user socketguard-net'
    expect child-tor PRESENT "$(state_child_ps tor "$ps_ours")"
    expect child-yggdrasil PRESENT "$(state_child_ps yggdrasil "$ps_ours")"
    expect child-obfs4-helper PRESENT "$(state_helper_ps $'/sbin/init\n./pluggable_transports/lyrebird')"
    expect child-obfs4-helper-full-path PRESENT "$(state_helper_ps $'/usr/lib/socketguard/third_party/tor/pluggable_transports/lyrebird')"
    expect child-obfs4-helper-absent ABSENT "$(state_helper_ps "$ps_ours")"
    expect child-obfs4-helper-other-lyrebird ABSENT "$(state_helper_ps $'/usr/bin/lyrebird')"
    expect child-none ABSENT "$(state_child_ps yggdrasil $'/sbin/init\n/usr/sbin/tor --runasdaemon 1')"
    expect child-system-yggdrasil-is-not-ours ABSENT "$(state_child_ps yggdrasil $'/usr/bin/yggdrasil -useconffile /etc/yggdrasil.conf')"
    expect child-tor-path-must-be-exact ABSENT "$(state_child_ps tor $'/opt/third_party/yggdrasil/yggdrasil')"
    expect account-getent PRESENT "$(state_account_getent 'socketguard-net:x:997:997::/nonexistent:/usr/sbin/nologin')"
    expect account-getent-absent ABSENT "$(state_account_getent '')"
    expect account-dscl PRESENT "$(state_account_dscl $'RecordName: socketguard-net\nUniqueID: 300')"
    expect account-dscl-absent ABSENT "$(state_account_dscl '<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)')"
    expect adapter-present PRESENT "$(state_link_ip '5: sgygg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 65535 qdisc fq_codel')"
    expect adapter-absent ABSENT "$(state_link_ip 'Device "sgygg0" does not exist.')"
    expect adapter-other-name ABSENT "$(state_link_ip '3: sgygg01: <BROADCAST>')"
    expect list-empty ABSENT "$(state_listed "" '/socketguard\.json$')"

    local ledger_arr='["fd00::1", "FD00:0:0:0::2/128"]'
    local ledger_obj='{"addresses": ["fd00::1"], "note": "x"}'
    local linux_ip=$'1: lo: <LOOPBACK>\n    inet6 ::1/128 scope host\n    inet6 fd00::1/128 scope global\n    inet6 fe80::1/64 scope link'
    local mac_if=$'lo0: flags=8049<UP>\n\tinet6 ::1 prefixlen 128\n\tinet6 fd00::1 prefixlen 128\n\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1'
    expect ledger-array-linux "fd00::1" "$(ledger_still_present "$ledger_arr" "$linux_ip" | tr '\n' ' ' | sed 's/ $//')"
    expect ledger-object-mac "fd00::1" "$(ledger_still_present "$ledger_obj" "$mac_if" | tr '\n' ' ' | sed 's/ $//')"
    expect ledger-gone "" "$(ledger_still_present "$ledger_arr" $'    inet6 ::1/128 scope host')"

    # address baseline: ULA and /128 count; link-local, ::1, temporary and SLAAC /64 do not
    local before_ip=$'1: lo: <LOOPBACK>\n    inet6 ::1/128 scope host\n2: eth0: <UP>\n    inet6 2001:db8::5/64 scope global dynamic\n    inet6 2001:db8::77/64 scope global temporary dynamic\n    inet6 fe80::1/64 scope link'
    local after_ip="$before_ip"$'\n3: sgygg0: <UP>\n    inet6 fd00::9/128 scope global\n    inet6 201:abcd::1/128 scope global\n    inet6 2001:db8::88/64 scope global temporary dynamic'
    local baseline_list; baseline_list=$(addr_candidates <<<"$before_ip")
    expect addr-baseline-empty "" "$baseline_list"
    expect addr-candidates-ula-and-host "201:abcd::1 fd00::9" "$(addr_candidates <<<"$after_ip" | tr '\n' ' ' | sed 's/ $//')"
    expect addr-candidates-mac "fd00::2" "$(addr_candidates <<<$'\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1\n\tinet6 fd00::2 prefixlen 64\n\tinet6 2001:db8::3 prefixlen 64 autoconf temporary' | tr '\n' ' ' | sed 's/ $//')"
    # planted leftover: the purge left addresses the baseline did not have
    expect addr-leftover-found "201:abcd::1 fd00::9" "$(new_addresses "$baseline_list" "$after_ip" | tr '\n' ' ' | sed 's/ $//')"
    expect addr-unchanged-host-ok "" "$(new_addresses "$baseline_list" "$before_ip")"
    expect addr-temporary-rotation-ignored "" "$(new_addresses "$baseline_list" "$before_ip"$'\n    inet6 2001:db8::99/64 scope global temporary dynamic')"
    expect addr-baseline-ula-kept-is-not-new "" "$(new_addresses "fd00::9" $'    inet6 fd00::9/128 scope global')"
    ITEMS=(); rec ABSENT config-dir; rec PRESENT new-addresses "fd00::9"
    evaluate absent >/dev/null; expect verdict-new-address-fails 1 $?

    # verdicts over synthetic items
    ITEMS=(); REQUIRED=" systemd-unit group config-dir "
    rec ABSENT systemd-unit; rec ABSENT group; rec ABSENT config-dir; rec ABSENT nft-table-inet
    evaluate absent >/dev/null; expect verdict-absent-clean 0 $?
    evaluate present >/dev/null; expect verdict-present-missing-required 3 $?
    ITEMS=(); rec PRESENT systemd-unit; rec PRESENT group; rec PRESENT config-dir; rec ABSENT nft-table-inet
    evaluate present >/dev/null; expect verdict-present-ok 0 $?
    evaluate absent >/dev/null; expect verdict-absent-leftover 3 $?
    ITEMS=(); rec UNKNOWN nft-table-inet
    evaluate absent >/dev/null; expect verdict-unknown-fails 1 $?
    ITEMS=(); rec PRESENT systemd-unit; rec PRESENT group; rec PRESENT config-dir; rec ABSENT database
    evaluate present | tail -1 >/dev/null; expect verdict-optional-not-counted 0 "${PIPESTATUS[0]}"

    if [ "$SELF_FAIL" = 0 ]; then echo "SELF-TEST PASSED"; else echo "SELF-TEST FAILED"; fi
    return "$SELF_FAIL"
}

# ---- main ----------------------------------------------------------------------------------

usage() { echo "usage: $0 expect-absent|expect-present [--allow-data] [--require NAME[,NAME]] [--ledger-export FILE] [--baseline FILE] | --save-addresses FILE | --self-test" >&2; exit 2; }

DATA_ITEMS=" config-dir data-dir config-json database database-wal database-shm setup-log temp-file dir-tor dir-yggdrasil dir-run account-socketguard-net "
ALLOWED=" "
mode="" ledger="" baseline="" save="" selftest=0 extra_required=""
while [ $# -gt 0 ]; do
    case "$1" in
        expect-absent) mode=absent ;;
        expect-present) mode=present ;;
        --ledger-export) [ $# -ge 2 ] || usage; ledger=$2; shift ;;
        --baseline) [ $# -ge 2 ] || usage; baseline=$2; shift ;;
        --save-addresses) [ $# -ge 2 ] || usage; save=$2; shift ;;
        --allow-data) ALLOWED=$DATA_ITEMS ;;
        --require) [ $# -ge 2 ] || usage; extra_required=$2; shift ;;
        --self-test) selftest=1 ;;
        *) usage ;;
    esac
    shift
done

if [ "$selftest" = 1 ]; then self_test; exit $?; fi
if [ -n "$save" ]; then
    live=$(live_addrs) || { echo "cannot list the IPv6 addresses: no ip/ifconfig" >&2; exit 2; }
    addr_candidates <<<"$live" >"$save" || exit 2
    echo "saved $(wc -l <"$save" | tr -d " ") address(es) to $save"
    exit 0
fi
[ -n "$mode" ] || usage
if [ -n "$baseline" ] && [ ! -r "$baseline" ]; then echo "cannot read baseline: $baseline" >&2; exit 2; fi
if [ -n "$ledger" ] && [ ! -r "$ledger" ]; then echo "cannot read ledger export: $ledger" >&2; exit 2; fi

case "$(uname -s)" in
    Linux) collect_linux ;;
    Darwin) collect_macos ;;
    *) echo "unsupported system $(uname -s); use footprint-check.ps1 on Windows" >&2; exit 2 ;;
esac
for n in ${extra_required//,/ }; do REQUIRED="$REQUIRED$n "; done
if [ -n "$ledger" ]; then
    if live=$(live_addrs); then add_ledger_item "$(cat "$ledger")" "$live"; else rec UNKNOWN ledger-addresses "no ip/ifconfig"; fi
fi
if [ -n "$baseline" ]; then add_baseline_item "$baseline"; fi

evaluate "$mode"
if [ $? -eq 0 ]; then exit 0; else exit 1; fi
