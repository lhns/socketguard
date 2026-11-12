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
# Managed networks (ADR 0052) add: the programs `tor` and `yggdrasil` running from a
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

run() { command -v "$1" >/dev/null 2>&1 && "$@" 2>&1 || true; }

# The processes and the shipped files, the same on both systems.
add_managed_items() { # third_party candidate directories...
    local ps_out; ps_out=$(run ps -eo args)
    rec "$(state_child_ps tor "$ps_out")" child-tor
    rec "$(state_child_ps yggdrasil "$ps_out")" child-yggdrasil
    rec "$(state_helper_ps "$ps_out")" child-obfs4-helper
    local dirs=() d
    [ -n "${SOCKETGUARD_THIRD_PARTY:-}" ] && dirs+=("$SOCKETGUARD_THIRD_PARTY")
    dirs+=("$@")
    rec "$(state_listed "$(existing "${dirs[@]}")" '/third_party$')" third-party-files
}
existing() { local p; for p in "$@"; do [ -e "$p" ] && printf '%s\n' "$p"; done; return 0; }

collect_linux() {
    local paths
    paths=$(existing /lib/systemd/system/socketguard.service /usr/lib/systemd/system/socketguard.service \
                     /etc/systemd/system/socketguard.service /etc/socketguard /var/lib/socketguard \
                     /run/socketguard.sock
            find /etc/socketguard /var/lib/socketguard -mindepth 1 -maxdepth 1 2>/dev/null)
    rec "$(state_nft_table inet "$(run nft list table inet socketguard)")" nft-table-inet
    rec "$(state_listed "$paths" 'systemd/system/socketguard\.service$')" systemd-unit
    rec "$(state_group_getent "$(run getent group socketguard)")" group
    rec "$(state_listed "$paths" '^/etc/socketguard$')" config-dir
    rec "$(state_listed "$paths" '^/var/lib/socketguard$')" data-dir
    add_file_items "$paths"
    rec "$(state_listed "$paths" '^/run/socketguard\.sock$')" socket
    rec "$(state_account_getent "$(run getent passwd socketguard-net)")" account-socketguard-net
    rec "$(state_link_ip "$(run ip -o link show sgygg0)")" adapter-sgygg0
    add_managed_items /usr/bin/third_party /usr/local/bin/third_party /usr/lib/socketguard/third_party /opt/socketguard/third_party
    LIVE_ADDRS=$(run ip -6 addr)
    REQUIRED=" systemd-unit group config-dir "
}

collect_macos() {
    local paths d="/Library/Application Support/SocketGuard"
    paths=$(existing /Library/LaunchDaemons/de.lhns.socketguard.plist "$d" /var/run/socketguard.sock
            find "$d" -mindepth 1 -maxdepth 1 2>/dev/null)
    rec "$(state_pf_anchor_rules "$(run pfctl -a socketguard -sr)")" pf-anchor-rules
    rec "$(state_pf_conf_line "$(cat /etc/pf.conf 2>/dev/null)")" pf-conf-anchor-line
    rec "$(state_listed "$paths" 'LaunchDaemons/de\.lhns\.socketguard\.plist$')" launchd-plist
    rec "$(state_group_dscl "$(run dscl . -read /Groups/socketguard)")" group
    rec "$(state_listed "$paths" '^/Library/Application Support/SocketGuard$')" config-dir
    add_file_items "$paths"
    rec "$(state_listed "$paths" '^/var/run/socketguard\.sock$')" socket
    rec "$(state_account_dscl "$(run dscl . -read /Users/socketguard-net)")" account-socketguard-net
    add_managed_items /usr/local/bin/third_party /usr/local/lib/socketguard/third_party "$d/third_party"
    LIVE_ADDRS=$(run ifconfig)
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

usage() { echo "usage: $0 expect-absent|expect-present [--allow-data] [--require NAME[,NAME]] [--ledger-export FILE] | --self-test" >&2; exit 2; }

DATA_ITEMS=" config-dir data-dir config-json database database-wal database-shm setup-log temp-file dir-tor dir-yggdrasil dir-run account-socketguard-net "
ALLOWED=" "
mode="" ledger="" selftest=0 extra_required=""
while [ $# -gt 0 ]; do
    case "$1" in
        expect-absent) mode=absent ;;
        expect-present) mode=present ;;
        --ledger-export) [ $# -ge 2 ] || usage; ledger=$2; shift ;;
        --allow-data) ALLOWED=$DATA_ITEMS ;;
        --require) [ $# -ge 2 ] || usage; extra_required=$2; shift ;;
        --self-test) selftest=1 ;;
        *) usage ;;
    esac
    shift
done

if [ "$selftest" = 1 ]; then self_test; exit $?; fi
[ -n "$mode" ] || usage
if [ -n "$ledger" ] && [ ! -r "$ledger" ]; then echo "cannot read ledger export: $ledger" >&2; exit 2; fi

LIVE_ADDRS=""
case "$(uname -s)" in
    Linux) collect_linux ;;
    Darwin) collect_macos ;;
    *) echo "unsupported system $(uname -s); use footprint-check.ps1 on Windows" >&2; exit 2 ;;
esac
for n in ${extra_required//,/ }; do REQUIRED="$REQUIRED$n "; done
if [ -n "$ledger" ]; then add_ledger_item "$(cat "$ledger")" "$LIVE_ADDRS"; fi

evaluate "$mode"
if [ $? -eq 0 ]; then exit 0; else exit 1; fi
