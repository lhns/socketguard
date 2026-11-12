# shellcheck shell=bash
# Helpers the package test scripts share (test/deb.sh, rpm-systemd.sh, pkg.sh and networks.sh).
# Source it, do not run it. Each script stays its own readable sequence of steps.
#
#   step TEXT           a heading
#   note TEXT           an indented line
#   ok TEXT             a check that passed (counted)
#   skip TEXT           a check this runner cannot do: said with the exact reason, counted, shown
#                       as a CI warning and listed by summary; never faked
#   fail TEXT           print TEXT, then on_fail (the script's own diagnostics), and exit 1
#   wait_until SECONDS CMD...   poll CMD once a second until it succeeds (false after SECONDS)
#   summary LABEL       "LABEL: N checks passed, M skipped" and the skips
#
# A script that wants diagnostics on failure defines on_fail before the first fail.

_LIB_OK=0
_LIB_SKIPPED=()

step() { printf '\n== %s\n' "$*"; }
note() { echo "  $*"; }
ok() { _LIB_OK=$((_LIB_OK + 1)); echo "  ok: $*"; }
skip() { _LIB_SKIPPED+=("$*"); echo "  SKIPPED: $*"; echo "::warning::SKIPPED: $*"; }

on_fail() { :; }
fail() {
    echo "FAIL: $*" >&2
    on_fail
    exit 1
}

wait_until() {
    local end=$((SECONDS + $1))
    shift
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -ge "$end" ] && return 1
        sleep 1
    done
}

summary() {
    echo
    echo "$1: $_LIB_OK checks passed, ${#_LIB_SKIPPED[@]} skipped"
    local s
    for s in ${_LIB_SKIPPED[@]+"${_LIB_SKIPPED[@]}"}; do echo "  skipped: $s"; done
}
