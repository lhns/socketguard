#!/bin/bash
# Wrapper script for cargo on this system.
# Git Bash's /usr/bin/link.exe shadows MSVC's linker, causing build failures.
# This script fixes PATH before invoking cargo.

MSVC_BIN="/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64"
export PATH="$MSVC_BIN:$(echo "$PATH" | sed 's|/usr/bin:||')"
exec cargo "$@"
