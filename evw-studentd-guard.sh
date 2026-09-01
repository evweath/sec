#!/bin/bash
# evw-studentd-guard.sh — kill studentd on sight, every 5 minutes.
#
# Requested 2026-09-01. Runs as root LaunchDaemon (com.evw.studentd-guard,
# KeepAlive). studentd is Apple's Classroom managed-device daemon — unneeded on
# this Mac and already service-disabled by evw-comms-setup.sh; this guard is
# belt-and-suspenders in case it ever respawns.
#
# ⚠️  airportd IS DELIBERATELY NOT IN THE KILL LIST.
# airportd IS the macOS Wi-Fi daemon: killing it drops the Wi-Fi link every
# time — the exact outage class root-caused and fixed on 2026-09-01
# (comms-guard/bluetoothd incident, see /Users/evw/dev/fix/netdiag/STATE.md).
# NEVER add: airportd, bluetoothd, wifid, mDNSResponder, configd.
#
# Deployed to: /usr/local/bin/evw-studentd-guard.sh
# LaunchDaemon: com.evw.studentd-guard  (root, KeepAlive=true)

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# As root, only trust a root-owned lib: a user-writable ancestor dir (e.g.
# Intel Homebrew's /usr/local) could plant one and have it sourced as root.
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }
EVW_GUARD_POLICY=continue   # daemon: a tripped breaker logs + skips, never exits

umask 077   # root logs in /private/var/log must not be world-readable

LOG="/private/var/log/evw-studentd-guard.log"
# Not root (e.g. manual run as user)? Fall back to a user-writable log
# instead of spamming "Permission denied" on every log line.
if ! touch "$LOG" 2>/dev/null; then LOG="$HOME/Library/Logs/$(basename "$LOG")"; fi
mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

INTERVAL=300   # 5 minutes, as requested

KILL_LIST=(
    studentd
)
# NEVER add: airportd bluetoothd wifid mDNSResponder configd — network/radio critical.

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

# probe wrapper: for pgrep rc 1 (no match) is a normal result, not a probe
# failure — only rc > 1 means the probe itself broke.
probe() { "$@" 2>/dev/null; [ $? -le 1 ]; }

log "=== evw-studentd-guard started (PID=$$, interval=${INTERVAL}s) ==="

while true; do
    for proc in "${KILL_LIST[@]}"; do
        pids=$(guard_run "probe" probe pgrep -x "$proc") || true
        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                ppid=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
                log "KILL $proc PID=$pid PPID=${ppid:-?}"
                guard_run "kill" kill -SIGKILL "$pid" 2>/dev/null || true
            done
        fi
    done
    sleep "$INTERVAL"
done
