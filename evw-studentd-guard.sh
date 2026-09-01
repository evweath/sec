#!/bin/bash
# evw-studentd-guard.sh — kill remote-connectivity daemons on sight, every 5 min.
#
# Requested 2026-09-01 (expanded from studentd-only to the full remote-access
# set: remote desktop/screensharing/ARD, AirPlay, Continuity/Handoff, Nearby,
# media-remote, conferencing, hotspot, SMB). All of these are already
# launchd-disabled by the lockdown — this guard is belt-and-suspenders for
# instances that respawn anyway (launchd "disabled" does not stop respawns).
#
# ⚠️  bluetoothd IS DELIBERATELY NOT IN THE KILL LIST (2026-09-01 incident):
# killing bluetoothd flaps the shared Wi-Fi/BT radio and caused the recurring
# internet outages fixed today — see /Users/evw/dev/security/netdiag/STATE.md.
# Same for airportd, wifid, mDNSResponder, configd, WirelessRadioManagerd.
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

INTERVAL=15    # seconds — practical suppression ceiling. Apple's continuity
               # stack relaunches within SECONDS of any kill and ignores
               # launchctl disable / bootout / trigger removal (all proven
               # 2026-09-01). Dead-time: ~50% at 60s, ~80% at 15s; below this
               # is pure churn for diminishing returns. bluetoothd EXCLUDED.

KILL_LIST=(
    studentd
    remoted
    screensharingd
    ARDAgent
    remotemanagementd
    RemoteManagementAgent
    AirPlayReceiver
    AirPlayUIAgent
    AirPlayXPCHelper
    rapportd
    sharingd
    identityservicesd
    nearbyd
    universalcontrol
    mediaremoted
    avconferenced
    PersonalHotspotAgent
    smbd
    NetBIOS
)
# NEVER add: airportd bluetoothd wifid mDNSResponder configd WirelessRadioManagerd
# — network/radio critical. bluetoothd especially: killing it flaps the shared
# Wi-Fi/BT radio (proven 2026-09-01 — user confirmed: keep it alive).

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
