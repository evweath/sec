#!/bin/bash
# evw-comms-guard.sh — kill all non-WiFi communication processes every 25s.
#
# Covered channels:
#   Bluetooth:          bluetoothd, bluetoothaudiod, BTLEServer, BTAvrcp
#   AirPlay:            AirPlayReceiver, AirPlayUIAgent, AirPlayXPCHelper
#   Universal Control:  universalcontrol
#   Handoff/Continuity: rapportd
#   Personal Hotspot:   PersonalHotspotAgent
#   Screen Sharing:     screensharingd, ARDAgent
#   Media Remote:       mediaremoted
#   Nearby/UWB:         nearbyd
#   Already-disabled (belt-and-suspenders):
#                       replayd, studentd, remotemanagementd, RemoteManagementAgent,
#                       sharingd, identityservicesd, replicatord, privatecloudcomputed
#
# Note: replayd-guard.sh kills replayd at 5s; this catches it at 25s as backup.
# Note: airportd and mDNSResponder are NOT in the kill list — needed for WiFi/DNS.
#
# Deployed to: /usr/local/bin/evw-comms-guard.sh
# LaunchDaemon: com.evw.comms-guard  (root, KeepAlive=true)

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

# ── DISABLED 2026-09-01 ─────────────────────────────────────────────────────
# This guard CAUSED the recurring internet outages it was meant to defend
# against: SIGKILLing bluetoothd every 25s tears down the shared Wi-Fi/Bluetooth
# radio on Apple Silicon, flapping en0 for 10–20s roughly every 100s.
# Root-caused with monitor + system-log correlation; full evidence:
#   /Users/evw/dev/fix/netdiag/STATE.md
# Do not re-enable without a redesign (e.g. one-time `launchctl disable`
# instead of a perpetual SIGKILL loop — and never touch bluetoothd).
COMMS_GUARD_ENABLED=${COMMS_GUARD_ENABLED:-0}
if [ "$COMMS_GUARD_ENABLED" != "1" ]; then
    echo "evw-comms-guard: DISABLED 2026-09-01 — it caused the recurring Wi-Fi outages (see header). Override: COMMS_GUARD_ENABLED=1" >&2
    exit 0
fi

umask 077   # root logs in /private/var/log must not be world-readable

LOG="/private/var/log/evw-comms-guard.log"
INTERVAL=25

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

# probe wrapper: for pgrep/lsof rc 1 (no match / nothing found) is a normal
# result, not a probe failure — only rc > 1 means the probe itself broke.
probe() { "$@" 2>/dev/null; [ $? -le 1 ]; }

WATCH=(
    # Bluetooth stack
    bluetoothd
    bluetoothaudiod
    BTLEServer
    BTAvrcp
    # AirPlay
    AirPlayReceiver
    AirPlayUIAgent
    AirPlayXPCHelper
    # Universal Control (keyboard/mouse sharing across Apple devices)
    universalcontrol
    # Handoff / Continuity relay
    rapportd
    # Personal Hotspot
    PersonalHotspotAgent
    # Screen Sharing / Remote Desktop
    screensharingd
    ARDAgent
    # Media Remote (allows other Apple devices to control media playback)
    mediaremoted
    # Nearby Interaction / UWB ranging
    nearbyd
    # Belt-and-suspenders for already-launchctl-disabled services
    replayd
    studentd
    remotemanagementd
    RemoteManagementAgent
    sharingd
    identityservicesd
    replicatord
    privatecloudcomputed
)

log "=== evw-comms-guard started (PID=$$, interval=${INTERVAL}s) ==="

while true; do
    for proc in "${WATCH[@]}"; do
        pids=$(guard_run "probe" probe pgrep -x "$proc") || true
        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                ppid=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
                reason=$(launchctl print "gui/501/com.apple.$proc" 2>/dev/null \
                    | grep "immediate reason" | tr -d '\t') || true
                net=$(guard_run "probe-net" probe lsof -i -n -P -p "$pid" \
                    | awk 'NR>1{print $9,$10}' | head -3 | tr '\n' ' ') || true
                log "KILL $proc PID=$pid PPID=${ppid:-?} reason=${reason:-n/a} net=${net:-(none)}"
                guard_run "kill" kill -SIGKILL "$pid" 2>/dev/null || true
            done
        fi
    done
    # ── en0 connectivity watchdog ─────────────────────────────────────────
    # Alert if WiFi interface goes down unexpectedly (attacker toggling it).
    EN0_STATE_FILE="/private/var/run/evw-en0-prev-state.txt"
    en0_now=$(guard_run "probe-en0" ifconfig en0 2>/dev/null | grep -o 'status: [a-z]*' | awk '{print $2}')
    en0_was=$(cat "$EN0_STATE_FILE" 2>/dev/null || echo "active")
    if [[ "$en0_was" == "active" && "$en0_now" != "active" ]]; then
        log "ALERT: en0 went DOWN (status='${en0_now}') — possible connectivity attack"
        CONSOLE_USER=$(stat -f '%Su' /dev/console 2>/dev/null || echo "")
        if [[ -n "$CONSOLE_USER" ]]; then
            CUID=$(id -u "$CONSOLE_USER" 2>/dev/null || echo "")
            [[ -n "$CUID" ]] && guard_run "notify-en0" launchctl asuser "$CUID" /usr/bin/osascript \
                -e 'display notification "WiFi interface en0 went down — possible attack" with title "SECURITY ALERT" subtitle "Connectivity Killed" sound name "Basso"' \
                2>/dev/null || true
        fi
    elif [[ "$en0_was" != "active" && "$en0_now" == "active" ]]; then
        log "INFO: en0 recovered (status='${en0_now}')"
    fi
    printf '%s' "${en0_now:-unknown}" > "$EN0_STATE_FILE"

    sleep "$INTERVAL"
done
