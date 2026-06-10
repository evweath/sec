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

LOG="/private/var/log/evw-comms-guard.log"
INTERVAL=25

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

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
        pids=$(pgrep -x "$proc" 2>/dev/null) || true
        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                ppid=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
                reason=$(launchctl print "gui/501/com.apple.$proc" 2>/dev/null \
                    | grep "immediate reason" | tr -d '\t') || true
                net=$(lsof -i -n -P -p "$pid" 2>/dev/null \
                    | awk 'NR>1{print $9,$10}' | head -3 | tr '\n' ' ') || true
                log "KILL $proc PID=$pid PPID=${ppid:-?} reason=${reason:-n/a} net=${net:-(none)}"
                kill -SIGKILL "$pid" 2>/dev/null || true
            done
        fi
    done
    # ── en0 connectivity watchdog ─────────────────────────────────────────
    # Alert if WiFi interface goes down unexpectedly (attacker toggling it).
    EN0_STATE_FILE="/private/var/run/evw-en0-prev-state.txt"
    en0_now=$(ifconfig en0 2>/dev/null | grep -o 'status: [a-z]*' | awk '{print $2}')
    en0_was=$(cat "$EN0_STATE_FILE" 2>/dev/null || echo "active")
    if [[ "$en0_was" == "active" && "$en0_now" != "active" ]]; then
        log "ALERT: en0 went DOWN (status='${en0_now}') — possible connectivity attack"
        CONSOLE_USER=$(stat -f '%Su' /dev/console 2>/dev/null || echo "")
        if [[ -n "$CONSOLE_USER" ]]; then
            CUID=$(id -u "$CONSOLE_USER" 2>/dev/null || echo "")
            [[ -n "$CUID" ]] && launchctl asuser "$CUID" /usr/bin/osascript \
                -e 'display notification "WiFi interface en0 went down — possible attack" with title "SECURITY ALERT" subtitle "Connectivity Killed" sound name "Basso"' \
                2>/dev/null || true
        fi
    elif [[ "$en0_was" != "active" && "$en0_now" == "active" ]]; then
        log "INFO: en0 recovered (status='${en0_now}')"
    fi
    printf '%s' "${en0_now:-unknown}" > "$EN0_STATE_FILE"

    sleep "$INTERVAL"
done
