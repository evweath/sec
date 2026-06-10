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
    sleep "$INTERVAL"
done
