#!/bin/bash
# netdiag/deploy10.sh — kill remote-connectivity daemons now + expand guard.
# bluetoothd is deliberately NOT touched (killing it flaps Wi-Fi — user confirmed).
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/deploy10.log) 2>&1
echo "=== deploy10.sh $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

KILL_NOW=(
    studentd remoted screensharingd ARDAgent remotemanagementd RemoteManagementAgent
    AirPlayReceiver AirPlayUIAgent AirPlayXPCHelper rapportd sharingd
    identityservicesd nearbyd universalcontrol mediaremoted avconferenced
    PersonalHotspotAgent smbd NetBIOS
)
echo "── killing running remote-connectivity processes (bluetoothd excluded):"
for proc in "${KILL_NOW[@]}"; do
    pids=$(pgrep -x "$proc" 2>/dev/null) || true
    [ -n "$pids" ] && { pkill -SIGKILL -x "$proc" && echo "  killed $proc ($pids)"; }
done

install -m 755 -o root -g wheel /Users/evw/dev/security/evw-studentd-guard.sh /usr/local/bin/evw-studentd-guard.sh && echo "guard updated (full remote set)"
launchctl kickstart -k system/com.evw.studentd-guard && echo "guard restarted"

sleep 6
echo "── verify: remote-connectivity processes still running (expect only bluetoothd/fairplayd):"
ps -eo pid,user,comm | grep -iE "studentd|remoted|screensharing|ARDAgent|RemoteManagement|AirPlay|rapportd|sharingd|identityservices|nearbyd|universalcontrol|mediaremoted|avconferenced|PersonalHotspot|smbd|NetBIOS|bluetoothd" | grep -v grep || echo "  (none)"
echo "── guard log:"
tail -5 /private/var/log/evw-studentd-guard.log 2>/dev/null || tail -5 /Users/evw/Library/Logs/evw-studentd-guard.log 2>/dev/null
echo "=== deploy10.sh done $(date) ==="
