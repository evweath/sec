#!/bin/bash
# netdiag/deploy11.sh — 60s remote-guard + system remoted disable.
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/deploy11.log) 2>&1
echo "=== deploy11.sh $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

install -m 755 -o root -g wheel /Users/evw/dev/security/evw-studentd-guard.sh /usr/local/bin/evw-studentd-guard.sh && echo "guard updated (INTERVAL=60)"
launchctl disable system/com.apple.remoted 2>/dev/null && echo "system/com.apple.remoted disabled" || echo "remoted disable: (already disabled or failed)"
pkill -SIGKILL -x remoted 2>/dev/null && echo "remoted killed" || true
launchctl kickstart -k system/com.evw.studentd-guard && echo "guard restarted @60s"

sleep 5
grep "^INTERVAL" /usr/local/bin/evw-studentd-guard.sh
pgrep -fl evw-studentd-guard.sh | head -1
echo "── guard log tail:"
tail -4 /private/var/log/evw-studentd-guard.log 2>/dev/null
echo "=== deploy11.sh done $(date) ==="
