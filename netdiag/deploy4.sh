#!/bin/bash
# netdiag/deploy4.sh — apply anchored-pf fix + live table test.
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/deploy4.log) 2>&1
echo "=== deploy4.sh $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

install -m 755 -o root -g wheel /Users/evw/dev/security/scripts/evw-auto-conn-guard.py /usr/local/bin/evw-auto-conn-guard.py && echo "updated conn-guard"
install -m 755 -o root -g wheel /Users/evw/dev/security/scripts/evw-auto-undo.sh       /usr/local/bin/evw-auto-undo.sh       && echo "updated undo"

launchctl kickstart -k system/com.evw.auto-conn-guard && echo "conn-guard restarted"
sleep 3
pgrep -f "evw-auto-conn-guard.py" >/dev/null && echo "verified: conn-guard running" || echo "ERROR: not running"

echo "── live table test (TEST-NET-3, harmless):"
pfctl -a com.ew.autoblock -t auto_evw_block -T add 203.0.113.99 2>&1
echo "  table now:"
pfctl -a com.ew.autoblock -t auto_evw_block -T show 2>&1 | grep -v ALTQ
ping -c1 -t2 203.0.113.99 >/dev/null 2>&1 && echo "  ping: answered (unexpected)" || echo "  ping: no answer (expected — TEST-NET is unroutable anyway)"
pfctl -a com.ew.autoblock -t auto_evw_block -T delete 203.0.113.99 2>&1
echo "  table after delete:"
pfctl -a com.ew.autoblock -t auto_evw_block -T show 2>&1 | grep -v ALTQ | head -3
echo "── undo tool smoke test:"
/usr/local/bin/evw-auto-undo.sh list 2>&1 | head -8
echo "=== deploy4.sh done $(date) ==="
