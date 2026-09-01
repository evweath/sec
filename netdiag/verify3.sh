#!/bin/bash
# netdiag/verify3.sh — read-only verification of the [AUTO-EVW] conn-guard stack.
echo "=== verify3 $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

echo "── conn-guard process:"
pgrep -fl "evw-auto-conn-guard.py" || echo "  NOT RUNNING"

echo "── AUTO-ACTIONS.md (last 12):"
tail -12 /var/log/mac-sentinel/AUTO-ACTIONS.md 2>/dev/null || echo "  (none yet)"

echo "── auto-block-state.json:"
cat /var/log/mac-sentinel/auto-block-state.json 2>/dev/null || echo "  (none yet)"

echo "── pf table auto_evw_block:"
pfctl -t auto_evw_block -T show 2>&1 | head -5
pfctl -a com.ew.autoblock -s rules 2>&1 | grep -v ALTQ | head -4

echo "── Little Snitch CLI authorization test:"
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
if "$LSCLI" export-model /var/log/mac-sentinel/ls-cli-test.json 2>&1; then
    /usr/bin/python3 -c "
import json
m = json.load(open('/var/log/mac-sentinel/ls-cli-test.json'))
print('  LS CLI OK — model exported, rules:', len(m.get('rules', [])))"
else
    echo "  LS CLI STILL UNAUTHORIZED"
fi
echo "=== verify3 done ==="
