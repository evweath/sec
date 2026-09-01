#!/bin/bash
# deploy5.sh — install human-timestamp mac-sentinel + restart + verify
echo "=== deploy5 $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must be root"; exit 1; }
install -m 755 -o root -g wheel /Users/evw/dev/security/scripts/mac-sentinel.py /usr/local/lib/mac-sentinel/mac-sentinel.py && echo "installed"
launchctl kickstart -k system/com.evw.mac-sentinel && echo "restarted"
sleep 6
pgrep -f "mac-sentinel/mac-sentinel.py" >/dev/null && echo "verified: running" || echo "ERROR: not running"
echo "── newest log entries (ts_human should be present):"
for f in /var/log/mac-sentinel/self_integrity.jsonl /var/log/mac-sentinel/file_changes.jsonl /var/log/mac-sentinel/master_events.jsonl; do
  [ -f "$f" ] && tail -1 "$f" | /usr/bin/python3 -c "
import json,sys
e = json.loads(sys.stdin.read())
print('  ts_human:', e.get('ts_human', 'MISSING'))
" && break
done
echo "=== deploy5 done ==="
