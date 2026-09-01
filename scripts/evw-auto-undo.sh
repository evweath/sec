#!/bin/bash
# evw-auto-undo.sh — [AUTO-EVW] undo tool for evw-auto-conn-guard actions.
#
#   evw-auto-undo.sh list          show recent actions + active blocks
#   evw-auto-undo.sh <action_id>   unblock the IP + queue LS rule removal
#   evw-auto-undo.sh all-blocks    flush EVERY auto block (pf table emptied)
#
# State: /var/log/mac-sentinel/auto-block-state.json
# Audit: /var/log/mac-sentinel/auto-actions.jsonl + AUTO-ACTIONS.md
# Run as root for pf changes: sudo evw-auto-undo.sh ...
set -uo pipefail
STATE=/var/log/mac-sentinel/auto-block-state.json
LSQ=/var/log/mac-sentinel/ls-rule-queue.json
TABLE=auto_evw_block
LS_SYNC=/usr/local/bin/evw-auto-ls-sync.sh

cmd="${1:-list}"

case "$cmd" in
  list)
    echo "== active auto blocks (pf table $TABLE) =="
    pfctl -a com.ew.autoblock -t "$TABLE" -T show 2>/dev/null || echo "  (none / need sudo)"
    echo
    echo "== state file =="
    [ -f "$STATE" ] && /usr/bin/python3 -c "
import json
st = json.load(open('$STATE'))
for ip, e in sorted(st.items(), key=lambda kv: -kv[1].get('ts', 0)):
    print('  {:<40} {:<22} undone={} score={} {}'.format(
        ip, e.get('action_id','?'), e.get('undone'), e.get('score'),
        ','.join(e.get('reasons', []))))" || echo "  (no state)"
    echo
    echo "== last 15 actions =="
    tail -15 /var/log/mac-sentinel/AUTO-ACTIONS.md 2>/dev/null || echo "  (none)"
    ;;
  all-blocks)
    pfctl -a com.ew.autoblock -t "$TABLE" -T flush && echo "flushed all entries from $TABLE"
    [ -f "$STATE" ] && /usr/bin/python3 -c "
import json, time
st = json.load(open('$STATE'))
for e in st.values():
    if not e.get('undone'):
        e['undone'] = True; e['undone_ts'] = int(time.time())
json.dump(st, open('$STATE', 'w'), indent=1)
print('state: all marked undone')"
    echo "$(date -Iseconds) [AUTO-EVW] all-blocks flushed by $(whoami)" >> /var/log/mac-sentinel/AUTO-ACTIONS.md
    ;;
  auto-*)
    AID="$cmd"
    IP=$(/usr/bin/python3 -c "
import json
st = json.load(open('$STATE'))
for ip, e in st.items():
    if e.get('action_id') == '$AID':
        print(ip); break" 2>/dev/null)
    if [ -z "$IP" ]; then echo "action_id $AID not found in state"; exit 1; fi
    pfctl -a com.ew.autoblock -t "$TABLE" -T delete "$IP" && echo "removed $IP from $TABLE"
    /usr/bin/python3 -c "
import json, time
st = json.load(open('$STATE'))
st['$IP']['undone'] = True; st['$IP']['undone_ts'] = int(time.time())
json.dump(st, open('$STATE', 'w'), indent=1)"
    # queue removal of the matching Little Snitch rule (applies on next sync)
    [ -f "$LSQ" ] && /usr/bin/python3 -c "
import json
q = json.load(open('$LSQ'))
for e in q:
    if e.get('action_id') == '$AID' and e.get('status') in ('queued', 'synced'):
        e['status'] = 'removed-pending-sync'
json.dump(q, open('$LSQ', 'w'), indent=1)" && echo "queued LS rule removal for $AID"
    [ -x "$LS_SYNC" ] && /bin/bash "$LS_SYNC" || true
    echo "$(date -Iseconds) [AUTO-EVW] $AID undone ($IP unblocked) by $(whoami)" >> /var/log/mac-sentinel/AUTO-ACTIONS.md
    echo "undone. NOTE: if a process was killed by this action, relaunch it manually."
    ;;
  *)
    echo "usage: $0 list | <action_id> | all-blocks"; exit 1;;
esac
