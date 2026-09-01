#!/bin/bash
# evw-auto-ls-sync.sh — [AUTO-EVW] merge queued auto-block deny rules into
# Little Snitch, and remove rules whose action was undone.
#
# PREREQUISITE (one-time, GUI): Little Snitch > Settings > Security >
#   "Command Line Tool Access" = ON. Without it the LS CLI refuses changes;
#   pf blocks still apply — this script just logs and exits 3.
#
# Safety: exports the model first, keeps a timestamped backup in
# /var/log/mac-sentinel/ before any restore-model. Debounced by the guard
# (>= 10 min) because restore-model briefly reloaded the ruleset.
set -uo pipefail
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
Q=/var/log/mac-sentinel/ls-rule-queue.json
LOGDIR=/var/log/mac-sentinel
LOG="$LOGDIR/AUTO-ACTIONS.md"
[ -f "$Q" ] || exit 0

WORK=$(mktemp -d /var/tmp/ls-sync.XXXXXXXX) || exit 1
trap 'rm -rf "$WORK"' EXIT

if ! "$LSCLI" export-model "$WORK/model.json" 2>"$WORK/err"; then
    echo "$(date -Iseconds) [AUTO-EVW] ls-sync: export failed — enable LS CLI access (Little Snitch > Settings > Security). $(head -2 "$WORK/err")" >> "$LOG"
    exit 3
fi
cp "$WORK/model.json" "$LOGDIR/ls-model-backup-$(date +%Y%m%d-%H%M%S).json"

OUT=$(/usr/bin/python3 - "$WORK/model.json" "$Q" <<'PYEOF'
import json, sys, time
model_path, q_path = sys.argv[1], sys.argv[2]
model = json.load(open(model_path))
rules = model.get("rules", [])
try:
    queue = json.load(open(q_path))
except Exception:
    queue = []
changed = False
for e in queue:
    if e.get("status") == "removed-pending-sync":
        aid = e["action_id"]
        before = len(rules)
        rules = [r for r in rules if aid not in str(r.get("notes", ""))]
        if len(rules) != before:
            changed = True
        e["status"] = "removed"
for e in queue:
    if e.get("status") == "queued":
        rules.append({
            "action": "deny", "process": "any",
            "remote-addresses": e["ip"],
            "notes": "[AUTO-EVW] {} {} {}".format(
                e["action_id"], ",".join(e.get("reasons", [])),
                time.strftime("%Y-%m-%d", time.gmtime(e.get("ts", 0)))),
            "origin": "frontend",
        })
        e["status"] = "synced"
        changed = True
if changed:
    model["rules"] = rules
    json.dump(model, open(model_path, "w"), indent=2)
json.dump(queue, open(q_path, "w"), indent=1)
print("changed" if changed else "nochange")
PYEOF
)

if [ "$OUT" = "changed" ]; then
    if "$LSCLI" restore-model "$WORK/model.json" 2>>"$WORK/err"; then
        echo "$(date -Iseconds) [AUTO-EVW] ls-sync: deny rules applied to Little Snitch" >> "$LOG"
    else
        echo "$(date -Iseconds) [AUTO-EVW] ls-sync: restore-model FAILED ($(head -2 "$WORK/err")) — model backup saved in $LOGDIR; pf blocks still active" >> "$LOG"
        exit 5
    fi
else
    echo "$(date -Iseconds) [AUTO-EVW] ls-sync: no changes" >> "$LOG"
fi
