#!/bin/bash
# netdiag/ls-hygiene-apply.sh — apply [AUTO-EVW-LS] rule cleanup with backup+verify.
# Deletes 16 rules (12 tracker allows, 2 trustd/OCSP denies, 2 configd denies).
# Undo: full rule copies in netdiag/logs/ls-hygiene-undo.json (+ model backup).
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/ls-hygiene-apply.log) 2>&1
echo "=== ls-hygiene-apply $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
ND=/Users/evw/dev/fix/netdiag/logs
WORK=$(mktemp -d /var/tmp/ls-hygiene.XXXXXXXX); trap 'rm -rf "$WORK"' EXIT

"$LSCLI" export-model "$WORK/model.json" || { echo "export FAILED"; exit 1; }
cp "$WORK/model.json" "/var/log/mac-sentinel/ls-model-pre-hygiene-$(date +%Y%m%d-%H%M%S).json" && echo "model backup saved"

/usr/bin/python3 /Users/evw/dev/security/scripts/ls-hygiene.py "$WORK/model.json" \
  --apply --report "$ND/ls-hygiene-report.md" --undo "$ND/ls-hygiene-undo.json" \
  || { echo "patch FAILED — model untouched (restore aborted)"; exit 1; }

"$LSCLI" restore-model "$WORK/model.json" || { echo "restore-model FAILED — backup in /var/log/mac-sentinel/"; exit 1; }
echo "model restored"

"$LSCLI" export-model "$WORK/verify.json" \
  && /usr/bin/python3 -c "
import json
m = json.load(open('$WORK/verify.json'))
rules = m.get('rules', [])
auto = sum(1 for r in rules if '[AUTO-EVW-LS]' in str(r.get('notes','')))
left = sum(1 for r in rules if r.get('action')=='allow' and str(r.get('remote-hosts','')) in {'a.klaviyo.com','fast.a.klaviyo.com','static.klaviyo.com','static-tracking.klaviyo.com','static-forms.klaviyo.com','acdn.adnxs.com','ads.pro-market.net','bat.bing.com'})
print('post-restore rules:', len(rules), ' auto-deny rules:', auto, ' tracker allows left:', left)
assert left == 0, 'TRACKER ALLOWS STILL PRESENT'
assert auto >= 1, 'AUTO-DENY RULES MISSING'"

chown evw:staff "$ND/ls-hygiene-report.md" "$ND/ls-hygiene-undo.json" 2>/dev/null
echo "=== ls-hygiene-apply done $(date) ==="
