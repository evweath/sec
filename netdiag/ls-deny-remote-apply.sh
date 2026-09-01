#!/bin/bash
# netdiag/ls-deny-remote-apply.sh — apply [AUTO-EVW] blanket denies with backup+verify.
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/ls-deny-remote-apply.log) 2>&1
echo "=== ls-deny-remote-apply $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
ND=/Users/evw/dev/fix/netdiag/logs
WORK=$(mktemp -d /var/tmp/ls-deny.XXXXXXXX); trap 'rm -rf "$WORK"' EXIT

"$LSCLI" export-model "$WORK/model.json" || { echo "export FAILED"; exit 1; }
cp "$WORK/model.json" "/var/log/mac-sentinel/ls-model-pre-denyremote-$(date +%Y%m%d-%H%M%S).json" && echo "model backup saved"

/usr/bin/python3 /Users/evw/dev/security/scripts/ls-deny-remote.py "$WORK/model.json" \
  --apply --undo "$ND/ls-deny-remote-undo.json" || { echo "patch FAILED — aborted"; exit 1; }

"$LSCLI" restore-model "$WORK/model.json" || { echo "restore FAILED — backup in /var/log/mac-sentinel/"; exit 1; }
echo "model restored"

"$LSCLI" export-model "$WORK/verify.json" && /usr/bin/python3 -c "
import json
m = json.load(open('$WORK/verify.json'))
rules = m.get('rules', [])
auto = [r for r in rules if '[AUTO-EVW] blanket-deny' in str(r.get('notes',''))]
print('verify: rules =', len(rules), ' [AUTO-EVW] blanket denies =', len(auto))
assert len(auto) >= 14, 'BLANKET DENIES MISSING'"
chown evw:staff "$ND/ls-deny-remote-undo.json" 2>/dev/null
echo "=== ls-deny-remote-apply done $(date) ==="
