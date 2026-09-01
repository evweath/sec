#!/bin/bash
# netdiag/ls-deny-screenshare-apply.sh — apply [AUTO-EVW] screen-sharing denies.
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/ls-deny-screenshare-apply.log) 2>&1
echo "=== ls-deny-screenshare-apply $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
ND=/Users/evw/dev/fix/netdiag/logs
WORK=$(mktemp -d /var/tmp/ls-ss.XXXXXXXX); trap 'rm -rf "$WORK"' EXIT

"$LSCLI" export-model "$WORK/model.json" || { echo "export FAILED"; exit 1; }
cp "$WORK/model.json" "/var/log/mac-sentinel/ls-model-pre-denyss-$(date +%Y%m%d-%H%M%S).json" && echo "model backup saved"

/usr/bin/python3 /Users/evw/dev/security/scripts/ls-deny-screenshare.py "$WORK/model.json" \
  --apply --undo "$ND/ls-deny-screenshare-undo.json" || { echo "patch FAILED — aborted"; exit 1; }

"$LSCLI" restore-model "$WORK/model.json" || { echo "restore FAILED — backup in /var/log/mac-sentinel/"; exit 1; }
echo "model restored"

"$LSCLI" export-model "$WORK/verify.json" && /usr/bin/python3 -c "
import json
m = json.load(open('$WORK/verify.json'))
rules = m.get('rules', [])
auto = [r for r in rules if 'block screen-sharing' in str(r.get('notes',''))]
print('verify: rules =', len(rules), ' screen-share denies =', len(auto))
assert len(auto) >= 20, 'SCREEN-SHARE DENIES MISSING'"
chown evw:staff "$ND/ls-deny-screenshare-undo.json" 2>/dev/null
echo "=== ls-deny-screenshare-apply done $(date) ==="
