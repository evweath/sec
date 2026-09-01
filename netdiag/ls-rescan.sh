#!/bin/bash
# netdiag/ls-rescan.sh — fresh LS model export + hygiene dry-run report.
set -uo pipefail
ND=/Users/evw/dev/fix/netdiag/logs
echo "=== ls-rescan $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

"/Applications/Little Snitch.app/Contents/Components/littlesnitch" \
  export-model "$ND/ls-model-current.json" || { echo "export FAILED"; exit 1; }
chown evw:staff "$ND/ls-model-current.json"; chmod 600 "$ND/ls-model-current.json"

/usr/bin/python3 -c "
import json
m = json.load(open('$ND/ls-model-current.json'))
from collections import Counter
rules = m.get('rules', [])
print('rules:', len(rules), dict(Counter(r.get('action') for r in rules)))"

/usr/bin/python3 /Users/evw/dev/security/scripts/ls-hygiene.py "$ND/ls-model-current.json" \
  --report "$ND/ls-hygiene-report.md" --undo "$ND/ls-hygiene-undo.json"
chown evw:staff "$ND/ls-hygiene-report.md" "$ND/ls-hygiene-undo.json" 2>/dev/null
echo "── report:"
cat "$ND/ls-hygiene-report.md"
echo "=== ls-rescan done ==="
