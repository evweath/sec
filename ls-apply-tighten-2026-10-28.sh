#!/usr/bin/env bash
set -euo pipefail

SEC_DIR="/Users/evw/dev/security"
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
SCAN_DIR="$SEC_DIR/scan-$(date +%F)"
TRANSFORM="$SEC_DIR/ls-tighten-2026-10-28.py"
REPORT="$SCAN_DIR/ls-tighten-2026-10-28-live-report.txt"
BACKUP="$SCAN_DIR/ls-model-pre-tighten-2026-10-28-$(date +%s).json"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root: sudo bash $0 [--dry-run]" >&2
    exit 1
fi
[[ -x "$LSCLI" && -f "$TRANSFORM" ]] || { echo "Little Snitch CLI or transform missing" >&2; exit 1; }
mkdir -p "$SCAN_DIR"
WORK=$(mktemp -d /var/tmp/ls-tighten-20261028.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

"$LSCLI" export-model "$WORK/live.json"
cp "$WORK/live.json" "$BACKUP"
chmod 600 "$BACKUP"
python3 "$TRANSFORM" "$WORK/live.json" "$WORK/final.json" --report "$REPORT"
chmod 600 "$REPORT"
cat "$REPORT"
CHANGED=$(python3 -c 'import re,sys; print(re.search(r"CHANGED=(\d+)", open(sys.argv[1]).read()).group(1))' "$REPORT")

if [[ "${1:-}" == "--dry-run" ]]; then
    echo "Dry run — live model untouched. Backup: $BACKUP"
    exit 0
fi
if [[ "$CHANGED" == 0 ]]; then
    echo "No target inversions found — live model untouched."
    exit 0
fi
read -r -p "Type APPLY to restore $CHANGED corrected rules into Little Snitch: " reply
[[ "$reply" == APPLY ]] || { echo "Aborted — live model untouched. Backup: $BACKUP"; exit 0; }

"$LSCLI" restore-model "$WORK/final.json"
"$LSCLI" export-model "$WORK/verify.json"
python3 "$TRANSFORM" "$WORK/verify.json" "$WORK/verify-final.json" --report "$WORK/verify-report.txt"
python3 - "$WORK/live.json" "$WORK/final.json" "$WORK/verify.json" "$WORK/verify-report.txt" <<'PY'
import json
import re
import sys

live, final, verify, report = sys.argv[1:]
before = json.load(open(live))["rules"]
expected = json.load(open(final))["rules"]
actual = json.load(open(verify))["rules"]
changed = int(re.search(r"CHANGED=(\d+)", open(report).read()).group(1))
assert changed == 0, "%d target allows remain" % changed
assert len(actual) == len(expected) == len(before), (len(before), len(expected), len(actual))
critical = ("replayd", "privatecloudcomputed", "remotemanagementd",
            "RemoteManagementAgent", "studentd", "launchctl", "kickstart",
            "datadoghq", "influxdata", "found.io")
missing = [name for name in critical
           if not any(r.get("action") == "deny" and name in str(r) for r in actual)]
assert not missing, "critical denies missing: %r" % missing
print("VERIFIED: no target allows remain; rule count preserved; critical denies present")
PY
chown evw:staff "$REPORT" "$BACKUP"
chmod 600 "$REPORT" "$BACKUP"
echo "Applied and verified. Pre-change backup: $BACKUP"
