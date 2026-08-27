#!/usr/bin/env bash
# =============================================================================
# ls-apply-tightening.sh — apply LS rule tightening to the LIVE Little Snitch model
#
# Run:  sudo bash /Users/evw/dev/security/ls-apply-tightening.sh [--dry-run]
#       --dry-run exports, dedups, tightens and shows the report, but imports nothing
#
# Flow (mirrors the toolkit's export/edit/restore idiom):
#   1. export the LIVE model (root) — never edits a stale snapshot
#   2. ls-dedup.py      — remove duplicate rules
#   3. ls-tighten-all.py — add guarded-daemon denies, prune monitor-unused and
#                          stale-binary allows, tighten browser/Terminal domain
#                          allows to tcp:443, scope OTS rules to the ots binary
#   4. show the full change report, require typing APPLY
#   5. restore-model the tightened rules; keep a backup of the pre-change model
# =============================================================================

set -euo pipefail

SEC_DIR="/Users/evw/dev/security"
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
SCAN_DIR="$SEC_DIR/scan-$(date +%F)"
REPORT="$SCAN_DIR/ls-tighten-report.txt"
BACKUP="$SCAN_DIR/ls-model-pre-tighten-$(date +%s).json"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

mkdir -p "$SCAN_DIR"
WORK=$(mktemp -d /var/tmp/ls-tighten.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

echo "[1/5] Exporting live model..."
"$LSCLI" export-model "$WORK/model.json"
cp "$WORK/model.json" "$BACKUP"
echo "      backup saved: $BACKUP"

echo "[2/5] Deduplicating..."
python3 "$SEC_DIR/ls-dedup.py" "$WORK/model.json" "$WORK/deduped.json"

echo "[3/5] Tightening..."
python3 "$SEC_DIR/ls-tighten-all.py" "$WORK/deduped.json" "$WORK/tightened.json" --report "$REPORT"

echo "[4/5] Change report ($REPORT):"
echo "----------------------------------------------------------------------"
cat "$REPORT"
echo "----------------------------------------------------------------------"
if [[ "${1:-}" == "--dry-run" ]]; then
    echo "Dry run — live model untouched. Backup: $BACKUP"
    exit 0
fi
read -r -p "Type APPLY to import these changes into Little Snitch: " reply
if [[ "$reply" != "APPLY" ]]; then
    echo "Aborted — live model untouched. Backup: $BACKUP"
    exit 0
fi

echo "[5/5] Importing..."
if "$LSCLI" restore-model "$WORK/tightened.json"; then
    echo "[✓] restore-model OK"
else
    echo "[✗] restore-model FAILED — live model may be unchanged. Backup: $BACKUP" >&2
    exit 1
fi

# Verify: re-export and confirm the guarded denies landed
"$LSCLI" export-model "$WORK/verify.json"
missing=0
for proc in apsd sharingd replicatord screensharingd; do
    if python3 -c "
import json, sys
m = json.load(open('$WORK/verify.json'))
ok = any(r.get('action')=='deny' and '$proc' in str(r.get('process','')) for r in m['rules'])
sys.exit(0 if ok else 1)"; then
        echo "[✓] deny rule present: $proc"
    else
        echo "[!] deny rule MISSING after import: $proc"
        missing=1
    fi
done

echo ""
if [[ $missing -eq 0 ]]; then
    echo "[✓] Tightening applied and verified. Report: $REPORT"
else
    echo "[!] Some rules missing post-import — check Little Snitch → Rules."
fi
echo "    Pre-change backup: $BACKUP"
