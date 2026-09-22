#!/usr/bin/env bash
# =============================================================================
# ls-apply-gmail-fix.sh — apply the gmail scoping fix to the LIVE Little Snitch model
#
# Run:  sudo bash /Users/evw/dev/security/ls-apply-gmail-fix.sh [--dry-run]
#       --dry-run exports, runs ls-gmail-fix.py and shows the report, imports nothing
#
# Flow (mirrors ls-apply-tightening.sh):
#   1. export the LIVE model (root) — never edits a stale snapshot
#   2. ls-gmail-fix.py — delete 1e100 sentinel per-IP rules, add scoped
#      WebKit.Networking -> gmail-domains tcp:443 allow
#   3. show the full change report, require typing APPLY
#   4. restore-model; keep a backup of the pre-change model
#   5. re-export and verify: scoped gmail rule present, 1e100 sentinel rules gone
# =============================================================================

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

SEC_DIR="/Users/evw/dev/security"
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
SCAN_DIR="$SEC_DIR/scan-$(date +%F)"
REPORT="$SCAN_DIR/ls-gmail-fix-report.txt"
BACKUP="$SCAN_DIR/ls-model-pre-gmail-fix-$(date +%s).json"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

mkdir -p "$SCAN_DIR"
WORK=$(mktemp -d /var/tmp/ls-gmail-fix.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

echo "[1/5] Exporting live model..."
guard_run "ls-export-model" "$LSCLI" export-model "$WORK/model.json" || true
cp "$WORK/model.json" "$BACKUP"
chmod 600 "$BACKUP"   # root-written file in a user dir — keep it owner-only
echo "      backup saved: $BACKUP"

echo "[2/5] Running gmail fix..."
guard_run "ls-gmail-fix" python3 "$SEC_DIR/ls-gmail-fix.py" "$WORK/model.json" "$WORK/fixed.json" --report "$REPORT" || true
[ -f "$REPORT" ] && chmod 600 "$REPORT"   # root-written report in a user dir — owner-only

echo "[3/5] Change report ($REPORT):"
echo "----------------------------------------------------------------------"
head -40 "$REPORT"
echo "  ... (full list in report file)"
tail -3 "$REPORT"
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

echo "[4/5] Importing..."
if guard_run "ls-restore-model" "$LSCLI" restore-model "$WORK/fixed.json"; then
    echo "[✓] restore-model OK"
else
    echo "[✗] restore-model FAILED — live model may be unchanged. Backup: $BACKUP" >&2
    exit 1
fi

echo "[5/5] Verifying..."
guard_run "ls-export-verify" "$LSCLI" export-model "$WORK/verify.json" || true
if python3 -c "
import json, sys
m = json.load(open('$WORK/verify.json'))
rules = m['rules']
def has_gmail(proc):
    return any(r.get('action')=='allow' and r.get('process')==proc
               and 'gmail.com' in (r.get('remote-domains') or []) for r in rules)
webkit = has_gmail('identifier.APPLE/com.apple.WebKit.Networking')
safari = has_gmail('identifier.APPLE/com.apple.Safari')
stale = sum(1 for r in rules if str(r.get('notes','')).startswith('[AUTO-EVW-LS] sentinel-deny')
            and '1e100.net' in str(r.get('notes','')))
print('webkit-rule=%s safari-rule=%s stale-1e100=%d' % (webkit, safari, stale))
sys.exit(0 if webkit and safari and stale == 0 else 1)"; then
    echo "[✓] Gmail fix applied and verified. Report: $REPORT"
else
    echo "[!] Verification incomplete — check Little Snitch → Rules. Backup: $BACKUP" >&2
    exit 1
fi
echo "    Pre-change backup: $BACKUP"
