#!/usr/bin/env bash
# =============================================================================
# ls-apply-shopify-whitelist.sh — apply the shopify scoping fix to the LIVE
# Little Snitch model
#
# Run:  sudo bash /Users/evw/dev/security/ls-apply-shopify-whitelist.sh [--dry-run]
#       --dry-run exports, runs ls-shopify-whitelist.py and shows the report,
#       imports nothing
#
# Flow (mirrors ls-apply-gmail-fix.sh):
#   1. export the LIVE model (root) — never edits a stale snapshot
#   2. ls-shopify-whitelist.py — delete Shopify sentinel per-IP rules (allow
#      AND deny), add scoped browser -> shopify-domains tcp:443 allows
#      (WebKit.Networking + Brave — Brave's catch-all deny blocks Shopify)
#   3. show the full change report, require typing APPLY
#   4. restore-model; keep a backup of the pre-change model
#   5. re-export and verify: scoped shopify rule present, Shopify sentinel
#      rules gone
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
REPORT="$SCAN_DIR/ls-shopify-whitelist-report.txt"
BACKUP="$SCAN_DIR/ls-model-pre-shopify-whitelist-$(date +%s).json"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

mkdir -p "$SCAN_DIR"
WORK=$(mktemp -d /var/tmp/ls-shopify-whitelist.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

echo "[1/5] Exporting live model..."
guard_run "ls-export-model" "$LSCLI" export-model "$WORK/model.json" || true
cp "$WORK/model.json" "$BACKUP"
chmod 600 "$BACKUP"   # root-written file in a user dir — keep it owner-only
echo "      backup saved: $BACKUP"

echo "[2/5] Running shopify whitelist..."
guard_run "ls-shopify-whitelist" python3 "$SEC_DIR/ls-shopify-whitelist.py" "$WORK/model.json" "$WORK/fixed.json" --report "$REPORT" || true
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
def has_scoped(proc):
    return any(r.get('action')=='allow' and r.get('process')==proc
               and 'myshopify.com' in (r.get('remote-domains') or []) for r in rules)
webkit = has_scoped('identifier.APPLE/com.apple.WebKit.Networking')
brave = has_scoped('identifier.KL8N8XSYF4/com.brave.Browser')
safari = has_scoped('identifier.APPLE/com.apple.Safari')
stale = sum(1 for r in rules if str(r.get('notes','')).startswith('[AUTO-EVW-LS] sentinel-deny')
            and ('Shopify' in str(r.get('notes',''))
                 or 'bc.googleusercontent.com' in str(r.get('notes',''))))
print('webkit-rule=%s brave-rule=%s safari-rule=%s stale-sentinel=%d' % (webkit, brave, safari, stale))
sys.exit(0 if webkit and brave and safari and stale == 0 else 1)"; then
    echo "[✓] Shopify whitelist applied and verified. Report: $REPORT"
else
    echo "[!] Verification incomplete — check Little Snitch → Rules. Backup: $BACKUP" >&2
    exit 1
fi
echo "    Pre-change backup: $BACKUP"
