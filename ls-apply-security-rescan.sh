#!/usr/bin/env bash
# =============================================================================
# ls-apply-security-rescan.sh — apply the 2026-09-03 security rescan to the
# LIVE Little Snitch model
#
# Run:  sudo bash /Users/evw/dev/security/ls-apply-security-rescan.sh [--dry-run]
#       --dry-run exports, dedups, rescans and shows the report, imports nothing
#
# Flow (mirrors ls-apply-tightening.sh — export/edit/restore idiom):
#   1. export the LIVE model (root) — never edits a stale snapshot
#   2. ls-dedup.py          — remove duplicate rules
#   3. ls-security-rescan.py — add tracker denies, delete tracker/risky allows,
#                              prune monitor-unused + stale-binary allows,
#                              tighten specific-host allows to tcp:443
#   4. show the full change report, require typing APPLY
#   5. restore-model; keep a backup of the pre-change model
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
REPORT="$SCAN_DIR/ls-security-rescan-report.txt"
BACKUP="$SCAN_DIR/ls-model-pre-rescan-$(date +%s).json"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

mkdir -p "$SCAN_DIR"
WORK=$(mktemp -d /var/tmp/ls-rescan.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

echo "[1/5] Exporting live model..."
guard_run "ls-export-model" "$LSCLI" export-model "$WORK/model.json" || true
cp "$WORK/model.json" "$BACKUP"
chmod 600 "$BACKUP"   # root-written file in a user dir — keep it owner-only
echo "      backup saved: $BACKUP"

echo "[2/5] Deduplicating..."
guard_run "ls-dedup" python3 "$SEC_DIR/ls-dedup.py" "$WORK/model.json" "$WORK/deduped.json" || true

echo "[3/5] Security rescan..."
guard_run "ls-security-rescan" python3 "$SEC_DIR/ls-security-rescan.py" "$WORK/deduped.json" "$WORK/rescanned.json" --report "$REPORT" || true
[ -f "$REPORT" ] && chmod 600 "$REPORT"

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
if guard_run "ls-restore-model" "$LSCLI" restore-model "$WORK/rescanned.json"; then
    echo "[✓] restore-model OK"
else
    echo "[✗] restore-model FAILED — live model may be unchanged. Backup: $BACKUP" >&2
    exit 1
fi

# Verify: re-export and confirm the tracker denies landed
guard_run "ls-export-verify" "$LSCLI" export-model "$WORK/verify.json" || true
missing=0
for domain in gator.volces.com apmplus.volces.com tab.volces.com queniuck.com \
              tiktok.com tiktokcdn-us.com tiktokv.us tiktokw.us ttcdn-us.com \
              tiktokshops.us bytedance.com zohopublic.com zohocdn.com \
              salesiq.zoho.com pagesense-collect.zoho.com pagesense-hb-collect.zoho.com; do
    if python3 -c "
import json, sys
m = json.load(open('$WORK/verify.json'))
ok = any(r.get('action')=='deny' and '$domain' in str(r.get('remote-domains','')) for r in m['rules'])
sys.exit(0 if ok else 1)"; then
        echo "[✓] deny rule present: $domain"
    else
        echo "[!] deny rule MISSING after import: $domain"
        missing=1
    fi
done

echo ""
if [[ $missing -eq 0 ]]; then
    echo "[✓] Rescan applied and verified. Report: $REPORT"
else
    echo "[!] Some rules missing post-import — check Little Snitch → Rules."
fi
echo "    Pre-change backup: $BACKUP"
