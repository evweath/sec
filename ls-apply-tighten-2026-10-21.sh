#!/usr/bin/env bash
# =============================================================================
# ls-apply-tighten-2026-10-21.sh — apply the 2026-10-21 LS tightening batch to
# the LIVE Little Snitch model
#
# Run:  sudo bash /Users/evw/dev/security/ls-apply-tighten-2026-10-21.sh [--dry-run]
#       --dry-run exports, dedups, tightens and shows the report, but imports nothing
#
# Flow (mirrors ls-apply-tightening.sh):
#   1. export the LIVE model (root) — never edits a stale snapshot; the
#      sentinel-deny-sync job mutates the model every ~5 min, so offline
#      copies of older exports must NOT be imported
#   2. ls-dedup.py              — remove duplicate rules (5 expected)
#   3. ls-tighten-all.py        — guarded-daemon denies / monitor-unused /
#                                 stale-binary prune / tcp:443 tightening
#                                 (expected no-op on 2026-10-21 posture)
#   4. ls-tighten-2026-10-21.py — flip the 4 flagged ad-rot Safari allows
#                                 (prreqcroab.icu x2, cdn.ravm.tv, pt.ispot.tv)
#                                 to deny
#   5. show the full change report, require typing APPLY
#   6. restore-model the tightened rules; keep a backup of the pre-change model
#   7. re-export and verify the 4 tracker denies landed
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
REPORT="$SCAN_DIR/ls-tighten-2026-10-21-report.txt"
BACKUP="$SCAN_DIR/ls-model-pre-tighten-$(date +%s).json"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

mkdir -p "$SCAN_DIR"
WORK=$(mktemp -d /var/tmp/ls-tighten.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

echo "[1/6] Exporting live model..."
guard_run "ls-export-model" "$LSCLI" export-model "$WORK/model.json" || true
cp "$WORK/model.json" "$BACKUP"
chmod 600 "$BACKUP"   # root-written file in a user dir — keep it owner-only
echo "      backup saved: $BACKUP"

echo "[2/6] Deduplicating..."
guard_run "ls-dedup" python3 "$SEC_DIR/ls-dedup.py" "$WORK/model.json" "$WORK/deduped.json" || true

echo "[3/6] Tightening (standard pass)..."
guard_run "ls-tighten-all" python3 "$SEC_DIR/ls-tighten-all.py" "$WORK/deduped.json" "$WORK/tightened.json" --report "$WORK/report-tighten-all.txt" || true

echo "[4/6] Flipping flagged ad-rot tracker allows to deny..."
guard_run "ls-tighten-2026-10-21" python3 "$SEC_DIR/ls-tighten-2026-10-21.py" "$WORK/tightened.json" "$WORK/final.json" --report "$WORK/report-trackers.txt" || true

{ cat "$WORK/report-tighten-all.txt" 2>/dev/null; echo; cat "$WORK/report-trackers.txt" 2>/dev/null; } > "$REPORT"
chmod 600 "$REPORT"   # root-written report in a user dir — owner-only

echo "[5/6] Change report ($REPORT):"
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

echo "[6/6] Importing..."
if guard_run "ls-restore-model" "$LSCLI" restore-model "$WORK/final.json"; then
    echo "[✓] restore-model OK"
else
    echo "[✗] restore-model FAILED — live model may be unchanged. Backup: $BACKUP" >&2
    exit 1
fi

# Verify: re-export and confirm the tracker denies landed
guard_run "ls-export-verify" "$LSCLI" export-model "$WORK/verify.json" || true
missing=0
for host in prreqcroab.icu pixel-ssn.prreqcroab.icu cdn.ravm.tv pt.ispot.tv; do
    if python3 -c "
import json, sys
m = json.load(open('$WORK/verify.json'))
ok = any(r.get('action')=='deny' and r.get('remote-hosts')=='$host' for r in m['rules'])
sys.exit(0 if ok else 1)"; then
        echo "[✓] deny rule present: $host"
    else
        echo "[!] deny rule MISSING after import: $host"
        missing=1
    fi
done

# and the code-signature-override any-denies must be gone
if python3 -c "
import json, sys
m = json.load(open('$WORK/verify.json'))
def bad(r):
    if r.get('action') != 'deny' or not r.get('overrideDueToCodeSignatureIssue'):
        return False
    p, v = str(r.get('process','')), str(r.get('via',''))
    return 'limactl' in p or 'Cellar/node' in p or 'Cellar/gh' in v
sys.exit(1 if any(bad(r) for r in m['rules']) else 0)"; then
    echo "[✓] code-signature-override any-denies removed (limactl, node, gh-via-iterm2)"
else
    echo "[!] code-signature-override any-denies STILL PRESENT after import"
    missing=1
fi
if [[ $missing -eq 0 ]]; then
    echo "[✓] Tightening applied and verified. Report: $REPORT"
else
    echo "[!] Some rules missing post-import — check Little Snitch → Rules."
fi
echo "    Pre-change backup: $BACKUP"
