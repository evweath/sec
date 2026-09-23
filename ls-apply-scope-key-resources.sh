#!/usr/bin/env bash
# =============================================================================
# ls-apply-scope-key-resources.sh — apply "option 1" LS scoping to the LIVE model
#
# Run:  sudo bash /Users/evw/dev/security/ls-apply-scope-key-resources.sh [--dry-run|--yes]
#       --dry-run  exports, dedups, scopes and shows the report, but imports nothing
#       --yes      skip the interactive APPLY prompt (for elevated non-TTY runs)
#
# Flow (mirrors ls-apply-tightening.sh):
#   1. export the LIVE model (root) — never edits a stale snapshot
#   2. ls-dedup.py               — remove duplicate rules
#   3. ls-scope-key-resources.py — add process+domain tcp:443 rules for key
#                                  resources (GitHub, Kimi) scoped to signed
#                                  processes; delete any-process -> literal-IP
#                                  allow rules; verify invariants
#   4. show the full change report, require typing APPLY (unless --yes)
#   5. restore-model the scoped rules; keep a backup of the pre-change model
#
# Rollback: sudo "/Applications/Little Snitch.app/Contents/Components/littlesnitch" \
#             restore-model <backup.json>
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
REPORT="$SCAN_DIR/ls-scope-key-resources-report.txt"
BACKUP="$SCAN_DIR/ls-model-pre-scope-$(date +%s).json"

DRY_RUN=0; YES=0
for a in "$@"; do
    case "$a" in
        --dry-run) DRY_RUN=1 ;;
        --yes)     YES=1 ;;
        *) echo "[!] unknown flag: $a (use --dry-run or --yes)" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

mkdir -p "$SCAN_DIR"
WORK=$(mktemp -d /var/tmp/ls-scope.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

echo "[1/5] Exporting live model..."
guard_run "ls-export-model" "$LSCLI" export-model "$WORK/model.json" || true
cp "$WORK/model.json" "$BACKUP"
chmod 600 "$BACKUP"   # root-written file in a user dir — keep it owner-only
echo "      backup saved: $BACKUP"

echo "[2/5] Deduplicating..."
guard_run "ls-dedup" python3 "$SEC_DIR/ls-dedup.py" "$WORK/model.json" "$WORK/deduped.json" || true

echo "[3/5] Scoping key resources..."
guard_run "ls-scope-key-resources" python3 "$SEC_DIR/ls-scope-key-resources.py" \
    "$WORK/deduped.json" "$WORK/scoped.json" --report "$REPORT" || true
[ -f "$REPORT" ] && chmod 600 "$REPORT"   # root-written report in a user dir — owner-only

echo "[4/5] Change report ($REPORT):"
echo "----------------------------------------------------------------------"
cat "$REPORT"
echo "----------------------------------------------------------------------"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "Dry run — live model untouched. Backup: $BACKUP"
    exit 0
fi
if [[ $YES -ne 1 ]]; then
    read -r -p "Type APPLY to import these changes into Little Snitch: " reply
    if [[ "$reply" != "APPLY" ]]; then
        echo "Aborted — live model untouched. Backup: $BACKUP"
        exit 0
    fi
fi

echo "[5/5] Importing..."
if guard_run "ls-restore-model" "$LSCLI" restore-model "$WORK/scoped.json"; then
    echo "[OK] restore-model OK"
else
    echo "[FAIL] restore-model FAILED — live model may be unchanged. Backup: $BACKUP" >&2
    exit 1
fi

# Verify: re-export and confirm scoping landed and guarded denies survived
guard_run "ls-export-verify" "$LSCLI" export-model "$WORK/verify.json" || true
if python3 - "$WORK/verify.json" <<'PYEOF'
import json, sys
rules = json.load(open(sys.argv[1]))["rules"]
leftover = [r for r in rules if r.get("action") == "allow" and "process" not in r
            and r.get("remote-addresses") and not r.get("protected") and r.get("origin") != "factory"]
if leftover:
    print(f"[!] {len(leftover)} unscoped IP allow rules STILL present post-import")
    sys.exit(1)
gh_denies = [r for r in rules if r.get("action") == "deny"
             and str(r.get("notes", "")).startswith("[AUTO-EVW-LS] sentinel-deny")
             and "github" in str(r.get("notes", "")).lower()]
if gh_denies:
    print(f"[!] {len(gh_denies)} sentinel GitHub deny rules STILL present post-import")
    sys.exit(1)
for proc in ("identifier.APPLE/com.apple.WebKit.Networking",
             "identifier.59GAB85EFG/com.apple.git-remote-http"):
    if not any(r.get("process") == proc and "github.com" in json.dumps(r.get("remote-domains", []))
               for r in rules):
        print(f"[!] scoped GitHub rule MISSING post-import: {proc}")
        sys.exit(1)
for g in ("replayd", "remotemanagementd", "sharingd", "screensharingd"):
    if not any(r.get("action") == "deny" and g in str(r.get("process", "")) for r in rules):
        print(f"[!] guarded deny MISSING post-import: {g}")
        sys.exit(1)
print(f"[OK] verified: 0 unscoped IP allows, scoped GitHub rules present, guarded denies intact "
      f"({len(rules)} rules total)")
PYEOF
then
    echo ""
    echo "[DONE] Key-resource scoping applied and verified. Report: $REPORT"
else
    echo ""
    echo "[!] Post-import verification failed — check Little Snitch -> Rules." >&2
    echo "    Rollback: sudo \"$LSCLI\" restore-model \"$BACKUP\"" >&2
    exit 1
fi
echo "    Pre-change backup: $BACKUP"
