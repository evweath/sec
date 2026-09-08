#!/usr/bin/env bash
# knockknock-scan.sh — KnockKnock CLI persistence scan into the dated scan dir.
# Enumerates every persistently-installed item (launch items, login items,
# extensions, shell configs, cron, emond, ...) — the generic malware-persistence
# detector. VirusTotal is skipped (no API key stored); Apple platform items are
# filtered by default. Run as root (sudo) for other users' cron jobs etc.
# Output: scan-YYYY-MM-DD/knockknock.json (+ console summary)
# Usage:  bash knockknock-scan.sh        (or: sudo bash knockknock-scan.sh)
set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

SEC_DIR="/Users/evw/dev/security"
SCAN_DIR="$SEC_DIR/scan-$(date +%F)"
KK="/Applications/KnockKnock.app/Contents/MacOS/KnockKnock"
OUT="$SCAN_DIR/knockknock.json"
mkdir -p "$SCAN_DIR"

if [ ! -x "$KK" ]; then
    echo "[!] KnockKnock not installed — brew install --cask knockknock" >&2
    exit 1
fi

echo "[*] KnockKnock $("$KK" -version 2>/dev/null | awk -F': ' '{print $2}') — scanning → $OUT"
guard_run "knockknock-scan" "$KK" -whosthere -pretty -skipVT > "$OUT"

python3 - "$OUT" <<'EOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"[!] could not parse {sys.argv[1]}: {e}", file=sys.stderr)
    sys.exit(1)
total = flagged = unsigned = 0
for cat, items in sorted(d.items()):
    if not isinstance(items, list):
        continue
    n = len(items)
    total += n
    for i in items:
        if not isinstance(i, dict):
            continue
        if i.get('infected') not in (None, 0, '0', False):
            flagged += 1
        sig = str(i.get('signature(s)', ''))
        if 'unsigned' in sig.lower():
            unsigned += 1
    if n:
        print(f'  {n:3d}  {cat}')
print(f'[✓] {total} persistent items | flagged: {flagged} | unsigned: {unsigned}')
sys.exit(2 if flagged else 0)
EOF
