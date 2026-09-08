#!/usr/bin/env bash
# lynis-audit.sh — run a Lynis system audit into the dated scan dir.
# As root: full audit. Unprivileged: a handful of root-only tests are skipped
# (noted at the end of the report). Never fatal on missing findings — exit
# code follows lynis itself only for real runtime errors.
# Output: scan-YYYY-MM-DD/lynis.log + lynis-report.dat
# Usage:  bash lynis-audit.sh        (or: sudo bash lynis-audit.sh)
set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

SEC_DIR="/Users/evw/dev/security"
SCAN_DIR="$SEC_DIR/scan-$(date +%F)"
mkdir -p "$SCAN_DIR"

if ! command -v lynis >/dev/null 2>&1; then
    echo "[!] lynis not installed — brew install lynis" >&2
    exit 1
fi

MODE=user; [ "$EUID" -eq 0 ] && MODE=root
echo "[*] lynis $(lynis --version 2>/dev/null || echo '?') — $MODE audit → $SCAN_DIR"

guard_run "lynis-audit" lynis audit system --quick --no-colors \
    --log-file "$SCAN_DIR/lynis.log" --report-file "$SCAN_DIR/lynis-report.dat"

# summary (report fields: hardening_index=NN, warning[]=..., suggestion[]=...)
REPORT="$SCAN_DIR/lynis-report.dat"
if [ -f "$REPORT" ]; then
    IDX=$(grep -E '^hardening_index' "$REPORT" | cut -d= -f2)
    WARN=$(grep -cE '^warning' "$REPORT" || true)
    SUGG=$(grep -cE '^suggestion' "$REPORT" || true)
    echo "[✓] hardening index: ${IDX:-?} | warnings: $WARN | suggestions: $SUGG"
    grep -E '^warning' "$REPORT" | sed 's/^warning\[\]=/  WARNING: /' | head -10
    echo "    report: $REPORT"
else
    echo "[!] no report produced — see $SCAN_DIR/lynis.log" >&2
    exit 1
fi
