#!/usr/bin/env bash
# Filesystem integrity baseline — Tier 1 + Tier 2 + Tier 3
# Hashes system binaries, /Library, and key config files.
# On subsequent runs, produces a delta report.

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

OTS="/Users/evw/Library/Python/3.9/bin/ots"
SECURITY_DIR="$HOME/dev/security"
DATE="$(date -u +%Y-%m-%d)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

BASELINE_DIR="$SECURITY_DIR/fs-baseline"
mkdir -p "$BASELINE_DIR"

MANIFEST="$BASELINE_DIR/fs-baseline-${DATE}.txt"
TMP="$BASELINE_DIR/.fs-baseline.tmp"
PREV=$(ls "$BASELINE_DIR"/fs-baseline-*.txt 2>/dev/null | grep -v "$DATE" | sort | tail -1 || true)

echo "=== Filesystem Integrity Baseline — $DATE ==="
[ -n "$PREV" ] && echo "Previous baseline: $(basename "$PREV")" || echo "First run — no delta"
echo ""

rm -f "$TMP"
touch "$TMP"

hash_tree() {
  local label="$1" dir="$2" exclude="${3:-NOMATCH_PLACEHOLDER}"
  [ -d "$dir" ] || { echo "  [skip] $dir"; return; }
  local n
  n=$(find "$dir" -type f 2>/dev/null | grep -cvE "$exclude" || true)
  echo "  $label ($dir) — $n files"
  find "$dir" -type f 2>/dev/null \
    | grep -vE "$exclude" \
    | sort \
    | while IFS= read -r f; do shasum -a 256 "$f" 2>/dev/null; done \
    >> "$TMP" || true
}

echo "--- Tier 1: System binaries ---"
guard_run "hash-tree" hash_tree "bin"         /bin
guard_run "hash-tree" hash_tree "sbin"        /sbin
guard_run "hash-tree" hash_tree "usr/bin"     /usr/bin
guard_run "hash-tree" hash_tree "usr/sbin"    /usr/sbin
guard_run "hash-tree" hash_tree "usr/libexec" /usr/libexec  "iRATBW\.mlmodelc|CoreSpeech\.framework|NaturalLanguage"

echo ""
echo "--- Tier 2: /Library ---"
guard_run "hash-tree" hash_tree "LaunchAgents"  /Library/LaunchAgents
guard_run "hash-tree" hash_tree "LaunchDaemons" /Library/LaunchDaemons
guard_run "hash-tree" hash_tree "Extensions"    /Library/Extensions
guard_run "hash-tree" hash_tree "Preferences"   /Library/Preferences  "ByHost"
guard_run "hash-tree" hash_tree "LS config"     "/Library/Application Support/Objective Development/Little Snitch" \
  "Connections\.replog|DNSCache\.replog|ip-address-database|\.cacheID"
guard_run "hash-tree" hash_tree "Security"      /Library/Security

echo ""
echo "--- Tier 3: Key config files ---"
for f in \
  /private/etc/hosts \
  /private/etc/pf.conf \
  /private/etc/sudoers \
  /etc/ssh/sshd_config \
  /etc/ssh/ssh_config \
  /private/etc/shells \
  /private/etc/paths \
  /Library/LaunchDaemons/com.evw.plist-monitor.plist \
  /usr/local/bin/evw-plist-monitor.sh; do
  [ -f "$f" ] && shasum -a 256 "$f" >> "$TMP" 2>/dev/null || true
done
echo "  Key config files hashed"

# Assemble manifest
{
  echo "# Filesystem Integrity Baseline"
  echo "# Date:    $TIMESTAMP"
  echo "# Machine: $(scutil --get ComputerName 2>/dev/null || hostname)"
  echo "# macOS:   $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
  echo "#"
  sort -k2 "$TMP"
} > "$MANIFEST"
rm -f "$TMP"

TOTAL=$(grep -c "^[a-f0-9]" "$MANIFEST" || true)
echo ""
echo "Total: $TOTAL files hashed"

# ── Delta ─────────────────────────────────────────────────────────────────────
MODIFIED=0; ADDED=0; REMOVED=0
if [ -n "$PREV" ]; then
  DELTA="$BASELINE_DIR/delta-$(basename "$PREV" .txt)--to--${DATE}.txt"
  echo ""
  echo "--- Delta vs $(basename "$PREV") ---"

  grep "^[a-f0-9]" "$PREV"     | awk '{h=$1; sub(/^[a-f0-9]+  /, ""); print h "\t" $0}' | sort -t$'\t' -k2 > /tmp/l5_prev.txt
  grep "^[a-f0-9]" "$MANIFEST" | awk '{h=$1; sub(/^[a-f0-9]+  /, ""); print h "\t" $0}' | sort -t$'\t' -k2 > /tmp/l5_curr.txt

  {
    echo "# Delta: $(basename "$PREV") → fs-baseline-${DATE}.txt"
    echo "# $TIMESTAMP"
    echo ""

    echo "=== MODIFIED ==="
    # Files present in both but with different hash
    join -t$'\t' -j 2 /tmp/l5_prev.txt /tmp/l5_curr.txt \
      | awk -F'\t' '$2 != $3 {print "MODIFIED", $1, "\n  prev:", $2, "\n  curr:", $3}' \
      || true

    echo ""
    echo "=== NEW ==="
    # Paths in curr not in prev
    comm -13 <(cut -f2 /tmp/l5_prev.txt) <(cut -f2 /tmp/l5_curr.txt) \
      | while read p; do echo "NEW      $p"; done || true

    echo ""
    echo "=== REMOVED ==="
    # Paths in prev not in curr
    comm -23 <(cut -f2 /tmp/l5_prev.txt) <(cut -f2 /tmp/l5_curr.txt) \
      | while read p; do echo "REMOVED  $p"; done || true

  } > "$DELTA" 2>/dev/null

  MODIFIED=$(grep -c "^MODIFIED" "$DELTA" || true)
  ADDED=$(grep -c "^NEW" "$DELTA" || true)
  REMOVED=$(grep -c "^REMOVED" "$DELTA" || true)
  rm -f /tmp/l5_prev.txt /tmp/l5_curr.txt

  echo "  Modified: $MODIFIED | New: $ADDED | Removed: $REMOVED"
  [ "$MODIFIED" -gt 0 ] && echo "  *** MODIFIED FILES — REVIEW $DELTA ***"
fi

# ── OTS stamp ─────────────────────────────────────────────────────────────────
echo ""
echo "--- OpenTimestamps stamp ---"
if [ -x "$OTS" ]; then
  guard_run "ots-stamp" "$OTS" stamp "$MANIFEST"
  echo "Proof: ${MANIFEST}.ots"
else
  echo "WARNING: ots not found at $OTS — skipping stamp (reinstall opentimestamps-client)"
fi

echo "$TIMESTAMP $(shasum -a 256 "$MANIFEST" | awk '{print $1}') fs-baseline-${DATE}.txt ($TOTAL files)" \
  >> "$SECURITY_DIR/l5-hash-log.txt"

# ── Commit ────────────────────────────────────────────────────────────────────
echo ""
cd "$SECURITY_DIR"
git add fs-baseline/ l5-hash-log.txt build-fs-baseline.sh
git commit -m "fs-baseline ${DATE}: ${TOTAL} files — mod=${MODIFIED} new=${ADDED} rm=${REMOVED} — OTS stamped"

echo ""
echo "=== Complete ==="
echo "Upgrade OTS proof in ~3 hours:"
echo "  $OTS upgrade ${MANIFEST}.ots && git -C $SECURITY_DIR add fs-baseline/ && git commit -m 'L5 fs-baseline upgrade ${DATE}'"
