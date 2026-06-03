#!/usr/bin/env bash
# L5 weekly ritual — build manifest, stamp with OpenTimestamps, commit proof.
# Run once per week: bash ~/dev/security/l5-stamp.sh
set -euo pipefail

OTS="/Users/evw/Library/Python/3.9/bin/ots"
SECURITY_DIR="$HOME/dev/security"
DATE="$(date -u +%Y-%m-%d)"
MANIFEST="$SECURITY_DIR/l5-manifest-${DATE}.txt"

cd "$SECURITY_DIR"

echo "=== L5 stamp — $DATE ==="

# Build manifest
{
  echo "# L5 Hash Manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Machine: $(scutil --get ComputerName 2>/dev/null || hostname)"
  echo "# Purpose: OpenTimestamps public hash witness"
  echo ""

  echo "# Core security files"
  for f in \
    MASTER-SECURITY-LOG.md \
    MASTER-SECURITY-LOG.pdf \
    MANIFEST.sha256 \
    evw-plist-monitor.sh \
    harden.sh \
    security-memory-manager.py \
    lock-remote-access.sh \
    generate-master-log-pdf.py \
    l5-stamp.sh \
    build-fs-baseline.sh \
    package-and-encrypt.sh \
    run-with-ls-silent.sh \
    scan-hashes.sh \
    PRESERVATION-GUIDE.md; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Security project .claude files"
  for f in \
    .claude/SESSION.md \
    .claude/settings.local.json; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Encrypted memory files"
  for f in \
    memory/short_term.csmem \
    memory/long_term.csmem; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Claude Code global config"
  CLAUDE_DIR="$HOME/.claude"
  for f in \
    "$CLAUDE_DIR/CLAUDE.md" \
    "$CLAUDE_DIR/settings.json" \
    "$CLAUDE_DIR/settings.local.json" \
    "$CLAUDE_DIR/export-conversation.sh" \
    "$CLAUDE_DIR/record-session.sh" \
    "$CLAUDE_DIR/hooks/pre-tool-use.sh" \
    "$CLAUDE_DIR/hooks/post-tool-use.sh" \
    "$CLAUDE_DIR/hooks/notify-on-stop.sh"; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  ${f/#$HOME/~}"
  done

  echo ""
  echo "# Claude Code binaries (all installed versions)"
  CLAUDE_VERSIONS="$HOME/.local/share/claude/versions"
  if [ -d "$CLAUDE_VERSIONS" ]; then
    for v in $(ls "$CLAUDE_VERSIONS" | sort); do
      f="$CLAUDE_VERSIONS/$v"
      [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  ~/.local/share/claude/versions/$v"
    done
  fi

  echo ""
  echo "# Scan summaries and triage reports"
  for d in $(ls -d scan-*/ 2>/dev/null | sort); do
    for f in "${d}SCAN-SUMMARY.md" "${d}TRIAGE-REPORT.md"; do
      [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
    done
  done

  echo ""
  echo "# LS deny rule files"
  find . -name "deny-rules-*.lsrules" | sort | while read f; do
    echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Most recent binary hash + LS model snapshots"
  LATEST_SCAN=$(ls -d scan-*/ 2>/dev/null | sort | tail -1)
  for f in "${LATEST_SCAN}binary-hashes.txt" "${LATEST_SCAN}ls-model.json"; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Hash log (accumulated session snapshots)"
  [ -f "l5-hash-log.txt" ] && echo "$(shasum -a 256 l5-hash-log.txt | awk '{print $1}')  l5-hash-log.txt"

} > "$MANIFEST"

echo "Manifest: $MANIFEST ($(wc -l < "$MANIFEST") lines)"

# Stamp
echo "Submitting to OpenTimestamps calendars..."
"$OTS" stamp "$MANIFEST"
echo "Proof: ${MANIFEST}.ots"

# Append to hash log
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $(shasum -a 256 "$MANIFEST" | awk '{print $1}') l5-manifest-${DATE}.txt" >> "$SECURITY_DIR/l5-hash-log.txt"

# Commit
git add "l5-manifest-${DATE}.txt" "l5-manifest-${DATE}.txt.ots" l5-hash-log.txt
git commit -m "L5 weekly stamp ${DATE} — $(wc -l < "$MANIFEST") file hashes timestamped"

echo ""
echo "=== Done. Upgrade proof in ~3 hours: ==="
echo "  $OTS upgrade ${MANIFEST}.ots"
echo "  git add ${MANIFEST}.ots && git commit -m 'L5 upgrade ${DATE}'"
