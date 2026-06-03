#!/usr/bin/env bash
# Per-scan file integrity snapshot — system binaries + security project + Claude.
# Output: scan-YYYY-MM-DD/file-hashes.txt  (and backward-compat binary-hashes.txt)
# Usage:  bash ~/dev/security/scan-hashes.sh [scan-dir]
set -euo pipefail

SECURITY_DIR="$HOME/dev/security"
DATE="$(date -u +%Y-%m-%d)"
SCAN_DIR="${1:-$SECURITY_DIR/scan-${DATE}}"
OUT="$SCAN_DIR/file-hashes.txt"
PREV_SCAN=$(ls -d "$SECURITY_DIR"/scan-*/ 2>/dev/null | grep -v "scan-${DATE}" | sort | tail -1 || true)
PREV_OUT="${PREV_SCAN}file-hashes.txt"
[ ! -f "$PREV_OUT" ] && PREV_OUT="${PREV_SCAN}binary-hashes.txt"

mkdir -p "$SCAN_DIR"

h() {
  [ -f "$1" ] || return 0
  local hash
  hash=$(shasum -a 256 "$1" 2>/dev/null | awk '{print $1}')
  [ -n "$hash" ] && echo "$hash  $1" || true
}

{
  echo "# File integrity snapshot"
  echo "# Date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Machine: $(scutil --get ComputerName 2>/dev/null || hostname)"
  echo ""

  echo "# ── System binaries ──────────────────────────────────────────"
  for f in \
    /usr/bin/ssh \
    /usr/sbin/sshd \
    /usr/libexec/sshd-keygen-wrapper \
    /bin/bash \
    /bin/sh \
    /bin/zsh \
    /usr/bin/python3 \
    /usr/bin/curl \
    /usr/bin/login \
    /usr/bin/perl \
    /usr/bin/nc \
    /usr/bin/openssl \
    /usr/sbin/tcpdump \
    /sbin/pfctl \
    /usr/bin/sudo \
    /usr/sbin/sysdiagnose \
    /usr/libexec/replayd \
    /usr/libexec/wifivelocityd \
    /usr/libexec/searchpartyuseragent; do
    h "$f"
  done

  echo ""
  echo "# ── Security project scripts ─────────────────────────────────"
  cd "$SECURITY_DIR"
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
    scan-hashes.sh \
    package-and-encrypt.sh \
    run-with-ls-silent.sh \
    PRESERVATION-GUIDE.md \
    com.evw.plist-monitor.plist; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# ── Security project .claude files ──────────────────────────"
  for f in \
    .claude/SESSION.md \
    .claude/settings.local.json; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# ── Encrypted memory files ───────────────────────────────────"
  for f in \
    memory/short_term.csmem \
    memory/long_term.csmem; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# ── Claude Code global config ────────────────────────────────"
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
  echo "# ── Claude Code binaries ─────────────────────────────────────"
  CLAUDE_VERSIONS="$HOME/.local/share/claude/versions"
  if [ -d "$CLAUDE_VERSIONS" ]; then
    for v in $(ls "$CLAUDE_VERSIONS" | sort); do
      f="$CLAUDE_VERSIONS/$v"
      [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  ~/.local/share/claude/versions/$v"
    done
  fi

} > "$OUT"

TOTAL=$(grep -c "^[a-f0-9]" "$OUT" || true)
echo "Hashed $TOTAL files → $OUT"

# Backward-compatible symlink so old scripts still find binary-hashes.txt
ln -sf "$(basename "$OUT")" "$SCAN_DIR/binary-hashes.txt" 2>/dev/null || \
  cp "$OUT" "$SCAN_DIR/binary-hashes.txt"

# ── Delta ─────────────────────────────────────────────────────────────────────
if [ -f "$PREV_OUT" ]; then
  DELTA="$SCAN_DIR/file-hash-diff-vs-$(basename "$(dirname "$PREV_OUT")").txt"
  echo ""
  echo "Diffing vs $(basename "$(dirname "$PREV_OUT")")/$(basename "$PREV_OUT")..."

  grep "^[a-f0-9]" "$PREV_OUT" | awk '{print $1, $2}' | sort -k2 > /tmp/sh_prev.txt
  grep "^[a-f0-9]" "$OUT"      | awk '{print $1, $2}' | sort -k2 > /tmp/sh_curr.txt

  {
    echo "# File hash delta"
    echo "# $(basename "$(dirname "$PREV_OUT")") → scan-${DATE}"
    echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""

    echo "=== MODIFIED ==="
    join -j 2 /tmp/sh_prev.txt /tmp/sh_curr.txt \
      | awk '$2 != $3 {print "MODIFIED", $1, "\n  prev:", $2, "\n  curr:", $3}' || true

    echo ""
    echo "=== NEW ==="
    comm -13 <(awk '{print $2}' /tmp/sh_prev.txt) <(awk '{print $2}' /tmp/sh_curr.txt) \
      | while read -r p; do echo "NEW      $p"; done || true

    echo ""
    echo "=== REMOVED ==="
    comm -23 <(awk '{print $2}' /tmp/sh_prev.txt) <(awk '{print $2}' /tmp/sh_curr.txt) \
      | while read -r p; do echo "REMOVED  $p"; done || true
  } > "$DELTA"

  MODIFIED=$(grep -c "^MODIFIED" "$DELTA" || true)
  ADDED=$(grep -c "^NEW" "$DELTA" || true)
  REMOVED=$(grep -c "^REMOVED" "$DELTA" || true)
  rm -f /tmp/sh_prev.txt /tmp/sh_curr.txt

  echo "Delta: modified=$MODIFIED new=$ADDED removed=$REMOVED → $DELTA"
  [ "$MODIFIED" -gt 0 ] && echo "*** MODIFIED FILES — REVIEW $DELTA ***"
else
  echo "(no previous scan found for delta)"
fi
