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

h() {
  [ -f "$1" ] || return 0
  local hash
  hash=$(shasum -a 256 "$1" 2>/dev/null | awk '{print $1}') || true
  if [ -n "$hash" ]; then
    echo "$hash  ${2:-$1}"
  else
    echo "UNREADABLE (needs sudo)  ${2:-$1}"
  fi
}

{
  echo "# L5 Hash Manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Machine: $(scutil --get ComputerName 2>/dev/null || hostname)"
  echo "# Purpose: OpenTimestamps public hash witness"
  echo ""

  # ── Core OS ────────────────────────────────────────────────────────────────
  echo "# Core OS / launchd"
  h /sbin/launchd
  h /usr/libexec/cfprefsd
  h /usr/libexec/nsurlsessiond

  echo ""
  echo "# System binaries (monitored)"
  for f in \
    /usr/bin/ssh /usr/sbin/sshd /usr/libexec/sshd-keygen-wrapper \
    /bin/bash /bin/sh /bin/zsh \
    /usr/bin/python3 /usr/bin/curl /usr/bin/login /usr/bin/perl \
    /usr/bin/nc /usr/bin/openssl /usr/sbin/tcpdump /sbin/pfctl \
    /usr/bin/sudo /usr/sbin/sysdiagnose \
    /usr/libexec/replayd /usr/libexec/wifivelocityd \
    /usr/libexec/searchpartyuseragent /usr/libexec/remotemanagementd \
    /System/Library/CoreServices/RemoteManagementAgent; do
    h "$f"
  done

  # ── Security project — all scripts (dynamic) ───────────────────────────────
  echo ""
  echo "# Security project scripts"
  for f in *.sh *.py; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Security project docs and manifests"
  for f in \
    MASTER-SECURITY-LOG.md \
    MASTER-SECURITY-LOG.pdf \
    MANIFEST.sha256 \
    PRESERVATION-GUIDE.md \
    com.evw.plist-monitor.plist \
    l5-hash-log.txt; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  # ── Security project .claude files ─────────────────────────────────────────
  echo ""
  echo "# Security project .claude files"
  for f in .claude/SESSION.md .claude/settings.local.json; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  # ── Encrypted memory ───────────────────────────────────────────────────────
  echo ""
  echo "# Encrypted memory files (repo)"
  for f in memory/short_term.csmem memory/long_term.csmem; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  # ── Claude global config ───────────────────────────────────────────────────
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

  # ── Claude project memory ──────────────────────────────────────────────────
  echo ""
  echo "# Claude Code project memory (security)"
  PROJ_MEM="$HOME/.claude/projects/-Users-evw-dev-security/memory"
  if [ -d "$PROJ_MEM" ]; then
    for f in "$PROJ_MEM"/*.md "$PROJ_MEM"/*.csmem; do
      [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  ${f/#$HOME/~}"
    done
  fi

  # ── Claude binaries ────────────────────────────────────────────────────────
  echo ""
  echo "# Claude Code binaries (all installed versions)"
  CLAUDE_VERSIONS="$HOME/.local/share/claude/versions"
  if [ -d "$CLAUDE_VERSIONS" ]; then
    for v in $(ls "$CLAUDE_VERSIONS" | sort); do
      f="$CLAUDE_VERSIONS/$v"
      [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  ~/.local/share/claude/versions/$v"
    done
  fi

  # ── Python ─────────────────────────────────────────────────────────────────
  echo ""
  echo "# Python binaries"
  h "$HOME/.pyenv/versions/3.13.13/bin/python3.13"
  h "/usr/bin/python3"

  # ── Third-party apps ───────────────────────────────────────────────────────
  echo ""
  echo "# Little Snitch binary"
  h "/Applications/Little Snitch.app/Contents/Components/littlesnitch"

  echo ""
  echo "# DuckDuckGo browser binary"
  h "/Applications/DuckDuckGo.app/Contents/MacOS/DuckDuckGo"

  # ── LaunchAgent/Daemon plists ──────────────────────────────────────────────
  echo ""
  echo "# LaunchAgent and LaunchDaemon plists"
  h "$HOME/Library/LaunchAgents/com.evw.donut-intel.plist"
  h "/Library/LaunchDaemons/com.evw.plist-monitor.plist"

  # ── DuckDuckGo settings snapshot ──────────────────────────────────────────
  echo ""
  echo "# DuckDuckGo preferences snapshot (zoom + appearance)"
  DDG_ZOOM=$(defaults read com.duckduckgo.macos.browser "preferences.appearance.default-page-zoom" 2>/dev/null || echo "unset")
  DDG_URL=$(defaults read com.duckduckgo.macos.browser "preferences.appearance.show-full-url" 2>/dev/null || echo "unset")
  DDG_SNAP="DDG_zoom=${DDG_ZOOM} DDG_show-full-url=${DDG_URL}"
  echo "$(echo -n "$DDG_SNAP" | shasum -a 256 | awk '{print $1}')  [DDG-prefs-snapshot: $DDG_SNAP]"

  # ── Scan summaries ─────────────────────────────────────────────────────────
  echo ""
  echo "# Scan summaries and triage reports"
  for d in $(ls -d scan-*/ 2>/dev/null | sort); do
    for f in "${d}SCAN-SUMMARY.md" "${d}TRIAGE-REPORT.md"; do
      [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
    done
  done

  # ── LS deny rule files ─────────────────────────────────────────────────────
  echo ""
  echo "# LS deny rule files"
  find . -name "deny-rules-*.lsrules" | sort | while read f; do
    echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  # ── Most recent binary hash + LS model ────────────────────────────────────
  echo ""
  echo "# Most recent binary hash + LS model snapshots"
  LATEST_SCAN=$(ls -d scan-*/ 2>/dev/null | sort | tail -1)
  for f in "${LATEST_SCAN}file-hashes.txt" "${LATEST_SCAN}binary-hashes.txt" "${LATEST_SCAN}ls-model.json"; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  # ── Hash log ───────────────────────────────────────────────────────────────
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
