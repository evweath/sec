#!/usr/bin/env bash
# Per-scan file integrity snapshot — ALL package-manager binaries, app
# binaries, persistence plists, system binaries, security project, Claude, Python.
# Output: scan-YYYY-MM-DD/file-hashes.txt  (and backward-compat binary-hashes.txt)
# Usage:  bash ~/dev/security/scan-hashes.sh [scan-dir]
set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

# Anchor to the repo unless the root-owned deployed copy is given the repo
# explicitly. Under the LaunchDaemon, HOME is /var/root or unset.
SECURITY_DIR="${EVW_SECURITY_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)}"
# User-profile files come from the repo owner's home ($OWNER_HOME/dev/security).
OWNER_HOME="$(dirname "$(dirname "$SECURITY_DIR")")"
DATE="$(date -u +%Y-%m-%d)"
SCAN_DIR="${1:-$SECURITY_DIR/scan-${DATE}}"
OUT="$SCAN_DIR/file-hashes.txt"
# Most recent previous scan that actually has a hash file to diff against.
PREV_SCAN=""
PREV_OUT=""
for d in $(ls -d "$SECURITY_DIR"/scan-*/ 2>/dev/null | grep -v "scan-${DATE}" | sort -r); do
  if [ -f "${d}file-hashes.txt" ]; then PREV_SCAN="$d"; PREV_OUT="${d}file-hashes.txt"; break; fi
  if [ -f "${d}binary-hashes.txt" ]; then PREV_SCAN="$d"; PREV_OUT="${d}binary-hashes.txt"; break; fi
done

mkdir -p "$SCAN_DIR"

h() {
  local f="$1"
  if [ -L "$f" ]; then
    # Symlink: identity = target string + resolved content. Catches brew-style
    # relinks (symlink recreated pointing elsewhere) AND content swaps under a
    # stable target — the 2026-10-20 gh lesson (gh was a 27-byte symlink whose
    # re-creation the old fixed list never even tracked).
    local tgt content hash
    tgt=$(readlink "$f" 2>/dev/null || echo "?")
    content=$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')
    hash=$(printf 'SYMLINK:%s:CONTENT:%s' "$tgt" "${content:-UNRESOLVED}" | shasum -a 256 | awk '{print $1}')
    echo "$hash  $f"
    return 0
  fi
  [ -f "$f" ] || return 0
  local hash
  hash=$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}') || true
  if [ -n "$hash" ]; then
    echo "$hash  $f"
  else
    echo "UNREADABLE (needs sudo)  $f"
  fi
}

{
  echo "# File integrity snapshot"
  echo "# Date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Machine: $(scutil --get ComputerName 2>/dev/null || hostname)"
  echo ""

  echo "# ── Core OS / launchd ────────────────────────────────────────"
  guard_run "h" h /sbin/launchd
  guard_run "h" h /usr/libexec/cfprefsd
  guard_run "h" h /usr/libexec/nsurlsessiond

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
    /usr/libexec/searchpartyuseragent \
    /usr/libexec/remotemanagementd \
    /System/Library/CoreServices/RemoteManagementAgent; do
    guard_run "h" h "$f"
  done

  echo ""
  echo "# ── Security project — all scripts ──────────────────────────"
  cd "$SECURITY_DIR"
  for f in *.sh *.py; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done
  # subdirs holding operational code (scripts/ installs to /usr/local/bin)
  for f in scripts/*.sh scripts/*.py lib/*.sh lib/*.py; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# ── Security project — docs and manifests ───────────────────"
  for f in \
    MASTER-SECURITY-LOG.md \
    MASTER-SECURITY-LOG.pdf \
    MANIFEST.sha256 \
    PRESERVATION-GUIDE.md \
    com.evw.plist-monitor.plist \
    l5-hash-log.txt; do
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
  echo "# ── Encrypted memory files (repo) ───────────────────────────"
  for f in \
    memory/short_term.csmem \
    memory/long_term.csmem; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# ── Claude Code global config ────────────────────────────────"
  CLAUDE_DIR="$OWNER_HOME/.claude"
  for f in \
    "$CLAUDE_DIR/CLAUDE.md" \
    "$CLAUDE_DIR/settings.json" \
    "$CLAUDE_DIR/settings.local.json" \
    "$CLAUDE_DIR/export-conversation.sh" \
    "$CLAUDE_DIR/record-session.sh" \
    "$CLAUDE_DIR/hooks/pre-tool-use.sh" \
    "$CLAUDE_DIR/hooks/post-tool-use.sh" \
    "$CLAUDE_DIR/hooks/notify-on-stop.sh"; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  ${f/#$OWNER_HOME/~}"
  done

  echo ""
  echo "# ── Claude Code project memory (security project) ───────────"
  PROJ_MEM="$OWNER_HOME/.claude/projects/-Users-evw-dev-security/memory"
  if [ -d "$PROJ_MEM" ]; then
    for f in "$PROJ_MEM"/*.md "$PROJ_MEM"/*.csmem "$PROJ_MEM"/MEMORY.md; do
      [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  ${f/#$OWNER_HOME/~}"
    done
  fi

  echo ""
  echo "# ── Claude Code binaries ─────────────────────────────────────"
  CLAUDE_VERSIONS="$OWNER_HOME/.local/share/claude/versions"
  if [ -d "$CLAUDE_VERSIONS" ]; then
    for v in $(ls "$CLAUDE_VERSIONS" | sort); do
      f="$CLAUDE_VERSIONS/$v"
      [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  ~/.local/share/claude/versions/$v"
    done
  fi

  echo ""
  echo "# ── Python — pyenv 3.13 + stdlib python3 ────────────────────"
  for f in \
    "$OWNER_HOME/.pyenv/versions/3.13.13/bin/python3.13" \
    "/usr/bin/python3"; do
    guard_run "h" h "$f"
  done

  echo ""
  echo "# ── Little Snitch binary ─────────────────────────────────────"
  guard_run "h" h "/Applications/Little Snitch.app/Contents/Components/littlesnitch"

  echo ""
  echo "# ── Lynis + KnockKnock ───────────────────────────────────────"
  guard_run "h" h /opt/homebrew/bin/lynis
  guard_run "h" h "/Applications/KnockKnock.app/Contents/MacOS/KnockKnock"

  echo ""
  echo "# ── DuckDuckGo browser binary ────────────────────────────────"
  guard_run "h" h "/Applications/DuckDuckGo.app/Contents/MacOS/DuckDuckGo"

  echo ""
  echo "# ── LaunchAgent/Daemon plists ────────────────────────────────"
  for f in \
    "$OWNER_HOME/Library/LaunchAgents/com.evw.donut-intel.plist" \
    "/Library/LaunchDaemons/com.evw.plist-monitor.plist"; do
    guard_run "h" h "$f"
  done

  echo ""
  echo "# ── ALL package-manager binaries (homebrew + /usr/local) ────"
  # Every file and symlink — no fixed list. Added after the 2026-10-20
  # brew-cascade incident: 250+ binaries here were outside the tracked set.
  for f in /opt/homebrew/bin/* /opt/homebrew/sbin/* /usr/local/bin/* /usr/local/sbin/*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    guard_run "h" h "$f"
  done

  echo ""
  echo "# ── ALL application binaries (/Applications) ────────────────"
  for f in /Applications/*.app/Contents/MacOS/*; do
    [ -e "$f" ] || continue
    guard_run "h" h "$f"
  done

  echo ""
  echo "# ── ALL persistence plists (LaunchAgents/Daemons) ───────────"
  for f in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist \
           "$OWNER_HOME/Library/LaunchAgents"/*.plist; do
    [ -f "$f" ] || continue
    guard_run "h" h "$f"
  done

} > "$OUT.tmp.$$"
# Atomic rename: two audits racing (boot+login, or debounce miss) can interleave
# a direct write and splice the baseline — a corrupted baseline either masks
# real changes or floods the next delta with phantom MODIFIED/NEW entries.
mv -f "$OUT.tmp.$$" "$OUT"

TOTAL=$(grep -c "^[a-f0-9]" "$OUT" || true)
echo "Hashed $TOTAL files → $OUT"

# Backward-compatible symlink
ln -sf "$(basename "$OUT")" "$SCAN_DIR/binary-hashes.txt" 2>/dev/null || \
  cp "$OUT" "$SCAN_DIR/binary-hashes.txt"

# ── Delta ─────────────────────────────────────────────────────────────────────
if [ -n "$PREV_SCAN" ] && [ -f "$PREV_OUT" ]; then
  DELTA="$SCAN_DIR/file-hash-diff-vs-$(basename "$(dirname "$PREV_OUT")").txt"
  echo ""
  echo "Diffing vs $(basename "$(dirname "$PREV_OUT")")/$(basename "$PREV_OUT")..."

  SH_PREV="$(mktemp /tmp/sh_prev.XXXXXXXX)"
  SH_CURR="$(mktemp /tmp/sh_curr.XXXXXXXX)"

  guard_run "delta-prev" grep "^[a-f0-9]" "$PREV_OUT" | awk '{h=$1; sub(/^[a-f0-9]+  /, ""); print h "\t" $0}' | sort -t$'\t' -k2 > "$SH_PREV" || true
  guard_run "delta-curr" grep "^[a-f0-9]" "$OUT"      | awk '{h=$1; sub(/^[a-f0-9]+  /, ""); print h "\t" $0}' | sort -t$'\t' -k2 > "$SH_CURR" || true

  {
    echo "# File hash delta"
    echo "# $(basename "$(dirname "$PREV_OUT")") → scan-${DATE}"
    echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""

    echo "=== MODIFIED ==="
    join -t$'\t' -j 2 "$SH_PREV" "$SH_CURR" \
      | awk -F'\t' '$2 != $3 {print "MODIFIED", $1, "\n  prev:", $2, "\n  curr:", $3}' || true

    echo ""
    echo "=== NEW ==="
    comm -13 <(cut -f2 "$SH_PREV") <(cut -f2 "$SH_CURR") \
      | while read -r p; do echo "NEW      $p"; done || true

    echo ""
    echo "=== REMOVED ==="
    comm -23 <(cut -f2 "$SH_PREV") <(cut -f2 "$SH_CURR") \
      | while read -r p; do echo "REMOVED  $p"; done || true
  } > "$DELTA"

  MODIFIED=$(grep -c "^MODIFIED" "$DELTA" || true)
  ADDED=$(grep -c "^NEW" "$DELTA" || true)
  REMOVED=$(grep -c "^REMOVED" "$DELTA" || true)
  rm -f "$SH_PREV" "$SH_CURR"

  echo "Delta: modified=$MODIFIED new=$ADDED removed=$REMOVED → $DELTA"
  if [ "$MODIFIED" -gt 0 ]; then
    echo "*** MODIFIED FILES — REVIEW $DELTA ***"
  fi
else
  echo "(no previous scan found for delta)"
fi
