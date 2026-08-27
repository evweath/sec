#!/usr/bin/env bash
# L5 comprehensive system stamp — full coverage: apps, configs, scripts, Claude, Python, security.
# Run weekly: bash ~/dev/security/l5-stamp.sh
set -euo pipefail

# Resolve ots dynamically — it has lived under various Python user dirs
OTS="$(command -v ots 2>/dev/null || true)"
if [ -z "$OTS" ]; then
  for c in "$HOME"/Library/Python/*/bin/ots "$HOME/.local/bin/ots"; do
    [ -x "$c" ] && OTS="$c" && break
  done
fi
SECURITY_DIR="$HOME/dev/security"
DATE="$(date -u +%Y-%m-%d)"
MANIFEST="$SECURITY_DIR/l5-manifest-full-${DATE}.txt"

cd "$SECURITY_DIR"

echo "=== L5 comprehensive stamp — $DATE ==="

h() {
  [ -f "$1" ] || return 0
  local hash label
  hash=$(shasum -a 256 "$1" 2>/dev/null | awk '{print $1}') || true
  label="${2:-${1/#$HOME/~}}"
  if [ -n "$hash" ]; then
    echo "$hash  $label"
  else
    echo "UNREADABLE (needs sudo)  $label"
  fi
}

hdir() {
  local dir="$1" label_prefix="${2:-}" ext="${3:-}"
  [ -d "$dir" ] || return 0
  if [ -n "$ext" ]; then
    find "$dir" -maxdepth 1 -name "$ext" -type f 2>/dev/null | sort | while read -r f; do
      h "$f" "${label_prefix}$(basename "$f")"
    done
  else
    find "$dir" -maxdepth 1 -type f 2>/dev/null | sort | while read -r f; do
      h "$f" "${label_prefix}$(basename "$f")"
    done
  fi
}

{
  echo "# L5 Comprehensive Hash Manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Machine: $(scutil --get ComputerName 2>/dev/null || hostname)"
  echo "# OS: $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
  echo "# Coverage: apps, configs, LaunchAgents/Daemons, Claude, Python, security, dotfiles, system"
  echo ""

  # ── Core OS / launchd ──────────────────────────────────────────────────────
  echo "# Core OS"
  for f in /sbin/launchd /usr/libexec/cfprefsd /usr/libexec/nsurlsessiond \
            /usr/libexec/replayd /usr/libexec/remotemanagementd \
            /System/Library/CoreServices/RemoteManagementAgent; do
    h "$f"
  done

  # ── System binaries ────────────────────────────────────────────────────────
  echo ""
  echo "# System binaries"
  for f in /usr/bin/ssh /usr/sbin/sshd /usr/libexec/sshd-keygen-wrapper \
            /bin/bash /bin/sh /bin/zsh /bin/launchctl \
            /usr/bin/python3 /usr/bin/curl /usr/bin/login /usr/bin/perl \
            /usr/bin/nc /usr/bin/openssl /usr/sbin/tcpdump /sbin/pfctl \
            /usr/sbin/sysdiagnose /usr/libexec/wifivelocityd \
            /usr/libexec/searchpartyuseragent \
            /usr/bin/codesign /usr/bin/security /usr/bin/spctl \
            /usr/bin/defaults /usr/bin/plutil /usr/bin/sqlite3 \
            /usr/bin/osascript /usr/bin/xattr /usr/bin/chflags \
            /usr/sbin/spindump /usr/bin/lsof /usr/bin/netstat \
            /usr/bin/nettop /usr/bin/dscl /usr/bin/id \
            /usr/bin/shasum /usr/bin/openssl /usr/bin/csrutil; do
    h "$f"
  done

  # ── Applications (/Applications/) ─────────────────────────────────────────
  echo ""
  echo "# Applications — main binaries + Info.plist"
  find /Applications -maxdepth 2 -name "*.app" -type d 2>/dev/null | sort | while read -r app; do
    appname=$(basename "${app%.app}")
    binary="$app/Contents/MacOS/$appname"
    info="$app/Contents/Info.plist"
    [ -f "$binary" ] && h "$binary" "Apps/$appname/MacOS/$appname"
    [ -f "$info"   ] && h "$info"   "Apps/$appname/Info.plist"
    # CodeResources (code signature manifest)
    coderes="$app/Contents/_CodeSignature/CodeResources"
    [ -f "$coderes" ] && h "$coderes" "Apps/$appname/_CodeSignature/CodeResources"
    # Try alternate binary name patterns
    if [ ! -f "$binary" ]; then
      alt=$(find "$app/Contents/MacOS/" -maxdepth 1 -type f 2>/dev/null | head -1)
      [ -n "$alt" ] && h "$alt" "Apps/$appname/MacOS/$(basename "$alt")"
    fi
  done

  # ── Homebrew binaries ──────────────────────────────────────────────────────
  echo ""
  echo "# Homebrew binaries"
  BREW_BIN="/opt/homebrew/bin"
  [ -d "$BREW_BIN" ] || BREW_BIN="/usr/local/bin"
  if [ -d "$BREW_BIN" ]; then
    find "$BREW_BIN" -maxdepth 1 -type f -o -maxdepth 1 -type l 2>/dev/null | sort | while read -r f; do
      # Only hash actual binaries (resolve symlinks to real files)
      real=$(readlink -f "$f" 2>/dev/null || echo "$f")
      [ -f "$real" ] && h "$real" "Homebrew/bin/$(basename "$f")"
    done
  fi

  # ── Deployed evw-* guards + launchd disabled list ─────────────────────────
  echo ""
  echo "# Deployed /usr/local/bin/evw-* and disabled.501.plist"
  find /usr/local/bin -maxdepth 1 -name "evw-*" -type f 2>/dev/null | sort | while read -r f; do h "$f" "/usr/local/bin/$(basename "$f")"; done
  h "/private/var/db/com.apple.xpc.launchd/disabled.501.plist"

  # ── Python ─────────────────────────────────────────────────────────────────
  echo ""
  echo "# Python binaries"
  for f in /usr/bin/python3 \
            "$HOME/.pyenv/versions/3.13.13/bin/python3.13" \
            "$HOME/.pyenv/versions/3.13.13/bin/python3" \
            "${OTS:-/dev/null}"; do
    h "$f"
  done

  echo ""
  echo "# Python scripts — ~/dev/ (excluding venv/pycache/site-packages)"
  find "$HOME/dev" -name "*.py" \
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/.git/*" \
    ! -path "*/venv/*" \
    ! -path "*/.venv/*" \
    ! -path "*/site-packages/*" \
    ! -path "*/build/*" \
    ! -path "*/dist/*" \
    2>/dev/null | sort | while read -r f; do
    h "$f" "${f/#$HOME/~}"
  done

  # ── Shell config / dotfiles ────────────────────────────────────────────────
  echo ""
  echo "# Shell config and dotfiles"
  for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" \
            "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" \
            "$HOME/.ssh/config" "$HOME/.ssh/known_hosts" "$HOME/.ssh/authorized_keys" \
            /etc/hosts /etc/shells /etc/zshrc /etc/zprofile \
            /etc/pam.d/sudo /etc/sudoers; do
    h "$f"
  done
  # SSH public keys hashed; private keys recorded by existence only
  find "$HOME/.ssh" -maxdepth 1 -name "*.pub" -type f 2>/dev/null | sort | while read -r f; do h "$f"; done
  find "$HOME/.ssh" -maxdepth 1 -name "id_*" -not -name "*.pub" -type f 2>/dev/null | sort | while read -r f; do
    echo "SSH_PRIVATE_KEY_EXISTS(not hashed)  $f"
  done

  # ── LaunchAgents and LaunchDaemons ─────────────────────────────────────────
  echo ""
  echo "# LaunchAgents — user"
  hdir "$HOME/Library/LaunchAgents" "~/Library/LaunchAgents/" "*.plist"

  echo ""
  echo "# LaunchAgents — system"
  hdir "/Library/LaunchAgents" "/Library/LaunchAgents/" "*.plist"

  echo ""
  echo "# LaunchDaemons — system"
  hdir "/Library/LaunchDaemons" "/Library/LaunchDaemons/" "*.plist"

  # ── User Preferences ──────────────────────────────────────────────────────
  echo ""
  echo "# User preferences — ~/Library/Preferences/"
  find "$HOME/Library/Preferences" -maxdepth 1 -name "*.plist" -type f 2>/dev/null | sort | while read -r f; do
    h "$f" "~/Library/Preferences/$(basename "$f")"
  done

  # ── System Preferences ────────────────────────────────────────────────────
  echo ""
  echo "# System preferences — /Library/Preferences/"
  find /Library/Preferences -maxdepth 1 -name "*.plist" -type f 2>/dev/null | sort | while read -r f; do
    h "$f" "/Library/Preferences/$(basename "$f")"
  done

  # ── Little Snitch ─────────────────────────────────────────────────────────
  echo ""
  echo "# Little Snitch"
  h "/Applications/Little Snitch.app/Contents/Components/littlesnitch"
  h "/Applications/Little Snitch.app/Contents/Info.plist" "Apps/Little Snitch/Info.plist"

  # ── DuckDuckGo ────────────────────────────────────────────────────────────
  echo ""
  echo "# DuckDuckGo"
  h "/Applications/DuckDuckGo.app/Contents/MacOS/DuckDuckGo"
  h "/Applications/DuckDuckGo.app/Contents/Info.plist" "Apps/DuckDuckGo/Info.plist"

  # ── Claude Code ───────────────────────────────────────────────────────────
  echo ""
  echo "# Claude Code — global config (all settings + hooks)"
  CLAUDE_DIR="$HOME/.claude"
  find "$CLAUDE_DIR" -maxdepth 2 -type f \
    ! -path "*/cache/*" \
    ! -path "*/history*" \
    ! -path "*/sessions/*" \
    ! -path "*/shell-snapshots/*" \
    ! -path "*/paste-cache/*" \
    ! -path "*/tool-results/*" \
    ! -path "*/telemetry/*" \
    ! -path "*/stats-cache*" \
    ! -path "*/file-history/*" \
    ! -path "*/downloads/*" \
    2>/dev/null | sort | while read -r f; do
    h "$f" "${f/#$HOME/~}"
  done

  echo ""
  echo "# Claude Code — project memory (all projects)"
  find "$CLAUDE_DIR/projects" -maxdepth 4 -type f \
    ! -path "*/tool-results/*" \
    2>/dev/null | sort | while read -r f; do
    h "$f" "${f/#$HOME/~}"
  done

  echo ""
  echo "# Claude Code — binaries (all installed versions)"
  CLAUDE_VERSIONS="$HOME/.local/share/claude/versions"
  if [ -d "$CLAUDE_VERSIONS" ]; then
    for v in $(ls "$CLAUDE_VERSIONS" | sort); do
      f="$CLAUDE_VERSIONS/$v"
      [ -f "$f" ] && h "$f" "~/.local/share/claude/versions/$v"
    done
  fi

  # ── Security project — all files ──────────────────────────────────────────
  echo ""
  echo "# Security project — all scripts and docs"
  for f in *.sh *.py *.md *.pdf *.txt; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Security project — .claude files"
  find .claude -type f 2>/dev/null | sort | while read -r f; do
    echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Security project — memory files (all)"
  find memory -type f 2>/dev/null | sort | while read -r f; do
    echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Security project — scan summaries"
  for d in $(ls -d scan-*/ 2>/dev/null | sort); do
    for f in "${d}SCAN-SUMMARY.md" "${d}TRIAGE-REPORT.md" "${d}tcc-audit.txt"; do
      [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
    done
  done

  echo ""
  echo "# Security project — LS deny rules"
  find . -name "deny-rules-*.lsrules" 2>/dev/null | sort | while read -r f; do
    echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  echo ""
  echo "# Security project — latest LS model"
  LATEST_SCAN=$(ls -d scan-*/ 2>/dev/null | sort | tail -1)
  for f in "${LATEST_SCAN}file-hashes.txt" "${LATEST_SCAN}ls-model.json"; do
    [ -f "$f" ] && echo "$(shasum -a 256 "$f" | awk '{print $1}')  $f"
  done

  # ── DuckDuckGo preferences snapshot ───────────────────────────────────────
  echo ""
  echo "# DuckDuckGo preferences snapshot"
  DDG_ZOOM=$(defaults read com.duckduckgo.macos.browser "preferences.appearance.default-page-zoom" 2>/dev/null || echo "unset")
  DDG_SNAP="DDG_zoom=${DDG_ZOOM}"
  echo "$(echo -n "$DDG_SNAP" | shasum -a 256 | awk '{print $1}')  [DDG-prefs: $DDG_SNAP]"

  # ── L5 hash log ───────────────────────────────────────────────────────────
  echo ""
  echo "# L5 hash log"
  [ -f "l5-hash-log.txt" ] && echo "$(shasum -a 256 l5-hash-log.txt | awk '{print $1}')  l5-hash-log.txt"

} > "$MANIFEST"

LINES=$(wc -l < "$MANIFEST" | tr -d ' ')
HASHES=$(grep -c "^[a-f0-9]" "$MANIFEST" || true)
echo "Manifest: $MANIFEST ($LINES lines, $HASHES file hashes)"

# Stamp
if [ -x "$OTS" ]; then
  echo "Submitting to OpenTimestamps calendars..."
  "$OTS" stamp "$MANIFEST"
  echo "Proof: ${MANIFEST}.ots"
else
  echo "WARNING: ots not found at $OTS — skipping stamp (reinstall opentimestamps-client)"
fi

# Append to hash log
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $(shasum -a 256 "$MANIFEST" | awk '{print $1}') l5-manifest-${DATE}.txt [comprehensive]" >> "$SECURITY_DIR/l5-hash-log.txt"

# Commit
git add "l5-manifest-full-${DATE}.txt" l5-hash-log.txt
[ -f "l5-manifest-full-${DATE}.txt.ots" ] && git add "l5-manifest-full-${DATE}.txt.ots"
git commit -m "L5 comprehensive stamp ${DATE} — ${HASHES} file hashes timestamped"

echo ""
echo "=== Done. Upgrade proof in ~3 hours: ==="
echo "  $OTS upgrade ${MANIFEST}.ots"
echo "  git add ${MANIFEST}.ots && git commit -m 'L5 full upgrade ${DATE}'"
