#!/usr/bin/env bash
# l5-full-home.sh — comprehensive home + system integrity manifest with OTS Bitcoin timestamping
# Covers: all home directory files, system LaunchAgents/Daemons, security scripts, Claude config,
#         Python apps, preferences, SSH keys, shell configs, /usr/local/bin, /Library
# Excludes: browser caches, node_modules, .git objects, macOS system caches, logs, pyc, tmp/usb
# Run: bash ~/dev/security/l5-full-home.sh
# Requires: ots at /Users/evw/Library/Python/3.9/bin/ots

set -uo pipefail

OTS="/Users/evw/Library/Python/3.9/bin/ots"
SECURITY_DIR="$HOME/dev/security"
DATE="$(date -u +%Y-%m-%d)"
TS="$(date -u +%Y-%m-%dT%H%M%SZ)"
MANIFEST="$SECURITY_DIR/l5-full-home-${DATE}.txt"
LOG="$SECURITY_DIR/l5-full-home-${DATE}.log"

echo "=== L5 Full Home Hash — $TS ===" | tee "$LOG"
echo "Manifest: $MANIFEST" | tee -a "$LOG"

h() {
  local file="$1"
  local label="${2:-${file/#$HOME/~}}"
  if [ ! -e "$file" ]; then return 0; fi
  if [ ! -r "$file" ]; then
    printf "UNREADABLE(sudo-required)  %s\n" "$label"
    return 0
  fi
  local hash
  hash=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
  if [ -n "$hash" ]; then
    printf "%s  %s\n" "$hash" "$label"
  else
    printf "UNREADABLE  %s\n" "$label"
  fi
}

{
  echo "# L5 Full Home Integrity Manifest"
  echo "# Generated: $TS"
  echo "# Machine: $(scutil --get ComputerName 2>/dev/null || hostname)"
  echo "# OS: $(sw_vers -productVersion 2>/dev/null) build $(sw_vers -buildVersion 2>/dev/null)"
  echo "# Scope: home directory + system security files + LaunchAgents/Daemons + /usr/local"
  echo "# Exclusions: node_modules, .git objects, Library/Caches, Library/Logs, __pycache__,"
  echo "#             .pyc, .claude_home, tmp/usb, ms-playwright, Library/Mail, Library/Containers/*/Caches"
  echo ""

  # ── 1. SECURITY PROJECT ────────────────────────────────────────────────────
  echo "# == SECURITY PROJECT: ~/dev/security/ =="
  find "$HOME/dev/security" \
    -not -path '*/.git/*' \
    -not -path '*/memory/scans/*' \
    -type f 2>/dev/null | sort | while read -r f; do h "$f"; done

  echo ""
  echo "# == SECURITY DEPLOYED SCRIPTS: /usr/local/bin/ =="
  find /usr/local/bin -maxdepth 1 -name "evw-*" -type f 2>/dev/null | sort | while read -r f; do h "$f" "/usr/local/bin/$(basename "$f")"; done

  echo ""
  echo "# == SECURITY DAEMONS: /Library/LaunchDaemons/ =="
  find /Library/LaunchDaemons -maxdepth 1 -name "com.evw.*" -type f 2>/dev/null | sort | while read -r f; do h "$f" "/Library/LaunchDaemons/$(basename "$f")"; done
  h "/private/var/db/com.apple.xpc.launchd/disabled.501.plist"

  # ── 2. CLAUDE CONFIG ───────────────────────────────────────────────────────
  echo ""
  echo "# == CLAUDE CONFIG: ~/.claude/ =="
  find "$HOME/.claude" \
    -not -path '*/.git/*' \
    -not -name '*.csmem' \
    -type f 2>/dev/null | sort | while read -r f; do h "$f"; done

  echo ""
  echo "# == CLAUDE MEMORY (encrypted): ~/.claude/projects/*/memory/ =="
  find "$HOME/.claude" -name "*.csmem" -type f 2>/dev/null | sort | while read -r f; do h "$f"; done

  # ── 3. SYSTEM LAUNCHAGENTS / DAEMONS ──────────────────────────────────────
  echo ""
  echo "# == SYSTEM LAUNCHAGENTS: /Library/LaunchAgents/ =="
  find /Library/LaunchAgents -maxdepth 1 -type f 2>/dev/null | sort | while read -r f; do h "$f" "/Library/LaunchAgents/$(basename "$f")"; done

  echo ""
  echo "# == USER LAUNCHAGENTS: ~/Library/LaunchAgents/ =="
  find "$HOME/Library/LaunchAgents" -maxdepth 1 -type f 2>/dev/null | sort | while read -r f; do h "$f"; done

  echo ""
  echo "# == KEY SYSTEM LAUNCHAGENTS (security-relevant): /System/Library/LaunchAgents/ =="
  for svc in com.apple.replayd com.apple.remotemanagementd com.apple.RemoteManagement \
             com.apple.sharingd com.apple.identityservicesd com.apple.replicatord \
             com.apple.privatecloudcomputed com.apple.studentd; do
    f="/System/Library/LaunchAgents/${svc}.plist"
    [ -f "$f" ] && h "$f" "/System/Library/LaunchAgents/${svc}.plist"
  done

  echo ""
  echo "# == KEY SYSTEM LAUNCHDAEMONS (security-relevant): /System/Library/LaunchDaemons/ =="
  for svc in com.apple.remotemanagementd com.apple.bluetoothd com.apple.locationd \
             com.apple.alf com.apple.configd com.apple.opendirectoryd; do
    f="/System/Library/LaunchDaemons/${svc}.plist"
    [ -f "$f" ] && h "$f" "/System/Library/LaunchDaemons/${svc}.plist"
  done

  # ── 4. SYSTEM PREFERENCES ──────────────────────────────────────────────────
  echo ""
  echo "# == SYSTEM PREFERENCES: /Library/Preferences/ =="
  find /Library/Preferences -maxdepth 1 -name "*.plist" -type f 2>/dev/null | sort | while read -r f; do
    h "$f" "/Library/Preferences/$(basename "$f")"
  done

  echo ""
  echo "# == USER PREFERENCES: ~/Library/Preferences/ =="
  find "$HOME/Library/Preferences" -maxdepth 1 -name "*.plist" -type f 2>/dev/null | sort | while read -r f; do h "$f"; done

  echo ""
  echo "# == LITTLE SNITCH PREFERENCES =="
  find "$HOME/Library/Application Support/at.obdev.LittleSnitch" -type f 2>/dev/null | sort | while read -r f; do h "$f"; done

  # ── 5. SHELL CONFIG / DOTFILES ─────────────────────────────────────────────
  echo ""
  echo "# == SHELL CONFIG / DOTFILES =="
  for f in ~/.zshrc ~/.zshenv ~/.zprofile ~/.bash_profile ~/.bashrc ~/.profile \
            ~/.gitconfig ~/.gitignore_global ~/.ssh/config ~/.ssh/known_hosts \
            ~/.ssh/authorized_keys /etc/hosts /etc/shells /etc/zshrc /etc/zshenv \
            /etc/pam.d/sudo /etc/sudoers; do
    h "$f"
  done
  # SSH keys (public only — private key hash is fine for integrity)
  find ~/.ssh -maxdepth 1 -name "*.pub" -type f 2>/dev/null | sort | while read -r f; do h "$f"; done
  find ~/.ssh -maxdepth 1 -name "id_*" -not -name "*.pub" -type f 2>/dev/null | sort | while read -r f; do
    printf "SSH_PRIVATE_KEY_EXISTS(not hashed)  %s\n" "$f"
  done

  # ── 6. SYSTEM BINARIES ─────────────────────────────────────────────────────
  echo ""
  echo "# == SYSTEM BINARIES =="
  for f in /sbin/launchd /usr/libexec/cfprefsd /usr/libexec/nsurlsessiond \
            /usr/libexec/replayd /usr/libexec/remotemanagementd \
            /System/Library/CoreServices/RemoteManagementAgent \
            /usr/bin/ssh /usr/sbin/sshd /bin/bash /bin/zsh /bin/launchctl \
            /usr/bin/python3 /usr/bin/curl /usr/bin/openssl /usr/bin/codesign \
            /usr/bin/security /usr/bin/spctl /usr/bin/defaults /usr/bin/plutil \
            /usr/bin/sqlite3 /usr/bin/osascript /usr/bin/chflags /usr/bin/lsof \
            /usr/bin/shasum /usr/bin/csrutil /usr/bin/dscl; do
    h "$f"
  done

  # ── 7. PYTHON INSTALLATIONS ────────────────────────────────────────────────
  echo ""
  echo "# == PYTHON: pyenv + system =="
  find "$HOME/.pyenv/versions" -name "python3*" -type f 2>/dev/null | sort | while read -r f; do h "$f"; done
  h "/usr/bin/python3"
  h "$(which python3 2>/dev/null)"
  # All .py files in home (excluding caches and venvs)
  echo ""
  echo "# == PYTHON SCRIPTS: all .py files in home =="
  find ~ \
    -not -path '*/\.git/*' \
    -not -path '*/node_modules/*' \
    -not -path '*/Library/Caches/*' \
    -not -path '*/__pycache__/*' \
    -not -path '*/\.claude_home/*' \
    -not -path '*/tmp/usb/*' \
    -not -path '*/site-packages/*' \
    -not -name '*.pyc' \
    -name "*.py" -type f 2>/dev/null | sort | while read -r f; do h "$f"; done

  # ── 8. APPLICATIONS ────────────────────────────────────────────────────────
  echo ""
  echo "# == APPLICATIONS: /Applications/ =="
  find /Applications -maxdepth 2 -name "*.app" -type d 2>/dev/null | sort | while read -r app; do
    appname=$(basename "${app%.app}")
    # Binary
    binary=$(find "$app/Contents/MacOS/" -maxdepth 1 -type f 2>/dev/null | head -1)
    [ -n "$binary" ] && h "$binary" "Apps/$appname/MacOS/$(basename "$binary")"
    # Info.plist
    [ -f "$app/Contents/Info.plist" ] && h "$app/Contents/Info.plist" "Apps/$appname/Info.plist"
    # CodeResources (code signature manifest)
    [ -f "$app/Contents/_CodeSignature/CodeResources" ] && h "$app/Contents/_CodeSignature/CodeResources" "Apps/$appname/_CodeSignature/CodeResources"
  done

  # ── 9. HOME DIRECTORY — ALL OTHER FILES ───────────────────────────────────
  echo ""
  echo "# == HOME DIRECTORY: all remaining files =="
  echo "# (excludes: node_modules, .git objects, Library/Caches, Library/Logs,"
  echo "#  __pycache__, .pyc, .claude_home, tmp/usb, ms-playwright, Library/Mail,"
  echo "#  Library/Containers/*/Caches, site-packages, .py files already covered above,"
  echo "#  dev/security already covered above)"
  find ~ \
    -not -path '*/.git/*' \
    -not -path '*/node_modules/*' \
    -not -path '*/Library/Caches/*' \
    -not -path '*/Library/Logs/*' \
    -not -path '*/.Trash/*' \
    -not -path '*/.cache/*' \
    -not -path '*/__pycache__/*' \
    -not -path '*/.claude_home/*' \
    -not -path '*/tmp/usb/*' \
    -not -path '*/Library/Containers/*/Caches/*' \
    -not -path '*/Library/Containers/*/Cache/*' \
    -not -path '*/ms-playwright/*' \
    -not -path '*/Library/Mail/*' \
    -not -path '*/site-packages/*' \
    -not -path '*/dev/security/*' \
    -not -path '*/.claude/*' \
    -not -path '*/Library/Preferences/*' \
    -not -path '*/Library/Application Support/at.obdev.LittleSnitch/*' \
    -not -name '*.pyc' \
    -type f 2>/dev/null | sort | while read -r f; do h "$f"; done

} > "$MANIFEST" 2>>"$LOG"

FILE_COUNT=$(grep -c "^[a-f0-9]\{64\}" "$MANIFEST" 2>/dev/null || echo 0)
UNREADABLE=$(grep -c "^UNREADABLE" "$MANIFEST" 2>/dev/null || echo 0)
echo "" | tee -a "$LOG"
echo "Files hashed:    $FILE_COUNT" | tee -a "$LOG"
echo "Unreadable:      $UNREADABLE" | tee -a "$LOG"
echo "Manifest:        $MANIFEST" | tee -a "$LOG"

# Hash the manifest itself
MANIFEST_HASH=$(shasum -a 256 "$MANIFEST" | awk '{print $1}')
echo "Manifest SHA-256: $MANIFEST_HASH" | tee -a "$LOG"

# Append to l5-hash-log.txt
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $MANIFEST_HASH l5-full-home-${DATE}" >> "$SECURITY_DIR/l5-hash-log.txt"

# Submit to OpenTimestamps
echo "" | tee -a "$LOG"
if [ -x "$OTS" ]; then
  echo "Submitting to OpenTimestamps calendars..." | tee -a "$LOG"
  "$OTS" stamp "$MANIFEST" 2>&1 | tee -a "$LOG"
else
  echo "WARNING: ots not found at $OTS — skipping stamp (reinstall opentimestamps-client)" | tee -a "$LOG"
fi

if [ -f "${MANIFEST}.ots" ]; then
  echo "" | tee -a "$LOG"
  echo "OTS proof written: ${MANIFEST}.ots" | tee -a "$LOG"
  echo "Bitcoin confirmation pending (~1 hour). Verify later with:" | tee -a "$LOG"
  echo "  $OTS verify ${MANIFEST}.ots" | tee -a "$LOG"
else
  echo "OTS stamp may have failed — check $LOG" | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
echo "=== Done: $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a "$LOG"
