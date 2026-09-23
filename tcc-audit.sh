#!/usr/bin/env bash
# TCC (privacy permissions) audit — screen capture, accessibility, input monitoring.
#
# Design: always run with sudo. TCC.db is FDA-protected even for root on modern
# macOS, so reads go through /usr/local/bin/evw-tcc-reader — a small signed
# helper that holds the Full Disk Access grant, scoped to exactly this fixed
# query (no SQL/path arguments). This keeps Terminal/iTerm FDA permanently
# revoked — granting a general interpreter FDA would be a far broader attack
# surface than this script needs. Falls back to direct sqlite3 for shells that
# already hold FDA.
#
# Usage: sudo bash ~/dev/security/tcc-audit.sh [scan-dir]
set -euo pipefail
umask 077   # root-written TCC-grant inventory must not land world-readable

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

[ "$(id -u)" = "0" ] || { echo "Run with sudo: sudo bash $0"; exit 1; }

# Locate the real user's home without relying on $HOME (which sudo may reset)
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo evw)}"
REAL_HOME=$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -n "$REAL_HOME" ] || REAL_HOME="/Users/$REAL_USER"

SECURITY_DIR="$REAL_HOME/dev/security"
DATE="$(date -u +%Y-%m-%d)"
SCAN_DIR="${1:-$SECURITY_DIR/scan-${DATE}}"
OUT="$SCAN_DIR/tcc-audit.txt"
mkdir -p "$SCAN_DIR"
rm -f "$OUT"   # break any pre-planted symlink before the root tee write below

SERVICES="'kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent','kTCCServiceCamera','kTCCServiceMicrophone'"
SQL="SELECT service,client,client_type,auth_value,last_modified,indirect_object_identifier FROM access WHERE service IN ($SERVICES) ORDER BY service,auth_value DESC;"

# Read rows via the FDA-scoped helper when present (same fixed query as $SQL);
# fall back to direct sqlite3 for shells that already hold FDA.
TCC_READER=/usr/local/bin/evw-tcc-reader
tcc_rows() {  # $1 = user|system
  local dbvar
  if [ -x "$TCC_READER" ] && "$TCC_READER" "$1" 2>/dev/null; then
    return 0
  fi
  dbvar=$([ "$1" = user ] && echo "$USER_TCC" || echo "$SYS_TCC")
  sqlite3 "$dbvar" "$SQL" 2>/dev/null
}

# auth_value: 0=denied 2=allowed 3=limited
decode_auth() {
  case "$1" in
    0) echo "DENIED" ;; 2) echo "ALLOWED" ;; 3) echo "LIMITED" ;; *) echo "val=$1" ;;
  esac
}

{
  echo "# TCC Permissions Audit"
  echo "# Date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Machine: $(scutil --get ComputerName 2>/dev/null || hostname)"
  echo "# User:    $REAL_USER (sudo — no Terminal FDA required)"
  echo ""

  # ── User TCC.db (root reads directly — no FDA needed) ────────────────────
  USER_TCC="$REAL_HOME/Library/Application Support/com.apple.TCC/TCC.db"
  echo "=== USER TCC.db ==="
  if [ -f "$USER_TCC" ]; then
    tcc_rows user | while IFS='|' read -r service client ctype auth mtime ioi; do
      status=$(decode_auth "$auth")
      echo "  [$status] $service → $client"
    done || true
    echo ""
    echo "  Raw (for diffing):"
    tcc_rows user | sed 's/^/  /' || true
  else
    echo "  Not found: $USER_TCC"
  fi

  echo ""
  echo "=== SYSTEM TCC.db ==="
  SYS_TCC="/Library/Application Support/com.apple.TCC/TCC.db"
  if [ -f "$SYS_TCC" ]; then
    tcc_rows system | while IFS='|' read -r service client ctype auth mtime ioi; do
      status=$(decode_auth "$auth")
      flag=""
      [ "$status" = "ALLOWED" ] && flag=" ←── GRANTED"
      echo "  [$status]$flag $service → $client"
    done || true
    echo ""
    echo "  Raw (for diffing):"
    tcc_rows system | sed 's/^/  /' || true
  else
    echo "  Not found: $SYS_TCC"
  fi

  echo ""
  echo "=== PRIVATE ENTITLEMENT BYPASSES (no TCC entry required) ==="
  echo "  These processes bypass TCC entirely via private entitlements:"
  echo "  replayd — com.apple.private.screencapturekit.noprompt (screen capture, no prompt, no TCC row)"
  echo "  ControlCenter — com.apple.private.screencapturekit.suppress-screen-indicator (hides orange dot)"
  echo "  Status: replayd LS deny rule ACTIVE, launchctl disabled, disabled.501.plist entry present"
  echo ""
  echo "  To check for active replayd recording:"
  echo "  pgrep replayd && lsof -p \$(pgrep replayd) | grep -iE 'mov|mp4|recording'"

  echo ""
  echo "=== DuckDuckGo ZOOM SETTING ==="
  ZOOM=$(defaults read com.duckduckgo.macos.browser "preferences.appearance.default-page-zoom" 2>/dev/null || echo "not set")
  echo "  preferences.appearance.default-page-zoom = $ZOOM"
  if [ "$ZOOM" != "1" ] && [ "$ZOOM" != "not set" ]; then
    echo "  *** WARNING: zoom is $ZOOM (not 1.0) — INCIDENT #17 indicator ***"
    echo "  Fix: defaults write com.duckduckgo.macos.browser preferences.appearance.default-page-zoom -string 1"
  else
    echo "  OK: zoom at 100%"
  fi

} | tee "$OUT"

echo ""
echo "Output: $OUT"
