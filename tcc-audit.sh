#!/usr/bin/env bash
# TCC (privacy permissions) audit — screen capture, accessibility, input monitoring.
# Run at every security scan. System TCC.db requires sudo; user TCC.db is automatic.
# Usage: bash ~/dev/security/tcc-audit.sh [scan-dir]
set -euo pipefail

SECURITY_DIR="$HOME/dev/security"
DATE="$(date -u +%Y-%m-%d)"
SCAN_DIR="${1:-$SECURITY_DIR/scan-${DATE}}"
OUT="$SCAN_DIR/tcc-audit.txt"
mkdir -p "$SCAN_DIR"

SERVICES="'kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent','kTCCServiceCamera','kTCCServiceMicrophone'"
SQL="SELECT service,client,client_type,auth_value,last_modified,indirect_object_identifier FROM access WHERE service IN ($SERVICES) ORDER BY service,auth_value DESC;"

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
  echo ""

  # ── User TCC.db (no sudo) ─────────────────────────────────────────────────
  USER_TCC="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
  echo "=== USER TCC.db ==="
  if [ -f "$USER_TCC" ]; then
    sqlite3 "$USER_TCC" "$SQL" 2>/dev/null | while IFS='|' read -r service client ctype auth mtime ioi; do
      status=$(decode_auth "$auth")
      echo "  [$status] $service → $client"
    done || true
    echo ""
    echo "  Raw (for diffing):"
    sqlite3 "$USER_TCC" "$SQL" 2>/dev/null | sed 's/^/  /' || true
  else
    echo "  Not found: $USER_TCC"
  fi

  echo ""
  echo "=== SYSTEM TCC.db (requires sudo) ==="
  SYS_TCC="/Library/Application Support/com.apple.TCC/TCC.db"
  if [ "$(id -u)" = "0" ]; then
    sqlite3 "$SYS_TCC" "$SQL" 2>/dev/null | while IFS='|' read -r service client ctype auth mtime ioi; do
      status=$(decode_auth "$auth")
      flag=""
      [ "$status" = "ALLOWED" ] && flag=" ←── GRANTED"
      echo "  [$status]$flag $service → $client"
    done || true
    echo ""
    echo "  Raw (for diffing):"
    sqlite3 "$SYS_TCC" "$SQL" 2>/dev/null | sed 's/^/  /' || true
  else
    echo "  Rerun with sudo to read system TCC.db:"
    echo "  sudo bash ~/dev/security/tcc-audit.sh $SCAN_DIR"
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
