#!/bin/bash
# Drift detection: compare current state against 2026-05-18 baseline + expected hardened state.
# Run periodically with sudo to catch "fake off" services or tampered binaries.

set -u

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

LOG="$(dirname "$0")/verify.log"
exec > >(tee -a "$LOG") 2>&1

echo "=========================================="
echo " VERIFY  $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================="
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root (sudo)." >&2
  exit 1
fi

section() { echo ""; echo "===== $* ====="; }

BASELINE_DIR=/Users/evw/dev/security/scan-2026-05-18
BASELINE_HASHES=$BASELINE_DIR/system-binary-hashes.txt
USER_NAME="evw"
USER_UID=$(id -u "$USER_NAME")

# ========== 1. Hash drift vs 2026-05-18 baseline ==========
section "1. /bin /sbin /usr/bin /usr/sbin /usr/libexec — hash diff vs baseline"
if [ ! -f "$BASELINE_HASHES" ]; then
  echo "ERROR: baseline not found at $BASELINE_HASHES"
else
  CURRENT=$(mktemp)
  collect_system_hashes() {
    find /bin /sbin /usr/bin /usr/sbin /usr/libexec -type f -print0 2>/dev/null \
      | xargs -0 shasum -a 256 2>/dev/null | sort
  }
  guard_run "shasum-drift" collect_system_hashes > "$CURRENT"
  BASELINE_SORTED=$(mktemp)
  sort "$BASELINE_HASHES" > "$BASELINE_SORTED"
  if diff -q "$BASELINE_SORTED" "$CURRENT" >/dev/null ; then
    echo "OK: $(wc -l < "$CURRENT" | tr -d ' ') binaries, 0 hash differences vs baseline"
  else
    ADDED=$(comm -13 "$BASELINE_SORTED" "$CURRENT" | wc -l | tr -d ' ')
    REMOVED=$(comm -23 "$BASELINE_SORTED" "$CURRENT" | wc -l | tr -d ' ')
    echo "DRIFT: $ADDED added/changed, $REMOVED removed/changed"
    echo "--- first 40 changed lines ---"
    diff "$BASELINE_SORTED" "$CURRENT" | head -40
  fi
  rm -f "$CURRENT" "$BASELINE_SORTED"
fi

# ========== 2. Listening sockets ==========
section "2. Listening TCP sockets (expect: empty)"
LSOF_TCP=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null)
if [ -z "$LSOF_TCP" ]; then
  echo "OK: no TCP listeners"
else
  echo "UNEXPECTED:"
  echo "$LSOF_TCP"
fi

section "2b. Listening UDP sockets (non-link-local)"
lsof -nP -iUDP 2>/dev/null | grep -v -E 'fe80:|127\.0\.0\.1' | head -30

# ========== 3. Expected-disabled services ==========
section "3. Services that should remain DISABLED"
EXPECTED_SYSTEM="com.openssh.sshd com.apple.screensharing com.apple.screensharing.agent com.apple.screensharing.menuextra com.apple.screensharing.MessagesAgent com.apple.RemoteDesktop.agent com.apple.RemoteDesktop.PrivilegeProxy com.apple.InternetSharing com.apple.AppleFileServer com.apple.smbd com.apple.netbiosd com.apple.AirPlayXPCHelper com.apple.mediasharingd"
DISABLED=$(launchctl print-disabled system 2>/dev/null)
FAIL=0
for label in $EXPECTED_SYSTEM ; do
  if echo "$DISABLED" | grep -q "\"$label\" => disabled" ; then
    printf "  OK     %s\n" "$label"
  else
    printf "  DRIFT  %s  (NOT disabled)\n" "$label"
    FAIL=$((FAIL+1))
  fi
done
[ "$FAIL" -eq 0 ] && echo "  (all expected services disabled)"

# ========== 4. Process audit: remote-access ==========
section "4. Process scan for remote-access daemons (expect: none)"
HITS=$(ps auxww | grep -i -E 'screensharingd|ARDAgent|/usr/sbin/sshd|teamviewer|anydesk|vnc|rustdesk|jumpdesktop|splashtop|chromeremote|logmein|nomachine|meshcentral' | grep -v grep)
if [ -z "$HITS" ]; then
  echo "OK: no remote-access daemons running"
else
  echo "UNEXPECTED:"
  echo "$HITS"
fi

# ========== 5. Firewall state ==========
section "5. Apple firewall state (expect: enabled, stealth on, block-all on)"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall

# ========== 6. Bluetooth state ==========
section "6. Bluetooth ControllerPowerState (expect: 0)"
guard_run "bluetooth-power-state" defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>&1

# ========== 7. AWDL state ==========
section "7. awdl0 interface (expect: down or no inet6 address)"
ifconfig awdl0 2>&1 | head -3

# ========== 8. System extensions (expect: only Little Snitch) ==========
section "8. System extensions (expect: only Little Snitch)"
systemextensionsctl list 2>&1 | head -20

# ========== 9. Config profiles (expect: none) ==========
section "9. Config profiles (expect: none)"
profiles list 2>&1 | head -10

# ========== 10. Persistence surface diff ==========
section "10. LaunchDaemons / LaunchAgents on /Library (expect: only Little Snitch + local.awdl-down)"
ls -la /Library/LaunchDaemons /Library/LaunchAgents 2>&1

section "10b. ~/Library/LaunchAgents (expect: empty)"
sudo -u "$USER_NAME" ls -la "/Users/$USER_NAME/Library/LaunchAgents" 2>&1

# ========== 11. cron + login hooks (expect: none) ==========
section "11. Cron + login hooks (expect: none)"
ls /var/at/jobs/ 2>&1
sudo -u "$USER_NAME" crontab -l 2>&1
defaults read /var/root/Library/Preferences/com.apple.loginwindow LoginHook 2>&1 || true
defaults read /Library/Preferences/com.apple.loginwindow LoginHook 2>&1 || true

# ========== 12. /etc/hosts (expect: default) ==========
section "12. /etc/hosts contents"
cat /etc/hosts

# ========== 13. TCC: ScreenCapture / Accessibility (expect: empty) ==========
section "13. TCC system DB: screen-capture/accessibility/input grants (expect: empty)"
sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, service, auth_value, datetime(last_modified,'unixepoch') FROM access WHERE service IN ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent') ORDER BY last_modified DESC;" 2>&1

section "13b. TCC user DB"
sudo -u "$USER_NAME" sqlite3 "/Users/$USER_NAME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, service, auth_value, datetime(last_modified,'unixepoch') FROM access WHERE service IN ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent') ORDER BY last_modified DESC;" 2>&1

echo ""
echo "=========================================="
echo " VERIFY COMPLETE  $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================="
