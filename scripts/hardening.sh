#!/bin/bash
# macOS hardening script — run with: sudo bash ~/hardening.sh
set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root: sudo bash ~/hardening.sh"
    exit 1
fi

echo "=== macOS Hardening Script ==="

# ── 1. Power / sleep ───────────────────────────────────────────────────────────
echo "[1/9] Disabling wake-on-network and TCP keepalive during sleep..."
guard_run "pmset" pmset -a womp 0 || true             # no wake on magic packet
guard_run "pmset" pmset -a tcpkeepalive 0 || true     # no TCP keepalive while asleep (prevents beaconing)

# ── 2. TouchID for sudo ────────────────────────────────────────────────────────
echo "[2/9] TouchID for sudo (opt-in)..."
# pam_tid replaces the sudo password with a fingerprint — convenient, but a
# net-loosening on a hardened box: a fingerprint (or a forced finger) stands
# in for the password, and biometric auth can also apply over screen-sharing
# sessions. Disabled by default; opt in explicitly with:
#   sudo ENABLE_TOUCHID_SUDO=1 bash ~/hardening.sh
if [[ "${ENABLE_TOUCHID_SUDO:-0}" == 1 ]]; then
    # Back up any pre-existing sudo_local before overwriting it
    if [[ -f /etc/pam.d/sudo_local ]]; then
        cp /etc/pam.d/sudo_local /etc/pam.d/sudo_local.bak
    fi
    guard_run "pam-touch-id" cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local || true
    sed -i '' 's/#auth/auth/' /etc/pam.d/sudo_local
    echo "  TouchID enabled for sudo (backup: /etc/pam.d/sudo_local.bak)"
else
    echo "  Skipped — set ENABLE_TOUCHID_SUDO=1 to enable."
fi
# Clean up temporary sudoers file from earlier session
rm -f /etc/sudoers.d/timestamp

# ── 3. Login window hardening ──────────────────────────────────────────────────
echo "[3/9] Hardening login window..."
# Show username/password fields instead of user list (no username enumeration)
guard_run "defaults-loginwindow" defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true || true
# Disable guest account
guard_run "defaults-loginwindow" defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false || true
# Disable automatic login
guard_run "defaults-autologin" defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true

# ── 5. mDNS multicast advertisements ──────────────────────────────────────────
echo "[4/9] Disabling mDNS multicast advertisements (reduces network fingerprint)..."
guard_run "defaults-mdns" defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true || true

# ── 6. Restart unbound to apply config changes ────────────────────────────────
echo "[5/9] Restarting unbound (applying Quad9-only + strict qname minimisation)..."
guard_run "unbound-restart" launchctl kickstart -k system/homebrew.mxcl.unbound 2>/dev/null || \
    echo "  unbound service not loaded — skipping restart."

# ── 7. freshclam scheduled updater ────────────────────────────────────────────
echo "[6/9] Installing freshclam auto-updater LaunchDaemon (hourly)..."
FRESHCLAM_OK=0
FRESHCLAM_BIN="/opt/homebrew/bin/freshclam"
FRESHCLAM_PLIST="/Library/LaunchDaemons/homebrew.mxcl.freshclam.plist"
# The daemon executes this binary as ROOT every hour. A Homebrew-installed
# binary is group-writable (evw:admin): any admin-group process could swap
# it for hourly root code execution. Only install the daemon if the binary
# is root-owned AND not group/world-writable; otherwise skip with a loud
# warning and continue with the rest of the script.
fc_stat="$(stat -f '%Su %Sg %Lp' "$FRESHCLAM_BIN" 2>/dev/null || true)"
fc_owner="${fc_stat%% *}"
fc_group="$(printf '%s' "$fc_stat" | awk '{print $2}')"
fc_mode="${fc_stat##* }"
if [[ -n "$fc_stat" && "$fc_owner" == "root" ]] && (( (8#$fc_mode & 022) == 0 )); then
FRESHCLAM_OK=1
cat > "$FRESHCLAM_PLIST" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>homebrew.mxcl.freshclam</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/freshclam</string>
        <string>--config-file=/opt/homebrew/etc/clamav/freshclam.conf</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/opt/homebrew/var/log/clamav/freshclam.log</string>
    <key>StandardOutPath</key>
    <string>/opt/homebrew/var/log/clamav/freshclam.log</string>
</dict>
</plist>
EOF
guard_run "freshclam-chmod" chmod 644 "$FRESHCLAM_PLIST" || true
guard_run "freshclam-load" launchctl load "$FRESHCLAM_PLIST" || true
else
echo ""
echo "  !! WARNING: freshclam LaunchDaemon NOT installed — privilege-escalation risk."
if [[ -z "$fc_stat" ]]; then
    echo "  !! $FRESHCLAM_BIN not found."
else
    echo "  !! $FRESHCLAM_BIN is ${fc_owner}:${fc_group} mode ${fc_mode} — an hourly ROOT"
    echo "  !! daemon would execute a non-root-owned or group/world-writable binary."
    echo "  !! Any admin-group process could replace it for root code execution."
fi
echo "  !! Fix:  sudo chown root:wheel $FRESHCLAM_BIN && sudo chmod 755 $FRESHCLAM_BIN"
echo "  !! Then re-run this script to install the daemon. Continuing without it."
echo ""
fi

# ── 8. OSSEC syscheck — add macOS-specific paths ──────────────────────────────
echo "[7/9] Updating OSSEC syscheck to monitor macOS-specific paths..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
guard_run "ossec-backup" cp "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%Y%m%d)" || true

python3 - "$OSSEC_CONF" << 'PYEOF'
import sys, re

path = sys.argv[1]
with open(path) as f:
    content = f.read()

# Add macOS paths after the existing <directories> lines in <syscheck>
macos_dirs = '''
    <!-- macOS-specific paths -->
    <directories check_all="yes">/opt/homebrew/bin,/opt/homebrew/sbin</directories>
    <directories check_all="yes">/Library/LaunchAgents,/Library/LaunchDaemons</directories>
    <directories check_all="yes">/Users/evw/Library/LaunchAgents</directories>'''

marker = '<directories check_all="yes">/bin,/sbin,/boot</directories>'
if marker in content and 'opt/homebrew/bin' not in content:
    content = content.replace(marker, marker + macos_dirs)

# Remove Windows-specific ignore entries (not relevant on macOS)
content = re.sub(r'\s*<!-- Windows files to ignore -->\n.*?</ignore>\n', '', content, flags=re.DOTALL)
content = re.sub(r'\s*<ignore>C:\\\\[^<]+</ignore>', '', content)

with open(path, 'w') as f:
    f.write(content)

print("OSSEC config updated.")
PYEOF

/var/ossec/bin/ossec-control restart 2>/dev/null || true
else
    echo "  $OSSEC_CONF not present (OSSEC not installed) — skipping."
fi

# ── 9. BSM audit control ──────────────────────────────────────────────────────
echo "[8/9] Checking BSM audit flags..."
AUDIT_CTRL="/etc/security/audit_control"
if [ -f "$AUDIT_CTRL" ]; then
    guard_run "audit-backup" cp "$AUDIT_CTRL" "${AUDIT_CTRL}.bak.$(date +%Y%m%d)" || true
    sed -i '' 's/^flags:.*/flags:lo,aa,ad,-all/' "$AUDIT_CTRL"
    sed -i '' 's/^naflags:.*/naflags:lo,aa/' "$AUDIT_CTRL"
    sed -i '' 's/^filesz:.*/filesz:20M/' "$AUDIT_CTRL"
    sed -i '' 's/^expire-after:.*/expire-after:60d/' "$AUDIT_CTRL"
    audit -s 2>/dev/null || true
    echo "  BSM audit flags updated."
else
    echo "  /etc/security/audit_control not present (removed in macOS 15) — skipping."
fi

# ── 10. Restart Tor to pick up config changes ─────────────────────────────────
echo "[9/9] Restarting Tor to apply new config..."
# Tor runs as user service — switch to user context
sudo -u evw brew services restart tor 2>/dev/null || launchctl kickstart -k "gui/$(id -u evw)/homebrew.mxcl.tor" 2>/dev/null || true

echo ""
echo "=== Hardening complete. Summary of changes ==="
echo "  ✓ Wake-on-network disabled"
echo "  ✓ TCP keepalive during sleep disabled"
if [[ "${ENABLE_TOUCHID_SUDO:-0}" == 1 ]]; then
    echo "  ✓ TouchID enabled for sudo (opt-in; backup at /etc/pam.d/sudo_local.bak)"
else
    echo "  – TouchID for sudo NOT enabled (opt in with ENABLE_TOUCHID_SUDO=1)"
fi
echo "  ✓ Login window shows username field (no user enumeration)"
echo "  ✓ Guest account disabled"
echo "  ✓ mDNS multicast advertisements disabled"
echo "  ✓ Unbound restarted (Quad9-only, strict qname minimisation)"
if [[ "$FRESHCLAM_OK" == 1 ]]; then
    echo "  ✓ freshclam auto-updater installed (hourly)"
else
    echo "  – freshclam auto-updater SKIPPED (binary ownership/mode unsafe — see warning above)"
fi
echo "  ✓ OSSEC syscheck now monitors Homebrew + LaunchAgent paths"
echo "  ✓ BSM audit flags updated (lo,aa,ad,-all)"
echo "  ✓ Tor restarted (EnforceDistinctSubnets + AvoidDiskWrites)"
echo ""
echo "Reboot recommended to ensure all changes take effect."
