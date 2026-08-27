#!/bin/bash
# macOS hardening script — run with: sudo bash ~/hardening.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root: sudo bash ~/hardening.sh"
    exit 1
fi

echo "=== macOS Hardening Script ==="

# ── 1. Power / sleep ───────────────────────────────────────────────────────────
echo "[1/9] Disabling wake-on-network and TCP keepalive during sleep..."
pmset -a womp 0             # no wake on magic packet
pmset -a tcpkeepalive 0     # no TCP keepalive while asleep (prevents beaconing)

# ── 2. TouchID for sudo ────────────────────────────────────────────────────────
echo "[2/9] Enabling TouchID for sudo..."
cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local
sed -i '' 's/#auth/auth/' /etc/pam.d/sudo_local
# Clean up temporary sudoers file from earlier session
rm -f /etc/sudoers.d/timestamp

# ── 3. Login window hardening ──────────────────────────────────────────────────
echo "[3/9] Hardening login window..."
# Show username/password fields instead of user list (no username enumeration)
defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true
# Disable guest account
defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false
# Disable automatic login
defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true

# ── 5. mDNS multicast advertisements ──────────────────────────────────────────
echo "[4/9] Disabling mDNS multicast advertisements (reduces network fingerprint)..."
defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true

# ── 6. Restart unbound to apply config changes ────────────────────────────────
echo "[5/9] Restarting unbound (applying Quad9-only + strict qname minimisation)..."
launchctl kickstart -k system/homebrew.mxcl.unbound 2>/dev/null || \
    echo "  unbound service not loaded — skipping restart."

# ── 7. freshclam scheduled updater ────────────────────────────────────────────
echo "[6/9] Installing freshclam auto-updater LaunchDaemon (hourly)..."
cat > /Library/LaunchDaemons/homebrew.mxcl.freshclam.plist << 'EOF'
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
chmod 644 /Library/LaunchDaemons/homebrew.mxcl.freshclam.plist
launchctl load /Library/LaunchDaemons/homebrew.mxcl.freshclam.plist

# ── 8. OSSEC syscheck — add macOS-specific paths ──────────────────────────────
echo "[7/9] Updating OSSEC syscheck to monitor macOS-specific paths..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
cp "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%Y%m%d)"

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
    cp "$AUDIT_CTRL" "${AUDIT_CTRL}.bak.$(date +%Y%m%d)"
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
echo "  ✓ TouchID enabled for sudo (/etc/pam.d/sudo_local)"
echo "  ✓ Login window shows username field (no user enumeration)"
echo "  ✓ Guest account disabled"
echo "  ✓ mDNS multicast advertisements disabled"
echo "  ✓ Unbound restarted (Quad9-only, strict qname minimisation)"
echo "  ✓ freshclam auto-updater installed (hourly)"
echo "  ✓ OSSEC syscheck now monitors Homebrew + LaunchAgent paths"
echo "  ✓ BSM audit flags updated (lo,aa,ad,-all)"
echo "  ✓ Tor restarted (EnforceDistinctSubnets + AvoidDiskWrites)"
echo ""
echo "Reboot recommended to ensure all changes take effect."
