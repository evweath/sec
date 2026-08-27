#!/bin/bash
# evw-dns-guard-setup.sh
#
# One-time install:
#   - evw-dns-guard.sh → runs every 5 min, re-pins DNS servers if any service drifts
#
# Must run as root: sudo bash ~/dev/security/evw-dns-guard-setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

GUARD_SRC="$SCRIPT_DIR/evw-dns-guard.sh"
GUARD_DST="/usr/local/bin/evw-dns-guard.sh"
GUARD_PLIST="/Library/LaunchDaemons/com.evw.dns-guard.plist"
GUARD_LABEL="com.evw.dns-guard"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root"
    exit 1
fi

echo "=== evw-dns-guard setup ==="
echo ""

echo "[1/4] Installing guard script..."
install -m 755 -o root -g wheel "$GUARD_SRC" "$GUARD_DST"
echo "      $GUARD_DST"

echo "[2/4] Writing LaunchDaemon plist..."
cat > "$GUARD_PLIST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.dns-guard</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/evw-dns-guard.sh</string>
    </array>

    <key>StartInterval</key>
    <integer>300</integer>

    <key>RunAtLoad</key>
    <true/>

    <key>UserName</key>
    <string>root</string>

    <key>StandardOutPath</key>
    <string>/private/var/log/evw-dns-guard.log</string>

    <key>StandardErrorPath</key>
    <string>/private/var/log/evw-dns-guard-err.log</string>
</dict>
</plist>
PLIST
chmod 644 "$GUARD_PLIST"
chown root:wheel "$GUARD_PLIST"
echo "      $GUARD_PLIST"

echo "[3/4] Loading daemon..."
launchctl unload "$GUARD_PLIST" 2>/dev/null || true
launchctl load -w "$GUARD_PLIST"

echo "[4/4] Verifying..."
sleep 2
launchctl print "system/$GUARD_LABEL" 2>/dev/null | grep -E '^\s+(state|pid) ' | head -4 || true

echo ""
echo "=== Done ==="
echo ""
echo "Guard: every 5 min → /private/var/log/evw-dns-guard.log"
echo "Live:  sudo tail -f /private/var/log/evw-dns-guard.log"
