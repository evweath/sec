#!/bin/bash
# evw-ls-watchdog-setup.sh
#
# One-time install: deploys evw-ls-watchdog.sh as a root LaunchDaemon
# that runs every 10 minutes to enforce Little Snitch rule hygiene.
#
# Must run as root: sudo bash ~/dev/security/evw-ls-watchdog-setup.sh

set -euo pipefail

SCRIPT_SRC="$(cd "$(dirname "$0")" && pwd)/evw-ls-watchdog.sh"
SCRIPT_DST="/usr/local/bin/evw-ls-watchdog.sh"
PLIST_DST="/Library/LaunchDaemons/com.evw.ls-watchdog.plist"
LABEL="com.evw.ls-watchdog"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root"
    exit 1
fi

echo "=== evw-ls-watchdog setup ==="
echo ""

echo "[1/4] Installing watchdog script..."
install -m 755 -o root -g wheel "$SCRIPT_SRC" "$SCRIPT_DST"
echo "      $SCRIPT_DST"

echo "[2/4] Writing LaunchDaemon plist..."
cat > "$PLIST_DST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.ls-watchdog</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/evw-ls-watchdog.sh</string>
    </array>

    <key>StartInterval</key>
    <integer>600</integer>

    <key>RunAtLoad</key>
    <true/>

    <key>UserName</key>
    <string>root</string>

    <key>StandardOutPath</key>
    <string>/private/var/log/evw-ls-watchdog.log</string>

    <key>StandardErrorPath</key>
    <string>/private/var/log/evw-ls-watchdog-err.log</string>
</dict>
</plist>
PLIST
chmod 644 "$PLIST_DST"
chown root:wheel "$PLIST_DST"
echo "      $PLIST_DST"

echo "[3/4] Loading daemon..."
# Unload first in case an old version is running
launchctl unload "$PLIST_DST" 2>/dev/null || true
launchctl load -w "$PLIST_DST"

echo "[4/4] Verifying..."
sleep 2
STATE=$(launchctl print "system/$LABEL" 2>/dev/null | grep -E 'state|pid' | head -4 || true)
echo "$STATE"

echo ""
echo "=== Done ==="
echo ""
echo "Watchdog runs every 10 minutes."
echo "Log: /private/var/log/evw-ls-watchdog.log"
echo "Errors: /private/var/log/evw-ls-watchdog-err.log"
echo ""
echo "Monitor live: sudo tail -f /private/var/log/evw-ls-watchdog.log"
