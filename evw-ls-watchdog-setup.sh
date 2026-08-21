#!/bin/bash
# evw-ls-watchdog-setup.sh
#
# One-time install:
#   - evw-ls-watchdog.sh       → runs every 10 min, enforces LS rule hygiene
#   - evw-ls-watchdog-monitor.sh → runs every 5 min, alerts if watchdog goes silent
#
# Must run as root: sudo bash ~/dev/security/evw-ls-watchdog-setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

WATCHDOG_SRC="$SCRIPT_DIR/evw-ls-watchdog.sh"
WATCHDOG_DST="/usr/local/bin/evw-ls-watchdog.sh"
WATCHDOG_PLIST="/Library/LaunchDaemons/com.evw.ls-watchdog.plist"
WATCHDOG_LABEL="com.evw.ls-watchdog"

MONITOR_SRC="$SCRIPT_DIR/evw-ls-watchdog-monitor.sh"
MONITOR_DST="/usr/local/bin/evw-ls-watchdog-monitor.sh"
MONITOR_PLIST="/Library/LaunchDaemons/com.evw.ls-watchdog-monitor.plist"
MONITOR_LABEL="com.evw.ls-watchdog-monitor"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root"
    exit 1
fi

echo "=== evw-ls-watchdog setup ==="
echo ""

echo "[1/6] Installing watchdog script..."
install -d -m 755 -o root -g wheel /usr/local/bin
install -m 755 -o root -g wheel "$WATCHDOG_SRC" "$WATCHDOG_DST"
echo "      $WATCHDOG_DST"

echo "[2/6] Writing watchdog LaunchDaemon plist..."
cat > "$WATCHDOG_PLIST" << 'PLIST'
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
chmod 644 "$WATCHDOG_PLIST"
chown root:wheel "$WATCHDOG_PLIST"
echo "      $WATCHDOG_PLIST"

echo "[3/6] Installing monitor script..."
install -m 755 -o root -g wheel "$MONITOR_SRC" "$MONITOR_DST"
echo "      $MONITOR_DST"

echo "[4/6] Writing monitor LaunchDaemon plist..."
cat > "$MONITOR_PLIST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.ls-watchdog-monitor</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/evw-ls-watchdog-monitor.sh</string>
    </array>

    <key>StartInterval</key>
    <integer>300</integer>

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
chmod 644 "$MONITOR_PLIST"
chown root:wheel "$MONITOR_PLIST"
echo "      $MONITOR_PLIST"

echo "[5/6] Loading daemons..."
launchctl unload "$WATCHDOG_PLIST" 2>/dev/null || true
launchctl load -w "$WATCHDOG_PLIST"
launchctl unload "$MONITOR_PLIST" 2>/dev/null || true
launchctl load -w "$MONITOR_PLIST"

echo "[6/6] Verifying..."
sleep 2
echo "  watchdog:"
launchctl print "system/$WATCHDOG_LABEL" 2>/dev/null | grep -E '^\s+(state|pid) ' | head -4 || true
echo "  monitor:"
launchctl print "system/$MONITOR_LABEL" 2>/dev/null | grep -E '^\s+(state|pid) ' | head -4 || true

echo ""
echo "=== Done ==="
echo ""
echo "Watchdog:  every 10 min → /private/var/log/evw-ls-watchdog.log"
echo "Monitor:   every  5 min → alert + log if watchdog goes silent for >15 min"
echo ""
echo "Monitor live: sudo tail -f /private/var/log/evw-ls-watchdog.log"
