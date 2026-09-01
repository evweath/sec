#!/bin/bash
# netdiag/deploy9.sh — alert terminal v3: escape-sequence resize, no Apple events.
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/deploy9.log) 2>&1
echo "=== deploy9.sh $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }
EVW_UID=501

install -m 755 -o root -g wheel /Users/evw/dev/security/scripts/evw-sentinel-alert-display.sh /usr/local/bin/evw-sentinel-alert-display.sh && echo "installed display script (self-resizing)"

cat > /Users/evw/Library/LaunchAgents/com.evw.sentinel-alert-term.plist << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.sentinel-alert-term</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/open</string>
        <string>-a</string>
        <string>Terminal</string>
        <string>/usr/local/bin/evw-sentinel-alert-display.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>StandardOutPath</key>
    <string>/Users/evw/Library/Logs/sentinel-alert-term-launchd.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/evw/Library/Logs/sentinel-alert-term-launchd.log</string>
</dict>
</plist>
PLIST_EOF
chown evw:staff /Users/evw/Library/LaunchAgents/com.evw.sentinel-alert-term.plist
chmod 644 /Users/evw/Library/LaunchAgents/com.evw.sentinel-alert-term.plist
echo "plist reverted to open -a Terminal (no Apple events)"

launchctl bootout "gui/$EVW_UID/com.evw.sentinel-alert-term" 2>/dev/null || true
launchctl bootstrap "gui/$EVW_UID" /Users/evw/Library/LaunchAgents/com.evw.sentinel-alert-term.plist \
  && echo "agent reloaded — new self-sizing terminal should open" || echo "agent load FAILED"
sleep 3
echo "── launchd log (expect clean — no -1743):"
tail -3 /Users/evw/Library/Logs/sentinel-alert-term-launchd.log 2>/dev/null || echo "  (clean)"
echo "── display log tail (new session header with legend):"
grep -A2 "Session start" /Users/evw/Library/Logs/mac-sentinel-alert-display.log 2>/dev/null | tail -4
echo "=== deploy9.sh done $(date) ==="
