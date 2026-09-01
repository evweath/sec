#!/bin/bash
# netdiag/deploy7.sh — sentinel alert-terminal stack: install, agent, restart, verify.
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/deploy7.log) 2>&1
echo "=== deploy7.sh $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

EVW_UID=501

install -m 755 -o root -g wheel /Users/evw/dev/security/scripts/mac-sentinel.py /usr/local/lib/mac-sentinel/mac-sentinel.py && echo "installed mac-sentinel.py"
install -m 755 -o root -g wheel /Users/evw/dev/security/scripts/evw-sentinel-alert-display.sh /usr/local/bin/evw-sentinel-alert-display.sh && echo "installed display script"

# ── per-user LaunchAgent: open the alert terminal at every login ─────────────
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
echo "wrote com.evw.sentinel-alert-term.plist"

launchctl bootout "gui/$EVW_UID/com.evw.sentinel-alert-term" 2>/dev/null || true
launchctl bootstrap "gui/$EVW_UID" /Users/evw/Library/LaunchAgents/com.evw.sentinel-alert-term.plist \
  && echo "agent loaded (alert Terminal should open now)" || echo "agent load FAILED"

# ── restart the sentinel with the feed-enabled code ──────────────────────────
launchctl kickstart -k system/com.evw.mac-sentinel && echo "mac-sentinel restarted"
sleep 4
pgrep -f "mac-sentinel/mac-sentinel.py" >/dev/null && echo "verified: sentinel running" || echo "ERROR: sentinel not running"

# ── verify the display pipeline with one synthetic alert through the feed ────
/usr/bin/python3 - << 'PYEOF'
import json, time
feed = "/Users/evw/Library/Logs/mac-sentinel-alert-feed.log"
entry = {"ts_human": time.strftime("%A, %B %d, %Y %I:%M:%S %p ") + time.tzname[0],
         "severity": "INFO", "data": {"event": "DISPLAY-PIPELINE-TEST",
         "note": "synthetic entry verifying feed -> terminal -> display log"}}
open(feed, "a").write(json.dumps(entry) + "\n")
print("test entry appended to feed")
PYEOF
chmod 644 /Users/evw/Library/Logs/mac-sentinel-alert-feed.log 2>/dev/null
sleep 3
echo "── display log content (should show header + numbered test entry):"
tail -8 /Users/evw/Library/Logs/mac-sentinel-alert-display.log 2>/dev/null || echo "  (display log not created yet — terminal may still be opening)"

# ── re-baseline config-sentinel (new user agent plist) ───────────────────────
sudo -u evw HOME=/Users/evw /bin/bash /Users/evw/dev/security/scripts/config-sentinel.sh --baseline 2>&1 | tail -1

echo "=== deploy7.sh done $(date) ==="
