#!/bin/bash
# netdiag/install-studentd-guard.sh — install + start com.evw.studentd-guard.
# Kills studentd every 5 min. airportd is deliberately NOT targeted (Wi-Fi daemon).
# RUN:  sudo bash /Users/evw/dev/fix/netdiag/install-studentd-guard.sh
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/install-studentd-guard.log) 2>&1
echo "=== install-studentd-guard started $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

install -m 755 -o root -g wheel \
  /Users/evw/dev/security/evw-studentd-guard.sh /usr/local/bin/evw-studentd-guard.sh \
  && echo "installed /usr/local/bin/evw-studentd-guard.sh"

cat > /Library/LaunchDaemons/com.evw.studentd-guard.plist << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.studentd-guard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/evw-studentd-guard.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>root</string>
    <key>StandardOutPath</key>
    <string>/private/var/log/evw-studentd-guard.log</string>
    <key>StandardErrorPath</key>
    <string>/private/var/log/evw-studentd-guard-err.log</string>
</dict>
</plist>
PLIST_EOF
chown root:wheel /Library/LaunchDaemons/com.evw.studentd-guard.plist
chmod 644 /Library/LaunchDaemons/com.evw.studentd-guard.plist
echo "wrote /Library/LaunchDaemons/com.evw.studentd-guard.plist"

launchctl bootout system/com.evw.studentd-guard 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.evw.studentd-guard.plist \
  && echo "daemon loaded"
sleep 2
launchctl print system/com.evw.studentd-guard >/dev/null 2>&1 \
  && echo "verified: com.evw.studentd-guard running" \
  || echo "ERROR: daemon not running after bootstrap"
echo "=== install-studentd-guard done $(date) ==="
