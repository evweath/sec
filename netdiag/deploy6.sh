#!/bin/bash
# netdiag/deploy6.sh — install + start com.evw.ls-hygiene-guard (5-min LS hygiene).
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/deploy6.log) 2>&1
echo "=== deploy6.sh $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

install -m 755 -o root -g wheel /Users/evw/dev/security/scripts/ls-hygiene.py /usr/local/bin/ls-hygiene.py && echo "installed ls-hygiene.py"
install -m 755 -o root -g wheel /Users/evw/dev/security/scripts/evw-ls-hygiene-guard.sh /usr/local/bin/evw-ls-hygiene-guard.sh && echo "installed guard"

cat > /Library/LaunchDaemons/com.evw.ls-hygiene-guard.plist << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.ls-hygiene-guard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/evw-ls-hygiene-guard.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>root</string>
    <key>StandardOutPath</key>
    <string>/private/var/log/evw-ls-hygiene-guard.log</string>
    <key>StandardErrorPath</key>
    <string>/private/var/log/evw-ls-hygiene-guard-err.log</string>
</dict>
</plist>
PLIST_EOF
chown root:wheel /Library/LaunchDaemons/com.evw.ls-hygiene-guard.plist
chmod 644 /Library/LaunchDaemons/com.evw.ls-hygiene-guard.plist

launchctl bootout system/com.evw.ls-hygiene-guard 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.evw.ls-hygiene-guard.plist && echo "daemon loaded"
sleep 6
pgrep -f "evw-ls-hygiene-guard.sh" >/dev/null && echo "verified: running" || echo "ERROR: not running"
echo "── first log lines:"
tail -3 /private/var/log/evw-ls-hygiene-guard.log 2>/dev/null
echo "=== deploy6.sh done $(date) ==="
