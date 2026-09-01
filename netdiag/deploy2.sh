#!/bin/bash
# netdiag/deploy2.sh — root step: deploy ip_intel + file-vault daemon.
#   1. ip_intel.py + patched mac-sentinel.py -> /usr/local/lib/mac-sentinel/
#   2. evw-file-vault.py -> /usr/local/bin/  (+ vault-restore.sh)
#   3. com.evw.file-vault LaunchDaemon installed + started
#   4. mac-sentinel restarted (picks up ip_intel import)
# RUN:  sudo bash /Users/evw/dev/fix/netdiag/deploy2.sh
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/deploy2.log) 2>&1
echo "=== deploy2.sh started $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

S=/Users/evw/dev/security/scripts

install -m 755 -o root -g wheel "$S/mac-sentinel.py"  /usr/local/lib/mac-sentinel/mac-sentinel.py && echo "installed mac-sentinel.py"
install -m 644 -o root -g wheel "$S/ip_intel.py"      /usr/local/lib/mac-sentinel/ip_intel.py      && echo "installed ip_intel.py"
install -m 755 -o root -g wheel "$S/evw-file-vault.py" /usr/local/bin/evw-file-vault.py            && echo "installed evw-file-vault.py"
install -m 755 -o root -g wheel "$S/vault-restore.sh"  /usr/local/bin/vault-restore.sh             && echo "installed vault-restore.sh"

cat > /Library/LaunchDaemons/com.evw.file-vault.plist << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.file-vault</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/usr/local/bin/evw-file-vault.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>UserName</key>
    <string>root</string>
    <key>StandardOutPath</key>
    <string>/var/log/mac-sentinel/file-vault-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/mac-sentinel/file-vault-daemon.log</string>
</dict>
</plist>
PLIST_EOF
chown root:wheel /Library/LaunchDaemons/com.evw.file-vault.plist
chmod 644 /Library/LaunchDaemons/com.evw.file-vault.plist
echo "wrote com.evw.file-vault.plist"

launchctl bootout system/com.evw.file-vault 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.evw.file-vault.plist && echo "file-vault daemon loaded"

launchctl kickstart -k system/com.evw.mac-sentinel && echo "mac-sentinel restarted"

sleep 4
pgrep -f "evw-file-vault.py" >/dev/null && echo "verified: file-vault running" || echo "ERROR: file-vault NOT running"
pgrep -f "mac-sentinel/mac-sentinel.py" >/dev/null && echo "verified: mac-sentinel running" || echo "ERROR: mac-sentinel NOT running"
ls /var/log/mac-sentinel/file-vault/ 2>/dev/null | head -3
echo "=== deploy2.sh done $(date) ==="
