#!/bin/bash
# netdiag/deploy3.sh — root step: install [AUTO-EVW] conn-guard + pf anchor.
#   1. evw-auto-conn-guard.py / evw-auto-undo.sh / evw-auto-ls-sync.sh -> /usr/local/bin
#   2. pf anchor com.ew.autoblock (table <auto_evw_block>) installed + loaded;
#      tagged stanza appended to /etc/pf.conf (grep-guarded, idempotent)
#   3. com.evw.auto-conn-guard LaunchDaemon installed + started
#   4. config-sentinel re-baselined as evw (pf.conf + new plist absorbed)
# RUN:  sudo bash /Users/evw/dev/fix/netdiag/deploy3.sh
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/deploy3.log) 2>&1
echo "=== deploy3.sh started $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

S=/Users/evw/dev/security/scripts
install -m 755 -o root -g wheel "$S/evw-auto-conn-guard.py" /usr/local/bin/evw-auto-conn-guard.py && echo "installed conn-guard"
install -m 755 -o root -g wheel "$S/evw-auto-undo.sh"       /usr/local/bin/evw-auto-undo.sh       && echo "installed undo"
install -m 755 -o root -g wheel "$S/evw-auto-ls-sync.sh"    /usr/local/bin/evw-auto-ls-sync.sh    && echo "installed ls-sync"

# ── pf anchor (tagged [AUTO-EVW], idempotent) ────────────────────────────────
cat > /etc/pf.anchors/com.ew.autoblock << 'ANCHOR_EOF'
# [AUTO-EVW] outbound/inbound blocks applied by evw-auto-conn-guard.
# Table entries carry a 1h TTL in the guard's state file; undo via
#   sudo evw-auto-undo.sh <action_id|all-blocks>
# Remove the stanza in /etc/pf.conf + this file to disable permanently.
table <auto_evw_block> persist
block drop out quick from any to <auto_evw_block>
block drop in  quick from <auto_evw_block> to any
ANCHOR_EOF
chown root:wheel /etc/pf.anchors/com.ew.autoblock && chmod 644 /etc/pf.anchors/com.ew.autoblock

STANZA='anchor "com.ew.autoblock"'
LOAD='load anchor "com.ew.autoblock" from "/etc/pf.anchors/com.ew.autoblock"'
if ! grep -qF "$STANZA" /etc/pf.conf; then
    cp /etc/pf.conf "/etc/pf.conf.bak.autoevw-$(date +%Y%m%d-%H%M%S)"
    printf '\n# ── [AUTO-EVW] conn-guard auto-block anchor (added 2026-09-01; delete this stanza + /etc/pf.anchors/com.ew.autoblock to disable) ──\n%s\n%s\n' "$STANZA" "$LOAD" >> /etc/pf.conf
    echo "patched /etc/pf.conf (backup saved)"
else
    echo "/etc/pf.conf already has autoblock stanza"
fi
pfctl -f /etc/pf.conf 2>&1 | head -3
pfctl -a com.ew.autoblock -s rules 2>&1 | head -5

# ── LaunchDaemon ─────────────────────────────────────────────────────────────
cat > /Library/LaunchDaemons/com.evw.auto-conn-guard.plist << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.auto-conn-guard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/usr/local/bin/evw-auto-conn-guard.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>UserName</key>
    <string>root</string>
    <key>StandardOutPath</key>
    <string>/var/log/mac-sentinel/auto-conn-guard-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/mac-sentinel/auto-conn-guard-daemon.log</string>
</dict>
</plist>
PLIST_EOF
chown root:wheel /Library/LaunchDaemons/com.evw.auto-conn-guard.plist
chmod 644 /Library/LaunchDaemons/com.evw.auto-conn-guard.plist
launchctl bootout system/com.evw.auto-conn-guard 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.evw.auto-conn-guard.plist && echo "conn-guard daemon loaded"

sleep 4
pgrep -f "evw-auto-conn-guard.py" >/dev/null && echo "verified: conn-guard running" || echo "ERROR: conn-guard NOT running"
pfctl -t auto_evw_block -T show 2>&1 | head -2

# ── Re-baseline config-sentinel as evw (absorbs pf.conf + new plist) ─────────
sudo -u evw HOME=/Users/evw /bin/bash /Users/evw/dev/security/scripts/config-sentinel.sh --baseline 2>&1 | tail -1

echo "=== deploy3.sh done $(date) ==="
