#!/bin/bash
# evw-ls-hourly-cleanup-setup.sh
#
# One-time install of the hourly Little Snitch cleanup:
#   - root-owned copies of the four LS transforms + the driver → /usr/local/bin
#   - com.evw.ls-hourly-cleanup LaunchDaemon (root, StartInterval=3600)
#   - runs the cleanup once and shows the log tail
#
# Must run as root: sudo bash ~/dev/security/evw-ls-hourly-cleanup-setup.sh

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN=/usr/local/bin
PLIST="/Library/LaunchDaemons/com.evw.ls-hourly-cleanup.plist"
LABEL="com.evw.ls-hourly-cleanup"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root"
    exit 1
fi

echo "=== evw-ls-hourly-cleanup setup ==="

echo "[1/5] Installing root-owned transforms + driver..."
guard_run "install-bindir" install -d -m 755 -o root -g wheel "$BIN" || true
for t in ls-dedup.py ls-tighten-all.py ls-security-rescan.py ls-hole-audit.py evw-ls-hourly-cleanup.sh; do
    guard_run "install-$t" install -m 755 -o root -g wheel "$SCRIPT_DIR/$t" "$BIN/$t"
    echo "      $BIN/$t"
done

echo "[2/5] Writing LaunchDaemon plist..."
guard_run "write-plist" cat > "$PLIST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.ls-hourly-cleanup</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/evw-ls-hourly-cleanup.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/private/var/log/evw-ls-hourly-cleanup-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/private/var/log/evw-ls-hourly-cleanup-stdout.log</string>
</dict>
</plist>
PLIST
chmod 644 "$PLIST"; chown root:wheel "$PLIST"

echo "[3/5] (Re)bootstrapping daemon..."
launchctl bootout system "$PLIST" 2>/dev/null || true
guard_run "bootstrap" launchctl bootstrap system "$PLIST"

echo "[4/5] First cleanup run..."
launchctl kickstart "system/$LABEL"
sleep 8

echo "[5/5] Status + log tail:"
launchctl print "system/$LABEL" 2>/dev/null | grep -E "state|last exit" | head -3 || true
tail -12 /private/var/log/evw-ls-hourly-cleanup.log 2>/dev/null || echo "(no log yet)"

echo ""
echo "[✓] Installed. Cleanup runs every 3600s; log: /private/var/log/evw-ls-hourly-cleanup.log"
echo "    Backups/undo/AUTO-ACTIONS: /var/log/mac-sentinel/"
