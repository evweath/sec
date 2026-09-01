#!/bin/bash
# evw-dns-guard-setup.sh
#
# One-time install:
#   - evw-dns-guard.sh → runs every 5 min, re-pins DNS servers if any service drifts
#
# Must run as root: sudo bash ~/dev/security/evw-dns-guard-setup.sh

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# As root, only trust a root-owned lib: a user-writable ancestor dir (e.g.
# Intel Homebrew's /usr/local) could plant one and have it sourced as root.
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

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
guard_run "install-guard" install -m 755 -o root -g wheel "$GUARD_SRC" "$GUARD_DST"
echo "      $GUARD_DST"

echo "[2/4] Writing LaunchDaemon plist..."
guard_run "write-plist" cat > "$GUARD_PLIST" << 'PLIST'
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
guard_run "chmod-plist" chmod 644 "$GUARD_PLIST"
guard_run "chown-plist" chown root:wheel "$GUARD_PLIST"
echo "      $GUARD_PLIST"

echo "[3/4] Loading daemon..."
launchctl unload "$GUARD_PLIST" 2>/dev/null || true
guard_run "launchctl-load" launchctl load -w "$GUARD_PLIST"

echo "[4/4] Verifying..."
sleep 2
launchctl print "system/$GUARD_LABEL" 2>/dev/null | grep -E '^\s+(state|pid) ' | head -4 || {
    echo "ERROR: $GUARD_LABEL not registered after load" >&2
    exit 1
}

echo ""
echo "=== Done ==="
echo ""
echo "Guard: every 5 min → /private/var/log/evw-dns-guard.log"
echo "Live:  sudo tail -f /private/var/log/evw-dns-guard.log"
