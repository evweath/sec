#!/bin/bash
# Rotate hostname to a random plausible device name.
# Run manually or via cron/launchd. Does not require a reboot.
# Usage: sudo /usr/local/bin/rotate_hostname.sh
#
# Install (root-owned pattern — the LaunchDaemon has no UserName so it runs as
# root; the script must therefore live at a root-owned path, NOT ~/dev):
#   sudo install -m 755 -o root -g wheel rotate_hostname.sh /usr/local/bin/
#   sudo cp rotate_hostname.plist /Library/LaunchDaemons/com.ew.rotate-hostname.plist
#   sudo chown root:wheel /Library/LaunchDaemons/com.ew.rotate-hostname.plist
#   sudo launchctl bootstrap system /Library/LaunchDaemons/com.ew.rotate-hostname.plist
# WARNING: never run this daemon from the ~/dev path — a root daemon executing a
# user-writable script is a local privilege-escalation vector.

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (use sudo)"
    exit 1
fi

# Pool of plausible generic hostnames that blend into typical home/office networks
NAMES=(
    "MacBook-Pro"
    "MacBook-Air"
    "Macintosh"
    "iMac"
    "Mac-mini"
    "DESKTOP-$(openssl rand -hex 3 | tr '[:lower:]' '[:upper:]')"
    "LAPTOP-$(openssl rand -hex 3 | tr '[:lower:]' '[:upper:]')"
    "HP-EliteBook"
    "ThinkPad-X1"
    "Surface-Pro"
    "WORKSTATION-$(openssl rand -hex 2 | tr '[:lower:]' '[:upper:]')"
    "Home-PC"
    "Office-Laptop"
    "android-$(openssl rand -hex 4)"
    "Galaxy-S25"
    "Pixel-9"
)

# Pick one at random (exclude current hostname)
CURRENT=$(scutil --get LocalHostName 2>/dev/null || hostname)
NEW_HOST=""
while [ -z "$NEW_HOST" ] || [ "$NEW_HOST" = "$CURRENT" ]; do
    NEW_HOST="${NAMES[$RANDOM % ${#NAMES[@]}]}"
done

echo "[$(date)] Rotating hostname: $CURRENT → $NEW_HOST"

guard_run "scutil-set" scutil --set HostName      "$NEW_HOST"
guard_run "scutil-set" scutil --set LocalHostName "$NEW_HOST"
guard_run "scutil-set" scutil --set ComputerName  "$NEW_HOST"

echo "[$(date)] Done. New hostname: $(scutil --get LocalHostName)"
echo "  Note: open shells show old prompt until refreshed (type 'exec \$SHELL')"
