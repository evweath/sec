#!/bin/bash
# Rotate hostname to a random plausible device name.
# Run manually or via cron/launchd. Does not require a reboot.
# Usage: sudo ./rotate_hostname.sh

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

scutil --set HostName      "$NEW_HOST"
scutil --set LocalHostName "$NEW_HOST"
scutil --set ComputerName  "$NEW_HOST"

echo "[$(date)] Done. New hostname: $(scutil --get LocalHostName)"
echo "  Note: open shells show old prompt until refreshed (type 'exec \$SHELL')"
